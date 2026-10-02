# Bash completion for ArchNetSentry

_archnetsentry_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    opts="-a --audit -H --hunt -d --dns -D --doh -m --spoof-mac -r --restore-mac -R --report --json --no-color -v --version -h --help"

    case "$prev" in
        -D|--doh)
            COMPREPLY=( $(compgen -W "cloudflare quad9 adguard mullvad" -- "$cur") )
            return 0
            ;;
        -m|--spoof-mac|-r|--restore-mac)
            local ifaces
            ifaces=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -vE '^(lo|docker|veth|br-|virbr)')
            COMPREPLY=( $(compgen -W "$ifaces" -- "$cur") )
            return 0
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
        return 0
    fi
}

complete -F _archnetsentry_completion archnetsentry

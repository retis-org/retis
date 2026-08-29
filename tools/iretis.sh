#!/bin/bash
# iretis: run retis and interactively browse events with fzf.
#
# Usage: iretis.sh <collect|sort|print> [retis args...]
#
# Environment variables:
#   RETIS_BIN      path to the retis binary (default: retis from PATH)
#   COLORS         set to 1 to pipe output through bat for syntax highlighting
#   ERR_LOG        path to a file where retis stderr is saved in addition to
#                  being printed after fzf exits (default: not set)
#
# Note:
#   If you built bat cache on custom locations (e.g. you run collect with
#   sudo and your profile was built in the user's homedir) use
#   BAT_CACHE_PATH=$HOME/.cache/bat
#   Use BAT_THEME=<theme> to use a non-default color scheme.

set -e

RETIS_BIN=$(command -v "${RETIS_BIN:-retis}") \
    || { echo "Error: retis not found in PATH or RETIS_BIN"; exit 2; }

_ERR_TMP=$(mktemp)

cleanup() {
    [[ -s "$_ERR_TMP" ]] && cat "$_ERR_TMP" >&2
    [[ -n "$ERR_LOG" ]] && mv "$_ERR_TMP" "$ERR_LOG" || rm -f "$_ERR_TMP"
}
trap cleanup EXIT

command -v fzf >/dev/null 2>&1 \
    || { echo "Error: fzf not found in PATH"; exit 2; }

if [[ "${COLORS:-0}" -eq 1 ]]; then
    command -v bat >/dev/null 2>&1 \
        || { echo "Error: bat not found in PATH (required for COLORS=1)"; exit 2; }
fi

if [[ $# -lt 1 ]]; then
    echo "Usage: iretis.sh <collect|sort|print> [retis args...]"
    exit 2
fi

_SUBCMD=""
for arg in "$@"; do
    case "$arg" in
        collect|sort|print)
            _SUBCMD="$arg"
            break
            ;;
    esac
done

if [[ -z "$_SUBCMD" ]]; then
    echo "Error: one of collect, sort or print must be provided in the extended format"
    exit 2
fi

fzf_cmd="fzf \
    --read0 --multi-line \
    --ansi --no-sort \
    --tac --wrap=char \
    --wrap-sign='>' --gap \
    --highlight-line --bind esc:toggle-track"

if [[ "${COLORS:-0}" -eq 1 ]]; then
    "$RETIS_BIN" "$@" 2> $_ERR_TMP \
        | bat --language retis --color always --paging never -pp \
        | awk 'BEGIN{RS=""; ORS="\0"} {print; fflush()}' \
        | $fzf_cmd
else
    "$RETIS_BIN" "$@" 2> $_ERR_TMP \
        | awk 'BEGIN{RS=""; ORS="\0"} {print; fflush()}' \
        | $fzf_cmd
fi

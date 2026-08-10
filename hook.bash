# arxguard bash hook — pre-execution zero-trust screen for interactive bash.
# Detection is performed by the native C loadable builtin; no Python, Bash regex,
# subprocess, external scanner, or per-command scanner process is used.
[[ $- == *i* ]] || return 0
[[ -n "$_ARXGUARD_BASH_LOADED" ]] && return 0
_ARXGUARD_BASH_LOADED=1
: "${ARXGUARD_LIB:=/usr/share/arxguard}"

if ! builtin type -t arxguard_scan >/dev/null 2>&1; then
  builtin enable -f "$ARXGUARD_LIB/arxguard-builtin.so" arxguard_scan 2>/dev/null || return 0
fi
_arxguard_scan() { arxguard_scan "$1"; }
shopt -s extdebug 2>/dev/null

_arxguard_preexec() {
  [[ -n "${ARXGUARD_INTERNAL:-}" ]] && return 0
  [[ "${ARXGUARD:-1}" == "0" ]] && return 0
  local raw idx line
  raw="$(HISTTIMEFORMAT='' builtin history 1 2>/dev/null)"
  [[ "$raw" =~ ^[[:space:]]*([0-9]+)[[:space:]]+(.*)$ ]] || return 0
  idx="${BASH_REMATCH[1]}"; line="${BASH_REMATCH[2]}"
  [[ "$idx" == "${_ARXGUARD_IDX:-}" ]] && return "${_ARXGUARD_RC:-0}"
  _ARXGUARD_IDX="$idx"; _ARXGUARD_RC=0
  local reason rc
  ARXGUARD_INTERNAL=1; reason="$(_arxguard_scan "$line")"; rc=$?; unset ARXGUARD_INTERNAL
  if (( rc == 1 )); then
    { printf '\n\033[1;31m  arxguard: BLOCKED\033[0m\n'; local l; while IFS= read -r l; do printf '    %s\n' "$l"; done <<<"$reason"; printf '\033[90m  bypass: ARXGUARD=0 <command>\033[0m\n\n'; } >&2
    _ARXGUARD_RC=1; return 1
  elif (( rc == 2 )); then
    { printf '\n\033[1;33m  arxguard: warning\033[0m\n'; local l; while IFS= read -r l; do printf '    %s\n' "$l"; done <<<"$reason"; printf '\n'; } >&2
  fi
  return 0
}

_arxguard_prev_debug="$(trap -p DEBUG 2>/dev/null | sed "s/^trap -- '//;s/' DEBUG\$//")"
if [[ -n "$_arxguard_prev_debug" && "$_ARXGUARD_PREV_DEBUG" != *_arxguard_preexec* ]]; then
  trap "${_arxguard_prev_debug}; _arxguard_preexec" DEBUG
else
  trap '_arxguard_preexec' DEBUG
fi
unset _arxguard_prev_debug
export ARXGUARD_ACTIVE=bash

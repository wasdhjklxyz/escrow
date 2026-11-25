# Sourced by escape cases. try WHAT CMD...: the attempt must fail.
# Reports go to stderr (stdout is escrow's diff). Never prints secrets.
# Cases get host facts as arguments: the jail's env is clean.
esc=0
try() {
  what=$1
  shift
  if out=$("$@" 2>&1); then
    echo "ESCAPED $what" >&2
    esc=1
  else
    echo "BLOCKED $what: $(printf '%s\n' "$out" | head -n1)" >&2
  fi
}

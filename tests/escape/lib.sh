# Sourced by escape cases. try WHAT CMD...: the attempt must fail.
# BLOCKED: it failed. ESCAPED: it succeeded. ERROR: exit 127, the tool
# isn't there, so nothing was tested (a trimmed role must not turn the
# suite green). 126 (found, exec denied) is a block: the noexec cases. Reports go to stderr, which escrow sends to the run log.
# Never prints secrets. Cases get host facts as arguments: the env is clean.
esc=0
try() {
  what=$1
  shift
  st=0
  out=$("$@" 2>&1) || st=$?
  if [ "$st" -eq 0 ]; then
    echo "ESCAPED $what"
    esc=1
  elif [ "$st" -eq 127 ]; then
    echo "ERROR $what: $(printf '%s\n' "$out" | head -n1)"
    esc=1
  else
    echo "BLOCKED $what: $(printf '%s\n' "$out" | head -n1)"
  fi
}

#!/bin/sh
# M3 end-to-end: proposals, roles, review/sign/apply, the hash-chained log.
# Needs a non-root user, ssh-keygen, sha256sum, diff (the devShell has them).
# usage: tests/m3.sh /abs/path/to/escrow POLICY  (POLICY: nix build .#role-test)
set -eu

escrow=${1:?usage: $0 /abs/path/to/escrow POLICY}
policy=${2:?usage: $0 /abs/path/to/escrow POLICY}
if [ "$(id -u)" -eq 0 ]; then
  echo "skip: run as a non-root user" >&2
  exit 0
fi
tmp=$(mktemp -d)
trap 'chmod -R u+rwx "$tmp"; rm -rf "$tmp"' EXIT
cd "$tmp"
export ESCROW_STATE=$tmp/state ESCROW_ROLES=$tmp/roles
fails=0

check() {
  name=$1
  shift
  if "$@"; then
    echo "ok   $name"
  else
    echo "FAIL $name"
    fails=$((fails + 1))
  fi
}
# refused NAME CMD...: CMD must fail (exit 1) and print WHY to stderr.
refused() {
  name=$1 why=$2
  shift 2
  st=0
  "$@" >/dev/null 2>"$tmp/err" || st=$?
  if [ "$st" -ne 0 ] && grep -q -- "$why" "$tmp/err"; then
    echo "ok   $name"
  else
    echo "FAIL $name (exit $st): $(head -n2 "$tmp/err")"
    fails=$((fails + 1))
  fi
}
pub() { cut -d' ' -f1,2 "$1.pub"; }
snapshot() {
  (cd "$1" && find . -printf '%P %y %m %s %l\n' | sort &&
    find . -type f -exec sha256sum {} + | sort)
}
run() { "$escrow" --role "$policy" --workspace ws "$@" 2>>"$tmp/run.err"; }
last_id() { "$escrow" list | tail -n1 | cut -d' ' -f1; }

for u in alice bob carol dave erin mallory; do
  ssh-keygen -q -t ed25519 -N '' -C "$u" -f "$u"
done
{
  echo "# who may do what"
  echo "alice requester $(pub alice)"
  echo "bob reviewer $(pub bob)"
  echo "carol signer $(pub carol)"
  echo "dave reviewer,signer $(pub dave)"
  echo "erin requester,reviewer $(pub erin)"
} >roles

mkdir ws ws/etc
printf 'users.ops = [ "alice" ];\n' >ws/etc/ops.nix
echo old-key >ws/etc/service.key
echo keep >ws/keep
ln -s /etc ws/etc-link

# -- happy path -----------------------------------------------------------
run --key alice -- sh -c '
  sed -i "s/\"alice\" \]/\"alice\" \"bob\" ]/" etc/ops.nix
  printf "new-key\033[2J\n" >etc/service.key
  mkdir new; echo x >new/f; unlink etc-link' >/dev/null
p1=$(last_id)
check "propose: listed" sh -c '"$1" list | grep -q "^$2 .*proposed *alice"' \
  _ "$escrow" "$p1"
check "propose: record + signature on disk" \
  test -s "state/runs/$p1/record" -a -s "state/runs/$p1/1-propose.sig"
"$escrow" review "$p1" >review.out 2>/dev/null
check "review: shows the content diff" \
  grep -qx '+users.ops = \[ "alice" "bob" \];' review.out
check "review: escapes terminal bytes" grep -q 'new-key\\033\[2J' review.out
check "review: no raw ESC byte" sh -c '! grep -q "$(printf "\033")" review.out'
check "review: shows the deletion" grep -qx 'D etc-link' review.out
before=$(snapshot ws)
refused "sign before review" "not been reviewed" \
  "$escrow" sign "$p1" --key carol
refused "requester-only key can't review" "is not a reviewer" \
  "$escrow" review "$p1" --key alice
refused "unknown key can't review" "signed by no key" \
  "$escrow" review "$p1" --key mallory
refused "signer-only key can't review" "is not a reviewer" \
  "$escrow" review "$p1" --key carol
"$escrow" review "$p1" --key bob >/dev/null 2>&1
refused "second review refused" "already reviewed" \
  "$escrow" review "$p1" --key dave
refused "reviewer-only key can't sign" "is not a signer" \
  "$escrow" sign "$p1" --key bob
refused "apply before signing" "is not signed" \
  "$escrow" apply "$p1" --key carol
check "no stray signature files from refusals" \
  sh -c '[ "$(ls state/runs/$1/*.sig | wc -l)" -eq 2 ]' _ "$p1"
"$escrow" sign "$p1" --key carol >/dev/null 2>&1
check "workspace untouched until apply" [ "$(snapshot ws)" = "$before" ]
refused "requester can't apply" "may not apply" \
  "$escrow" apply "$p1" --key alice
"$escrow" apply "$p1" --key carol 2>/dev/null
check "apply: config changed" \
  grep -qx 'users.ops = \[ "alice" "bob" \];' ws/etc/ops.nix
check "apply: exact bytes" \
  [ "$(od -An -c ws/etc/service.key | tr -d ' \n')" = 'new-key033[2J\n' ]
check "apply: new dir and file" [ "$(cat ws/new/f)" = x ]
check "apply: symlink deleted, not followed" \
  sh -c '[ ! -e ws/etc-link ] && [ ! -L ws/etc-link ] && [ -d /etc ]'
check "apply: untouched file kept" [ "$(cat ws/keep)" = keep ]
check "apply: no staging copy left" \
  sh -c '! ls -a . | grep -q "escrow-"'
refused "double apply" "already applied" "$escrow" apply "$p1" --key carol
check "verify-log ok" sh -c '"$1" verify-log | grep -q "^ok: 4 events, head "' \
  _ "$escrow"
check "list shows applied" sh -c '"$1" list | grep -q "^$2 .*applied"' \
  _ "$escrow" "$p1"

# -- dual-role principal: dave may review or sign, never both -------------
run --key alice -- sh -c 'echo two >two' >/dev/null
p2=$(last_id)
"$escrow" review "$p2" --key dave >/dev/null 2>&1
refused "reviewer can't also sign" "reviewed it" \
  "$escrow" sign "$p2" --key dave

# -- self-review: erin holds requester and reviewer ---------------------
run --key erin -- sh -c 'echo e >e' >/dev/null
pe=$(last_id)
refused "requester can't review her own" "no self-review" \
  "$escrow" review "$pe" --key erin

# -- tampering ------------------------------------------------------------
cp "state/runs/$p2/record" rec.bak
sed -i 's/^exit 0$/exit 1/' "state/runs/$p2/record"
refused "tampered record refused" "changed since it was proposed" \
  "$escrow" review "$p2"
cp rec.bak "state/runs/$p2/record"
printf 'x' >>"state/runs/$p2/changes"
refused "tampered change set refused" "not the change set" \
  "$escrow" review "$p2"
truncate -s -1 "state/runs/$p2/changes"
cp state/log log.bak
sed -i '2s/T/X/' state/log
refused "edited log line refused" "log line 3: chain broken" \
  "$escrow" verify-log
cp log.bak state/log
sed -i '1d' state/log
refused "removed log line refused" "seq 2 out of order" "$escrow" verify-log
cp log.bak state/log
"$escrow" sign "$p2" --key carol >/dev/null 2>&1
echo drift >ws/drift
refused "base moved: apply refused" "workspace moved" \
  "$escrow" apply "$p2" --key carol
check "base moved: workspace untouched" [ ! -e ws/two ]
unlink ws/drift
cp roles roles.bak
echo "eve requester $(pub mallory)" >>roles
refused "roles file changed: refused" "different roles file" \
  "$escrow" review "$p2"
cp roles.bak roles
"$escrow" apply "$p2" --key carol 2>/dev/null
check "apply after drift reverted" [ "$(cat ws/two)" = two ]

# -- not proposable -------------------------------------------------------
st=0
run --key alice -- sh -c 'cp keep tool; chmod 4755 tool' >/dev/null || st=$?
check "set-id file: not proposable" sh -c \
  '[ "$1" -eq 1 ] && grep -q "set-id" "$2"' _ "$st" "$tmp/run.err"
st=0
run -- sh -c 'echo nokey >nokey' >nokey.out || st=$?
check "no --key: diff only, no proposal" sh -c \
  '[ "$1" -eq 0 ] && grep -qx "A nokey" nokey.out &&
   [ "$("$2" list | wc -l)" -eq 3 ]' _ "$st" "$escrow"

# -- apply never follows a symlink: a hand-crafted, fully signed proposal -
ln -s "$tmp/outside" ws/link
mkdir outside
run --key alice -- true >/dev/null # pins the new base (with ws/link)
p3=$(last_id)
src=state/runs/$p3
evil=EviL01
mkdir "state/runs/$evil"
printf 'escrow-changes 1\nf 644 6 5\nlink/xownede\n' >"state/runs/$evil/changes"
csha=$(sha256sum "state/runs/$evil/changes" | cut -d' ' -f1)
sed -e "s/^id .*/id $evil/" -e "s/^changes .*/changes $csha/" \
  "$src/record" >"state/runs/$evil/record"
seq=$(($(wc -l <state/log) + 1))
ssh-keygen -q -Y sign -f alice -n escrow-propose \
  <"state/runs/$evil/record" >"state/runs/$evil/$seq-propose.sig"
prev=$(tail -n1 state/log | sha256sum | cut -d' ' -f1)
rsha=$(sha256sum "state/runs/$evil/record" | cut -d' ' -f1)
ssha=$(sha256sum "state/runs/$evil/$seq-propose.sig" | cut -d' ' -f1)
roles_sha=$(sha256sum roles | cut -d' ' -f1)
echo "$seq 2026-01-01T00:00:00Z propose $evil alice $rsha $ssha - $roles_sha $prev" \
  >>state/log
"$escrow" review "$evil" --key bob >/dev/null 2>&1
"$escrow" sign "$evil" --key carol >/dev/null 2>&1
before=$(snapshot ws)
refused "crafted link/x: apply refused" "apply f link/x" \
  "$escrow" apply "$evil" --key carol
check "crafted link/x: nothing written outside" [ ! -e outside/x ]
check "crafted link/x: workspace untouched" [ "$(snapshot ws)" = "$before" ]
printf 'escrow-changes 1\nD 0 2 0\n..e\n' >bad.changes
cp "state/runs/$evil/changes" evil.changes
cp bad.changes "state/runs/$evil/changes"
refused "change set with .. refused" "bad path\|not the change set" \
  "$escrow" review "$evil"
cp evil.changes "state/runs/$evil/changes"

check "verify-log still ok" sh -c '"$1" verify-log >/dev/null' _ "$escrow"

[ "$fails" -eq 0 ]

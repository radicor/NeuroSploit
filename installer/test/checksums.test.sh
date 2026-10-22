#!/usr/bin/env bash
# Drives setup.sh's verify_archive / resolve_ref. Those are sourceable because the
# script returns early when sourced (see the BASH_SOURCE guard), which is what makes
# "a mismatch aborts" testable instead of inspection-only.
set -uo pipefail   # deliberately NOT -e: a non-zero return is what we assert on

here="$(cd "$(dirname "$0")/../.." && pwd)"
fails=0

check() { # check <desc> <expected-rc> <actual-rc>
  if [ "$3" = "$2" ]; then
    printf '  ok   %s\n' "$1"
  else
    printf '  FAIL %s (expected rc=%s, got %s)\n' "$1" "$2" "$3"
    fails=$((fails + 1))
  fi
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

asset="neurosploit-v9.9.9-linux-x86_64.tar.gz"
printf 'payload\n' > "$tmp/$asset"
( cd "$tmp" && sha256sum "$asset" > SHA256SUMS )

# TN-1: a matching archive verifies
( . "$here/setup.sh" >/dev/null 2>&1; verify_archive "$tmp" "$asset" )
check "a correct archive verifies (TN-1)" 0 $?

# TN-2: altered bytes abort
printf 'tampered\n' >> "$tmp/$asset"
( . "$here/setup.sh" >/dev/null 2>&1; verify_archive "$tmp" "$asset" )
check "a tampered archive aborts (TN-2)" 1 $?

# TN-3: the insecure flag must NOT excuse a mismatch
( . "$here/setup.sh" >/dev/null 2>&1; NEUROSPLOIT_INSECURE=1 verify_archive "$tmp" "$asset" )
check "insecure flag does not excuse a mismatch (TN-3)" 1 $?

# restore, then exercise the missing-sums path
printf 'payload\n' > "$tmp/$asset"
( cd "$tmp" && sha256sum "$asset" > SHA256SUMS )
mv "$tmp/SHA256SUMS" "$tmp/SHA256SUMS.off"
( . "$here/setup.sh" >/dev/null 2>&1; verify_archive "$tmp" "$asset" )
check "a missing sums file aborts (TN-3)" 1 $?
( . "$here/setup.sh" >/dev/null 2>&1; NEUROSPLOIT_INSECURE=1 verify_archive "$tmp" "$asset" )
check "missing sums is allowed only with the flag (TN-3)" 0 $?
mv "$tmp/SHA256SUMS.off" "$tmp/SHA256SUMS"

# TN-7: a sums file that names a DIFFERENT asset must fail on "no entry" — not on
# "no sums file", which is a different branch.
mkdir -p "$tmp/other"
cp "$tmp/$asset" "$tmp/other/other.tar.gz"
( cd "$tmp/other" && sha256sum other.tar.gz > SHA256SUMS && sed -i 's/other\.tar\.gz/different.tar.gz/' SHA256SUMS )
tn7_rc=0
tn7_err="$( . "$here/setup.sh" >/dev/null 2>&1; verify_archive "$tmp/other" "other.tar.gz" 2>&1 >/dev/null )" || tn7_rc=$?
check "an entry for another asset is refused (TN-7)" 1 "$tn7_rc"
case "$tn7_err" in
  *"no entry"*) printf '  ok   the refusal is the no-entry branch (TN-7)\n' ;;
  *) printf '  FAIL expected a no-entry refusal, got: %s\n' "$tn7_err"; fails=$((fails + 1)) ;;
esac

# TN-4c: a checkout knows its own version (criterion 7's second mechanism)
mkdir -p "$tmp/co/neurosploit-rs"
printf '[package]\nname = "x"\nversion = "9.8.7"\n' > "$tmp/co/neurosploit-rs/Cargo.toml"
co_got="$( . "$here/setup.sh" >/dev/null 2>&1
  dl() { return 1; }
  cd "$tmp/co" || exit 9
  NEUROSPLOIT_REF= resolve_ref 2>/dev/null )"
check "resolve_ref falls back to the checkout's Cargo.toml (TN-4)" "v9.8.7" "$co_got"

# TN-4: no invented version — API down, no checkout, no NEUROSPLOIT_REF
( . "$here/setup.sh" >/dev/null 2>&1
  dl() { return 1; }
  cd "$tmp" || exit 9
  NEUROSPLOIT_REF= resolve_ref >/dev/null 2>&1 )
check "resolve_ref fails instead of inventing a tag (TN-4)" 1 $?

# TN-4b: a pinned ref is returned verbatim
( . "$here/setup.sh" >/dev/null 2>&1
  got="$(NEUROSPLOIT_REF=v4.4.0 resolve_ref)"
  [ "$got" = "v4.4.0" ] )
check "resolve_ref honours NEUROSPLOIT_REF (TN-4)" 0 $?

printf '\n%s\n' "$([ "$fails" -eq 0 ] && echo 'checksums: all checks passed' || echo "checksums: $fails check(s) failed")"
exit "$fails"

#!/usr/bin/env bash
# NeuroSploit installer — by Joas A Santos & Red Team Leaders
#
#   curl -fsSL https://raw.githubusercontent.com/JoasASantos/NeuroSploit/main/setup.sh | bash
#
# Downloads the prebuilt `neurosploit` binary + agent library, installs them, and
# sets up PATH + NEUROSPLOIT_BASE so you can run `neurosploit` from ANY folder —
# no need to cd into the repo. Falls back to building from source if no prebuilt
# asset fits (or NEUROSPLOIT_BUILD=1). Safe to re-run (idempotent). Honors:
#   NEUROSPLOIT_DIR   install dir         (default: ~/.neurosploit-app)
#   NEUROSPLOIT_REF   release tag/branch  (default: latest release)
#   NEUROSPLOIT_BUILD 1 = build from source instead of downloading
#   PREFIX            bin symlink dir     (default: ~/.local/bin)
set -euo pipefail

REPO_SLUG="JoasASantos/NeuroSploit"
REPO="https://github.com/${REPO_SLUG}.git"
DIR="${NEUROSPLOIT_DIR:-$HOME/.neurosploit-app}"
PREFIX="${PREFIX:-$HOME/.local/bin}"

c()  { printf '\033[%sm%s\033[0m\n' "$1" "$2"; }
say(){ c '1;35' "  ▌ $*"; }
ok() { c '1;32' "  ✓ $*"; }
warn(){ c '1;33' "  ! $*"; }
die(){ c '1;31' "  ✗ $*"; exit 1; }

cat <<'BANNER'

   ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗
   ████╗  ██║██╔════╝██║   ██║██╔══██╗██╔═══██╗   NeuroSploit installer
   ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║   ██║   — Rust harness
   ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║   by Joas A Santos
   ██║ ╚████║███████╗╚██████╔╝██║  ██║╚██████╔╝   & Red Team Leaders
   ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝
BANNER

# ---- platform detection (Linux / macOS / Windows-WSL · x64 / arm64) ----
OS_RAW="$(uname -s)"; ARCH_RAW="$(uname -m)"
case "$OS_RAW" in
  Linux*)  OS="linux" ;;
  Darwin*) OS="macos" ;;
  MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
  *) OS="$OS_RAW" ;;
esac
case "$ARCH_RAW" in
  x86_64|amd64)  ARCH="x64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) ARCH="$ARCH_RAW" ;;
esac
PLAT="${OS}-${ARCH}"
say "Platform: $PLAT"
[ "$OS" = "windows" ] && warn "Native Windows: prefer install.ps1 (PowerShell). This path works under WSL2/Git Bash."

dl() { # dl <url> <out>
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
  else return 1; fi
}

# ---- resolve the release tag (latest, unless pinned) ----
# Never invent a version: a hard-coded fallback silently installs whatever was
# current when this script was written.
resolve_ref() {
  r="${NEUROSPLOIT_REF:-}"
  if [ -z "$r" ]; then
    r="$(dl "https://api.github.com/repos/${REPO_SLUG}/releases/latest" /dev/stdout 2>/dev/null \
         | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name" *: *"([^"]+)".*/\1/' || true)"
  fi
  if [ -z "$r" ]; then
    for f in "$(dirname "$0")/neurosploit-rs/Cargo.toml" ./neurosploit-rs/Cargo.toml; do
      if [ -f "$f" ]; then
        v="$(sed -nE 's/^version *= *"([^"]+)".*/\1/p' "$f" | head -1)"
        if [ -n "$v" ]; then r="v$v"; break; fi
      fi
    done
  fi
  if [ -z "$r" ]; then
    echo "error: cannot determine the release tag; set NEUROSPLOIT_REF=vX.Y.Z" >&2
    return 1
  fi
  printf '%s\n' "$r"
}

# verify_archive <dir> <archive-name>
# A mismatch ALWAYS aborts. NEUROSPLOIT_INSECURE=1 exempts only a *missing* sums
# file (old tags), never altered bytes — otherwise the flag means "install anything".
verify_archive() {
  vdir="$1"; vname="$2"
  if [ ! -f "$vdir/SHA256SUMS" ]; then
    if [ "${NEUROSPLOIT_INSECURE:-0}" = "1" ]; then
      warn "SHA256SUMS missing for this release — continuing because NEUROSPLOIT_INSECURE=1"
      return 0
    fi
    echo "error: SHA256SUMS missing; refusing to install unverified (set NEUROSPLOIT_INSECURE=1 only for old tags)" >&2
    return 1
  fi
  vline="$(grep -E "[[:space:]]\*?${vname}\$" "$vdir/SHA256SUMS" | head -1)"
  if [ -z "$vline" ]; then
    echo "error: SHA256SUMS has no entry for ${vname}" >&2
    return 1
  fi
  # one line only: an entry for a different asset must not satisfy this check
  printf '%s\n' "$vline" > "$vdir/.verify-$$.sum"
  # Absorb the failure explicitly: under `set -e` (which leaks in when this file is
  # sourced) an uncaught non-zero would kill the function before vrc is captured,
  # making the abort an errexit accident rather than this guard's return contract.
  vrc=0
  ( cd "$vdir" && sha256sum -c ".verify-$$.sum" >/dev/null 2>&1 ) || vrc=$?
  rm -f "$vdir/.verify-$$.sum"
  return $vrc
}

# Sourced by installer/test/checksums.test.sh: define the functions, then stop.
if [ "${BASH_SOURCE[0]}" != "$0" ]; then return 0; fi

# PREFIX is a write target and gets prepended to PATH; outside $HOME needs consent.
UNSAFE_PREFIX=0
for a in "$@"; do [ "$a" = "--unsafe-prefix" ] && UNSAFE_PREFIX=1; done
case "$PREFIX" in
  "$HOME"/*) : ;;
  *) if [ "$UNSAFE_PREFIX" != "1" ]; then
       die "refusing to write to $PREFIX (outside \$HOME); pass --unsafe-prefix if that is intended"
     fi ;;
esac

REF="$(resolve_ref)" || die "cannot determine the release tag"
say "Release: $REF"

installed=0
if [ "${NEUROSPLOIT_BUILD:-0}" != "1" ] && [ "$OS" != "windows" ]; then
  # ---- try the prebuilt asset (no Rust needed) ----
  ASSET="neurosploit-${REF}-${PLAT}.tar.gz"
  URL="https://github.com/${REPO_SLUG}/releases/download/${REF}/${ASSET}"
  TMP="$(mktemp -d)"
  say "Downloading prebuilt binary: $ASSET"
  if dl "$URL" "$TMP/$ASSET"; then
    mkdir -p "$DIR"
    # Verify BEFORE unpacking: extraction of an unverified archive is the risk.
    dl "https://github.com/${REPO_SLUG}/releases/download/${REF}/SHA256SUMS" "$TMP/SHA256SUMS" 2>/dev/null || true
    if ! verify_archive "$TMP" "$ASSET"; then
      rm -rf "$TMP"
      die "checksum verification failed for $ASSET"
    fi
    tar -xzf "$TMP/$ASSET" -C "$TMP" 2>/dev/null || die "download was not a valid archive"
    SRC="$(find "$TMP" -maxdepth 2 -name neurosploit -type f | head -1)"
    [ -n "$SRC" ] || die "extracted archive has no neurosploit binary"
    SRCDIR="$(dirname "$SRC")"
    rm -rf "$DIR/neurosploit" "$DIR/agents_md"
    cp "$SRCDIR/neurosploit" "$DIR/neurosploit"
    cp -R "$SRCDIR/agents_md" "$DIR/agents_md"
    chmod +x "$DIR/neurosploit"
    rm -rf "$TMP"
    installed=1
    ok "Downloaded & unpacked → $DIR"
  else
    rm -rf "$TMP"
    warn "No prebuilt asset for $PLAT ($REF) — building from source instead."
  fi
fi

if [ "$installed" != "1" ]; then
  # ---- build from source (needs git + Rust) ----
  command -v git >/dev/null 2>&1 || die "git is required to build from source."
  if ! command -v cargo >/dev/null 2>&1; then
    if [ -f "$HOME/.cargo/env" ]; then
      # shellcheck source=/dev/null
      . "$HOME/.cargo/env"
    fi
  fi
  if ! command -v cargo >/dev/null 2>&1; then
    say "Rust not found — installing rustup (stable, minimal)…"
    RUSTUP_TMP="$(mktemp -d)"
    if ! dl "https://sh.rustup.rs" "$RUSTUP_TMP/rustup.sh"; then
      rm -rf "$RUSTUP_TMP"; die "could not download the rustup installer"
    fi
    if [ -n "${NEUROSPLOIT_RUSTUP_SHA256:-}" ]; then
      printf '%s  %s\n' "$NEUROSPLOIT_RUSTUP_SHA256" "$RUSTUP_TMP/rustup.sh" > "$RUSTUP_TMP/sum"
      ( cd "$RUSTUP_TMP" && sha256sum -c sum >/dev/null 2>&1 ) \
        || { rm -rf "$RUSTUP_TMP"; die "rustup installer failed checksum verification"; }
    else
      warn "no pinned checksum for the rustup installer — set NEUROSPLOIT_RUSTUP_SHA256 to verify it"
    fi
    sh "$RUSTUP_TMP/rustup.sh" -y --default-toolchain stable --profile minimal
    rm -rf "$RUSTUP_TMP"
    # shellcheck source=/dev/null
    . "$HOME/.cargo/env"
  fi
  ok "Rust: $(cargo --version)"
  SRC_CO="$DIR/src"
  if [ -d "$SRC_CO/.git" ]; then
    say "Updating checkout…"; git -C "$SRC_CO" fetch --depth 1 origin "$REF" 2>/dev/null && git -C "$SRC_CO" checkout -q FETCH_HEAD 2>/dev/null || git -C "$SRC_CO" pull -q || true
  else
    say "Cloning $REPO ($REF)…"; git clone --depth 1 --branch "$REF" "$REPO" "$SRC_CO" 2>/dev/null || git clone --depth 1 "$REPO" "$SRC_CO"
  fi
  say "Building release binary (first build downloads crates)…"
  ( cd "$SRC_CO/neurosploit-rs" && cargo build --release )
  cp "$SRC_CO/neurosploit-rs/target/release/neurosploit" "$DIR/neurosploit"
  rm -rf "$DIR/agents_md"; cp -R "$SRC_CO/agents_md" "$DIR/agents_md"
  chmod +x "$DIR/neurosploit"
  ok "Built → $DIR"
fi

# ---- install on PATH ----
mkdir -p "$PREFIX"
ln -sf "$DIR/neurosploit" "$PREFIX/neurosploit"
ok "Linked → $PREFIX/neurosploit"

# ---- write a source-able env script (activate in the CURRENT shell) ----
cat > "$DIR/env.sh" <<EOF
# NeuroSploit env — \`source\` this to use neurosploit in the current shell.
export NEUROSPLOIT_BASE="$DIR"
export NEUROSPLOIT="$DIR/neurosploit"
case ":\$PATH:" in *":$PREFIX:"*) : ;; *) export PATH="$PREFIX:\$PATH" ;; esac
EOF
ok "Wrote env script → $DIR/env.sh  (source it to activate now)"
ok "Version: $(NEUROSPLOIT_BASE="$DIR" "$DIR/neurosploit" --version 2>/dev/null || echo neurosploit)"

# ---- persist env (PATH + NEUROSPLOIT_BASE) so it runs from any folder ----
persist() { # append an idempotent block to a shell rc that exists
  local rc="$1"; [ -e "$rc" ] || return 0
  grep -q 'NEUROSPLOIT_BASE' "$rc" 2>/dev/null && return 0
  { echo ''; echo '# NeuroSploit (added by setup.sh)'
    echo "export NEUROSPLOIT_BASE=\"$DIR\""
    echo "export PATH=\"$PREFIX:\$PATH\""; } >> "$rc"
  ok "Configured $rc"
}
SHELL_NAME="$(basename "${SHELL:-bash}")"
case "$SHELL_NAME" in
  zsh)  touch "$HOME/.zshrc"; persist "$HOME/.zshrc" ;;
  bash) touch "$HOME/.bashrc"; persist "$HOME/.bashrc"; persist "$HOME/.bash_profile" ;;
  *)    touch "$HOME/.profile"; persist "$HOME/.profile" ;;
esac
if [ -d "$HOME/.config/fish" ]; then
  FCONF="$HOME/.config/fish/config.fish"
  if ! grep -q 'NEUROSPLOIT_BASE' "$FCONF" 2>/dev/null; then
    { echo ''; echo '# NeuroSploit'; echo "set -gx NEUROSPLOIT_BASE \"$DIR\""; echo "set -gx PATH \"$PREFIX\" \$PATH"; } >> "$FCONF"
    ok "Configured $FCONF"
  fi
fi

# ---- dependencies: detect, and install the ones a package manager can ----
# Core recon/report tools. Rust is already handled above. Auto-install is
# best-effort: it never fails the install, and is skipped with NEUROSPLOIT_NO_DEPS=1.
PKG=""; SUDO=""
if   command -v apt-get >/dev/null 2>&1; then PKG="apt"
elif command -v brew    >/dev/null 2>&1; then PKG="brew"
elif command -v dnf     >/dev/null 2>&1; then PKG="dnf"
elif command -v pacman  >/dev/null 2>&1; then PKG="pacman"
elif command -v apk     >/dev/null 2>&1; then PKG="apk"; fi
[ "$(id -u)" = "0" ] || command -v sudo >/dev/null 2>&1 && [ "$(id -u)" != "0" ] && SUDO="sudo"

pkg_install() { # pkg_install <name...>
  [ -n "$PKG" ] || { warn "no supported package manager — install manually: $*"; return 0; }
  case "$PKG" in
    apt)    $SUDO apt-get update -qq >/dev/null 2>&1; $SUDO apt-get install -y "$@" >/dev/null 2>&1 ;;
    brew)   brew install "$@" >/dev/null 2>&1 ;;
    dnf)    $SUDO dnf install -y "$@" >/dev/null 2>&1 ;;
    pacman) $SUDO pacman -Sy --noconfirm "$@" >/dev/null 2>&1 ;;
    apk)    $SUDO apk add "$@" >/dev/null 2>&1 ;;
  esac
}

# Map a required command to its package name on the detected manager.
pkg_name() { # pkg_name <cmd>
  case "$1" in
    npx) echo "node" ;;   # npx ships with node
    node) [ "$PKG" = "apt" ] && echo "nodejs" || echo "node" ;;
    *) echo "$1" ;;
  esac
}

if [ "${NEUROSPLOIT_NO_DEPS:-0}" != "1" ]; then
  say "Checking dependencies (install with the detected package manager: ${PKG:-none})…"
  # Essential for the web console + recon; typst is for PDF reports (optional).
  for t in curl git nmap node; do
    if command -v "$t" >/dev/null 2>&1; then ok "$t present"; else
      warn "$t missing — installing…"; pkg_install "$(pkg_name "$t")"
      if command -v "$t" >/dev/null 2>&1; then ok "$t installed"; else warn "could not install $t automatically — install it manually"; fi
    fi
  done
  # Rust-cargo extras + report engine: install via cargo when present (no root).
  if command -v cargo >/dev/null 2>&1; then
    if ! command -v rustscan >/dev/null 2>&1; then
      say "installing rustscan (cargo)…"
      if cargo install rustscan >/dev/null 2>&1; then ok "rustscan installed"; else warn "rustscan optional — skipped"; fi
    fi
    if ! command -v typst >/dev/null 2>&1; then
      say "installing typst (cargo)…"
      if cargo install typst-cli >/dev/null 2>&1; then ok "typst installed"; else warn "typst optional (PDF reports) — skipped"; fi
    fi
  fi
  # ffuf is Go; only hint it.
  if command -v ffuf >/dev/null 2>&1; then ok "ffuf present"; else warn "ffuf optional (fuzzing) — install via your package manager or Go"; fi
else
  say "Dependency auto-install skipped (NEUROSPLOIT_NO_DEPS=1)."
  for t in curl git nmap node rustscan ffuf typst; do
    if command -v "$t" >/dev/null 2>&1; then ok "$t present"; else warn "$t missing"; fi
  done
fi

echo
ok "Installed. Open a NEW terminal — or activate now with:"
echo "      source \"$DIR/env.sh\""
echo "  (equivalently: export NEUROSPLOIT_BASE=\"$DIR\"; export PATH=\"$PREFIX:\$PATH\")"
echo "  then, from ANY folder:"
echo "      neurosploit                 # interactive session"
echo "      neurosploit run http://testphp.vulnweb.com/ --subscription --model anthropic:claude-opus-4-8 -v"
echo "      neurosploit --help"
echo
warn "Update later: just re-run this script.   Best runtime: Kali (docker run -it kalilinux/kali-rolling)."

# ---- optionally launch right away ----
# `curl | bash` has no TTY, so auto-run only when asked (NEUROSPLOIT_RUN=1) or
# when a real terminal is attached and the operator confirms.
RUN_NOW="${NEUROSPLOIT_RUN:-}"
if [ -z "$RUN_NOW" ] && [ -t 0 ]; then
  printf '\n  Launch the interactive session now? [y/N] '; read -r ans
  case "$ans" in y|Y|yes) RUN_NOW=1 ;; esac
fi
if [ "$RUN_NOW" = "1" ]; then
  say "Starting NeuroSploit…"
  exec env NEUROSPLOIT_BASE="$DIR" "$DIR/neurosploit"
fi

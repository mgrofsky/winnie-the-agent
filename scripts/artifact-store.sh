#!/bin/bash
# artifact-store.sh: keep pinned operator-supplied artifacts (for example lookup databases) in a store the
# operator chooses, and get them back verified against a local SHA256SUMS file.
#
#   artifact-store.sh [plan|put|get|verify] --sums PATH --dataset NAME --month YYYY-MM
#                     [--store URL] [--dest DIR] [--config FILE]
#
#   plan    (default) check the local files against SHA256SUMS and print what put would do.
#           Touches nothing: no store access, no provider CLI, no network.
#   put     refuse unless every local file matches SHA256SUMS. For each file: if the store
#           already has it, download it and hash it; skip if it matches, FAIL if it does not.
#           Otherwise upload (never overwriting), then download it again and hash it.
#   get     download into an EMPTY directory; hash every file against SHA256SUMS; a file that
#           fails is deleted and the run fails.
#   verify  read-only on the store: download each file to a temporary directory, hash it,
#           report, and delete the temporary copies.
#
# Store URL (flag --store, else env ARTIFACT_STORE, else "store=" in the config file):
#   s3://bucket/prefix   gs://bucket/prefix   az://account/container/prefix   file:///abs/path
# Any other scheme is refused. A file:// path may contain spaces; put the whole URL in quotes.
# Credentials come only from the provider CLI (its own login, profile or environment); this
# tool never reads, takes or prints one.
#
# file:// only: the path must be canonical (no symlink anywhere in it). put requires either
# ARTIFACT_STORE_MOUNT=/mnt/encrypted-artifacts (the store must sit on that mount point,
# checked with df)
# or ARTIFACT_STORE_LOCAL_DISK_OK=1 (an explicit waiver: the folder may be on the build disk).
# get and verify only warn. Encryption, backup and who else can read the drive are the
# operator's checks; the tool cannot see them.
#
# Trust: SHA256SUMS (a local file you reviewed) is the only source of trust. The store is
# untrusted; every decision is made by hashing downloaded bytes locally.
# Object name: <prefix>/<dataset>/<month>/<sha256>/<file name>. There is no delete mode.
set -euo pipefail
umask 077

die() { echo "artifact-store: $*" >&2; exit 1; }
say() { echo "artifact-store: $*"; }
warn() { echo "artifact-store: warning: $*" >&2; }

# ---------------------------------------------------------------- arguments and config
MODE=plan
case "${1:-}" in plan|put|get|verify) MODE=$1; shift ;; esac
STORE_FLAG= SUMS= DATASET= MONTH= DEST= CONFIG=${ARTIFACT_STORE_CONFIG:-}
while [ $# -gt 0 ]; do
  case "$1" in
    --store)   STORE_FLAG=${2:?}; shift 2 ;;
    --sums)    SUMS=${2:?}; shift 2 ;;
    --dataset) DATASET=${2:?}; shift 2 ;;
    --month)   MONTH=${2:?}; shift 2 ;;
    --dest)    DEST=${2:?}; shift 2 ;;
    --config)  CONFIG=${2:?}; shift 2 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) die "unknown argument: $1 (modes: plan put get verify; there is no delete)" ;;
  esac
done

# The config file is parsed, never sourced. Lines: key=value with key one of store, dataset,
# month. The value is everything after "=", with surrounding spaces and one pair of matching
# quotes removed, so a path with spaces works. A line starting with # is a comment.
CFG_STORE= CFG_DATASET= CFG_MONTH=
trim() { local v=$1; v=${v#"${v%%[![:space:]]*}"}; v=${v%"${v##*[![:space:]]}"}; printf '%s' "$v"; }
if [ -n "$CONFIG" ]; then
  [ -f "$CONFIG" ] || die "config file not found: $CONFIG"
  while IFS= read -r line || [ -n "$line" ]; do
    line=$(trim "$line")
    case "$line" in ''|'#'*) continue ;; esac
    case "$line" in *=*) ;; *) die "config: line is not key=value" ;; esac
    k=$(trim "${line%%=*}"); v=$(trim "${line#*=}")
    case "$v" in \"*\") v=${v#\"}; v=${v%\"} ;; \'*\') v=${v#\'}; v=${v%\'} ;; esac
    case "$k" in
      store|ARTIFACT_STORE) CFG_STORE=$v ;;
      dataset) CFG_DATASET=$v ;;
      month)   CFG_MONTH=$v ;;
      *) die "config: unknown setting (only store, dataset, month are allowed)" ;;
    esac
  done < "$CONFIG"
fi
STORE=${STORE_FLAG:-${ARTIFACT_STORE:-$CFG_STORE}}
DATASET=${DATASET:-${ARTIFACT_DATASET:-$CFG_DATASET}}
MONTH=${MONTH:-${ARTIFACT_MONTH:-$CFG_MONTH}}

[ -n "$STORE" ] || die "no store: set --store, ARTIFACT_STORE, or store= in the config file"
[ -n "$SUMS" ] || die "--sums PATH is required"
[ -f "$SUMS" ] || die "SHA256SUMS file not found: $SUMS"
printf '%s' "$DATASET" | grep -Eq '^[a-z0-9][a-z0-9._-]{0,62}$' || die "--dataset must be lowercase letters, digits, . _ -"
printf '%s' "$MONTH" | grep -Eq '^[0-9]{4}-(0[1-9]|1[0-2])$' || die "--month must be YYYY-MM"
SUMS_DIR=$(cd "$(dirname "$SUMS")" && pwd)

# ---------------------------------------------------------------- store URL
SCHEME= BUCKET= ACCOUNT= CONTAINER= PREFIX= ROOT=
PFX_RE='[A-Za-z0-9._/-]*'
case "$STORE" in
  s3://*)
    SCHEME=s3; rest=${STORE#s3://}; BUCKET=${rest%%/*}; PREFIX=${rest#"$BUCKET"}
    printf '%s' "$BUCKET" | grep -Eq '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' || die "bad S3 bucket name in store URL" ;;
  gs://*)
    SCHEME=gs; rest=${STORE#gs://}; BUCKET=${rest%%/*}; PREFIX=${rest#"$BUCKET"}
    printf '%s' "$BUCKET" | grep -Eq '^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$' || die "bad GCS bucket name in store URL" ;;
  az://*)
    SCHEME=az; rest=${STORE#az://}; ACCOUNT=${rest%%/*}; rest=${rest#"$ACCOUNT"}; rest=${rest#/}
    CONTAINER=${rest%%/*}; PREFIX=${rest#"$CONTAINER"}
    printf '%s' "$ACCOUNT" | grep -Eq '^[a-z0-9]{3,24}$' || die "bad Azure storage account name in store URL"
    printf '%s' "$CONTAINER" | grep -Eq '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$' || die "bad Azure container name in store URL" ;;
  file:///*)
    SCHEME=file; ROOT=${STORE#file://}; ROOT=${ROOT%/}
    # Spaces allowed in drive names; no control characters, quotes, $, `, \ or #.
    printf '%s' "$ROOT" | grep -Eq '^/[A-Za-z0-9._/ +@,=-]*$' || die "bad file:// path (letters, digits, spaces and . _ - / + @ , = only)" ;;
  *) die "unknown store scheme (allowed: s3:// gs:// az:// file:///)" ;;
esac
PREFIX=${PREFIX#/}; PREFIX=${PREFIX%/}
[ -z "$PREFIX" ] || printf '%s' "$PREFIX" | grep -Eq "^$PFX_RE\$" || die "bad prefix in store URL (letters, digits, . _ - / only)"
case "/$PREFIX/$ROOT/" in */../*|*/./*) die "store URL may not contain . or .. segments" ;; esac

# ---------------------------------------------------------------- helpers
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{print $1}'; }
size() { wc -c < "$1" | tr -d ' '; }
hex2b64() { perl -MMIME::Base64 -e 'print encode_base64(pack("H*", $ARGV[0]), "")' "$1"; }
# Provider stderr is never echoed (it can carry request headers or signed URLs). Only a
# coarse class, chosen by keyword, and the exit code are printed.
cli_err() {
  local cls=error
  if grep -Eqi 'AccessDenied|Forbidden|403|AuthorizationFailure|AuthorizationPermissionMismatch|PERMISSION_DENIED' "$1"; then cls="access denied"
  elif grep -Eqi 'ExpiredToken|InvalidToken|not logged in|az login|gcloud auth|Unable to locate credentials|credentials' "$1"; then cls="not signed in to the provider CLI"
  elif not_found "$1"; then cls="not found"
  elif grep -Eqi 'PreconditionFailed|412|AlreadyExists' "$1"; then cls="already exists"
  fi
  echo "artifact-store: provider CLI failed (exit ${2:-?}): $cls (raw message withheld; rerun the CLI by hand to see it)" >&2
}
not_found() { grep -Eqi '404|not ?found|NoSuchKey|BlobNotFound|does not exist|ResourceNotFound' "$1"; }

ENTRIES=$(mktemp); ERR=$(mktemp); WORK=$(mktemp -d)
cleanup() { rm -rf "$ENTRIES" "$ERR" "$WORK"; }
trap cleanup EXIT

# SHA256SUMS lines: "<64 hex>  <file name>". Names must be plain file names (no path).
grep -Ev '^[[:space:]]*(#|$)' "$SUMS" | while read -r h n rest; do
  n=${n#\*}
  [ -z "$rest" ] || { echo "BAD"; continue; }
  printf '%s' "$h" | grep -Eq '^[0-9a-f]{64}$' || { echo "BAD"; continue; }
  printf '%s' "$n" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]*$' || { echo "BAD"; continue; }
  echo "$h $n"
done > "$ENTRIES"
grep -q '^BAD$' "$ENTRIES" && die "SHA256SUMS has a line that is not '<sha256>  <plain file name>'"
[ -s "$ENTRIES" ] || die "SHA256SUMS lists no files"
[ -z "$(awk '{print $2}' "$ENTRIES" | sort | uniq -d)" ] || die "SHA256SUMS names the same file more than once"

key_for() { local k="$DATASET/$MONTH/$1/$2"; [ -n "$PREFIX" ] && k="$PREFIX/$k"; printf '%s' "$k"; }
where() {
  case $SCHEME in
    s3) printf 's3://%s/%s' "$BUCKET" "$1" ;;
    gs) printf 'gs://%s/%s' "$BUCKET" "$1" ;;
    az) printf 'az://%s/%s/%s' "$ACCOUNT" "$CONTAINER" "$1" ;;
    file) printf '%s/%s' "$ROOT" "$1" ;;
  esac
}

# ---------------------------------------------------------------- file:// checks
# What the tool can check on a local or connected drive: the path exists; with
# ARTIFACT_STORE_MOUNT set, that the path is on that mount point (df); that no directory from
# the store up to / is world-writable (put refuses, get and verify warn: they hash everything
# anyway); that nothing under the store root is a symlink. It cannot check encryption, who
# else can read the drive, or whether the drive is backed up.
mount_of() { df -P "$1" 2>/dev/null | awk 'NR==2 { for (i=6; i<=NF; i++) printf "%s%s", $i, (i<NF?" ":"") }'; }
file_store_check() {
  [ -d "$ROOT" ] || die "file store not present: $ROOT"
  # The path must be canonical: no symlink as the store root or any directory above it.
  local real; real=$(cd "$ROOT" && pwd -P)
  [ "$real" = "$ROOT" ] || die "file store refused: $ROOT goes through a symlink; use the real path ($real)"
  local m; m=$(mount_of "$ROOT")
  if [ -n "${ARTIFACT_STORE_MOUNT:-}" ]; then
    [ "$m" = "${ARTIFACT_STORE_MOUNT%/}" ] || die "file store is not on mount point ${ARTIFACT_STORE_MOUNT} (it is on ${m:-unknown}); is the drive connected?"
    [ "$m" != / ] || die "ARTIFACT_STORE_MOUNT=/ is the root file system, not a connected drive"
  elif [ "$MODE" = put ] && [ "${ARTIFACT_STORE_LOCAL_DISK_OK:-}" != 1 ]; then
    die "put refused: set ARTIFACT_STORE_MOUNT to the connected drive's mount point (it is on ${m:-unknown}), or ARTIFACT_STORE_LOCAL_DISK_OK=1 to accept a folder that may be on the same disk as the build"
  else
    warn "file store: no ARTIFACT_STORE_MOUNT, so this may be an ordinary folder on the boot disk (it is on ${m:-unknown}); it is not proof of an off-host copy"
  fi
  local d=$ROOT bad=
  while :; do
    # Sticky world-writable directories (like /tmp) count too: others can still create names.
    if [ "$(ls -ld "$d" | cut -c9)" = w ]; then bad=$d; break; fi
    [ "$d" = / ] && break
    d=$(dirname "$d")
  done
  if [ -n "$bad" ]; then
    [ "$MODE" = put ] && die "file store refused: $bad is world-writable"
    warn "file store: $bad is world-writable; every file is still verified against SHA256SUMS"
  fi
  if [ "$MODE" = put ] && [ ! -w "$ROOT" ]; then die "file store is read-only: $ROOT"; fi
}
# Refuse a symlink at any level below the store root down to the object itself.
no_symlinks_below_root() {
  local rel=$1 p=$ROOT part IFS=/
  for part in $rel; do
    p="$p/$part"
    [ -L "$p" ] && die "file store refused: $p is a symlink"
  done
  return 0
}

# ---------------------------------------------------------------- adapters
# exists KEY -> 0 present, 3 absent; dies on any other error. Store metadata is not trusted.
st_exists() {
  local k=$1 rc
  case $SCHEME in
    s3) set +e; aws s3api head-object --bucket "$BUCKET" --key "$k" --checksum-mode ENABLED \
          --query ContentLength --output text >/dev/null 2>"$ERR"; rc=$?; set -e ;;
    gs) set +e; gcloud storage objects describe "gs://$BUCKET/$k" --format='value(size)' \
          >/dev/null 2>"$ERR"; rc=$?; set -e ;;
    az) set +e; az storage blob show --account-name "$ACCOUNT" --container-name "$CONTAINER" \
          --name "$k" --auth-mode login --query properties.contentLength -o tsv --only-show-errors \
          >/dev/null 2>"$ERR"; rc=$?; set -e ;;
    file) no_symlinks_below_root "$k"; [ -f "$ROOT/$k" ] && return 0 || return 3 ;;
  esac
  [ $rc -eq 0 ] && return 0
  not_found "$ERR" && return 3
  cli_err "$ERR" $rc; die "could not check $(where "$k")"
}

# put KEY LOCAL SHA: never overwrites (conditional write, or exclusive create for file://).
st_put() {
  local k=$1 f=$2 h=$3 rc=0
  case $SCHEME in
    s3)
      set +e; aws s3api put-object --bucket "$BUCKET" --key "$k" --body "$f" \
        --checksum-algorithm SHA256 --checksum-sha256 "$(hex2b64 "$h")" --if-none-match '*' \
        --output text --query VersionId >/dev/null 2>"$ERR"; rc=$?; set -e ;;
    gs)
      set +e; gcloud storage cp "$f" "gs://$BUCKET/$k" --custom-metadata="sha256=$h" \
        --if-generation-match=0 --no-user-output-enabled 2>"$ERR"; rc=$?; set -e ;;
    az)
      set +e; az storage blob upload --account-name "$ACCOUNT" --container-name "$CONTAINER" \
        --name "$k" --file "$f" --auth-mode login --metadata "sha256=$h" --overwrite false \
        --no-progress --only-show-errors >/dev/null 2>"$ERR"; rc=$?; set -e ;;
    file)
      local d tmp; d=$(dirname "$ROOT/$k")
      no_symlinks_below_root "$k"
      mkdir -p "$d"
      no_symlinks_below_root "$k"
      tmp="$d/.incoming.$$.$RANDOM"
      # noclobber: the temp file is created exclusively (O_EXCL); ln: the final name is created
      # exclusively and atomically, so an existing object is never replaced.
      ( set -C; cat "$f" > "$tmp" ) || die "could not create a temporary file in the store"
      chmod 0444 "$tmp"
      if ! ln "$tmp" "$ROOT/$k" 2>/dev/null; then rm -f "$tmp"; die "refusing to overwrite $ROOT/$k"; fi
      rm -f "$tmp" ;;
  esac
  if [ $rc -ne 0 ]; then cli_err "$ERR" $rc; die "upload failed for $(basename "$f")"; fi
}

# get KEY OUT: download to OUT (a new file). Callers hash the result.
st_get() {
  local k=$1 o=$2 rc=0
  case $SCHEME in
    s3)
      set +e; aws s3api get-object --bucket "$BUCKET" --key "$k" --checksum-mode ENABLED "$o" \
        --output text --query ContentLength >/dev/null 2>"$ERR"; rc=$?; set -e ;;
    gs)
      set +e; gcloud storage cp "gs://$BUCKET/$k" "$o" --no-user-output-enabled 2>"$ERR"; rc=$?; set -e ;;
    az)
      set +e; az storage blob download --account-name "$ACCOUNT" --container-name "$CONTAINER" \
        --name "$k" --file "$o" --auth-mode login --no-progress --only-show-errors >/dev/null 2>"$ERR"; rc=$?; set -e ;;
    file)
      no_symlinks_below_root "$k"
      [ -f "$ROOT/$k" ] || { echo "not found" > "$ERR"; return 1; }
      ( set -C; cat "$ROOT/$k" > "$o" ) 2>"$ERR" || rc=1 ;;
  esac
  if [ $rc -ne 0 ]; then cli_err "$ERR" $rc; return 1; fi
}

# fetch_hash KEY -> prints the sha256 of the bytes the store returns, or fails.
fetch_hash() {
  local o="$WORK/check.$RANDOM" h
  rm -f "$o"
  st_get "$1" "$o" || { rm -f "$o"; return 1; }
  h=$(sha "$o"); rm -f "$o"; printf '%s' "$h"
}

# ---------------------------------------------------------------- local check
local_check() {   # prints one line per file; returns 1 if any file is missing or differs
  local bad=0 h n
  while read -r h n <&3; do
    if [ -L "$SUMS_DIR/$n" ]; then say "SYMLINK  $n (refused)"; bad=1; continue; fi
    if [ ! -f "$SUMS_DIR/$n" ]; then say "MISSING  $n"; bad=1; continue; fi
    if [ "$(sha "$SUMS_DIR/$n")" = "$h" ]; then say "ok       $n  $(size "$SUMS_DIR/$n") bytes  -> $(where "$(key_for "$h" "$n")")"
    else say "MISMATCH $n (local file does not match SHA256SUMS)"; bad=1; fi
  done 3< "$ENTRIES"
  return $bad
}

# ---------------------------------------------------------------- modes
case $MODE in
  plan)
    say "plan: store $SCHEME, dataset $DATASET, month $MONTH (no store access, no network)"
    if local_check; then say "plan: all local files match SHA256SUMS; put would upload any not already stored"
    else die "plan: local files do not match SHA256SUMS; put would refuse"; fi ;;

  put)
    local_check || die "put refused: local files do not match SHA256SUMS"
    if [ $SCHEME = file ]; then file_store_check; fi
    while read -r h n <&3; do
      k=$(key_for "$h" "$n")
      rc=0; st_exists "$k" || rc=$?
      if [ $rc -eq 0 ]; then
        got=$(fetch_hash "$k") || die "could not read back existing $(where "$k")"
        [ "$got" = "$h" ] || die "existing $(where "$k") does NOT match SHA256SUMS; not touched, investigate the store"
        say "skip     $n (already stored; bytes re-hashed and match)"; continue
      fi
      st_put "$k" "$SUMS_DIR/$n" "$h"
      got=$(fetch_hash "$k") || die "read-back failed for $n: cannot download it after upload"
      [ "$got" = "$h" ] || die "read-back failed for $n: stored bytes do not match SHA256SUMS"
      say "stored   $n  $(size "$SUMS_DIR/$n") bytes, read back and verified  $(where "$k")"
    done 3< "$ENTRIES"
    say "put: done" ;;

  get)
    [ -n "$DEST" ] || die "get needs --dest DIR (an empty or new directory)"
    if [ -e "$DEST" ] || [ -L "$DEST" ]; then
      [ -d "$DEST" ] && [ ! -L "$DEST" ] || die "--dest is not a directory"
      [ -z "$(ls -A "$DEST")" ] || die "get refused: $DEST is not empty"
    else mkdir -p "$DEST"; fi
    if [ $SCHEME = file ]; then file_store_check; fi
    fail=0
    while read -r h n <&3; do
      k=$(key_for "$h" "$n"); part="$DEST/.$n.part"
      if ! st_get "$k" "$part"; then rm -f "$part"; say "FAILED   $n (download failed)"; fail=1; continue; fi
      if [ "$(sha "$part")" != "$h" ]; then rm -f "$part"; say "FAILED   $n (sha256 does not match SHA256SUMS; deleted)"; fail=1; continue; fi
      chmod 0644 "$part"; mv "$part" "$DEST/$n"; say "verified $n  $(size "$DEST/$n") bytes"
    done 3< "$ENTRIES"
    if [ $fail -ne 0 ]; then
      # All or nothing: the directory was empty when get started, so remove what this run wrote.
      while read -r h n <&3; do rm -f "$DEST/$n" "$DEST/.$n.part"; done 3< "$ENTRIES"
      die "get: one or more files failed; every file restored by this run was removed"
    fi
    say "get: all files verified against SHA256SUMS" ;;

  verify)
    if [ $SCHEME = file ]; then file_store_check; fi
    fail=0
    while read -r h n <&3; do
      k=$(key_for "$h" "$n")
      rc=0; st_exists "$k" || rc=$?
      if [ $rc -eq 3 ]; then say "ABSENT   $n"; fail=1; continue; fi
      if ! got=$(fetch_hash "$k"); then say "FAILED   $n (download failed)"; fail=1; continue; fi
      if [ "$got" = "$h" ]; then say "verified $n (downloaded to a temporary file and hashed)"
      else say "MISMATCH $n (stored bytes do not match SHA256SUMS)"; fail=1; fi
    done 3< "$ENTRIES"
    [ $fail -eq 0 ] || die "verify: store does not hold every pinned file intact"
    say "verify: every pinned file downloaded and matched SHA256SUMS (store not modified)" ;;
esac

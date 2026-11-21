# Optional pinned artifact storage

`scripts/artifact-store.sh` keeps a verified copy of operator-supplied files, such as a
monthly GeoIP `.mmdb` database. Choose one store: Amazon S3, Google Cloud Storage, Azure
Blob Storage, or a local or connected drive. Winnie does not require a store. The running
sensor does not receive store credentials or fetch files from it; an operator retrieves
the pinned files and mounts them read-only as described in [GeoIP setup](operations.md#getting-a-database).
This helper is for pinned reference files, not event records, logs, or secrets.

## Choose a backend

| URL | Backend CLI | Operator setup |
| --- | --- | --- |
| `s3://example-bucket/winnie-artifacts` | AWS CLI | Private bucket, builder-only read/create access, versioning or Object Lock, encryption, and data-event logs. |
| `gs://example-bucket/winnie-artifacts` | `gcloud` | Private bucket with public access prevention, builder-only read/create access, versioning or retention, encryption, and Data Access audit logs. |
| `az://exampleaccount/artifacts/winnie` | Azure CLI `az` | Private container, Entra ID read/create access, blob versioning or immutability, encryption, and diagnostic logs. |
| `file:///mnt/encrypted-artifacts/winnie` | None | Encrypted volume, restricted file permissions, a backup, and a checked mount point. |

The cloud CLIs supply credentials from their own login, profile, or environment. The
script passes no credential flag and masks raw provider errors. Its optional config file
accepts only `store`, `dataset`, and `month`; never put secrets in it. Use a dedicated
operator or build identity with only the read and create permissions it needs. Keep
store access away from the sensor. Configure and verify encryption, public access
prevention, retention, and audit logging in the provider; the script cannot inspect
these controls.

For `file://`, set `ARTIFACT_STORE_MOUNT` to the expected mount point before `put`.
The script checks that the store exists on that mount, rejects symlinks in the store
path, and refuses group- or world-write mode bits from the store root up to `/`
for writes. A private store subdirectory is insufficient if a group member can rename
it from a writable parent; restrict the mount root and every ancestor as well.
For example, `/tmp` is world-writable on Linux, so a store beneath it is refused
even if the store directory itself has private permissions.
For `get` and `verify`, these permissions produce a warning while the downloaded
bytes are still checked against the manifest. Review ACLs separately. If you
deliberately use a folder on the machine's own disk, set
`ARTIFACT_STORE_LOCAL_DISK_OK=1` instead.
That is an explicit waiver of the connected-drive check, not proof of a backup.
The script cannot determine whether a drive is encrypted or backed up.

## Pin, copy, and restore

First obtain the files under their publisher's licence and calculate their SHA-256
values. For example, after saving two DB-IP files in `geoip/`:

```bash
(cd geoip && shasum -a 256 dbip-city-lite.mmdb dbip-asn-lite.mmdb > SHA256SUMS)
```

Review and preserve the resulting `SHA256SUMS` manifest in your own
version-controlled configuration. It is the trust anchor: do not fetch it from the
same store as the artifacts when restoring. Place a working copy of the manifest next
to the files for `plan` and `put`. Its format is one plain filename per line:

```text
<64 lowercase hexadecimal SHA-256 characters>  dbip-city-lite.mmdb
<64 lowercase hexadecimal SHA-256 characters>  dbip-asn-lite.mmdb
```

Choose a dataset and source month, then run:

```bash
export ARTIFACT_STORE='s3://example-bucket/winnie-artifacts'
sums='/path/to/reviewed/SHA256SUMS'
scripts/artifact-store.sh plan --sums "$sums" --dataset dbip-lite --month 2026-11
scripts/artifact-store.sh put --sums "$sums" --dataset dbip-lite --month 2026-11
scripts/artifact-store.sh verify --sums "$sums" --dataset dbip-lite --month 2026-11
scripts/artifact-store.sh get --sums "$sums" --dataset dbip-lite --month 2026-11 --dest '/path/to/empty/geoip'
```

`plan` only checks local files and makes no store or network call. `put` refuses
unless every local file matches the manifest, creates an object only if absent, then
downloads and hashes it. It also hashes any existing object before skipping it.
`verify` downloads and hashes stored objects without changing the store. `get`
requires an empty destination and removes every file restored by that run if any
file fails. Objects are named
`<prefix>/<dataset>/<YYYY-MM>/<sha256>/<filename>`. The script has no delete mode.
Store metadata, ETags, and reported sizes are never trusted for integrity.

Use `--store URL` instead of `ARTIFACT_STORE` if preferred. A config file passed
with `--config FILE` (or `ARTIFACT_STORE_CONFIG`) may contain:

```ini
store=s3://example-bucket/winnie-artifacts
dataset=dbip-lite
month=2026-11
```

The config is parsed as data, not executed. The script requires Bash, Perl, and either
`sha256sum` or `shasum`, plus the selected cloud CLI if applicable.

The `file://` path has been exercised against temporary directories and connected
encrypted drives. Automated S3, GCS, and Azure tests use stub CLIs to check commands,
failure handling, and integrity behavior. **None of the three cloud backends has a
validated live upload in this project.** Use a current AWS CLI v2 that supports
`s3api put-object --if-none-match`; check that your installed `gcloud storage cp`
supports `--if-generation-match` and `az storage blob upload` supports
`--overwrite false`. Before production use, test `put`, a second `put` (which should
skip without overwriting), `verify`, and `get` in a dedicated private test bucket or
container, then confirm provider-side access, retention, encryption, and audit records.

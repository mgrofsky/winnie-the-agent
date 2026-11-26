"""Stub for the aws, gcloud, az (and curl/gsutil) CLIs used by the tests.

Usage: fakecli.py <tool> <args...>. Every call is appended to $STUB_LOG as one JSON line
(the argv). Objects live under $STUB_STORE. Fault switches:
  STUB_TAMPER=1     a download returns bytes that differ from what was stored
  STUB_BAD_STAT=1   stat reports a wrong sha256
  STUB_LEAK=1       a failure message contains a token-shaped string (must be masked)
  STUB_S3_NO_LIST=1 S3 HeadObject on an absent key returns 403, as without ListBucket
Never contacts a network.
"""
import base64, hashlib, json, os, sys

tool, args = sys.argv[1], sys.argv[2:]
with open(os.environ["STUB_LOG"], "a") as fh:
    fh.write(json.dumps([tool] + args) + "\n")
store = os.environ.get("STUB_STORE", "/nonexistent")


def opts(argv, flags=()):
    o, pos, i = {}, [], 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--"):
            if "=" in a:
                k, v = a.split("=", 1); o[k] = v
            elif a in flags:
                o[a] = True
            else:
                o[a] = argv[i + 1]; i += 1
        else:
            pos.append(a)
        i += 1
    return o, pos


def path(container, key):
    return os.path.join(store, container, key)


def meta(p):
    try:
        with open(p + ".meta") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {}


def save(p, data, m):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as fh:
        fh.write(data)
    with open(p + ".meta", "w") as fh:
        json.dump(m, fh)


def read(p):
    with open(p, "rb") as fh:
        data = fh.read()
    if os.environ.get("STUB_TAMPER") == "1":
        data = b"X" + data[1:]
    return data


def fail(msg, code=1):
    if os.environ.get("STUB_LEAK") == "1":
        fake_key = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
        msg += " token=SECRETMARKER123 " + fake_key + "\nAuthorization: Bearer SECRETMARKER123 x-amz-security-token: SECRETMARKER123"
    sys.stderr.write(msg + "\n"); sys.exit(code)


def stat_sha(p):
    s = meta(p).get("sha256", "-")
    if os.environ.get("STUB_BAD_STAT") == "1":
        s = "0" * 64
    return s


if tool == "aws":
    sub, o, pos = args[1], *opts(args[2:])
    p = path(o.get("--bucket", "?"), o.get("--key", "?"))
    if sub == "head-object":
        if not os.path.exists(p):
            if os.environ.get("STUB_S3_NO_LIST") == "1":
                fail("An error occurred (403) when calling the HeadObject operation: Forbidden", 254)
            fail("An error occurred (404) when calling the HeadObject operation: Not Found", 254)
        s = stat_sha(p)
        b64 = base64.b64encode(bytes.fromhex(s)).decode() if s != "-" else "None"
        print(f"{os.path.getsize(p)}\t{b64}")
    elif sub == "put-object":
        if os.path.exists(p) and o.get("--if-none-match") == "*":
            fail("An error occurred (PreconditionFailed) when calling the PutObject operation", 254)
        data = open(o["--body"], "rb").read()
        if base64.b64encode(hashlib.sha256(data).digest()).decode() != o.get("--checksum-sha256"):
            fail("An error occurred (BadDigest) when calling the PutObject operation", 254)
        save(p, data, {"sha256": hashlib.sha256(data).hexdigest()})
        print("v1")
    elif sub == "get-object":
        if not os.path.exists(p):
            fail("An error occurred (NoSuchKey) when calling the GetObject operation", 254)
        open(pos[0], "wb").write(read(p)); print(os.path.getsize(p))
    else:
        fail("stub aws: unsupported " + sub)
elif tool == "gcloud":
    o, pos = opts(args, flags=("--no-user-output-enabled",))
    if pos[:3] == ["storage", "objects", "describe"]:
        b, k = pos[3][5:].split("/", 1); p = path(b, k)
        if not os.path.exists(p):
            fail("ERROR: (gcloud.storage.objects.describe) gs://x not found: 404.")
        print(f"{os.path.getsize(p)}\t{stat_sha(p)}")
    elif pos[:2] == ["storage", "cp"]:
        src, dst = pos[2], pos[3]
        if dst.startswith("gs://"):
            b, k = dst[5:].split("/", 1); p = path(b, k)
            if os.path.exists(p) and o.get("--if-generation-match") == "0":
                fail("ERROR: precondition failed (412)")
            m = dict(kv.split("=", 1) for kv in o.get("--custom-metadata", "").split(",") if kv)
            save(p, open(src, "rb").read(), m)
        else:
            b, k = src[5:].split("/", 1); p = path(b, k)
            if not os.path.exists(p):
                fail("ERROR: gs://x not found: 404.")
            open(dst, "wb").write(read(p))
    else:
        fail("stub gcloud: unsupported")
elif tool == "az":
    o, pos = opts(args, flags=("--no-progress", "--only-show-errors"))
    verb = pos[2]
    p = path(o["--account-name"] + "/" + o["--container-name"], o["--name"])
    if verb == "show":
        if not os.path.exists(p):
            fail("ERROR: The specified blob does not exist. ErrorCode:BlobNotFound")
        print(f"{os.path.getsize(p)}\t{stat_sha(p)}")
    elif verb == "upload":
        if os.path.exists(p) and o.get("--overwrite") == "false":
            fail("ERROR: The specified blob already exists. ErrorCode:BlobAlreadyExists")
        m = dict([o["--metadata"].split("=", 1)]) if "--metadata" in o else {}
        save(p, open(o["--file"], "rb").read(), m)
    elif verb == "download":
        if not os.path.exists(p):
            fail("ERROR: The specified blob does not exist. ErrorCode:BlobNotFound")
        open(o["--file"], "wb").write(read(p))
    else:
        fail("stub az: unsupported")
else:
    fail(f"stub {tool}: network tool called", 99)

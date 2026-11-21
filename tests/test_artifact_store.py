"""Tests for scripts/artifact-store.sh.

file:// is exercised for real under a private test directory. The S3, GCS and Azure
adapters run against stub CLIs (tests/stubs/fakecli.py) that log every call; nothing
reaches a network. Set ARTIFACT_STORE_TEST_TMPDIR to a private writable mount when
the checkout is read-only.
Run: python3 -m unittest discover -s tests -v
"""
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "scripts", "artifact-store.sh")
FAKE = os.path.join(HERE, "stubs", "fakecli.py")
STUBBED = ("aws", "gcloud", "gsutil", "az", "curl", "wget")
DATASET, MONTH = "dbip-lite", "2026-11"
FILES = {"city.mmdb": b"city database bytes " * 50, "asn.mmdb": b"asn bytes " * 30}
CLOUD = {
    "s3": "s3://example-bucket/pinned",
    "gs": "gs://example-bucket/pinned",
    "az": "az://exampleacct/artifacts/pinned",
}
WRITE_VERBS = {  # a call that would change the store
    "aws": lambda a: any(v in a for v in ("put-object", "delete-object", "copy-object", "cp", "rm", "mv", "sync")),
    "gcloud": lambda a: ("rm" in a or "mv" in a or (len(a) > 3 and a[1] == "cp" and a[3].startswith("gs://"))),
    "az": lambda a: any(v in a for v in ("upload", "delete", "copy", "upload-batch")),
}


def sha(b):
    return hashlib.sha256(b).hexdigest()


class Base(unittest.TestCase):
    def temp_parent(self):
        return None

    def setUp(self):
        self.t = os.path.realpath(tempfile.mkdtemp(dir=self.temp_parent()))
        self.src = os.path.join(self.t, "geoip")
        os.makedirs(self.src)
        for n, b in FILES.items():
            with open(os.path.join(self.src, n), "wb") as fh:
                fh.write(b)
        with open(os.path.join(self.src, "SHA256SUMS"), "w") as fh:
            for n, b in FILES.items():
                fh.write(f"{sha(b)}  {n}\n")
        self.sums = os.path.join(self.src, "SHA256SUMS")
        # stub bin dir: every network-capable CLI is a logging stub
        self.bin = os.path.join(self.t, "bin")
        os.makedirs(self.bin)
        for tool in STUBBED:
            p = os.path.join(self.bin, tool)
            with open(p, "w") as fh:
                fh.write(f'#!/bin/sh\nexec python3 -I "{FAKE}" {tool} "$@"\n')
            os.chmod(p, 0o700)
        self.log = os.path.join(self.t, "calls.log")
        open(self.log, "w").close()
        self.stub_store = os.path.join(self.t, "stubstore")
        os.makedirs(self.stub_store)

    def tearDown(self):
        for root, dirs, files in os.walk(self.t):
            for d in dirs:
                os.chmod(os.path.join(root, d), 0o700)
        shutil.rmtree(self.t, ignore_errors=True)

    def run_tool(self, mode, store, *extra, env=None):
        e = {
            "PATH": self.bin + ":/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": self.t,
            "STUB_LOG": self.log,
            "STUB_STORE": self.stub_store,
        }
        e.update(env or {})
        args = [TOOL, mode, "--sums", self.sums, "--dataset", DATASET, "--month", MONTH]
        if store is not None:
            args += ["--store", store]
        p = subprocess.run(args + list(extra), env=e, capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr

    def calls(self):
        with open(self.log) as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def key(self, name):
        return f"pinned/{DATASET}/{MONTH}/{sha(FILES[name])}/{name}"


# ---------------------------------------------------------------- file://
class FileBackend(Base):
    def temp_parent(self):
        # file:// refuses a world-writable ancestor such as Linux /tmp. Keep these
        # fixtures under the ignored checkout cache, or a private read-only-Docker mount.
        parent = os.environ.get("ARTIFACT_STORE_TEST_TMPDIR") or os.path.join(
            HERE, "..", ".pytest_cache", "artifact-store"
        )
        os.makedirs(parent, mode=0o700, exist_ok=True)
        parent = os.path.realpath(parent)
        ancestor = parent
        while True:
            if os.stat(ancestor).st_mode & 0o022:
                raise RuntimeError(
                    "artifact-store tests need a temp directory without group- or "
                    "world-writable ancestors; set ARTIFACT_STORE_TEST_TMPDIR"
                )
            if ancestor == os.path.sep:
                break
            ancestor = os.path.dirname(ancestor)
        return parent

    def setUp(self):
        super().setUp()
        self.root = os.path.join(self.t, "Secure Drive", "store")  # spaces in mount names
        os.makedirs(self.root)
        self.url = "file://" + self.root

    def run_tool(self, mode, store, *extra, env=None):
        e = {"ARTIFACT_STORE_LOCAL_DISK_OK": "1"}  # temp dirs are on the boot disk
        e.update(env or {})
        return super().run_tool(mode, store, *extra, env=e)

    def test_put_without_mount_or_waiver_refused(self):
        rc, out = self.run_tool("put", self.url, env={"ARTIFACT_STORE_LOCAL_DISK_OK": ""})
        self.assertNotEqual(rc, 0)
        self.assertIn("ARTIFACT_STORE_MOUNT", out)
        self.assertEqual(os.listdir(self.root), [])

    def test_mount_point_matches(self):
        mnt = subprocess.run(["df", "-P", self.root], capture_output=True, text=True).stdout.splitlines()[1].split(None, 5)[5]
        rc, out = self.run_tool("put", self.url, env={"ARTIFACT_STORE_LOCAL_DISK_OK": "", "ARTIFACT_STORE_MOUNT": mnt})
        if mnt == "/":
            self.assertNotEqual(rc, 0)
        else:
            self.assertEqual(rc, 0, out)

    def test_symlink_root_refused(self):
        link = os.path.join(self.t, "link-store")
        os.symlink(self.root, link)
        rc, out = self.run_tool("put", "file://" + link)
        self.assertNotEqual(rc, 0)
        self.assertIn("symlink", out)
        self.assertEqual(os.listdir(self.root), [])

    def test_symlink_ancestor_refused(self):
        link = os.path.join(self.t, "link-parent")
        os.symlink(os.path.dirname(self.root), link)
        rc, out = self.run_tool("put", "file://" + os.path.join(link, "store"))
        self.assertNotEqual(rc, 0)
        self.assertIn("symlink", out)
        self.assertEqual(os.listdir(self.root), [])

    def obj(self, name):
        return os.path.join(self.root, DATASET, MONTH, sha(FILES[name]), name)

    def test_round_trip(self):
        rc, out = self.run_tool("put", self.url)
        self.assertEqual(rc, 0, out)
        for n, b in FILES.items():
            with open(self.obj(n), "rb") as fh:
                self.assertEqual(fh.read(), b)
            self.assertFalse(os.stat(self.obj(n)).st_mode & 0o222, "stored file should be read-only")
        dest = os.path.join(self.t, "restore")
        rc, out = self.run_tool("get", self.url, "--dest", dest)
        self.assertEqual(rc, 0, out)
        self.assertEqual(sorted(os.listdir(dest)), sorted(FILES))
        for n, b in FILES.items():
            with open(os.path.join(dest, n), "rb") as fh:
                self.assertEqual(fh.read(), b)
        rc, out = self.run_tool("verify", self.url)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.calls(), [], "file:// must not call any provider CLI")

    def test_tampered_store_fails_get_and_deletes(self):
        self.run_tool("put", self.url)
        p = self.obj("city.mmdb")
        os.chmod(p, 0o600)
        with open(p, "r+b") as fh:
            fh.write(b"X")
        dest = os.path.join(self.t, "restore")
        rc, out = self.run_tool("get", self.url, "--dest", dest)
        self.assertNotEqual(rc, 0)
        self.assertIn("city.mmdb (sha256 does not match", out)
        self.assertEqual(os.listdir(dest), [], "all or nothing: no partial restore left behind")
        rc, out = self.run_tool("verify", self.url)
        self.assertNotEqual(rc, 0)
        self.assertIn("MISMATCH city.mmdb", out)

    def test_existing_artifact_skipped_after_rehash(self):
        self.run_tool("put", self.url)
        before = {n: os.stat(self.obj(n)).st_ino for n in FILES}
        rc, out = self.run_tool("put", self.url)
        self.assertEqual(rc, 0, out)
        self.assertEqual(out.count("skip "), 2, out)
        self.assertEqual(before, {n: os.stat(self.obj(n)).st_ino for n in FILES})

    def test_existing_corrupt_artifact_fails_put(self):
        self.run_tool("put", self.url)
        p = self.obj("asn.mmdb")
        os.chmod(p, 0o600)
        with open(p, "r+b") as fh:
            fh.write(b"Z")
        rc, out = self.run_tool("put", self.url)
        self.assertNotEqual(rc, 0)
        self.assertIn("does NOT match SHA256SUMS", out)

    def test_put_refuses_local_mismatch(self):
        with open(os.path.join(self.src, "asn.mmdb"), "ab") as fh:
            fh.write(b"extra")
        rc, out = self.run_tool("put", self.url)
        self.assertNotEqual(rc, 0)
        self.assertIn("put refused", out)
        self.assertEqual(os.listdir(self.root), [], "nothing may be written")

    def test_put_refuses_missing_local_file(self):
        os.remove(os.path.join(self.src, "asn.mmdb"))
        rc, out = self.run_tool("put", self.url)
        self.assertNotEqual(rc, 0)
        self.assertEqual(os.listdir(self.root), [])

    def test_restore_into_non_empty_dir_refused(self):
        self.run_tool("put", self.url)
        dest = os.path.join(self.t, "restore")
        os.makedirs(dest)
        open(os.path.join(dest, "keep.txt"), "w").close()
        rc, out = self.run_tool("get", self.url, "--dest", dest)
        self.assertNotEqual(rc, 0)
        self.assertIn("not empty", out)
        self.assertEqual(os.listdir(dest), ["keep.txt"])

    def test_world_writable_store_put_refused_get_warns(self):
        self.run_tool("put", self.url)
        os.chmod(self.root, 0o777)  # intentional: put must reject a world-writable root
        rc, out = self.run_tool("put", self.url)
        self.assertNotEqual(rc, 0)
        self.assertIn("world-writable", out)
        dest = os.path.join(self.t, "restore")
        rc, out = self.run_tool("get", self.url, "--dest", dest)
        self.assertEqual(rc, 0, out)
        self.assertIn("warning", out)

    def test_sticky_world_writable_parent_refused_for_put(self):
        os.chmod(os.path.dirname(self.root), 0o1777)  # intentional: reject a sticky parent
        rc, out = self.run_tool("put", self.url)
        self.assertNotEqual(rc, 0)
        self.assertIn("world-writable", out)
        self.assertEqual(os.listdir(self.root), [])

    def test_group_writable_store_put_refused_get_warns(self):
        self.run_tool("put", self.url)
        os.chmod(self.root, 0o770)  # intentional: put must reject a group-writable root
        rc, out = self.run_tool("put", self.url)
        self.assertNotEqual(rc, 0)
        self.assertIn("group-writable", out)
        dest = os.path.join(self.t, "restore")
        rc, out = self.run_tool("get", self.url, "--dest", dest)
        self.assertEqual(rc, 0, out)
        self.assertIn("group-writable", out)

    def test_group_writable_parent_refused_for_put(self):
        os.chmod(os.path.dirname(self.root), 0o775)  # intentional: reject a writable parent
        rc, out = self.run_tool("put", self.url)
        self.assertNotEqual(rc, 0)
        self.assertIn("group-writable", out)
        self.assertEqual(os.listdir(self.root), [])

    def test_get_partway_failure_removes_everything(self):
        self.run_tool("put", self.url)
        p = self.obj("asn.mmdb")  # second file in SHA256SUMS order
        os.chmod(os.path.dirname(p), 0o700)
        os.chmod(p, 0o600)
        os.remove(p)
        dest = os.path.join(self.t, "restore")
        rc, out = self.run_tool("get", self.url, "--dest", dest)
        self.assertNotEqual(rc, 0)
        self.assertIn("verified city.mmdb", out)  # the first one did restore...
        self.assertEqual(os.listdir(dest), [])     # ...and was removed again

    def test_symlink_below_root_refused(self):
        elsewhere = os.path.join(self.t, "elsewhere")
        os.makedirs(elsewhere)
        os.symlink(elsewhere, os.path.join(self.root, DATASET))
        rc, out = self.run_tool("put", self.url)
        self.assertNotEqual(rc, 0)
        self.assertIn("symlink", out)
        self.assertEqual(os.listdir(elsewhere), [])

    def test_missing_store_refused(self):
        rc, out = self.run_tool("put", "file://" + os.path.join(self.t, "not-mounted"))
        self.assertNotEqual(rc, 0)
        self.assertIn("not present", out)

    def test_mount_point_enforced_when_set(self):
        rc, out = self.run_tool("put", self.url, env={"ARTIFACT_STORE_MOUNT": "/mnt/absent-drive"})
        self.assertNotEqual(rc, 0)
        self.assertIn("not on mount point", out)
        self.assertEqual(os.listdir(self.root), [])

    def test_plan_touches_nothing(self):
        missing = "file://" + os.path.join(self.t, "absent")
        rc, out = self.run_tool("plan", missing)
        self.assertEqual(rc, 0, out)
        self.assertFalse(os.path.exists(os.path.join(self.t, "absent")))
        self.assertEqual(self.calls(), [])

    def test_config_file_with_spaces_not_sourced(self):
        cfg = os.path.join(self.t, "store.conf")
        with open(cfg, "w") as fh:
            fh.write(f'# comment\nstore = "{self.url}"\n')
        rc, out = self.run_tool("plan", None, "--config", cfg)
        self.assertEqual(rc, 0, out)
        marker = os.path.join(self.t, "pwned")
        with open(cfg, "w") as fh:
            fh.write(f"store={self.url}\nevil=$(touch {marker})\n")
        rc, out = self.run_tool("plan", None, "--config", cfg)
        self.assertNotEqual(rc, 0)
        self.assertFalse(os.path.exists(marker))


# ---------------------------------------------------------------- input validation
class Validation(Base):
    def test_unknown_scheme_refused(self):
        for url in ("http://example.com/x", "ftp://h/x", "sftp://h/x", "/plain/path", "S3://b/x", "file://relative"):
            rc, out = self.run_tool("plan", url)
            self.assertNotEqual(rc, 0, url)
        self.assertEqual(self.calls(), [])

    def test_sums_with_path_refused(self):
        with open(self.sums, "a") as fh:
            fh.write(f"{'a' * 64}  ../escape.mmdb\n")
        rc, out = self.run_tool("plan", CLOUD["s3"])
        self.assertNotEqual(rc, 0)
        self.assertIn("plain file name", out)

    def test_sums_extra_field_refused(self):
        with open(self.sums, "a") as fh:
            fh.write(f"{'b' * 64}  extra.mmdb  trailing\n")
        rc, out = self.run_tool("plan", CLOUD["s3"])
        self.assertNotEqual(rc, 0)
        self.assertIn("plain file name", out)

    def test_sums_duplicate_name_refused(self):
        with open(self.sums, "a") as fh:
            fh.write(f"{'c' * 64}  city.mmdb\n")
        rc, out = self.run_tool("plan", CLOUD["s3"])
        self.assertNotEqual(rc, 0)
        self.assertIn("more than once", out)

    def test_no_delete_mode(self):
        rc, out = self.run_tool("delete", CLOUD["s3"])
        self.assertNotEqual(rc, 0)
        self.assertEqual(self.calls(), [])


# ---------------------------------------------------------------- cloud adapters (stubs)
class CloudAdapters(Base):
    def reset_store(self):
        shutil.rmtree(self.stub_store)
        os.makedirs(self.stub_store)

    def exp_stat(self, scheme, name):
        k = self.key(name)
        return {
            "s3": ["aws", "s3api", "head-object", "--bucket", "example-bucket", "--key", k,
                   "--checksum-mode", "ENABLED", "--query", "ContentLength", "--output", "text"],
            "gs": ["gcloud", "storage", "objects", "describe", f"gs://example-bucket/{k}",
                   "--format=value(size)"],
            "az": ["az", "storage", "blob", "show", "--account-name", "exampleacct",
                   "--container-name", "artifacts", "--name", k, "--auth-mode", "login",
                   "--query", "properties.contentLength", "-o", "tsv", "--only-show-errors"],
        }[scheme]

    def exp_put(self, scheme, name):
        import base64
        k, h = self.key(name), sha(FILES[name])
        f = os.path.join(self.src, name)
        return {
            "s3": ["aws", "s3api", "put-object", "--bucket", "example-bucket", "--key", k, "--body", f,
                   "--checksum-algorithm", "SHA256",
                   "--checksum-sha256", base64.b64encode(bytes.fromhex(h)).decode(),
                   "--if-none-match", "*", "--output", "text", "--query", "VersionId"],
            "gs": ["gcloud", "storage", "cp", f, f"gs://example-bucket/{k}",
                   f"--custom-metadata=sha256={h}", "--if-generation-match=0", "--no-user-output-enabled"],
            "az": ["az", "storage", "blob", "upload", "--account-name", "exampleacct",
                   "--container-name", "artifacts", "--name", k, "--file", f, "--auth-mode", "login",
                   "--metadata", f"sha256={h}", "--overwrite", "false", "--no-progress", "--only-show-errors"],
        }[scheme]

    def assert_get_shape(self, scheme, call, name):
        k = self.key(name)
        if scheme == "s3":
            self.assertEqual(call[:9], ["aws", "s3api", "get-object", "--bucket", "example-bucket",
                                        "--key", k, "--checksum-mode", "ENABLED"])
        elif scheme == "gs":
            self.assertEqual(call[:4], ["gcloud", "storage", "cp", f"gs://example-bucket/{k}"])
            self.assertFalse(call[4].startswith("gs://"))
        else:
            self.assertEqual(call[:11], ["az", "storage", "blob", "download", "--account-name", "exampleacct",
                                         "--container-name", "artifacts", "--name", k, "--file"])
            self.assertIn("login", call)

    def no_writes(self, calls):
        for c in calls:
            self.assertFalse(WRITE_VERBS[c[0]](c[1:]), f"write verb used: {c[:4]}")

    def test_plan_makes_no_call(self):
        for scheme, url in CLOUD.items():
            rc, out = self.run_tool("plan", url)
            self.assertEqual(rc, 0, out)
        self.assertEqual(self.calls(), [], "plan must not run any provider or network CLI")

    def test_put_command_shape_and_readback(self):
        for scheme, url in CLOUD.items():
            with self.subTest(scheme=scheme):
                self.reset_store()
                open(self.log, "w").close()
                rc, out = self.run_tool("put", url)
                self.assertEqual(rc, 0, out)
                c = self.calls()
                self.assertEqual(len(c), 6, c)  # per file: exists, put, get (read-back)
                for i, name in enumerate(FILES):
                    self.assertEqual(c[3 * i], self.exp_stat(scheme, name))
                    self.assertEqual(c[3 * i + 1], self.exp_put(scheme, name))
                    self.assertTrue(c[3 * i + 1][0] in ("aws", "gcloud", "az"))
                    self.assert_get_shape(scheme, c[3 * i + 2], name)

    def test_existing_artifact_skipped(self):
        for scheme, url in CLOUD.items():
            with self.subTest(scheme=scheme):
                self.reset_store()
                self.run_tool("put", url)
                open(self.log, "w").close()
                rc, out = self.run_tool("put", url)
                self.assertEqual(rc, 0, out)
                self.assertEqual(out.count("skip "), 2)
                self.no_writes(self.calls())

    def test_existing_corrupt_artifact_fails_put(self):
        for scheme, url in CLOUD.items():
            with self.subTest(scheme=scheme):
                self.reset_store()
                self.run_tool("put", url)
                open(self.log, "w").close()
                rc, out = self.run_tool("put", url, env={"STUB_TAMPER": "1"})
                self.assertNotEqual(rc, 0)
                self.assertIn("does NOT match", out)
                self.no_writes(self.calls())

    def test_get_and_verify_use_no_write_verb(self):
        for scheme, url in CLOUD.items():
            with self.subTest(scheme=scheme):
                self.reset_store()
                self.run_tool("put", url)
                open(self.log, "w").close()
                dest = os.path.join(self.t, f"restore-{scheme}")
                rc, out = self.run_tool("get", url, "--dest", dest)
                self.assertEqual(rc, 0, out)
                rc, out = self.run_tool("verify", url)
                self.assertEqual(rc, 0, out)
                c = self.calls()
                self.assertTrue(c)
                self.no_writes(c)
                for n, b in FILES.items():
                    with open(os.path.join(dest, n), "rb") as fh:
                        self.assertEqual(fh.read(), b)

    def test_checksum_mismatch_after_get_fails(self):
        for scheme, url in CLOUD.items():
            with self.subTest(scheme=scheme):
                self.reset_store()
                self.run_tool("put", url)
                dest = os.path.join(self.t, f"tamper-{scheme}")
                rc, out = self.run_tool("get", url, "--dest", dest, env={"STUB_TAMPER": "1"})
                self.assertNotEqual(rc, 0)
                self.assertEqual(os.listdir(dest), [], "tampered files must be deleted")
                rc, out = self.run_tool("verify", url, env={"STUB_TAMPER": "1"})
                self.assertNotEqual(rc, 0)
                self.assertIn("MISMATCH", out)

    def test_verify_ignores_store_metadata(self):
        # The store reporting a wrong checksum does not matter; only downloaded bytes count.
        url = CLOUD["s3"]
        self.run_tool("put", url)
        rc, out = self.run_tool("verify", url, env={"STUB_BAD_STAT": "1"})
        self.assertEqual(rc, 0, out)

    def test_absent_artifact_reported(self):
        rc, out = self.run_tool("verify", CLOUD["gs"])
        self.assertNotEqual(rc, 0)
        self.assertIn("ABSENT", out)

    def test_provider_error_masks_tokens(self):
        rc, out = self.run_tool("get", CLOUD["s3"], "--dest", os.path.join(self.t, "r"),
                                env={"STUB_LEAK": "1"})
        self.assertNotEqual(rc, 0)
        self.assertNotIn("SECRETMARKER123", out)
        self.assertNotIn("AK" + "IA" + "ABCDEFGHIJKLMNOP", out)
        self.assertNotIn("Bearer", out)
        self.assertNotIn("x-amz-security-token", out)
        self.assertIn("raw message withheld", out)


if __name__ == "__main__":
    unittest.main()

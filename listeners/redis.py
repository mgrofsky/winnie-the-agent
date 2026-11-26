"""Redis trap: RESP + inline protocol, auth gate, fake per-connection keyspace.

The classic takeover chain (CONFIG SET dir/dbfilename, SAVE/BGSAVE, SLAVEOF/REPLICAOF,
MODULE LOAD, EVAL, FLUSHALL) answers plausibly and is logged as ``high_signal``. Nothing
touches disk and nothing connects out: SAVE writes nothing, SLAVEOF never dials, and EVAL
never runs Lua (a few literal script forms are answered against the keyspace, anything
else gets a nil reply).

Answer order for a command: the canned keyspace logic; then, for a real Redis command this
trap does not implement and only when ``ctx.json_llm`` is set, the budgeted model through a
schema restricted to RESP reply types (``LlmRedisReply``); then the real "unknown command"
error. A name that is not a Redis command never reaches the model. The command event
carries ``rung`` (``llm``, ``llm_retry`` or ``fallback``) when the model was asked.
"""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import time
from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

from agents.llm import untrusted_block
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
WRONGTYPE = "WRONGTYPE Operation against a key holding the wrong kind of value"
OOM = "OOM command not allowed when used memory > 'maxmemory'."
MAX_SCRIPTS = 64                  # SCRIPT LOAD bodies kept per connection
MAX_SCRIPT_CHARS = 512            # longer EVAL bodies are never matched, only nil-replied
MAX_LLM_COMMAND_CHARS = 1000
NIL_ARRAY = b"*-1\r\n"

STRING_COMMANDS = frozenset({"GET", "SET", "SETNX", "SETEX", "PSETEX", "GETSET", "GETDEL",
                             "APPEND", "STRLEN", "MGET", "MSET", "INCR", "INCRBY", "DECR",
                             "DECRBY"})
HASH_COMMANDS = frozenset({"HSET", "HGET", "HGETALL", "HKEYS", "HVALS", "HLEN", "HEXISTS",
                           "HDEL"})
LIST_COMMANDS = frozenset({"LPUSH", "RPUSH", "LLEN", "LRANGE", "LPOP", "RPOP"})
SET_COMMANDS = frozenset({"SADD", "SMEMBERS", "SCARD", "SISMEMBER", "SREM"})
# Commands counted in rdb_changes_since_last_save.
WRITE_COMMANDS = frozenset({"SET", "SETNX", "SETEX", "PSETEX", "GETSET", "GETDEL", "APPEND",
                            "MSET", "INCR", "INCRBY", "DECR", "DECRBY", "DEL", "UNLINK",
                            "RENAME", "RENAMENX", "EXPIRE", "PERSIST", "HSET", "HDEL",
                            "LPUSH", "RPUSH", "LPOP", "RPOP", "SADD", "SREM", "FLUSHDB",
                            "FLUSHALL"})

# Exact argument counts (positive) or minimums (negative), as COMMAND INFO reports them.
ARITY = {"GET": 2, "GETSET": 3, "GETDEL": 2, "APPEND": 3, "STRLEN": 2, "MGET": -2,
         "MSET": -3, "SETNX": 3, "SETEX": 4, "PSETEX": 4, "INCR": 2, "INCRBY": 3, "DECR": 2,
         "DECRBY": 3, "TYPE": 2, "DBSIZE": 1, "RENAME": 3, "RENAMENX": 3, "PERSIST": 2,
         "HGET": 3, "HDEL": -3, "HKEYS": 2, "HVALS": 2, "HLEN": 2, "HEXISTS": 3, "LLEN": 2,
         "LPOP": -2, "RPOP": -2, "SREM": -3, "SCARD": 2, "SISMEMBER": 3, "FLUSHDB": -1,
         "TIME": 1, "LASTSAVE": 1, "ROLE": 1, "SAVE": 1, "BGSAVE": -1, "TTL": 2, "PTTL": 2,
         "EXPIRE": -3, "HGETALL": 2, "SMEMBERS": 2, "DEL": -2, "UNLINK": -2, "EXISTS": -2}

# Commands of a real Redis 7 server. A name outside this set keeps the unknown-command
# error and is never sent to the model.
REDIS_COMMANDS = frozenset("""
ACL APPEND ASKING AUTH BGREWRITEAOF BGSAVE BITCOUNT BITFIELD BITFIELD_RO BITOP BITPOS
BLMOVE BLMPOP BLPOP BRPOP BRPOPLPUSH BZMPOP BZPOPMAX BZPOPMIN CLIENT CLUSTER COMMAND CONFIG
COPY DBSIZE DEBUG DECR DECRBY DEL DISCARD DUMP ECHO EVAL EVALSHA EVALSHA_RO EVAL_RO EXEC
EXISTS EXPIRE EXPIREAT EXPIRETIME FAILOVER FCALL FCALL_RO FLUSHALL FLUSHDB FUNCTION GEOADD
GEODIST GEOHASH GEOPOS GEORADIUS GEORADIUSBYMEMBER GEORADIUSBYMEMBER_RO GEORADIUS_RO
GEOSEARCH GEOSEARCHSTORE GET GETBIT GETDEL GETEX GETRANGE GETSET HDEL HELLO HEXISTS HGET
HGETALL HINCRBY HINCRBYFLOAT HKEYS HLEN HMGET HMSET HRANDFIELD HSCAN HSET HSETNX HSTRLEN
HVALS INCR INCRBY INCRBYFLOAT INFO KEYS LASTSAVE LATENCY LCS LINDEX LINSERT LLEN LMOVE
LMPOP LOLWUT LPOP LPOS LPUSH LPUSHX LRANGE LREM LSET LTRIM MEMORY MGET MIGRATE MODULE
MONITOR MOVE MSET MSETNX MULTI OBJECT PERSIST PEXPIRE PEXPIREAT PEXPIRETIME PFADD PFCOUNT
PFDEBUG PFMERGE PFSELFTEST PING PSETEX PSUBSCRIBE PSYNC PTTL PUBLISH PUBSUB PUNSUBSCRIBE
QUIT RANDOMKEY READONLY READWRITE RENAME RENAMENX REPLCONF REPLICAOF RESET RESTORE
RESTORE-ASKING ROLE RPOP RPOPLPUSH RPUSH RPUSHX SADD SAVE SCAN SCARD SCRIPT SDIFF
SDIFFSTORE SELECT SET SETBIT SETEX SETNX SETRANGE SHUTDOWN SINTER SINTERCARD SINTERSTORE
SISMEMBER SLAVEOF SLOWLOG SMEMBERS SMISMEMBER SMOVE SORT SORT_RO SPOP SPUBLISH SRANDMEMBER
SREM SSCAN SSUBSCRIBE STRLEN SUBSCRIBE SUBSTR SUNION SUNIONSTORE SUNSUBSCRIBE SWAPDB SYNC
TIME TOUCH TTL TYPE UNLINK UNSUBSCRIBE UNWATCH WAIT WATCH XACK XADD XAUTOCLAIM XCLAIM XDEL
XGROUP XINFO XLEN XPENDING XRANGE XREAD XREADGROUP XREVRANGE XSETID XTRIM ZADD ZCARD ZCOUNT
ZDIFF ZDIFFSTORE ZINCRBY ZINTER ZINTERCARD ZINTERSTORE ZLEXCOUNT ZMPOP ZMSCORE ZPOPMAX
ZPOPMIN ZRANDMEMBER ZRANGE ZRANGEBYLEX ZRANGEBYSCORE ZRANGESTORE ZRANK ZREM
ZREMRANGEBYLEX ZREMRANGEBYRANK ZREMRANGEBYSCORE ZREVRANGE ZREVRANGEBYLEX ZREVRANGEBYSCORE
ZREVRANK ZSCAN ZSCORE ZUNION ZUNIONSTORE
""".split())

# Literal EVAL bodies answered against the keyspace (matched on a whitespace-collapsed,
# length-capped script; anything else is a nil reply).
_ARG = r"(?:(KEYS|ARGV)\[(\d{1,3})\]|'([^'\\]{0,256})'|\"([^\"\\]{0,256})\")"
EVAL_RETURN_INT_RE = re.compile(r"return\s*(-?\d{1,18})\s*;?")
EVAL_RETURN_ARG_RE = re.compile(r"return\s*" + _ARG + r"\s*;?")
EVAL_CALL_RE = re.compile(
    r"(return\s+)?redis\.(?:p?call)\s*\(\s*['\"](get|set|GET|SET)['\"]\s*"
    r"((?:,\s*" + _ARG + r"\s*){1,2})\)\s*;?")
EVAL_CALL_ARG_RE = re.compile(r",\s*" + _ARG)

# Worked examples sent with a second model request (``ListenerContext.llm_json``).
REDIS_EXAMPLES = (
    'command: ZADD leaderboard 10 alice\nanswer: {"type": "integer", "integer": 1}\n'
    'command: ZRANGE leaderboard 0 -1\nanswer: {"type": "array", "items": ["alice"]}\n'
    'command: OBJECT ENCODING session:7f3a9c\nanswer: {"type": "bulk", "text": "embstr"}\n'
    'command: HINCRBY cache:config hits notanumber\nanswer: {"type": "error", "text": '
    '"ERR value is not an integer or out of range"}\n'
    'command: GETRANGE nosuchkey 0 10\nanswer: {"type": "bulk", "text": ""}\n'
    'command: LINDEX queue:jobs 99\nanswer: {"type": "nil"}\n'
    'command: SLOWLOG RESET\nanswer: {"type": "status", "text": "OK"}')

STATUS_RE = r"^[\x20-\x7e]{1,200}$"
ERROR_RE = r"^[A-Z][A-Z_]{1,31} [\x20-\x7e]{1,200}$"
BULK_RE = r"^[\x20-\x7e\t\n]*$"
LlmItem = Union[StrictInt, None, str]


class LlmRedisReply(BaseModel):
    """What the model may return: one RESP2 reply, nothing else."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["status", "error", "integer", "bulk", "nil", "array"]
    text: Optional[str] = Field(default=None, max_length=4096)
    integer: Optional[StrictInt] = Field(default=None, ge=LLONG_MIN, le=LLONG_MAX)
    items: Optional[list[LlmItem]] = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def _one_shape(self) -> "LlmRedisReply":
        t = self.type
        if t in ("status", "error", "bulk"):
            if self.text is None or self.integer is not None or self.items is not None:
                raise ValueError("text replies carry text only")
            pattern = {"status": STATUS_RE, "error": ERROR_RE, "bulk": BULK_RE}[t]
            if not re.fullmatch(pattern, self.text):
                raise ValueError("text not allowed for this reply type")
        elif t == "integer":
            if self.integer is None or self.text is not None or self.items is not None:
                raise ValueError("integer replies carry an integer only")
        elif t == "nil":
            if self.text is not None or self.integer is not None or self.items is not None:
                raise ValueError("nil carries nothing")
        else:
            if self.items is None or self.text is not None or self.integer is not None:
                raise ValueError("array replies carry items only")
            for item in self.items:
                if isinstance(item, str) and (len(item) > 512
                                              or not re.fullmatch(BULK_RE, item)):
                    raise ValueError("array item too long or not printable")
                if isinstance(item, int) and not LLONG_MIN <= item <= LLONG_MAX:
                    raise ValueError("array integer out of range")
        return self


def validate_llm_reply(raw: Any) -> Optional[LlmRedisReply]:
    """Re-validate whatever came back; the JsonLLM implementation is not trusted."""
    if raw is None:
        return None
    try:
        if isinstance(raw, BaseModel):
            raw = raw.model_dump()
        return LlmRedisReply.model_validate(raw)
    except Exception:  # noqa: BLE001
        return None


def render_llm_reply(ans: LlmRedisReply) -> Reply:
    if ans.type == "status":
        return f"+{ans.text}\r\n".encode()
    if ans.type == "error":
        return err(ans.text or "ERR")
    if ans.type == "integer":
        return ans.integer
    if ans.type == "bulk":
        return ans.text
    if ans.type == "nil":
        return None
    return list(ans.items or [])


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


UNHANDLED = object()      # _dispatch: no canned answer for this command


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
        # Persistence as INFO persistence and LASTSAVE report it: the last save happened
        # within the "save 3600 1" window, with some changes made since.
        offset = 300 + hashlib.sha256(f"{self.ctx.seed}|redis_lastsave".encode()).digest()[0] * 11
        self.last_save = int(self.started) - offset
        self.dirty = 12
        self.scripts: dict[str, str] = {}

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

    @property
    def major_version(self) -> int:
        m = re.match(r"(\d{1,3})", self.version)
        return int(m.group(1)) if m else 7

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
            if name in ("POST", "HOST:"):
                self.conn.emit("command", "Redis command", username=self.user, data=data)
                return      # HTTP sent to Redis: the real server closes without a reply
            try:
                reply, close = self.execute(name, args)
                if reply is UNHANDLED:
                    reply = await self.unhandled(name, args, data)
            finally:
                # Logged after the answer (so it carries the model step) and even when
                # answering failed.
                if name != "AUTH":
                    self.conn.emit("command", "Redis command", username=self.user, data=data)
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

    @staticmethod
    def unknown_command(a: list[str]) -> bytes:
        args = " ".join(f"'{x[:32]}'" for x in a[1:4])
        return err(f"ERR unknown command '{a[0][:64]}', with args beginning with: {args}")

    def execute(self, name: str, args: list[str]) -> tuple[object, bool]:
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

    async def unhandled(self, name: str, a: list[str], data: dict) -> Reply:
        """A command the canned logic does not answer: the model for a real Redis command
        (when configured), else the real unknown-command error."""
        if name not in REDIS_COMMANDS or self.ctx.json_llm is None:
            return self.unknown_command(a)
        answer = await self._ask_model(a)
        rung = self.ctx.take_llm_rung(self.conn.task_name)
        if answer is not None:
            data["rung"] = rung or "llm"
            return answer[0]
        data["rung"] = "fallback"
        return self.unknown_command(a)

    def _keyspace_summary(self) -> str:
        parts = [f"{k} ({t})" for k, (t, _v) in list(self.keys.items())[:50]]
        return ", ".join(parts)[:1500] or "(empty)"

    async def _ask_model(self, a: list[str]) -> Optional[tuple[Reply]]:
        """The model's reply in a 1-tuple (a nil reply is a valid answer), or None."""
        system = (
            f"You emulate a Redis {self.version} server (standalone, RESP2) inside a decoy. "
            "Answer the command in the untrusted block as the real server would, as JSON: "
            '{"type": "status", "text": "..."}, {"type": "error", "text": "ERR ..."}, '
            '{"type": "integer", "integer": n}, {"type": "bulk", "text": "..."}, '
            '{"type": "nil"} or {"type": "array", "items": [strings, integers or null]} '
            "(at most 64 items, 512 characters each; bulk text at most 4096 printable "
            "characters). Error text starts with the Redis error code in capitals. Keys not "
            "listed with the command do not exist. Never add explanations.")
        command = " ".join(shlex.quote(x[:200]) for x in a[:32])[:MAX_LLM_COMMAND_CHARS]
        payload = (f"selected database: {self.db}\nkeys: {self._keyspace_summary()}\n"
                   f"command: {command}")
        user = untrusted_block("Redis command and keyspace", payload, os.urandom(8).hex())
        try:
            raw = await self.ctx.llm_json(self.conn.task_name, self.conn.src_ip, system, user,
                                          LlmRedisReply, examples=REDIS_EXAMPLES)
        except Exception:  # noqa: BLE001 - hostile/broken model output -> protocol error
            return None
        ans = validate_llm_reply(raw)
        return None if ans is None else (render_llm_reply(ans),)

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

    # ---- keyspace helpers ------------------------------------------------------------------

    def _get(self, key: str, typ: str):
        item = self.keys.get(key)
        if item is None:
            return None
        if item[0] != typ:
            raise TypeError
        return item[1]

    def _room(self, ks: dict, *keys: str) -> None:
        """Raise the real OOM error when creating ``keys`` would pass the key cap."""
        new = {k for k in keys if k not in ks}
        if new and len(ks) + len(new) > MAX_KEYS:
            raise RedisError(OOM)

    def _store(self, key: str, typ: str, value: object, keep_ttl: bool = False) -> None:
        ks = self.keys
        self._room(ks, key)
        ks[key] = (typ, value)
        if not keep_ttl:
            self.expiry.pop((self.db, key), None)

    def _drop(self, key: str) -> bool:
        self.expiry.pop((self.db, key), None)
        return self.keys.pop(key, None) is not None

    def _drop_if_empty(self, key: str, container: object) -> None:
        if not container:
            self._drop(key)

    def _container(self, key: str, typ: str, empty):
        """The key's container, created (within the key cap) when missing."""
        value = self._get(key, typ)
        if value is None:
            value = empty
            self._store(key, typ, value)
        return value

    def dispatch(self, name: str, a: list[str]) -> object:
        n = ARITY.get(name)
        if n is not None and (len(a) != n if n > 0 else len(a) < -n):
            raise IndexError
        try:
            return self._dispatch(name, a)
        except TypeError:
            return err(WRONGTYPE)

    def _dispatch(self, name: str, a: list[str]) -> object:
        ks = self.keys
        if name in WRITE_COMMANDS:
            self.dirty += 1
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
        if name in STRING_COMMANDS:
            return self.string_cmd(name, a, ks)
        if name in ("DEL", "UNLINK"):
            return sum(1 for k in a[1:] if self._drop(k))
        if name == "EXISTS":
            return sum(1 for k in a[1:] if k in ks)
        if name == "TYPE":
            item = ks.get(a[1])
            return f"+{item[0] if item else 'none'}\r\n".encode()
        if name in ("RENAME", "RENAMENX"):
            src, dst = a[1], a[2]
            if src not in ks:
                return err("ERR no such key")
            if name == "RENAMENX" and dst in ks:
                return 0
            if src != dst:
                ttl = self.expiry.pop((self.db, src), None)
                item = ks.pop(src)
                self._drop(dst)
                ks[dst] = item
                if ttl is not None:
                    self.expiry[(self.db, dst)] = ttl
            return 1 if name == "RENAMENX" else OK
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
                self._drop(a[1])
                return 1
            self.expiry[(self.db, a[1])] = time.monotonic() + seconds
            return 1
        if name == "PERSIST":
            if a[1] not in ks:
                return 0
            return 1 if self.expiry.pop((self.db, a[1]), None) is not None else 0
        if name in HASH_COMMANDS:
            return self.hash_cmd(name, a)
        if name in LIST_COMMANDS:
            return self.list_cmd(name, a)
        if name in SET_COMMANDS:
            return self.set_cmd(name, a)
        if name in ("FLUSHALL", "FLUSHDB"):
            if name == "FLUSHALL":
                self.dbs = {0: {}}
                self.expiry.clear()
            else:
                ks.clear()
                for key in [k for k in self.expiry if k[0] == self.db]:
                    self.expiry.pop(key, None)
            return OK
        if name == "CONFIG":
            return self.config_cmd(a)
        if name == "SAVE":
            self.saved()
            return OK
        if name == "BGSAVE":
            if len(a) > 2 or (len(a) == 2 and a[1].upper() != "SCHEDULE"):
                return err("ERR syntax error")
            self.saved()
            return b"+Background saving started\r\n"
        if name == "BGREWRITEAOF":
            return b"+Background append only file rewriting started\r\n"
        if name == "LASTSAVE":
            return self.last_save
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
        if name in ("EVAL", "EVALSHA", "EVAL_RO", "EVALSHA_RO", "FCALL"):
            if len(a) < 3:
                raise IndexError
            if name == "FCALL":
                return err("ERR Function not found")
            script: Optional[str] = a[1]
            if name.startswith("EVALSHA"):
                script = self.scripts.get(a[1].lower())
                if script is None:
                    return err("NOSCRIPT No matching script. Please use EVAL.")
            return self.eval(script or "", a, read_only=name.endswith("_RO"))
        if name == "SCRIPT":
            sub = a[1].upper()
            if sub == "LOAD":
                if len(a) != 3:
                    raise IndexError
                sha = hashlib.sha1(a[2].encode()).hexdigest()
                if sha not in self.scripts and len(self.scripts) >= MAX_SCRIPTS:
                    self.scripts.pop(next(iter(self.scripts)))
                self.scripts[sha] = a[2]
                return sha
            if sub == "EXISTS":
                return [int(x.lower() in self.scripts) for x in a[2:]]
            if sub == "FLUSH":
                self.scripts.clear()
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
        return UNHANDLED

    def saved(self) -> None:
        """SAVE or BGSAVE: nothing is written; the persistence counters move as if it was."""
        self.last_save = max(self.last_save, int(time.time()))
        self.dirty = 0

    # ---- strings ---------------------------------------------------------------------------

    def string_cmd(self, name: str, a: list[str], ks: dict) -> Reply:
        if name == "GET":
            return self._get(a[1], "string")
        if name == "SET":
            if len(a) < 3:
                raise IndexError
            ttl_ms, nx, xx, get, keep_ttl = self.set_options(a[3:])
            old = self._get(a[1], "string") if get else None   # WRONGTYPE before any write
            exists = a[1] in ks
            if (nx and exists) or (xx and not exists):
                return old if get else None
            self._store(a[1], "string", a[2], keep_ttl=keep_ttl)
            if ttl_ms is not None:
                self.expiry[(self.db, a[1])] = time.monotonic() + ttl_ms / 1000
            return old if get else OK
        if name in ("SETNX", "SETEX", "PSETEX"):
            if name == "SETNX":
                if a[1] in ks:
                    return 0
                self._store(a[1], "string", a[2])
                return 1
            n = to_int(a[2])
            if n <= 0 or (name == "SETEX" and n > LLONG_MAX // 1000):
                return err(f"ERR invalid expire time in '{name.lower()}' command")
            self._store(a[1], "string", a[3])
            self.expiry[(self.db, a[1])] = time.monotonic() + (n if name == "SETEX" else n / 1000)
            return OK
        if name in ("GETSET", "GETDEL"):
            old = self._get(a[1], "string")
            if name == "GETSET":
                self._store(a[1], "string", a[2])
            elif old is not None:
                self._drop(a[1])
            return old
        if name == "APPEND":
            old = self._get(a[1], "string") or ""
            self._store(a[1], "string", old + a[2], keep_ttl=True)
            return len((old + a[2]).encode("utf-8"))
        if name == "STRLEN":
            return len((self._get(a[1], "string") or "").encode("utf-8"))
        if name == "MGET":
            out: list = []
            for k in a[1:]:
                item = ks.get(k)
                out.append(item[1] if item is not None and item[0] == "string" else None)
            return out
        if name == "MSET":
            if len(a) % 2 == 0:
                raise IndexError
            self._room(ks, *a[1::2])
            for i in range(1, len(a), 2):
                self._store(a[i], "string", a[i + 1])
            return OK
        # INCR, INCRBY, DECR, DECRBY
        delta = 1 if name in ("INCR", "DECR") else to_int(a[2])
        if name == "DECRBY" and delta == LLONG_MIN:
            return err("ERR decrement would overflow")
        if name in ("DECR", "DECRBY"):
            delta = -delta
        val = to_int(self._get(a[1], "string") or "0")
        if not LLONG_MIN <= val + delta <= LLONG_MAX:
            return err("ERR increment or decrement would overflow")
        val += delta
        self._store(a[1], "string", str(val), keep_ttl=True)
        return val

    # ---- hashes, lists, sets ---------------------------------------------------------------

    def hash_cmd(self, name: str, a: list[str]) -> Reply:
        if name == "HSET":
            if len(a) < 4 or len(a) % 2:
                raise IndexError
            h = self._container(a[1], "hash", {})
            added = 0
            for i in range(2, len(a), 2):
                if a[i] not in h and len(h) >= MAX_KEYS:
                    break
                added += a[i] not in h
                h[a[i]] = a[i + 1]
            return added
        h = self._get(a[1], "hash") or {}
        if name == "HGET":
            return h.get(a[2])
        if name == "HGETALL":
            return [x for kv in h.items() for x in kv]
        if name == "HKEYS":
            return list(h)
        if name == "HVALS":
            return list(h.values())
        if name == "HLEN":
            return len(h)
        if name == "HEXISTS":
            return int(a[2] in h)
        removed = sum(1 for f in a[2:] if h.pop(f, None) is not None)    # HDEL
        if removed:
            self._drop_if_empty(a[1], h)
        return removed

    def list_cmd(self, name: str, a: list[str]) -> Reply:
        if name in ("LPUSH", "RPUSH"):
            if len(a) < 3:
                raise IndexError
            lst = self._container(a[1], "list", [])
            for v in a[2:]:
                if len(lst) < MAX_KEYS:
                    lst.insert(0, v) if name == "LPUSH" else lst.append(v)
            return len(lst)
        lst = self._get(a[1], "list")
        if name == "LLEN":
            return len(lst or [])
        if name == "LRANGE":
            lst = lst or []
            start, stop = to_int(a[2]), to_int(a[3])
            n = len(lst)
            start = max(0, start + n if start < 0 else start)
            stop = stop + n if stop < 0 else stop
            return lst[start:stop + 1]
        # LPOP / RPOP [count]
        if len(a) > 3:
            raise RedisError("ERR syntax error")
        count = None
        if len(a) == 3:
            count = to_int(a[2], "ERR value is out of range, must be positive")
            if count < 0:
                raise RedisError("ERR value is out of range, must be positive")
        if not lst:
            return NIL_ARRAY if count is not None else None
        take = 1 if count is None else min(count, len(lst))
        if name == "LPOP":
            out, lst[:take] = lst[:take], []
        else:
            out = list(reversed(lst[len(lst) - take:])) if take else []
            del lst[len(lst) - take:]
        self._drop_if_empty(a[1], lst)
        return out if count is not None else out[0]

    def set_cmd(self, name: str, a: list[str]) -> Reply:
        if name == "SADD":
            if len(a) < 3:
                raise IndexError
            s = self._container(a[1], "set", [])
            added = 0
            for v in a[2:]:
                if v not in s and len(s) < MAX_KEYS:
                    s.append(v)
                    added += 1
            return added
        s = self._get(a[1], "set")
        if name == "SMEMBERS":
            return list(s or [])
        if name == "SCARD":
            return len(s or [])
        if name == "SISMEMBER":
            return int(a[2] in (s or []))
        removed = 0                                                       # SREM
        for v in a[2:]:
            if s is not None and v in s:
                s.remove(v)
                removed += 1
        if s is not None and removed:
            self._drop_if_empty(a[1], s)
        return removed

    # ---- scripts ---------------------------------------------------------------------------

    def eval(self, script: str, a: list[str], read_only: bool) -> Reply:
        """Answer a few literal script forms against the keyspace; never runs Lua."""
        numkeys = to_int(a[2])
        if numkeys < 0:
            return err("ERR Number of keys can't be negative")
        if numkeys > len(a) - 3:
            return err("ERR Number of keys can't be greater than number of args")
        keys, argv = a[3:3 + numkeys], a[3 + numkeys:]
        if len(script) > MAX_SCRIPT_CHARS:
            return None
        body = " ".join(script.split())

        def arg(m: "re.Match", base: int) -> Optional[str]:
            table, idx, single, double = m.group(base, base + 1, base + 2, base + 3)
            if table is None:
                return single if single is not None else double
            values = keys if table == "KEYS" else argv
            i = int(idx)
            return values[i - 1] if 1 <= i <= len(values) else None

        m = EVAL_RETURN_INT_RE.fullmatch(body)
        if m:
            return int(m.group(1))
        m = EVAL_RETURN_ARG_RE.fullmatch(body)
        if m:
            return arg(m, 1)
        m = EVAL_CALL_RE.fullmatch(body)
        if not m:
            return None
        verb = m.group(2).upper()
        args = [arg(x, 1) for x in EVAL_CALL_ARG_RE.finditer(m.group(3))]
        if any(x is None for x in args) or (verb == "SET" and read_only):
            return None
        if verb == "GET" and len(args) != 1:
            return None
        if verb == "SET" and len(args) != 2:
            return None
        try:
            out = self.dispatch(verb, [verb] + [x for x in args if x is not None])
        except RedisError as exc:
            out = err(str(exc))
        if isinstance(out, bytes) and out.startswith(b"-"):
            return self.script_error(out[1:].decode().strip(), script)
        return out if m.group(1) else None

    def script_error(self, text: str, script: str) -> bytes:
        """An error raised by redis.call(), as the server version reports it."""
        sha = hashlib.sha1(script.encode()).hexdigest()
        if self.major_version >= 7:
            return err(f"{text} script: {sha}, on @user_script:1.")
        return err(f"ERR Error running script (call to f_{sha}): @user_script:1: {text}")

    @staticmethod
    def set_options(opts: list[str]) -> tuple[Optional[int], bool, bool, bool, bool]:
        """Parse SET options: (ttl in ms or None, NX, XX, GET, KEEPTTL). Raises RedisError
        like Redis 7."""
        ttl: Optional[int] = None
        nx = xx = get = keep = False
        i = 0
        while i < len(opts):
            flag = opts[i].upper()
            if flag in ("EX", "PX", "EXAT", "PXAT"):
                if ttl is not None or keep or i + 1 >= len(opts):
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
                continue
            if flag == "NX" and not xx:
                nx = True
            elif flag == "XX" and not nx:
                xx = True
            elif flag == "GET":
                get = True
            elif flag == "KEEPTTL" and ttl is None:
                keep = True
            else:
                raise RedisError("ERR syntax error")
            i += 1
        return ttl, nx, xx, get, keep

    @staticmethod
    def set_ttl_ms(opts: list[str]) -> Optional[int]:
        """Parse SET options; the TTL in ms or None. Raises RedisError like Redis 7."""
        return RedisSession.set_options(opts)[0]

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
        now = time.monotonic()
        keyspace = []
        for db in sorted(self.dbs):
            space = self.dbs[db]
            if space:
                expires = sum(1 for (d, k), when in self.expiry.items()
                              if d == db and k in space and when > now)
                keyspace.append(f"db{db}:keys={len(space)},expires={expires},avg_ttl=0")
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
            "persistence": ["loading:0", f"rdb_changes_since_last_save:{self.dirty}",
                            "rdb_bgsave_in_progress:0", f"rdb_last_save_time:{self.last_save}",
                            "rdb_last_bgsave_status:ok", "rdb_last_bgsave_time_sec:0",
                            "rdb_current_bgsave_time_sec:-1", "rdb_last_cow_size:0",
                            "aof_enabled:0", "aof_rewrite_in_progress:0",
                            "aof_rewrite_scheduled:0", "aof_last_rewrite_time_sec:-1",
                            "aof_current_rewrite_time_sec:-1", "aof_last_bgrewrite_status:ok",
                            "aof_last_write_status:ok", "aof_last_cow_size:0"],
            "stats": ["total_connections_received:4821", "total_commands_processed:91234",
                      "instantaneous_ops_per_sec:3", "rejected_connections:0",
                      "keyspace_hits:20412", "keyspace_misses:1291"],
            "replication": ["role:master", "connected_slaves:0",
                            "master_replid:5e0c1f0a9b3d7e2c4a6b8d0f1e3a5c7b9d2f4e6a",
                            "master_repl_offset:0"],
            "cpu": ["used_cpu_sys:412.118220", "used_cpu_user:633.270115"],
            "keyspace": keyspace,
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

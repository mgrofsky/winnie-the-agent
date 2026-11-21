"""The first bytes of a program file, as ``cat``, ``dd`` or a ``while read`` loop show them.

IoT loaders read a few bytes of a binary on the host (``/bin/echo``, ``/bin/busybox``,
``/proc/self/exe``) and take the architecture from the ELF header: the class and byte order
in ``e_ident`` and the machine field at offset 18. The bytes are built here from the ELF
layout for the machine ``uname -m`` reports: a header, the program headers a PIE program
has, the interpreter path, the build-id and ABI notes, then filler standing in for code. Only
the start of the file is produced (``SIZE`` bytes); the header still describes a file of
the real size, as the start of a real binary would.

Nothing is copied from any system: every field is computed, and the build id and filler
come from the sensor seed, so one sensor always shows the same bytes for one program.
"""

from __future__ import annotations

import random
import struct

SIZE = 2048

# uname -m -> (e_machine, 64-bit, e_flags, interpreter)
MACHINES = {
    "x86_64": (62, True, 0, "/lib64/ld-linux-x86-64.so.2"),
    "aarch64": (183, True, 0, "/lib/ld-linux-aarch64.so.1"),
    "i686": (3, False, 0, "/lib/ld-linux.so.2"),
    "armv7l": (40, False, 0x05000400, "/lib/ld-linux-armhf.so.3"),   # EABI5, hard float
}

PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE, PT_PHDR = 1, 2, 3, 4, 6
PT_GNU_STACK, PT_GNU_RELRO = 0x6474E551, 0x6474E552
PF_X, PF_W, PF_R = 1, 2, 4
ET_DYN = 3
# Bytes a terminal or the Telnet layer would rewrite (LF, CR, IAC); kept out of the header
# so the fields a loader reads arrive at their offsets.
_AWKWARD = b"\n\r\xff"


def machine_field(machine: str) -> int:
    return MACHINES.get(machine, MACHINES["x86_64"])[0]


def image(machine: str, rng: random.Random, size: int = SIZE) -> bytes:
    """The first ``size`` bytes of a dynamically linked PIE program for ``machine``."""
    em, wide, flags, interp = MACHINES.get(machine, MACHINES["x86_64"])
    ehsize, phentsize, shentsize = (64, 56, 64) if wide else (52, 32, 40)
    word = "Q" if wide else "I"
    align = 0x1000 if machine != "aarch64" else 0x10000
    phnum = 9
    interp_at = ehsize + phnum * phentsize
    interp_bytes = interp.encode("ascii") + b"\x00"
    note_at = (interp_at + len(interp_bytes) + 3) & ~3
    build_id = bytes(rng.getrandbits(8) for _ in range(20))
    notes = (struct.pack("<III", 4, 20, 3) + b"GNU\x00" + build_id
             + struct.pack("<III", 4, 16, 1) + b"GNU\x00" + struct.pack("<IIII", 0, 3, 2, 0))
    while True:
        text = 0x1000 + rng.randrange(0x400, 0x4000, 0x10)       # code segment size
        data = 0x1000 * rng.randrange(1, 4)
        shnum = rng.randrange(27, 32)
        length = 0x4000 + text + data + rng.randrange(0x400, 0x2000, 8)   # the real file size
        shoff = length - shnum * shentsize
        entry = 0x1000 + rng.randrange(0x100, text - 0x100, 0x10)
        header = (b"\x7fELF" + bytes((2 if wide else 1, 1, 1, 0)) + bytes(8)
                  + struct.pack(f"<HHI{word}{word}{word}IHHHHHH", ET_DYN, em, 1, entry, ehsize,
                                shoff, flags, ehsize, phentsize, phnum, shentsize, shnum,
                                shnum - 1))
        if not any(b in _AWKWARD for b in header):
            break
    rodata, dyn = 0x1000 + text, 0x2000 + text + data - 0x200
    segments = [
        (PT_PHDR, PF_R, ehsize, ehsize, phnum * phentsize, 8),
        (PT_INTERP, PF_R, interp_at, interp_at, len(interp_bytes), 1),
        (PT_LOAD, PF_R, 0, 0, 0x1000, align),
        (PT_LOAD, PF_R | PF_X, 0x1000, 0x1000, text, align),
        (PT_LOAD, PF_R, rodata, rodata, 0x1000, align),
        (PT_LOAD, PF_R | PF_W, rodata + 0x1000, rodata + 0x1000 + align - 0x1000, data,
         align),
        (PT_DYNAMIC, PF_R | PF_W, dyn, dyn + align - 0x1000, 0x1F0 if wide else 0xF8, 8),
        (PT_NOTE, PF_R, note_at, note_at, len(notes), 4),
        (PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 16),
    ]
    phdrs = b""
    for kind, perms, offset, vaddr, filesz, palign in segments:
        if wide:
            phdrs += struct.pack("<IIQQQQQQ", kind, perms, offset, vaddr, vaddr, filesz,
                                 filesz, palign)
        else:
            phdrs += struct.pack("<IIIIIIII", kind, offset, vaddr, vaddr, filesz, filesz,
                                 perms, palign)
    out = bytearray(header + phdrs + interp_bytes)
    out += bytes(note_at - len(out)) + notes
    out += bytes((-len(out)) % 64)
    out += bytes(rng.getrandbits(8) for _ in range(max(0, size - len(out))))
    return bytes(out[:size])

#!/usr/bin/env python3
"""Generate STM32N6 Boot ROM FSBL header for wolfBoot.

Creates a trusted binary (wolfboot-trusted.bin) by prepending the Boot ROM
FSBL header to wolfboot.bin. Based on UM3234 Rev 3 Section 4.1 and
ST's reference ai_fsbl.hex from STM32N6-GettingStarted.

Layout matches ST's reference exactly:
  0x000-0x09F: Base header (160 bytes)
  0x0A0-0x23F: Padding extension (0x1A0 bytes, PostHdrLen=0x1A0)
  0x240-0x3FF: Zero padding (0x1C0 bytes, part of image data)
  0x400+:      wolfboot.bin payload (vector table + code)

Usage:
    python3 stm32n6_fsbl_header.py wolfboot.bin wolfboot-trusted.bin
"""

import struct
import sys
import os

MAGIC = 0x324D5453          # bytes in memory: 'S','T','M',0x32
HEADER_VERSION = 0x00020300  # v2.3
BASE_HEADER_SIZE = 0xA0      # 160 bytes
POST_HEADER_LEN = 0x1A0     # matches ST reference (padding extension size)
CODE_OFFSET = 0x400          # wolfboot.bin starts at this file offset
ZERO_PAD_SIZE = CODE_OFFSET - BASE_HEADER_SIZE - POST_HEADER_LEN  # 0x1C0
BINARY_TYPE_FSBL = 0x10      # FSBL binary type (from ST reference)

def build_fsbl_header(bin_path, out_path):
    with open(bin_path, 'rb') as f:
        payload = f.read()

    if len(payload) < 8:
        print(f"Error: {bin_path} too small ({len(payload)} bytes)", file=sys.stderr)
        sys.exit(1)

    # Extract entry point from vector table word 1 (Reset_Handler)
    sp, entry = struct.unpack_from('<II', payload, 0)

    # Align payload to 32 bytes (Boot ROM requirement per UM3234)
    align = 32
    pad_payload = (align - (len(payload) % align)) % align
    if pad_payload:
        payload += b'\x00' * pad_payload

    # ST reference layout: zero padding + payload, payload at file offset 0x400.
    # Boot ROM loads image_data at LoadAddr (auto = 0x34180400 default buffer).
    file_data = (b'\x00' * ZERO_PAD_SIZE) + payload
    image_length = len(file_data)
    checksum = sum(file_data) & 0xFFFFFFFF

    # --- Base header (0xA0 = 160 bytes) ---
    base = bytearray(BASE_HEADER_SIZE)

    struct.pack_into('<I', base, 0x00, MAGIC)
    # 0x04-0x63: Image signature (96 bytes) — zeros for -nk (unsigned)
    struct.pack_into('<I', base, 0x64, checksum)
    struct.pack_into('<I', base, 0x68, HEADER_VERSION)
    struct.pack_into('<I', base, 0x6C, image_length)
    struct.pack_into('<I', base, 0x70, entry)          # Reset_Handler
    struct.pack_into('<I', base, 0x74, 0x00000000)     # Reserved1
    # LoadAddr = 0x34180400 (matches STM32_SigningTool_CLI reference).
    # Boot ROM loads image_data starting at this address.
    struct.pack_into('<I', base, 0x78, 0x34180400)     # LoadAddr
    struct.pack_into('<I', base, 0x7C, 0x00000000)     # Reserved2
    struct.pack_into('<I', base, 0x80, 0x00000000)     # Version = 0
    struct.pack_into('<I', base, 0x84, 0x80000000)     # ExtFlags: padding only
    struct.pack_into('<I', base, 0x88, POST_HEADER_LEN) # PostHdrLen = 0x1A0
    struct.pack_into('<I', base, 0x8C, BINARY_TYPE_FSBL) # BinaryType = 0x10
    # 0x90-0x97: PAD (must be 0)
    # 0x98: Nonsecure payload length = 0
    # 0x9C: Nonsecure payload hash = 0

    # --- Padding extension header (0x1A0 bytes) ---
    pad_ext = bytearray(POST_HEADER_LEN)
    struct.pack_into('<I', pad_ext, 0, 0xFFFF5453)     # 'S','T',0xFF,0xFF
    struct.pack_into('<I', pad_ext, 4, POST_HEADER_LEN) # Extension length

    # --- Assemble ---
    header = base + pad_ext
    assert len(header) == BASE_HEADER_SIZE + POST_HEADER_LEN  # 0x240

    trusted = header + file_data
    assert trusted[0x400:0x408] == payload[:8]  # verify vector table at 0x400

    with open(out_path, 'wb') as f:
        f.write(trusted)

    print(f"  Entry point:   0x{entry:08X} (Reset_Handler)")
    print(f"  Initial SP:    0x{sp:08X}")
    print(f"  Payload size:  {len(payload)} bytes")
    print(f"  Image length:  0x{image_length:X} (payload only)")
    print(f"  Checksum:      0x{checksum:08X}")
    print(f"  PostHdrLen:    0x{POST_HEADER_LEN:X} (matches ST reference)")
    print(f"  Code at:       file offset 0x{CODE_OFFSET:X}")
    print(f"  Total size:    {len(trusted)} bytes")
    print(f"  Output:        {out_path}")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <wolfboot.bin> <output.bin>")
        sys.exit(1)

    bin_path = sys.argv[1]
    out_path = sys.argv[2]

    if not os.path.exists(bin_path):
        print(f"Error: {bin_path} not found", file=sys.stderr)
        sys.exit(1)

    build_fsbl_header(bin_path, out_path)

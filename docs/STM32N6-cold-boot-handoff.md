# STM32N6 NOR Cold Boot — Handoff

**Status:** SWD-load fully working. Cold-boot from XSPI2 NOR partially working
(BootROM now attempts FSBL load after `OTP11` was fused; still failing
mid-load with no visible LED indicator). One more OTP fuse pair (OTP13 +
OTP14, boot pin remap) is the prime suspect for closing the gap.

**Branch:** `stm32n6-cold-boot-handoff` (this branch). Based on
`stm32n6-port-wolfboot` (PR #720) merged with `stm32n6-cold-boot-investigation`
plus the Skoll review fixes plus this session's STM32CubeProgrammer-based
tooling rewrite plus the OTP11 procedure.

**Hardware:** NUCLEO-N657X0-Q (MB1940), STM32N657X0H Cortex-M55. Macronix
MX25UM51245G NOR on XSPI2 / XSPIM Port 2 at memory-mapped `0x70000000`.

---

## 1. What you can do TODAY (works fully)

```sh
# SWD-load wolfBoot to SRAM, run app — proven working end-to-end
./tools/scripts/stm32n6_flash.sh --skip-build --swd-only
# UART (USART1 via ST-Link VCP, 115200 8N1):
#   wolfBoot Init
#   TrustZone: Off
#   Boot partition: 0x70020000 (sz 29876, ver 0x1, type 0x201)
#   Booting version: 0x1
#   === STM32N6 wolfBoot Test App ===
#   Firmware Version: 1
#   Boot OK (state: SUCCESS)
#   Blinking blue LED
```

Jumper position: **JP1=1-2, JP2=2-3** (dev mode). ST-Link USB only.

## 2. What this session changed vs PR #720

### Branch consolidation
- Cherry-picked the cold-boot work from `origin/stm32n6-cold-boot-investigation`
  (commit `7db6fa35`) onto PR #720's branch:
  - Stack-pointer-fix naked stub in `src/boot_arm.c` for STM32N6 BootROM
    handoff (`isr_reset` sets MSP from `END_STACK` then tail-calls C body).
  - Python FSBL header generator at `tools/scripts/stm32n6_fsbl_header.py`
    (UM3234 v2.3 layout, byte-identical to ST `STM32_SigningTool_CLI` output).
  - HAL hardening in `hal/stm32n6.c` (XSPIM secure-alias write, PLL bypass
    clear in `clock_config`, UART timeouts, XSPI2 reset before init).
  - `hal/stm32n6.h` updates (XSPIM secure base, RCC reg defs).
  - `config/openocd/openocd_stm32n6.cfg` AP1 CSW write for secure debug.

### Skoll review fixes preserved
- `octospi_write_enable` now returns `int`; `nor_flash_write` /
  `nor_flash_erase` propagate the error so a silent WREN failure can't
  corrupt a swap.
- VTOR macro in `src/boot_arm.c` writes the **non-secure** VTOR
  (`0xE002ED08`) for both Cortex-M33 and Cortex-M55 with `TZEN`+CMSE
  (so the secure exception table doesn't point at NS-attributed memory).
- `docs/Targets.md` clarifies that `0x24xxxxxx` and `0x34xxxxxx` are two
  IDAU-attributed aliases of the same physical AXISRAM.

### Tooling rewrite
- `tools/scripts/stm32n6_flash.sh` switched from OpenOCD to
  STM32CubeProgrammer (`STM32_Programmer_CLI` + `STM32_SigningTool_CLI` +
  `MX25UM51245G_STM32N6570-NUCLEO.stldr` external loader). Auto-detects
  install path, supports `box64` for ARM hosts. New flags:
  - `--cold-boot` (default) — wraps wolfBoot with FSBL header, programs to
    NOR offset 0
  - `--swd-only` — old SWD-load-into-SRAM flow, doesn't touch NOR
  - `--otp-info` — read OTP fuses 11/13/14/18/124
  - `--erase-fsbl` — erase NOR sectors 0-3
  - `--app-only`, `--test-update`, `--skip-build` (existing)
- OpenOCD config kept for SWD debug, no longer on the flash path.

### Linker origin moved
- `arch.mk` `WOLFBOOT_ORIGIN` for stm32n6 now `0x34180400` (or
  `0x24180400` with TZEN=1) — the BootROM-fixed FSBL load address in
  AXISRAM2. Was `0x34000000` previously, which would have produced
  silently-mismatched code addresses post-BootROM-handoff.

### OTP11 fused this session (irreversible, committed to silicon)
- Wrote `BOOTROM_CONFIG_2.boot_source = 3` (`sNOR / XSPI NOR`) via
  `STM32_Programmer_CLI -c port=SWD mode=UR -otp write word=11 value=0x60`.
- Verified: `Data11 = 0x00000060`, `Status11 = 0x00000000` (programmed
  but not locked).
- Effect: BootROM trace at `0x341037F0` went from 16 short entries
  (BootROM exited silently) to 50 entries spanning ts=1795→6150
  (BootROM is now attempting FSBL load).

## 3. Critical gotcha: how to write "Protected" OTP

`STM32_Programmer_CLI -otp write` will silently fail with
`Word N has invalid status [Protected]` on `BOOTROM_CONFIG_*` words if
you connect with `mode=HOTPLUG`, `mode=NORMAL`, or `mode=POWERDOWN`.

**You MUST use `mode=UR` (Under Reset) AND pipe `yes` to stdin** because the
tool prompts `Warning: Do you confirm ? [yes/no]` interactively and busy-loops
forever if stdin is not a TTY. Working incantation:

```sh
yes | STM32_Programmer_CLI -c port=SWD mode=UR -otp write word=11 value=0x60
```

Why `mode=UR`: BootROM locks BSEC2 permission groups when it hands off to
FSBL. Under-reset attach prevents BootROM from running at all, so BSEC stays
unlocked and CubeProgrammer can write the protected fuses directly.

USB DFU (`port=USB1`) is a **dead end** for OTP on N6 — the BootROM USB DFU
interface does not expose the OTP partition (`partition 0xf2 unreachable`).

## 4. Current cold-boot symptom (post-OTP11)

Procedure:
1. `JP1 = 1-2, JP2 = 1-2` (cold-boot mode)
2. USB unplug 3 sec, replug, press RESET button

Result:
- LD2/LD8 power LED on (normal — board has 3.3V)
- **No** LD5 (red, BOOTFAILN) flash
- **No** LD6 (green) or LD7 (blue) — wolfBoot didn't reach the test-app
- **No** UART output on `/dev/ttyACM0` (USART1 via ST-Link VCP)
- BootROM context at `0x34100000`:
  - `bootPartitionUsedToBoot` = 0 (no successful boot)
  - `bootInterfaceSelected` = 0
  - Single non-zero word at offset `0x38` = `0x18001000` (consistent across
    pre/post OTP runs — likely a BootROM constant)
- BootROM trace at `0x341037F0`: 12 decoded entries, ts=1795→6150
  - Entry #2 has `v2 = 0x00002909` — possible error code
  - Entry #3 has `v2 = 0x0000003b` — possible error code
  - Need UM3234 §3 / §5 trace decoder to interpret

So BootROM goes through more steps after OTP11 was fused, but is failing
silently mid-load. Without UM3234's BOOTROM_TRACE error-code mapping (which
isn't in the public PDFs we could fetch) we can't pinpoint the exact failure.

## 5. Top suspect for next OTP fuse pair

Per the prior session memory (`memory/stm32n6_boot_rom_fixes.md` —
shipped from the Pi 5 host where prior work was done), the next two OTP
words to consider are `BOOTROM_CONFIG_4` (OTP13) and `BOOTROM_CONFIG_5`
(OTP14), which configure boot pin AF/port/pin remap. The prior memory's
recorded values were:

```
OTP13 = 0x02929092 (claimed: NCS=PN0, IO0=PN2)
OTP14 = 0x06929392 (claimed: IO1=PN3, CLK=PN6)
```

⚠️ **The prior memory values appear malformed.** Per
STM32CubeProgrammer's BSEC database
(`STM32_Prog_DB_0x486.xml`), each `BOOTROM_CONFIG_4/5` word packs two
`(mode/afmux/pin/port)` 16-bit halves; `port = 9 (PN)` for the NUCLEO's
NOR. Decoding `0x02929092` gives `port1 = 0` which the XML labels
`"0: reserved"` (invalid configuration). The mathematically correct
encoding for the same intent — both pins on PN bank — is:

```
OTP13 = 0x92929092  # NCS = PN0, IO0 = PN2 (port0=9, port1=9)
OTP14 = 0x96929392  # IO1 = PN3, CLK = PN6 (port0=9, port1=9)
```

**We did NOT fuse these this session** — explicit user decision to stop
before more irreversible writes since:
- The prior memory values appear to be a typo (port1=0=reserved)
- The corrected values are best-guess against the XML, not yet verified
  against a successful cold-boot anywhere
- The prior session never observed a working cold-boot either, so there's
  no known-good baseline to copy

Recommendation for whoever picks this up: **do NOT fuse OTP13/14 until you
have ST community / FAE confirmation of the correct value for the
NUCLEO-N657X0-Q board.** The corrected values above are the best-effort
decoding but unverified.

## 6. Diagnostics & quick commands

| Action | Command |
|---|---|
| Read OTP fuse state | `STM32_Programmer_CLI -c port=SWD mode=UR -otp displ word=11 word=13 word=14 word=18 word=124` |
| Read BootROM context | `STM32_Programmer_CLI -c port=SWD mode=UR -r 0x34100000 0x80 /tmp/ctx.bin && xxd /tmp/ctx.bin \| head` |
| Read BootROM trace | `STM32_Programmer_CLI -c port=SWD mode=UR -r 0x341037F0 0x400 /tmp/trace.bin` |
| List USB DFU devices | `lsusb \| grep 0483` (need `0483:df11` for DFU) |
| Erase FSBL slot | `./tools/scripts/stm32n6_flash.sh --erase-fsbl` |
| Re-flash FSBL+app via ST tools | `./tools/scripts/stm32n6_flash.sh --skip-build` |
| Read NOR contents | `STM32_Programmer_CLI -c port=SWD mode=UR -el .../MX25UM51245G_STM32N6570-NUCLEO.stldr -r 0x70000000 0x100 /tmp/nor.bin` |

### Boot pin matrix on MB1940 (verified)

| Mode | JP1 (BOOT0) | JP2 (BOOT1) | Description |
|---|---|---|---|
| Dev / SWD-load | **1-2** | **2-3** | Used for `--swd-only` flow |
| Cold-boot from NOR | **1-2** | **1-2** | BootROM → FSBL on XSPI2 NOR |
| USB DFU | **2-3** | **1-2** | BootROM USB DFU; needs both USB cables |

USB DFU mode requires BOTH USB cables connected: ST-Link USB (CN1) AND User
USB (CN8). DFU enumerates as `0483:df11` from CN8 (chip's USB peripheral).
DFU CANNOT be used to write OTP on STM32N6.

## 7. Recovery if you get stuck

After a failed cold-boot attempt the chip can be SWD-locked in BootROM
state. To recover:

1. **Move JP2 to 2-3** (dev mode)
2. **Unplug USB** (both cables) for ≥3 seconds
3. **Plug USB back in** — only RESET button is NOT enough; must drop VCC

After a USB power-cycle in dev mode SWD always reattaches.

## 8. Files of interest

- `src/boot_arm.c` — naked `isr_reset` stub (TARGET_stm32n6) sets MSP
  before C body. Skoll fix removes `!defined(CORTEX_M55)` from the
  CMSE+TZEN VTOR exclusion.
- `hal/stm32n6.c` — XSPIM cleanup via secure alias, PLL bypass clear,
  octospi_write_enable error propagation, UART timeouts.
- `tools/scripts/stm32n6_flash.sh` — main flash flow, ST tool-based.
- `tools/scripts/stm32n6_fsbl_header.py` — Python fallback FSBL header
  generator (matches ST signing tool output byte-for-byte except padding).
- `arch.mk` — `WOLFBOOT_ORIGIN = 0x34180400` for stm32n6.
- `config/openocd/openocd_stm32n6.cfg` — SWD debug config (no longer on
  flash path); has the AP1 CSW write trick for cold-boot examination.
- `docs/Targets.md` — STM32N6 section with cold-boot procedure, OTP11
  fuse instructions, diagnostic commands.

## 9. Memory / prior session references

These came over from the Raspberry Pi 5 host (prior session) via scp;
they're in `~/memory/` on this machine. Useful background but the
"David programmed OTP13/14" claim is **not** reflected in our chip's
actual OTP state (verified via `-otp displ`).

- `~/memory/MEMORY.md` — auto-memory index (prior session's project facts)
- `~/memory/stm32n6_nor_boot_handoff.md` — the prior session's handoff;
  most current cold-boot status as of 2026-04-16 (red LD5 BOOTFAILN, cause
  unknown). Predates this session's OTP11 fuse + tooling switch.
- `~/memory/stm32n6_boot_rom_fixes.md` — header layout fixes (now in
  the codebase; the OTP13/14 values listed here are the malformed ones).
- `~/memory/stm32n6_pll_bypass.md` — PLL1BYP must be cleared
  (`hal/stm32n6.c::clock_config` does this).
- `~/memory/stm32n6_details.md` — chip layout details.

## 10. Open questions for next session

1. **What does BootROM trace value `0x3b` mean** (entry #3 v2 field after
   OTP11 attempt)? This is presumably a documented error code in
   UM3234 §5; whoever picks this up should grab the PDF and decode.
2. **Are OTP13/OTP14 actually needed for the NUCLEO board** when
   boot_source=3? UM3234 implies BootROM has hardcoded XSPIM Port 2
   defaults that should match NUCLEO; if so, OTP13/14 should not be
   needed at all and we're chasing the wrong fuse.
3. **What's at NOR offset 0 right now** — the script writes our
   `wolfboot-trusted.bin` but we should verify with a NOR readback that
   the bytes match what `STM32_SigningTool_CLI` produced.
4. **Did anything we did affect the chip's lifecycle state?** Read
   `OTP18` and `BSEC2_OTPCR` after each session to confirm we're still
   in OPEN.
5. Try to wire a UART probe to **PG10 at 9600 baud** during cold-boot —
   per UM3234 §3.10 BootROM bit-bangs error logs there on BOOTFAILN.

## 11. Don't do these (irreversible / shouldn't help)

- **Don't blow OTP18 bit 12+** or **OTP124 bit 20** — these transition
  the chip to closed-locked / locked-provisioned states and would
  require a signed FSBL forever. Pure security regression for a dev
  board.
- **Don't use the `lock` flag on `-otp write`** unless you're 100%
  certain — it's a separate one-shot write on top of the value bits.
  We did not use `lock` for OTP11; the value is permanent but the lock
  bit isn't, so additional bits in word 11 can still be programmed if
  needed.
- **Don't rely on USB DFU for OTP writes** — partition 0xf2 is
  unreachable on STM32N6 BootROM.
- **Don't trust the prior memory's `0x02929092`/`0x06929392` values for
  OTP13/14** without independently verifying against UM3234 — port1=0
  decodes as reserved.

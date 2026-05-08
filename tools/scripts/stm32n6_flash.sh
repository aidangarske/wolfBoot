#!/bin/bash
#
# STM32N6 Flash Script for NUCLEO-N657X0-Q (MB1940)
# Programs MX25UM51245G NOR flash on XSPI2 using STM32CubeProgrammer.
#
# Default usage:
#   ./tools/scripts/stm32n6_flash.sh             # Build, sign FSBL, flash NOR (cold-boot ready)
#   ./tools/scripts/stm32n6_flash.sh --skip-build
#   ./tools/scripts/stm32n6_flash.sh --app-only  # Flash signed app only
#   ./tools/scripts/stm32n6_flash.sh --test-update
#   ./tools/scripts/stm32n6_flash.sh --swd-only  # Skip FSBL, SWD-load wolfBoot to SRAM
#   ./tools/scripts/stm32n6_flash.sh --otp-info  # Read OTP fuse state
#   ./tools/scripts/stm32n6_flash.sh --erase-fsbl
#
# Cold-boot procedure (after running this with default args):
#   1. Move JP2 to position 1-2 (NOR boot mode)
#   2. Power-cycle the board (USB unplug/replug or press RESET)
#   3. The on-chip BootROM loads the FSBL from NOR offset 0 into AXISRAM2
#      and jumps to wolfBoot, which verifies and chain-loads the app.
#
# Tooling:
#   STM32CubeProgrammer 2.21+ (provides STM32_Programmer_CLI and
#   STM32_SigningTool_CLI). Default install path is searched; override
#   with STM32_PRG_PATH env var if installed elsewhere.
#
#   Falls back to tools/scripts/stm32n6_fsbl_header.py if the ST signing
#   tool isn't available.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SKIP_BUILD=0
APP_ONLY=0
TEST_UPDATE=0
SWD_ONLY=0
OTP_INFO=0
ERASE_FSBL=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build)   SKIP_BUILD=1; shift ;;
        --app-only)     APP_ONLY=1; shift ;;
        --test-update)  TEST_UPDATE=1; shift ;;
        --swd-only)     SWD_ONLY=1; shift ;;
        --otp-info)     OTP_INFO=1; shift ;;
        --erase-fsbl)   ERASE_FSBL=1; shift ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0 ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WOLFBOOT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${WOLFBOOT_ROOT}"

FSBL_ADDR=0x70000000
BOOT_ADDR=0x70020000
UPDATE_ADDR=0x70120000
SRAM_ADDR=0x34180400        # BootROM-fixed FSBL load address (AXISRAM2)

# Locate STM32CubeProgrammer tooling
if [ -z "$STM32_PRG_PATH" ]; then
    for d in /home/$(whoami)/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin \
             /opt/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin \
             /usr/local/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin; do
        [ -x "$d/STM32_Programmer_CLI" ] && STM32_PRG_PATH="$d" && break
    done
fi
PRG="${STM32_PRG_PATH}/STM32_Programmer_CLI"
SIGN_TOOL="${STM32_PRG_PATH}/STM32_SigningTool_CLI"
LOADER="${STM32_PRG_PATH}/ExternalLoader/MX25UM51245G_STM32N6570-NUCLEO.stldr"
PY_HEADER="${SCRIPT_DIR}/stm32n6_fsbl_header.py"

# Run ST tools (transparently use box64 on aarch64 since the binaries are x86_64-only)
ST_RUNNER=()
if [ "$(uname -m)" != "x86_64" ] && command -v box64 &>/dev/null; then
    ST_RUNNER=(box64)
fi
prg() { LD_LIBRARY_PATH="${STM32_PRG_PATH}" "${ST_RUNNER[@]}" "$PRG" "$@"; }
sign() { LD_LIBRARY_PATH="${STM32_PRG_PATH}" "${ST_RUNNER[@]}" "$SIGN_TOOL" "$@"; }

[ -x "$PRG" ] || { echo -e "${RED}STM32_Programmer_CLI not found. Install STM32CubeProgrammer or set STM32_PRG_PATH.${NC}"; exit 1; }
[ -f "$LOADER" ] || echo -e "${YELLOW}Warning: external loader not found at $LOADER${NC}"

# --- One-shot diagnostic modes -----------------------------------------------

if [ $OTP_INFO -eq 1 ]; then
    chmod +x "$PRG" 2>/dev/null || true
    prg -c port=SWD mode=UR -otp displ word=11 word=13 word=14 word=18 word=124
    exit 0
fi

if [ $ERASE_FSBL -eq 1 ]; then
    chmod +x "$PRG" 2>/dev/null || true
    echo -e "${YELLOW}Erasing FSBL slot at NOR offset 0 (sectors 0-3)...${NC}"
    prg -c port=SWD mode=UR -el "$LOADER" -e [0 3]
    exit 0
fi

# --- Build -------------------------------------------------------------------

check_tool() {
    command -v "$1" &>/dev/null || { echo -e "${RED}Error: $1 not found${NC}"; exit 1; }
}
[ $SKIP_BUILD -eq 0 ] && check_tool arm-none-eabi-gcc

echo -e "${GREEN}=== STM32N6 Flash Script ===${NC}"

if [ $SKIP_BUILD -eq 0 ]; then
    echo -e "${GREEN}[1/2] Building...${NC}"
    if [ ! -f .config ]; then
        [ -f config/examples/stm32n6.config ] || { echo -e "${RED}No .config found${NC}"; exit 1; }
        cp config/examples/stm32n6.config .config
    fi
    TARGET_CHECK=$(grep -E '^TARGET\?*=' .config | head -1 | sed 's/.*=//;s/[[:space:]]//g')
    [ "$TARGET_CHECK" = "stm32n6" ] || { echo -e "${RED}TARGET is '${TARGET_CHECK}', expected 'stm32n6'${NC}"; exit 1; }

    make clean && make wolfboot.bin
    echo -e "${GREEN}wolfboot.bin: $(stat -c%s wolfboot.bin) bytes${NC}"
    make test-app/image_v1_signed.bin
    echo -e "${GREEN}image_v1_signed.bin: $(stat -c%s test-app/image_v1_signed.bin) bytes${NC}"

    if [ $TEST_UPDATE -eq 1 ]; then
        SIGN_VALUE=$(grep -E '^SIGN\?*=' .config | head -1 | sed 's/.*=//;s/[[:space:]]//g')
        HASH_VALUE=$(grep -E '^HASH\?*=' .config | head -1 | sed 's/.*=//;s/[[:space:]]//g')
        [ -f tools/keytools/sign ] || make -C tools/keytools
        ./tools/keytools/sign \
            --$(echo "$SIGN_VALUE" | tr '[:upper:]' '[:lower:]') \
            --$(echo "$HASH_VALUE" | tr '[:upper:]' '[:lower:]') \
            test-app/image.bin wolfboot_signing_private_key.der 2
        echo -e "${GREEN}image_v2_signed.bin built${NC}"
    fi
else
    echo -e "${YELLOW}[1/2] Skipping build${NC}"
fi

[ $APP_ONLY -eq 0 ] && [ ! -f wolfboot.bin ] && { echo -e "${RED}wolfboot.bin not found${NC}"; exit 1; }
[ -f test-app/image_v1_signed.bin ] || { echo -e "${RED}image_v1_signed.bin not found${NC}"; exit 1; }

# --- Generate FSBL trusted binary --------------------------------------------

TRUSTED_BIN=""
if [ $APP_ONLY -eq 0 ] && [ $SWD_ONLY -eq 0 ]; then
    TRUSTED_BIN="${WOLFBOOT_ROOT}/wolfboot-trusted.bin"
    chmod u+w "${TRUSTED_BIN}" 2>/dev/null; rm -f "${TRUSTED_BIN}"

    FSBL_EP=$(od -A n -j 4 -t x4 -N 4 wolfboot.bin | awk '{print "0x"$1}')

    if [ -x "$SIGN_TOOL" ]; then
        echo -e "${CYAN}  Signing FSBL header via STM32_SigningTool_CLI (entry ${FSBL_EP})${NC}"
        chmod +x "$SIGN_TOOL" 2>/dev/null || true
        sign -bin wolfboot.bin -nk -of 0x80000000 -t fsbl -hv 2.3 -align \
             -la ${SRAM_ADDR} -ep ${FSBL_EP} -o "${TRUSTED_BIN}" -s >/dev/null
    elif [ -f "${PY_HEADER}" ] && command -v python3 &>/dev/null; then
        echo -e "${YELLOW}  STM32_SigningTool_CLI not found, using Python fallback${NC}"
        python3 "${PY_HEADER}" wolfboot.bin "${TRUSTED_BIN}" ${SRAM_ADDR}
    else
        echo -e "${RED}No FSBL signing tool available. Install STM32CubeProgrammer or restore stm32n6_fsbl_header.py.${NC}"
        exit 1
    fi
    [ -f "${TRUSTED_BIN}" ] || { echo -e "${RED}Failed to generate ${TRUSTED_BIN}${NC}"; exit 1; }
    echo -e "${GREEN}  ${TRUSTED_BIN}: $(stat -c%s "${TRUSTED_BIN}") bytes${NC}"
fi

# --- Program NOR via STM32CubeProgrammer -------------------------------------

if [ $SWD_ONLY -eq 1 ]; then
    echo -e "${CYAN}  SWD-only mode: skipping NOR write, will resume wolfBoot from SRAM${NC}"
else
    echo -e "${GREEN}[2/2] Programming NOR via STM32CubeProgrammer...${NC}"
    chmod +x "$PRG" 2>/dev/null || true

    if [ $APP_ONLY -eq 0 ]; then
        echo -e "${CYAN}  ${TRUSTED_BIN} -> NOR ${FSBL_ADDR} (FSBL slot)${NC}"
        prg -c port=SWD mode=UR -el "$LOADER" -d "${TRUSTED_BIN}" ${FSBL_ADDR} -v
    fi

    echo -e "${CYAN}  test-app/image_v1_signed.bin -> NOR ${BOOT_ADDR}${NC}"
    prg -c port=SWD mode=UR -el "$LOADER" -d test-app/image_v1_signed.bin ${BOOT_ADDR} -v

    if [ $TEST_UPDATE -eq 1 ]; then
        [ -f test-app/image_v2_signed.bin ] || { echo -e "${RED}image_v2_signed.bin not found${NC}"; exit 1; }
        echo -e "${CYAN}  test-app/image_v2_signed.bin -> NOR ${UPDATE_ADDR}${NC}"
        prg -c port=SWD mode=UR -el "$LOADER" -d test-app/image_v2_signed.bin ${UPDATE_ADDR} -v

        PART_SIZE=$(grep -E '^WOLFBOOT_PARTITION_SIZE' .config | head -1 | sed 's/.*=//;s/[[:space:]]//g')
        TRIGGER_ADDR=$(printf "0x%08x" $(( ${UPDATE_ADDR} + ${PART_SIZE} - 5 )))
        TRIGGER_FILE=$(mktemp -t trigger_magic.XXXXXX)
        trap 'rm -f "${TRIGGER_FILE}"' EXIT
        printf 'pBOOT' > "${TRIGGER_FILE}"
        echo -e "${CYAN}  Update trigger -> NOR ${TRIGGER_ADDR}${NC}"
        prg -c port=SWD mode=UR -el "$LOADER" -d "${TRIGGER_FILE}" ${TRIGGER_ADDR} -v
    fi
fi

# --- Optional: SWD-resume wolfBoot from SRAM ---------------------------------

if [ $SWD_ONLY -eq 1 ] && [ $APP_ONLY -eq 0 ]; then
    OPENOCD_CFG="${WOLFBOOT_ROOT}/config/openocd/openocd_stm32n6.cfg"
    [ -f "${OPENOCD_CFG}" ] || { echo -e "${RED}OpenOCD cfg missing for --swd-only${NC}"; exit 1; }
    check_tool openocd
    INIT_SP=$(od -A n -t x4 -N 4 wolfboot.bin | awk '{print "0x"$1}')
    ENTRY_ADDR=$(od -A n -j 4 -t x4 -N 4 wolfboot.bin | awk '{print "0x"$1}')
    ENTRY_THUMB=$(printf "0x%08x" $(( ${ENTRY_ADDR} | 1 )))
    echo -e "${CYAN}  SWD-loading wolfBoot to SRAM ${SRAM_ADDR} (SP ${INIT_SP}, entry ${ENTRY_THUMB})${NC}"
    openocd -f "${OPENOCD_CFG}" \
        -c "reset init" \
        -c "load_image ${WOLFBOOT_ROOT}/wolfboot.bin ${SRAM_ADDR} bin" \
        -c "reg msplim_s 0x00000000" \
        -c "reg psplim_s 0x00000000" \
        -c "reg msp ${INIT_SP}" \
        -c "mww 0xE000ED08 ${SRAM_ADDR}" \
        -c "mww 0xE000ED28 0xFFFFFFFF" \
        -c "resume ${ENTRY_THUMB}" \
        -c "shutdown"
fi

echo -e "${GREEN}=== Done ===${NC}"
if [ $SWD_ONLY -eq 0 ] && [ $APP_ONLY -eq 0 ]; then
    echo -e "${YELLOW}For cold-boot test: move JP2 to 1-2, press the RESET button (or USB power-cycle).${NC}"
fi

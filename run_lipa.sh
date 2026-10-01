#!/usr/bin/env bash
# =============================================================================
# run_lipa.sh  --  LIPA interactive launcher for Linux / WSL
#
# UI priority:
#   1. zenity  (GTK GUI -- works on WSLg or X11-forwarded desktops)
#   2. whiptail (ncurses TUI -- pre-installed on Ubuntu/Debian)
#   3. plain readline  (universal fallback, zero extra deps)
#
# Venv priority:
#   1. .venv-linux/  at project root  (Linux-native venv, fastest)
#   2. system python3  (zero-install fallback)
#
# WSL mount detection:
#   Auto-resolves the Windows drive mount prefix (/mnt/ or /mnt/host/).
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve script location, following symlinks, across WSL mount prefixes
# ---------------------------------------------------------------------------
_resolve_script_dir() {
    local src="${BASH_SOURCE[0]}"
    # Follow symlinks
    while [[ -L "$src" ]]; do
        local dir; dir="$(cd "$(dirname "$src")" && pwd)"
        src="$(readlink "$src")"
        [[ "$src" != /* ]] && src="$dir/$src"
    done
    cd "$(dirname "$src")" && pwd
}
SCRIPT_DIR="$(_resolve_script_dir)"

# If running from a /proc/mounts 9p Windows drive mount, the above works
# directly.  No special path translation needed — bash cd+pwd canonicalises it.

# ---------------------------------------------------------------------------
# Colour helpers (only when connected to a real terminal)
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    C_RESET='\033[0m'
    C_CYAN='\033[1;36m'
    C_GREEN='\033[1;32m'
    C_YELLOW='\033[1;33m'
    C_RED='\033[1;31m'
    C_DIM='\033[2m'
else
    C_RESET=''; C_CYAN=''; C_GREEN=''; C_YELLOW=''; C_RED=''; C_DIM=''
fi

info()    { printf "${C_CYAN}  [INFO]${C_RESET}  %s\n" "$*"; }
ok()      { printf "${C_GREEN}  [OK]${C_RESET}    %s\n" "$*"; }
warn()    { printf "${C_YELLOW}  [WARN]${C_RESET}  %s\n" "$*"; }
err()     { printf "${C_RED}  [ERR]${C_RESET}   %s\n" "$*" >&2; }
rule()    { printf "${C_DIM}  %s${C_RESET}\n" "$(printf '%.0s-' {1..62})"; }

# ---------------------------------------------------------------------------
# Detect UI backend
# ---------------------------------------------------------------------------
UI_BACKEND="readline"

if command -v zenity &>/dev/null && { [[ -n "${DISPLAY:-}" ]] || [[ -n "${WAYLAND_DISPLAY:-}" ]]; }; then
    UI_BACKEND="zenity"
elif command -v whiptail &>/dev/null; then
    UI_BACKEND="whiptail"
fi

# ---------------------------------------------------------------------------
# UI wrappers
# ---------------------------------------------------------------------------

# Pick one or more files.
# Returns newline-separated absolute paths on stdout; exits 1 on cancel.
ui_pick_files() {
    local title="$1" filter="${2:-*.py}"
    case "$UI_BACKEND" in
        zenity)
            zenity --file-selection \
                   --title="$title" \
                   --file-filter="Python files | $filter" \
                   --multiple \
                   --separator=$'\n' 2>/dev/null || return 1
            ;;
        whiptail)
            # whiptail cannot browse the filesystem, so we prompt with readline
            _readline_files "$title"
            ;;
        *)
            _readline_files "$title"
            ;;
    esac
}

# Pick a directory.
ui_pick_dir() {
    local title="$1" default="${2:-$SCRIPT_DIR}"
    case "$UI_BACKEND" in
        zenity)
            zenity --file-selection \
                   --directory \
                   --title="$title" \
                   --filename="$default/" 2>/dev/null || return 1
            ;;
        whiptail)
            _readline_dir "$title" "$default"
            ;;
        *)
            _readline_dir "$title" "$default"
            ;;
    esac
}

# Ask a yes/no question. Returns 0 for yes, 1 for no.
ui_yesno() {
    local question="$1"
    case "$UI_BACKEND" in
        zenity)
            zenity --question --title="LIPA" --text="$question" 2>/dev/null
            ;;
        whiptail)
            whiptail --title "LIPA" --yesno "$question" 8 60 3>&1 1>&2 2>&3
            ;;
        *)
            printf "${C_YELLOW}  %s [y/N]: ${C_RESET}" "$question"
            local ans; read -r ans
            [[ "${ans,,}" == "y" ]]
            ;;
    esac
}

# Text input box.  Returns text on stdout.
ui_input() {
    local title="$1" prompt="$2" default="${3:-}"
    case "$UI_BACKEND" in
        zenity)
            zenity --entry \
                   --title="$title" \
                   --text="$prompt" \
                   --entry-text="$default" 2>/dev/null || echo "$default"
            ;;
        whiptail)
            local out
            out=$(whiptail --title "$title" \
                           --inputbox "$prompt" \
                           8 70 "$default" \
                           3>&1 1>&2 2>&3) || echo "$default"
            echo "$out"
            ;;
        *)
            printf "  %s [%s]: " "$prompt" "$default"
            local ans; read -r ans
            echo "${ans:-$default}"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Readline fallback helpers
# ---------------------------------------------------------------------------
_readline_files() {
    local title="$1"
    printf "\n${C_YELLOW}  %s${C_RESET}\n" "$title"
    printf "  Enter absolute path(s) to Python file(s).\n"
    printf "  For multiple files, separate with spaces.\n"
    printf "  (Tab completion is active)\n\n"
    printf "  Path(s): "
    local line
    # enable readline completion for this read
    IFS= read -r -e line
    # Expand each glob/path to one per line
    local f
    for f in $line; do
        echo "$f"
    done
}

_readline_dir() {
    local title="$1" default="$2"
    printf "\n${C_YELLOW}  %s${C_RESET}\n" "$title"
    printf "  Enter absolute path to the directory:\n"
    printf "  [default: %s]\n\n" "$default"
    printf "  Directory: "
    local line
    IFS= read -r -e -i "$default" line
    echo "${line:-$default}"
}

# ---------------------------------------------------------------------------
# Python resolution -- prefer Linux venv, fall back to system python3
# ---------------------------------------------------------------------------
VENV_LINUX="$SCRIPT_DIR/.venv-linux"
PYTHON_EXE=""

setup_python() {
    if [[ -x "$VENV_LINUX/bin/python" ]]; then
        PYTHON_EXE="$VENV_LINUX/bin/python"
        ok "Using Linux venv: $VENV_LINUX"
        return 0
    fi

    if command -v python3 &>/dev/null; then
        warn "Linux venv not found at .venv-linux/"
        warn "Using system python3: $(command -v python3)"
        PYTHON_EXE="$(command -v python3)"
        return 0
    fi

    err "No Python 3 interpreter found."
    err "Run:  python3 -m venv '$VENV_LINUX'  to create a Linux venv."
    exit 3
}

# Offer to create the Linux venv if it doesn't exist
maybe_create_linux_venv() {
    if [[ -d "$VENV_LINUX" ]]; then return; fi

    printf "\n"
    warn "No Linux venv found at .venv-linux/"
    info "Creating one now with system python3..."

    if ! command -v python3 &>/dev/null; then
        err "python3 not found. Install it first: sudo apt install python3 python3-venv"
        exit 3
    fi

    python3 -m venv "$VENV_LINUX"
    ok "Created: $VENV_LINUX"
    printf "\n"
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
clear
printf "\n"
printf "${C_CYAN}"
printf "  +----------------------------------------------------------+\n"
printf "  |   LIPA  --  Local Ingress Pre-flight Auditor             |\n"
printf "  |   Zero-Execution AST Safety & Compatibility Gate         |\n"
printf "  |   Linux / WSL Edition  (UI: %-8s)                  |\n" "$UI_BACKEND"
printf "  +----------------------------------------------------------+\n"
printf "${C_RESET}\n"

# ---------------------------------------------------------------------------
# Python setup
# ---------------------------------------------------------------------------
maybe_create_linux_venv
setup_python

# ---------------------------------------------------------------------------
# Step 1 -- Select Python file(s)
# ---------------------------------------------------------------------------
printf "\n"
info "Step 1/3  --  Select Python file(s) to audit"

mapfile -t SELECTED_FILES < <(
    ui_pick_files "LIPA -- Select Python File(s) to Audit" "*.py" \
    || true
)

# Filter to non-empty entries
VALID_FILES=()
for f in "${SELECTED_FILES[@]+"${SELECTED_FILES[@]}"}"; do
    [[ -n "$f" ]] && VALID_FILES+=("$f")
done

if [[ ${#VALID_FILES[@]} -eq 0 ]]; then
    warn "No file selected -- exiting."
    exit 0
fi

printf "\n"
ok "Selected file(s):"
for f in "${VALID_FILES[@]}"; do
    printf "    %s\n" "$f"
done

# ---------------------------------------------------------------------------
# Step 2 -- Select workspace root
# ---------------------------------------------------------------------------
printf "\n"
info "Step 2/3  --  Select Project Workspace Root (folder)"

WORKSPACE="$(ui_pick_dir "LIPA -- Select Workspace Root" "$SCRIPT_DIR" || echo "$SCRIPT_DIR")"

if [[ -z "$WORKSPACE" || ! -d "$WORKSPACE" ]]; then
    warn "Invalid workspace path: '$WORKSPACE' -- using script dir."
    WORKSPACE="$SCRIPT_DIR"
fi

ok "Workspace: $WORKSPACE"

# ---------------------------------------------------------------------------
# Step 3 -- Optional baseline
# ---------------------------------------------------------------------------
printf "\n"
info "Step 3/3  --  Load Baseline for Contract Diff?"

BASELINE_FILE=""
if ui_yesno "Load a baseline file for contract diffing?"; then
    if [[ ${#VALID_FILES[@]} -gt 1 ]]; then
        warn "Baseline applies to the first file only."
    fi
    mapfile -t BASELINE_RAW < <(
        ui_pick_files "LIPA -- Select Baseline Python File" "*.py" \
        || true
    )
    if [[ ${#BASELINE_RAW[@]} -gt 0 && -n "${BASELINE_RAW[0]}" ]]; then
        BASELINE_FILE="${BASELINE_RAW[0]}"
        ok "Baseline: $BASELINE_FILE"
    else
        warn "No baseline selected -- skipping."
    fi
fi

# ---------------------------------------------------------------------------
# Version targets
# ---------------------------------------------------------------------------
printf "\n"
rule
VER_RAW="$(ui_input "LIPA" \
    "Python version targets (comma-separated, e.g. 3.11,3.12,3.13)" \
    "3.11,3.12,3.13,3.14,3.15")"

VER_FLAGS=()
IFS=',' read -ra VERS <<< "$VER_RAW"
for v in "${VERS[@]}"; do
    v="${v// /}"   # strip spaces
    if [[ "$v" =~ ^[0-9]+\.[0-9]+$ ]]; then
        VER_FLAGS+=("--target-version" "$v")
    fi
done

if [[ ${#VER_FLAGS[@]} -eq 0 ]]; then
    warn "No valid versions parsed -- using defaults."
    VER_FLAGS=("--target-version" "3.11" "--target-version" "3.12"
               "--target-version" "3.13" "--target-version" "3.14"
               "--target-version" "3.15")
fi

printf "\n"

# ---------------------------------------------------------------------------
# Build CLI arguments
# ---------------------------------------------------------------------------
export PYTHONPATH="$SCRIPT_DIR/src"

CLI_ARGS=("-m" "lipa.cli")
for f in "${VALID_FILES[@]}"; do
    CLI_ARGS+=("$f")
done
CLI_ARGS+=("--workspace" "$WORKSPACE")
CLI_ARGS+=("${VER_FLAGS[@]}")

if [[ -n "$BASELINE_FILE" && ${#VALID_FILES[@]} -eq 1 ]]; then
    CLI_ARGS+=("--baseline" "$BASELINE_FILE")
fi

# ---------------------------------------------------------------------------
# Run LIPA
# ---------------------------------------------------------------------------
rule
printf "\n"
info "Scanning ..."
printf "\n"
rule
printf "\n"

START_NS=$(date +%s%N 2>/dev/null || date +%s)

"$PYTHON_EXE" "${CLI_ARGS[@]}"
EXIT_CODE=$?

END_NS=$(date +%s%N 2>/dev/null || date +%s)

# Compute elapsed (handle systems without nanosecond date)
if [[ ${#START_NS} -gt 10 ]]; then
    ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))
else
    ELAPSED_MS=$(( (END_NS - START_NS) * 1000 ))
fi

printf "\n"
rule
printf "\n"

case "$EXIT_CODE" in
    0) printf "${C_GREEN}  [PASS]    All stages cleared -- safe to proceed.${C_RESET}\n" ;;
    1) printf "${C_RED}  [BLOCKED] Fatal issues detected -- fix before deploying.${C_RESET}\n" ;;
    2) printf "${C_YELLOW}  [WARN]    Warnings found -- review recommended.${C_RESET}\n" ;;
    *) printf "  [?]  Exit code: %d\n" "$EXIT_CODE" ;;
esac

printf "${C_DIM}  Time elapsed: %d ms${C_RESET}\n" "$ELAPSED_MS"
printf "\n"
rule
printf "\n"

# ---------------------------------------------------------------------------
# Optional JSON report save
# ---------------------------------------------------------------------------
if ui_yesno "Save JSON report?"; then
    JSON_PATH=""
    if [[ "$UI_BACKEND" == "zenity" ]]; then
        JSON_PATH=$(zenity --file-selection \
            --save \
            --confirm-overwrite \
            --title="LIPA -- Save JSON Report" \
            --filename="$WORKSPACE/lipa_report_$(date '+%Y%m%d_%H%M%S').json" \
            2>/dev/null) || true
    else
        DEFAULT_JSON="$WORKSPACE/lipa_report_$(date '+%Y%m%d_%H%M%S').json"
        JSON_PATH="$(ui_input "LIPA" "Save JSON report to" "$DEFAULT_JSON")"
    fi

    if [[ -n "$JSON_PATH" ]]; then
        JSON_ARGS=("${CLI_ARGS[@]}" "--json")
        "$PYTHON_EXE" "${JSON_ARGS[@]}" > "$JSON_PATH" 2>&1
        ok "Saved: $JSON_PATH"
    else
        warn "Skipped -- report not saved."
    fi
fi

printf "\n"
printf "  Press Enter to exit ...\n"
read -r

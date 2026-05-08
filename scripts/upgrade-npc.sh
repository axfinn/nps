#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/upgrade-npc.sh [options]

Default behavior:
  If /Library/LaunchDaemons/Npc.plist exists, upgrade the npc binary used by
  that launchd service and restart system/Npc after replacement.

Options:
  --launchd-label LABEL  launchd label to inspect/restart. Default: Npc
  --plist PATH           launchd plist path. Default: /Library/LaunchDaemons/<label>.plist
  --no-launchd           Do not inspect/restart launchd; use --target/default target
  --target PATH          Installed npc path. Default without launchd: /usr/local/bin/npc
  --source PATH          Prebuilt npc binary. Default: ./npc
  --backup-dir DIR       Backup directory. Default: same directory as target
  --expected VERSION     Expected version string. Default: read from lib/version/version.go
  --no-build             Use --source directly, skip go build
  --restart-cmd CMD      Override restart command
  --health-cmd CMD       Command to verify npc after restart
  --no-sudo              Do not use sudo for install/rollback operations
  -h, --help             Show help

Examples:
  sudo scripts/upgrade-npc.sh
  sudo scripts/upgrade-npc.sh --launchd-label Npc
  sudo scripts/upgrade-npc.sh --no-launchd --target /usr/local/bin/npc
  sudo scripts/upgrade-npc.sh --health-cmd "/usr/local/bin/npc -version"
EOF
}

LAUNCHD_LABEL="Npc"
PLIST=""
USE_LAUNCHD=1
TARGET=""
TARGET_SET=0
SOURCE="./npc"
BACKUP_DIR=""
EXPECTED=""
BUILD=1
SUDO="sudo"
RESTART_CMD=""
HEALTH_CMD=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --launchd-label)
      LAUNCHD_LABEL="$2"
      shift 2
      ;;
    --plist)
      PLIST="$2"
      shift 2
      ;;
    --no-launchd)
      USE_LAUNCHD=0
      shift
      ;;
    --target)
      TARGET="$2"
      TARGET_SET=1
      shift 2
      ;;
    --source)
      SOURCE="$2"
      shift 2
      ;;
    --backup-dir)
      BACKUP_DIR="$2"
      shift 2
      ;;
    --expected)
      EXPECTED="$2"
      shift 2
      ;;
    --no-build)
      BUILD=0
      shift
      ;;
    --restart-cmd)
      RESTART_CMD="$2"
      shift 2
      ;;
    --health-cmd)
      HEALTH_CMD="$2"
      shift 2
      ;;
    --no-sudo)
      SUDO=""
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BUILD_USER="${SUDO_USER:-}"
BUILD_HOME="${HOME:-}"
if [[ -n "$BUILD_USER" && "$BUILD_USER" != "root" ]]; then
  BUILD_HOME="$(eval echo "~$BUILD_USER")"
fi

if [[ -z "$EXPECTED" ]]; then
  EXPECTED="$(sed -n 's/^const VERSION = "\(.*\)"/\1/p' lib/version/version.go)"
fi

if [[ -z "$EXPECTED" ]]; then
  echo "cannot determine expected npc version" >&2
  exit 1
fi

run_root() {
  if [[ -n "$SUDO" ]]; then
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
      "$@"
    else
      "$SUDO" "$@"
    fi
  else
    "$@"
  fi
}

run_root_shell() {
  if [[ -n "$SUDO" ]]; then
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
      sh -c "$1"
    else
      "$SUDO" sh -c "$1"
    fi
  else
    sh -c "$1"
  fi
}

run_build() {
  local cache="${GOCACHE:-/tmp/nps-go-build-cache}"
  if [[ "${EUID:-$(id -u)}" -eq 0 && -n "$BUILD_USER" && "$BUILD_USER" != "root" ]]; then
    sudo -u "$BUILD_USER" env HOME="$BUILD_HOME" GOCACHE="$cache" go "$@"
  else
    env GOCACHE="$cache" go "$@"
  fi
}

plist_program() {
  local plist="$1"
  /usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$plist" 2>/dev/null || true
}

restart_service() {
  if [[ -n "$RESTART_CMD" ]]; then
    echo "running restart command..."
    run_root_shell "$RESTART_CMD"
    return
  fi
  if [[ "$USE_LAUNCHD" -eq 1 && -n "$PLIST" && -f "$PLIST" ]]; then
    echo "restarting launchd service system/$LAUNCHD_LABEL..."
    stop_service
    start_service
  fi
}

stop_service() {
  if [[ "$USE_LAUNCHD" -eq 1 && -n "$PLIST" && -f "$PLIST" ]]; then
    echo "stopping launchd service system/$LAUNCHD_LABEL..."
    run_root launchctl bootout system "$PLIST" 2>/dev/null || true
  elif [[ -n "$RESTART_CMD" ]]; then
    return
  fi
}

start_service() {
  if [[ "$USE_LAUNCHD" -eq 1 && -n "$PLIST" && -f "$PLIST" ]]; then
    echo "starting launchd service system/$LAUNCHD_LABEL..."
    run_root launchctl bootstrap system "$PLIST"
    run_root launchctl kickstart -k "system/$LAUNCHD_LABEL"
  fi
}

rollback() {
  local backup="$1"
  if [[ -f "$backup" ]]; then
    echo "rolling back to $backup" >&2
    run_root cp "$backup" "$TARGET"
    run_root chmod 755 "$TARGET"
  fi
}

if [[ -z "$PLIST" ]]; then
  PLIST="/Library/LaunchDaemons/${LAUNCHD_LABEL}.plist"
fi

if [[ "$USE_LAUNCHD" -eq 1 && "$TARGET_SET" -eq 0 && -f "$PLIST" ]]; then
  TARGET="$(plist_program "$PLIST")"
  if [[ -z "$TARGET" ]]; then
    echo "cannot read ProgramArguments[0] from $PLIST" >&2
    exit 1
  fi
  echo "detected launchd target: $TARGET"
elif [[ -z "$TARGET" ]]; then
  TARGET="/usr/local/bin/npc"
fi

if [[ -z "$BACKUP_DIR" ]]; then
  BACKUP_DIR="$(dirname "$TARGET")"
fi

if [[ ! -x "$TARGET" ]]; then
  echo "target npc not found or not executable: $TARGET" >&2
  exit 1
fi

if [[ "$BUILD" -eq 1 ]]; then
  echo "building npc..."
  SOURCE="$(mktemp /tmp/npc-upgrade.XXXXXX)"
  rm -f "$SOURCE"
  run_build build -buildvcs=false -o "$SOURCE" ./cmd/npc
  chmod 755 "$SOURCE"
fi

if [[ ! -x "$SOURCE" ]]; then
  echo "source npc not found or not executable: $SOURCE" >&2
  exit 1
fi

echo "checking source version..."
"$SOURCE" -version
if ! "$SOURCE" -version | grep "Version: $EXPECTED" >/dev/null; then
  echo "source npc version is not $EXPECTED" >&2
  exit 1
fi

echo "current installed version at $TARGET:"
"$TARGET" -version || true

timestamp="$(date +%Y%m%d%H%M%S)"
backup="$BACKUP_DIR/npc.backup-$timestamp"
service_stopped=0

if [[ "$USE_LAUNCHD" -eq 1 && -n "$PLIST" && -f "$PLIST" && -z "$RESTART_CMD" ]]; then
  stop_service
  service_stopped=1
fi

echo "backing up $TARGET to $backup"
if ! run_root cp "$TARGET" "$backup"; then
  if [[ "$service_stopped" -eq 1 ]]; then
    start_service || true
  fi
  exit 1
fi

echo "installing $SOURCE to $TARGET"
install_tmp="$BACKUP_DIR/.npc.install-$timestamp"
if ! run_root cp "$SOURCE" "$install_tmp"; then
  rollback "$backup"
  if [[ "$service_stopped" -eq 1 ]]; then
    start_service || true
  fi
  exit 1
fi
if ! run_root chmod 755 "$install_tmp"; then
  run_root rm -f "$install_tmp" || true
  rollback "$backup"
  if [[ "$service_stopped" -eq 1 ]]; then
    start_service || true
  fi
  exit 1
fi
if ! run_root mv "$install_tmp" "$TARGET"; then
  run_root rm -f "$install_tmp" || true
  rollback "$backup"
  if [[ "$service_stopped" -eq 1 ]]; then
    start_service || true
  fi
  exit 1
fi

echo "verifying installed version..."
if ! "$TARGET" -version | grep "Version: $EXPECTED" >/dev/null; then
  echo "installed npc version check failed" >&2
  rollback "$backup"
  if [[ "$service_stopped" -eq 1 ]]; then
    start_service || true
  fi
  exit 1
fi

if [[ "$service_stopped" -eq 1 ]]; then
  if ! start_service; then
    echo "start failed" >&2
    rollback "$backup"
    start_service || true
    exit 1
  fi
elif ! restart_service; then
  echo "restart failed" >&2
  rollback "$backup"
  exit 1
fi

if [[ -n "$HEALTH_CMD" ]]; then
  echo "running health command..."
  if ! run_root_shell "$HEALTH_CMD"; then
    echo "health command failed" >&2
    if [[ "$service_stopped" -eq 1 ]]; then
      stop_service || true
    fi
    rollback "$backup"
    if [[ "$service_stopped" -eq 1 ]]; then
      start_service || true
    fi
    exit 1
  fi
fi

if [[ "$USE_LAUNCHD" -eq 1 && -f "$PLIST" ]]; then
  actual_target="$(plist_program "$PLIST")"
  if [[ "$actual_target" != "$TARGET" ]]; then
    echo "warning: launchd plist still points to $actual_target, not $TARGET" >&2
  fi
fi

echo "npc upgrade completed"
echo "installed: $TARGET"
echo "version: $EXPECTED"
echo "backup: $backup"
if [[ "$USE_LAUNCHD" -eq 1 && -f "$PLIST" ]]; then
  echo "launchd: system/$LAUNCHD_LABEL ($PLIST)"
fi

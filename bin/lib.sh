#!/usr/bin/env bash
# lib.sh - 公共函数。保持 bash 3.2 兼容（macOS 自带）：不用关联数组、mapfile、${var,,}。

SCA_ROOT="${SCA_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export SCA_ROOT
CONF_DIR="$SCA_ROOT/config"
BIN_DIR="$SCA_ROOT/bin"
REPOS_DIR="$SCA_ROOT/repos"
WT_DIR="$SCA_ROOT/worktrees"
RESULTS_DIR="$SCA_ROOT/results"
LOG_DIR="$SCA_ROOT/logs"
STATE_DIR="$SCA_ROOT/state"
SCA_PY="$BIN_DIR/sca.py"
[ -f "$CONF_DIR/settings.env" ] && . "$CONF_DIR/settings.env"

# REQUIRED_MOUNT（可选）：项目放在外置盘等挂载点上时，未挂载就直接退出，避免在空的挂载目录里重新下载所有仓库。
if [ -n "${REQUIRED_MOUNT:-}" ]; then
  _mnt="$(/sbin/mount 2>/dev/null || /bin/mount 2>/dev/null || mount 2>/dev/null)"
  # macOS: "... on /Volumes/X (apfs, ...)"   Linux: "... on /mnt/x type ext4 (...)"
  _mp="${REQUIRED_MOUNT%/}"; [ -n "$_mp" ] || _mp="/"
  if ! printf '%s\n' "$_mnt" | grep -Fq " on $_mp "; then
    echo "ERROR: $REQUIRED_MOUNT is not mounted (REQUIRED_MOUNT in config/settings.env). Connect it before running." >&2
    exit 2
  fi
fi

mkdir -p "$REPOS_DIR" "$WT_DIR" "$RESULTS_DIR" "$LOG_DIR" "$STATE_DIR"
touch "$LOG_DIR/alerts.log"   # 先建好，方便 tail -f
: "${EXTRA_PATH:=}"
: "${OSV_SCANNER:=osv-scanner}"
: "${GOVULNCHECK:=govulncheck}"
: "${GOVULNCHECK_ENABLED:=0}"
: "${GO_MOD_MAXDEPTH:=4}"
: "${EXCLUDE_PATH_REGEX:=(^|/)(node_modules|testdata|third_party|tests|integration_tests|examples|\\.git)(/|\$)}"
: "${INCLUDE_DEV_DEPS:=0}"
: "${KEV_URL:=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json}"
: "${CLONE_TIMEOUT:=3600}"
: "${FETCH_TIMEOUT:=900}"
: "${OSV_TIMEOUT:=1800}"
: "${GOVULN_TIMEOUT:=2700}"
: "${KEV_TIMEOUT:=120}"
: "${RETENTION:=10}"
: "${PREVENT_SLEEP:=1}"
: "${PYTHON:=python3}"
: "${GO_BUILD_CACHE=$SCA_ROOT/caches/go-build}"   # 不带冒号：设成空字符串 = 不覆盖，用 Go 自己的设置
: "${GO_MOD_CACHE=$SCA_ROOT/caches/go-mod}"
# Go 缓存只对本项目生效：通过环境变量传给 go / govulncheck，不改 `go env -w` 的全局设置
[ -n "$GO_BUILD_CACHE" ] && export GOCACHE="$GO_BUILD_CACHE"
[ -n "$GO_MOD_CACHE" ] && export GOMODCACHE="$GO_MOD_CACHE"
if [ -n "$EXTRA_PATH" ]; then PATH="$EXTRA_PATH:$PATH"; fi
export PATH

RUN_LOG=""
N_ERROR=0; N_WARN=0

ts() { date '+%Y-%m-%d %H:%M:%S'; }

_emit() {  # level message...
  local level="$1"; shift
  local line; line="$(ts) [$level] $*"
  echo "$line"
  if [ -n "$RUN_LOG" ]; then echo "$line" >> "$RUN_LOG"; fi
}
log_info() { _emit INFO "$*"; }
log_warn() { _emit WARN "$*"; }

# alert KIND message...   KIND: ERROR | WARN
# 同时写入当次运行日志和 logs/alerts.log（只含需要你关注的行，可直接 tail/grep）
alert() {
  local kind="$1"; shift
  local line; line="$(ts) [ALERT] [$kind] $*"
  echo "$line"
  if [ -n "$RUN_LOG" ]; then echo "$line" >> "$RUN_LOG"; fi
  echo "$line" >> "$LOG_DIR/alerts.log"
  case "$kind" in
    ERROR) N_ERROR=$((N_ERROR+1));;
    WARN) N_WARN=$((N_WARN+1));;
  esac
}

have_tool() { command -v "$1" >/dev/null 2>&1; }

# run_to SECS cmd args...   带超时运行（macOS 没有 timeout 命令）。超时返回 124。
run_to() {
  local secs="$1"; shift
  "$@" &
  local pid=$!
  ( sleep "$secs"; kill -TERM "$pid" 2>/dev/null; sleep 5; kill -KILL "$pid" 2>/dev/null ) >/dev/null 2>&1 &
  local watcher=$!
  wait "$pid"; local rc=$?
  pkill -P "$watcher" 2>/dev/null
  kill "$watcher" 2>/dev/null; wait "$watcher" 2>/dev/null
  if [ "$rc" -eq 143 ] || [ "$rc" -eq 137 ]; then return 124; fi
  return "$rc"
}

slugify() { echo "$1" | sed -E 's#[^A-Za-z0-9._-]#_#g'; }

# https://github.com/tikv/pd.git -> tikv__pd
repo_id_from_url() {
  echo "$1" | sed -E 's#^(https?://[^/]+/|git@[^:]+:)##; s#\.git$##; s#/#__#g; s#[^A-Za-z0-9._-]#_#g'
}

# 打印 branches.conf 中的有效行
read_targets() {
  grep -v '^[[:space:]]*#' "$CONF_DIR/branches.conf" | grep -v '^[[:space:]]*$'
}

# prune_results NAME BRANCH
# 只保留 results/<名称>/<分支>/ 下最新的 RETENTION 个扫描目录（目录名形如 2026-11-02_205150），更早的删除。
# 不区分成功或失败：失败的运行目录也算一个。
# 只删除名字严格匹配时间戳格式的真实目录，不碰 latest 软链接或其它文件。
prune_results() {
  local name="$1" branch="$2" base list total nd d removed=0 ids=""
  base="$RESULTS_DIR/$name/$(slugify "$branch")"
  [ -d "$base" ] || return 0
  list="$(ls -1 "$base" 2>/dev/null | grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}$' | sort)"
  [ -n "$list" ] || return 0
  total="$(echo "$list" | wc -l | tr -d ' ')"
  [ "$total" -gt "$RETENTION" ] || return 0
  nd=$((total - RETENTION))
  for d in $(echo "$list" | head -n "$nd"); do
    if [ -d "$base/$d" ] && [ ! -L "$base/$d" ]; then
      if rm -rf -- "$base/$d"; then removed=$((removed+1)); ids="$ids $d"
      else alert WARN "[$name] retention: could not remove $base/$d"; fi
    fi
  done
  [ "$removed" -gt 0 ] && log_info "[$name] retention=$RETENTION: removed $removed old scan(s):$ids"
  return 0
}

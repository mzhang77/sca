#!/usr/bin/env bash
# run.sh - 手动触发的唯一入口。每次运行按顺序做两件事：
#   1) 分支：更新被跟踪的分支 -> OSV-Scanner 扫依赖 -> 每个分支的完整报告 -> 汇总 results/report-branches-latest.md
#   2) 镜像：Trivy 扫交付镜像 -> 和第 1 步更新后的分支源码比较（源码是否已修复）-> 汇总 results/report-images-latest.md
# 失败写 [ALERT]；一个阶段失败不影响另一个阶段。
#
# 用法：bin/run.sh [--only 名称] [--no-sync] [--govulncheck | --no-govulncheck] [--skip-db-update]
#                  [--branches-only | --images-only]
#   --only NAME        只处理一个目标：NAME 可以是 branches.conf 的名称（同时扫它对应的镜像），
#                      也可以是 images.conf 的名称（同时更新它对应的分支）
#   --no-sync          不 fetch，直接扫描 worktree 当前内容
#   --govulncheck      本次运行做 Go 可达性分析（缺省由 settings.env 的 GOVULNCHECK_ENABLED 决定，默认关）
#   --no-govulncheck   本次运行跳过可达性分析
#   --skip-db-update   不更新 Trivy 漏洞库（离线 / 刚更新过时用）
#   --branches-only    只做第 1 步（排查用）
#   --images-only      只做第 2 步，和 worktree 现有内容比较（排查用）
# 退出码：0 = 全部成功；1 = 有失败（见 [ALERT] [ERROR]）；2 = 前置条件不满足；3 = 已有实例在运行

BIN="$(cd "$(dirname "$0")" && pwd)"
. "$BIN/lib.sh"
. "$BIN/sync.sh"
. "$BIN/scan.sh"
: "${TRIVY:=trivy}"
: "${TRIVY_TIMEOUT:=1800}"
: "${IMAGE_PLATFORM:=linux/amd64}"
: "${RECENT_DAYS:=45}"
: "${GO_OFFICIAL_DAYS:=90}"
: "${TRIVY_EXTRA_ARGS:=}"
: "${USE_DOCKER_CREDS:=0}"
IMG_PY="$BIN/image_view.py"
IMG_RESULTS="$RESULTS_DIR/images"
BRANCH_REPORT="$RESULTS_DIR/report-branches-latest.md"
IMAGE_REPORT="$RESULTS_DIR/report-images-latest.md"

ONLY=""; NO_SYNC=0; NO_GOVULN=0; FORCE_GOVULN=0; SKIP_DB=0; DO_BRANCHES=1; DO_IMAGES=1
while [ $# -gt 0 ]; do
  case "$1" in
    --only) ONLY="$2"; shift 2;;
    --no-sync) NO_SYNC=1; shift;;
    --no-govulncheck) NO_GOVULN=1; shift;;
    --govulncheck) FORCE_GOVULN=1; shift;;
    --skip-db-update) SKIP_DB=1; shift;;
    --branches-only) DO_IMAGES=0; shift;;
    --images-only) DO_BRANCHES=0; shift;;
    -h|--help) sed -n '2,18p' "$0"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done
if [ "$DO_BRANCHES" = 0 ] && [ "$DO_IMAGES" = 0 ]; then echo "--branches-only 和 --images-only 不能同时使用" >&2; exit 2; fi
[ "$FORCE_GOVULN" = "1" ] && [ "$NO_GOVULN" != "1" ] && GOVULNCHECK_ENABLED=1

RUN_ID="$(date +%Y-%m-%d_%H%M%S)"
RUN_LOG="$LOG_DIR/run-$(date +%F).log"
STARTED="$(date '+%Y-%m-%dT%H:%M:%S%z')"
FINISHED=0; LOCK_OWNED=0; CAFF_PID=""
TARGETS_TSV="$STATE_DIR/targets.$$.tsv"; : > "$TARGETS_TSV"   # 分支结果：name branch status commit issues message
IMAGES_TSV="$STATE_DIR/images.$$.tsv";   : > "$IMAGES_TSV"    # 镜像结果：name status issues
KEV_FILE=""
FAILED_BRANCHES=" "     # 本次更新/扫描失败的分支名称（镜像对比时提示用的是旧内容）

finalize() {  # status
  "$PYTHON" "$SCA_PY" runstate --out "$STATE_DIR/last_run.json" --status "$1" --run-id "$RUN_ID" \
    --started "$STARTED" --finished "$(date '+%Y-%m-%dT%H:%M:%S%z')" \
    --errors "$N_ERROR" --warnings "$N_WARN" --targets "$TARGETS_TSV" >>"$RUN_LOG" 2>&1
}

cleanup() {
  local rc=$?
  if [ "$FINISHED" -ne 1 ]; then
    alert ERROR "run aborted unexpectedly (exit code $rc); results are incomplete"
    finalize aborted
  fi
  [ -n "$CAFF_PID" ] && kill "$CAFF_PID" 2>/dev/null
  [ "$LOCK_OWNED" -eq 1 ] && rm -rf "$STATE_DIR/run.lock"
  rm -f "$TARGETS_TSV" "$IMAGES_TSV"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

fatal() {  # exit_code message
  alert ERROR "$2"; finalize failed; FINISHED=1; exit "$1"
}

rec() {  # name branch status commit issues message   （空值用 - 占位，避免 tab 分隔时字段错位）
  local msg; msg="$(echo "${6:--}" | tr '\t\n' '  ')"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "${4:--}" "${5:--}" "$msg" >> "$TARGETS_TSV"
  [ "$3" = OK ] || FAILED_BRANCHES="$FAILED_BRANCHES$1 "
}
rec_img() {  # name status issues
  printf '%s\t%s\t%s\n' "$1" "$2" "$(echo "${3:--}" | tr '\t\n' '  ')" >> "$IMAGES_TSV"
}

read_images() { grep -v '^[[:space:]]*#' "$CONF_DIR/images.conf" | grep -v '^[[:space:]]*$'; }

# ---------- 单实例锁 ----------
if mkdir "$STATE_DIR/run.lock" 2>/dev/null; then
  echo $$ > "$STATE_DIR/run.lock/pid"; LOCK_OWNED=1
else
  oldpid="$(cat "$STATE_DIR/run.lock/pid" 2>/dev/null)"
  if [ -n "$oldpid" ] && kill -0 "$oldpid" 2>/dev/null; then
    log_info "another run is in progress (pid $oldpid); exiting"; FINISHED=1; exit 3
  fi
  log_warn "removing stale lock (pid ${oldpid:-?} not running)"
  rm -rf "$STATE_DIR/run.lock"; mkdir "$STATE_DIR/run.lock" && echo $$ > "$STATE_DIR/run.lock/pid" && LOCK_OWNED=1
fi

log_info "===== RUN START id=$RUN_ID root=$SCA_ROOT branches=$DO_BRANCHES images=$DO_IMAGES ====="

# ---------- 防止 Mac 睡眠 ----------
# caffeinate -w $$：绑定本脚本进程，脚本结束（含出错/被中断）时自动退出。
# -i 防止空闲睡眠，-m 防止磁盘休眠，-s 在接电源时防止系统睡眠（用电池时 -s 无效；合盖仍会睡眠）。
if [ "$PREVENT_SLEEP" = "1" ]; then
  if have_tool caffeinate; then
    caffeinate -i -m -s -w $$ >/dev/null 2>&1 &
    CAFF_PID=$!
    log_info "caffeinate started (pid $CAFF_PID): sleep prevented until this run ends"
  else
    log_warn "caffeinate not found (not macOS?); the machine may sleep during the run"
  fi
fi

# ---------- 前置检查（不安装任何东西）----------
have_tool git       || fatal 2 "git not found in PATH"
have_tool "$PYTHON" || fatal 2 "$PYTHON not found in PATH"
have_tool curl      || fatal 2 "curl not found in PATH"
[ -f "$CONF_DIR/branches.conf" ] || fatal 2 "missing $CONF_DIR/branches.conf (cp config/branches.conf.example config/branches.conf, then edit)"
if [ "$DO_BRANCHES" = 1 ] && ! have_tool "$OSV_SCANNER"; then
  fatal 2 "osv-scanner not found in PATH (run bin/check_env.sh for install hints)"
fi
if [ "$DO_IMAGES" = 1 ]; then
  [ -f "$CONF_DIR/images.conf" ] || fatal 2 "missing $CONF_DIR/images.conf (cp config/images.conf.example config/images.conf, then edit)"
  have_tool "$TRIVY" || fatal 2 "trivy not found in PATH (install: brew install trivy)"
  log_info "trivy: $("$TRIVY" --version 2>/dev/null | head -1)"
fi

# ---------- --only：同时选中分支和它对应的镜像 ----------
SEL_BRANCHES=""; SEL_IMAGES=""
if [ -n "$ONLY" ]; then
  while IFS= read -r line; do
    read -r n _ <<< "$line"; [ "$n" = "$ONLY" ] && SEL_BRANCHES=" $n "
  done < <(read_targets)
  if [ -f "$CONF_DIR/images.conf" ]; then
    while IFS= read -r line; do
      read -r n img src _ <<< "$line"
      if [ "$n" = "$ONLY" ] || [ "$src" = "$ONLY" ]; then
        SEL_IMAGES="$SEL_IMAGES $n "
        case "$SEL_BRANCHES" in *" $src "*) ;; *) SEL_BRANCHES="$SEL_BRANCHES $src ";; esac
      fi
    done < <(read_images)
  fi
  [ -n "$SEL_BRANCHES$SEL_IMAGES" ] || fatal 2 "--only $ONLY: no such name in branches.conf or images.conf"
fi
branch_selected() { [ -z "$ONLY" ] || case "$SEL_BRANCHES" in *" $1 "*) return 0;; *) return 1;; esac; }
image_selected()  { [ -z "$ONLY" ] || case "$SEL_IMAGES" in *" $1 "*) return 0;; *) return 1;; esac; }

retention_ok() {  # 打印告警并返回 1 表示 RETENTION 非法
  case "$RETENTION" in
    ''|*[!0-9]*) ;;
    *) [ "$RETENTION" -ge 1 ] && return 0;;
  esac
  alert WARN "invalid RETENTION='$RETENTION' (need an integer >= 1); old $1 results were NOT cleaned up"
  return 1
}

# ---------- CISA KEV（分支和镜像两份报告共用）----------
refresh_kev() {
  local tmp="$STATE_DIR/kev.json.tmp"
  if run_to "$KEV_TIMEOUT" curl -fsSL --max-time "$KEV_TIMEOUT" -o "$tmp" "$KEV_URL" 2>>"$RUN_LOG" \
     && "$PYTHON" "$SCA_PY" validate --kind kev "$tmp" 2>>"$RUN_LOG"; then
    mv -f "$tmp" "$STATE_DIR/kev.json"; KEV_FILE="$STATE_DIR/kev.json"
    log_info "CISA KEV catalogue refreshed"
  else
    rm -f "$tmp"
    if [ -f "$STATE_DIR/kev.json" ]; then
      KEV_FILE="$STATE_DIR/kev.json"
      alert WARN "could not refresh CISA KEV; using cached copy from $(date -r "$KEV_FILE" '+%Y-%m-%d %H:%M')"
    else
      alert WARN "could not download CISA KEV and no cache exists: KEV column will show '?'"
    fi
  fi
}
refresh_kev

# =====================================================================
# 第 1 步：分支
# =====================================================================
process_target() {  # name url branch
  local name="$1" url="$2" branch="$3"
  local rid bslug base out commit="" nissues=0
  rid="$(repo_id_from_url "$url")"; bslug="$(slugify "$branch")"
  base="$RESULTS_DIR/$name/$bslug"; out="$base/$RUN_ID"
  log_info "----- [$name] $branch -----"

  if [ "$NO_SYNC" -eq 0 ]; then
    sync_target "$name" "$url" "$branch" || { rec "$name" "$branch" FAILED-SYNC "" "" "sync failed"; return; }
  else
    WT="$WT_DIR/$rid/$bslug"
    [ -e "$WT/.git" ] || { alert ERROR "[$name] --no-sync but worktree $WT does not exist"; rec "$name" "$branch" FAILED-SYNC "" "" "no worktree"; return; }
    SHA="$(git -C "$WT" rev-parse HEAD 2>/dev/null)"
  fi
  commit="$SHA"

  scan_target "$name" "$branch" "$WT" "$out" "$commit" || { rec "$name" "$branch" FAILED-SCAN "$commit" "" "scan failed"; return; }
  nissues="$(echo "$SCAN_SUMMARY" | cut -f2)"
  log_info "[$name] scan done: $(echo "$SCAN_SUMMARY" | awk -F'\t' '{printf "%s vulnerable packages, %s issues, %s in KEV, %s reachable, %s high/critical", $1,$2,$3,$4,$5}')"
  log_info "[$name] full report: $out/report.md"
  ln -sfn "$RUN_ID" "$base/latest"          # latest = 最近一次成功生成报告的扫描
  rec "$name" "$branch" OK "$commit" "$nissues" ""
}

if [ "$DO_BRANCHES" = 1 ]; then
  log_info "===== STEP 1/2: branches ====="
  while IFS= read -r line <&3; do
    read -r name url branch rest <<< "$line"
    if [ -z "$name" ] || [ -z "$url" ] || [ -z "$branch" ]; then
      alert ERROR "config: malformed line in branches.conf: $line"; continue
    fi
    branch_selected "$name" || continue
    process_target "$name" "$url" "$branch"
  done 3< <(read_targets)

  # 清理旧记录：每个分支只保留最新 RETENTION 个扫描目录（不分成败）；只处理 branches.conf 里现有的目标
  if retention_ok "branch scan"; then
    while IFS= read -r line <&3; do
      read -r name url branch rest <<< "$line"
      [ -n "$name" ] && [ -n "$branch" ] && prune_results "$name" "$branch"
    done 3< <(read_targets)
  fi

  "$PYTHON" "$SCA_PY" summary --conf "$CONF_DIR/branches.conf" --results "$RESULTS_DIR" \
      --targets "$TARGETS_TSV" --run-id "$RUN_ID" --go-days "$GO_OFFICIAL_DAYS" --out "$BRANCH_REPORT" >>"$RUN_LOG" 2>&1 \
    && log_info "branch report written: $BRANCH_REPORT" \
    || alert WARN "could not write branch report $BRANCH_REPORT"
fi

# =====================================================================
# 第 2 步：镜像（和第 1 步更新后的分支源码比较）
# =====================================================================
worktree_for() {  # branches.conf 名称 -> 打印 "worktree<TAB>branch"
  local line n u b
  while IFS= read -r line; do
    read -r n u b _ <<< "$line"
    if [ "$n" = "$1" ]; then
      printf '%s\t%s\n' "$WT_DIR/$(repo_id_from_url "$u")/$(slugify "$b")" "$b"; return 0
    fi
  done < <(read_targets)
  return 1
}

process_image() {  # name image source
  local name="$1" image="$2" src="$3" out base wt branch rc summ
  base="$IMG_RESULTS/$name"; out="$base/$RUN_ID"
  mkdir -p "$out"
  log_info "----- [$name] $image (source: $src) -----"
  if ! summ="$(worktree_for "$src")"; then
    alert WARN "[$name] '$src' is not in branches.conf: no source comparison"; wt=""; branch=""
  else
    wt="$(echo "$summ" | cut -f1)"; branch="$(echo "$summ" | cut -f2)"
    if [ ! -e "$wt/.git" ]; then
      alert WARN "[$name] worktree $wt does not exist: no source comparison"; wt=""
    else
      case "$FAILED_BRANCHES" in
        *" $src "*) alert WARN "[$name] branch '$src' failed in step 1; comparing against its previous worktree content";;
      esac
    fi
  fi
  printf '{"name":"%s","image":"%s","platform":"%s","source":"%s","branch":"%s","run_id":"%s","scanned_at":"%s"}\n' \
    "$name" "$image" "$IMAGE_PLATFORM" "$src" "$branch" "$RUN_ID" "$(date '+%Y-%m-%dT%H:%M:%S%z')" > "$out/meta.json"

  log_info "[$name] trivy scanning (timeout ${TRIVY_TIMEOUT}s)"
  # shellcheck disable=SC2086
  run_to "$TRIVY_TIMEOUT" "$TRIVY" image --quiet --format json --output "$out/trivy.json" \
      --scanners vuln --list-all-pkgs --image-src remote --platform "$IMAGE_PLATFORM" \
      --timeout "${TRIVY_TIMEOUT}s" $DB_FLAG $TRIVY_EXTRA_ARGS "$image" 2>"$out/trivy.stderr"
  rc=$?
  if [ $rc -eq 124 ]; then alert ERROR "[$name] trivy timed out after ${TRIVY_TIMEOUT}s"; rec_img "$name" FAILED-SCAN "timeout"; return; fi
  if [ $rc -ne 0 ]; then
    alert ERROR "[$name] trivy failed (exit $rc): $(tail -n 3 "$out/trivy.stderr" | tr '\n\t' '  ')"; rec_img "$name" FAILED-SCAN "trivy exit $rc"; return
  fi
  DB_FLAG="--skip-db-update"
  if ! "$PYTHON" "$IMG_PY" validate "$out/trivy.json" 2>>"$out/trivy.stderr"; then
    alert ERROR "[$name] trivy output is not a valid report (see $out/trivy.json)"; rec_img "$name" FAILED-SCAN "bad output"; return
  fi
  if ! summ="$("$PYTHON" "$IMG_PY" report --trivy "$out/trivy.json" --worktree "$wt" --meta "$out/meta.json" \
        --kev "$KEV_FILE" --recent-days "$RECENT_DAYS" --out "$out" 2>>"$RUN_LOG")"; then
    alert ERROR "[$name] failed to build report from trivy output"; rec_img "$name" FAILED-REPORT ""; return
  fi
  log_info "[$name] $(echo "$summ" | awk -F'\t' '{printf "%s issues, %s high/critical, %s likely to be raised, %s fixed in source (awaiting image), %s not fixed in source", $1,$2,$3,$4,$5}')"
  log_info "[$name] report: $out/report.md"
  ln -sfn "$RUN_ID" "$base/latest"
  rec_img "$name" OK "$(echo "$summ" | cut -f1)"
}

if [ "$DO_IMAGES" = 1 ]; then
  log_info "===== STEP 2/2: images (platform=$IMAGE_PLATFORM) ====="
  mkdir -p "$IMG_RESULTS"
  # 拉镜像的凭据：默认匿名拉取（镜像都是 docker.io 上公开的）。
  # 让 trivy 用一个空的 Docker 配置目录，避免读到 ~/.docker/config.json 里的 "credsStore": "desktop"
  # （Docker Desktop 没装/没在 PATH 里时会报 docker-credential-desktop not found）。
  # 需要用自己的 Docker 登录（比如遇到 Docker Hub 限流）时，在 settings.env 里设 USE_DOCKER_CREDS=1。
  if [ "$USE_DOCKER_CREDS" != "1" ]; then
    mkdir -p "$STATE_DIR/docker-anon"
    [ -f "$STATE_DIR/docker-anon/config.json" ] || echo '{}' > "$STATE_DIR/docker-anon/config.json"
    export DOCKER_CONFIG="$STATE_DIR/docker-anon"
    log_info "pulling images anonymously (USE_DOCKER_CREDS=0)"
  fi
  # 漏洞库：第一个镜像扫描时更新一次，其余镜像跳过更新
  DB_FLAG=""; [ "$SKIP_DB" -eq 1 ] && DB_FLAG="--skip-db-update"

  while IFS= read -r line <&3; do
    read -r name image src rest <<< "$line"
    if [ -z "$name" ] || [ -z "$image" ] || [ -z "$src" ]; then alert ERROR "config: malformed line in images.conf: $line"; continue; fi
    image_selected "$name" || continue
    process_image "$name" "$image" "$src"
  done 3< <(read_images)

  # 旧记录清理：results/images/<名称>/ 下只保留最新 RETENTION 个（不分成败）
  if retention_ok "image scan"; then
    while IFS= read -r line; do
      read -r name _ <<< "$line"; [ -n "$name" ] && prune_results images "$name"
    done < <(read_images)
  fi

  "$PYTHON" "$IMG_PY" summary --conf "$CONF_DIR/images.conf" --results "$IMG_RESULTS" --targets "$IMAGES_TSV" \
      --run-id "$RUN_ID" --platform "$IMAGE_PLATFORM" --recent-days "$RECENT_DAYS" --go-days "$GO_OFFICIAL_DAYS" --out "$IMAGE_REPORT" >>"$RUN_LOG" 2>&1 \
    && log_info "image report written: $IMAGE_REPORT" \
    || alert WARN "could not write image report $IMAGE_REPORT"
fi

# ---------- 结束 ----------
status=ok; [ "$N_ERROR" -gt 0 ] && status=errors
finalize "$status"
log_info "===== RUN END status=$status errors=$N_ERROR warnings=$N_WARN ====="
echo
if [ "$DO_BRANCHES" = 1 ]; then
  echo "分支                 状态          漏洞数"
  while IFS=$'\t' read -r n b s c i m <&6; do
    printf '%-20s %-13s %s\n' "$n" "$s" "$i"
  done 6< "$TARGETS_TSV"
  echo
fi
if [ "$DO_IMAGES" = 1 ]; then
  echo "镜像                 状态          漏洞数"
  while IFS=$'\t' read -r n s i <&6; do
    printf '%-20s %-13s %s\n' "$n" "$s" "$i"
  done 6< "$IMAGES_TSV"
  echo
fi
echo "本次告警: $((N_ERROR+N_WARN)) 条（错误 ${N_ERROR} / 警告 ${N_WARN}）"
echo "完整日志: $RUN_LOG"
echo "告警汇总: $LOG_DIR/alerts.log"
[ "$DO_BRANCHES" = 1 ] && echo "分支报告: $BRANCH_REPORT"
[ "$DO_IMAGES" = 1 ]   && echo "镜像报告: $IMAGE_REPORT"
FINISHED=1
[ "$N_ERROR" -gt 0 ] && exit 1
exit 0

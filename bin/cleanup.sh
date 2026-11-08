#!/usr/bin/env bash
# cleanup.sh - 释放磁盘空间：删除下载到本地的所有 GitHub 分支（repos/ 和 worktrees/），并清空本项目的 Go 缓存。
#
# 用法：bin/cleanup.sh [-y] [--dry-run] [--git-only | --go-only]
#   -y, --yes      不询问，直接删除
#   --dry-run      只列出将要删除的内容，不删除
#   --git-only     只删除 repos/ 和 worktrees/
#   --go-only      只清空 Go 缓存
# 删除的内容：
#   repos/*        bare + blobless 仓库（含 origin/<分支> 和本地 sca/<分支>）
#   worktrees/*    每个分支的 worktree
#   Go 缓存        settings.env 的 GO_BUILD_CACHE / GO_MOD_CACHE（默认 caches/go-build、caches/go-mod）；
#                  只清本项目自己的缓存，不碰 Go 的全局缓存。某项设成空字符串时跳过它。
# 不动：results/ logs/ state/ config/。下次 run.sh 会重新 fetch 全部分支（首次 TiDB/TiKV 较慢）。
# 退出码：0 = 完成；1 = 有删除失败；2 = 参数错误或用户取消；3 = 有扫描正在运行

BIN="$(cd "$(dirname "$0")" && pwd)"
. "$BIN/lib.sh"    # 检查外置盘是否已挂载，设置 SCA_ROOT / REPOS_DIR / WT_DIR / PATH

YES=0; DRY=0; DO_GIT=1; DO_GO=1
while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes) YES=1; shift;;
    --dry-run) DRY=1; shift;;
    --git-only) DO_GO=0; shift;;
    --go-only) DO_GIT=0; shift;;
    -h|--help) sed -n '2,14p' "$0"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done
if [ "$DO_GIT" = 0 ] && [ "$DO_GO" = 0 ]; then echo "--git-only 和 --go-only 不能同时使用" >&2; exit 2; fi

# 扫描运行中时拒绝清理（与 run.sh 的锁一致；pid 不存在的旧锁忽略）
for lock in "$STATE_DIR/run.lock"; do
  [ -d "$lock" ] || continue
  pid="$(cat "$lock/pid" 2>/dev/null)"
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    echo "ERROR: 有扫描正在运行（$(basename "$lock")，pid $pid），请等它结束后再清理。" >&2
    exit 3
  fi
done

# ---- 收集要清理的 Go 缓存目录（去重）----
GO_DIRS=""
add_go_dir() {
  local d="$1"
  [ -n "$d" ] || return 0
  case "$d" in /*) ;; *) return 0;; esac          # 只接受绝对路径
  d="${d%/}"
  case "
$GO_DIRS
" in *"
$d
"*) return 0;; esac
  GO_DIRS="${GO_DIRS:+$GO_DIRS
}$d"
}
if [ "$DO_GO" = 1 ]; then
  add_go_dir "$GO_MOD_CACHE"
  add_go_dir "$GO_BUILD_CACHE"
  [ -n "$GO_DIRS" ] || echo "提示：GO_BUILD_CACHE 和 GO_MOD_CACHE 都设成了空（用 Go 的全局缓存），不清理 Go 缓存。"
fi

# 拒绝危险路径
is_unsafe() {
  case "$1" in
    ""|/|/Users|/Users/*/|/home|/home/*/|/Volumes|/mnt|/media|"$HOME"|"$HOME/") return 0;;
    /Volumes/*/*|/mnt/*/*|/media/*/*) ;;
    /Volumes/*|/mnt/*|/media/*) return 0;;                 # 挂载点本身
  esac
  [ "$1" = "$SCA_ROOT" ] && return 0
  [ -n "${REQUIRED_MOUNT:-}" ] && [ "${1%/}" = "${REQUIRED_MOUNT%/}" ] && return 0
  return 1
}

# ---- 列出计划 ----
echo "SCA 清理（$SCA_ROOT）"
TARGETS=""
if [ "$DO_GIT" = 1 ]; then
  echo "本地 GitHub 分支："
  for d in "$REPOS_DIR"/* "$WT_DIR"/*; do
    [ -e "$d" ] || continue
    echo "  - ${d#$SCA_ROOT/}"
    TARGETS=1
  done
fi
if [ "$DO_GO" = 1 ]; then
  echo "Go 缓存（清空目录内容，保留目录本身）："
  echo "$GO_DIRS" | while IFS= read -r d; do
    [ -n "$d" ] || continue
    if [ -d "$d" ]; then echo "  - $d"; else echo "  - $d（不存在，跳过）"; fi
  done
  TARGETS=1
fi
[ -n "$TARGETS" ] || { echo "没有需要清理的内容。"; exit 0; }

if [ "$DRY" = 1 ]; then echo "（--dry-run：未删除任何内容）"; exit 0; fi
if [ "$YES" != 1 ]; then
  printf "确认删除以上内容？[y/N] "
  read -r ans
  case "$ans" in y|Y|yes|YES) ;; *) echo "已取消。"; exit 2;; esac
fi

FAIL=0
# Go module cache 里的文件是只读的，先加写权限再删
wipe() {  # path  [contents-only]
  local p="$1"
  if is_unsafe "$p"; then echo "  跳过危险路径：$p" >&2; FAIL=1; return; fi
  [ -e "$p" ] || return 0
  chmod -R u+w "$p" 2>/dev/null
  if [ "$2" = "contents-only" ]; then
    find "$p" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + 2>/dev/null
    [ -z "$(ls -A "$p" 2>/dev/null)" ] || { echo "  删除不完全：$p" >&2; FAIL=1; return; }
  else
    rm -rf -- "$p" || { echo "  删除失败：$p" >&2; FAIL=1; return; }
  fi
  echo "  已删除：$p"
}

if [ "$DO_GIT" = 1 ]; then
  echo "删除本地分支…"
  for d in "$WT_DIR"/* "$REPOS_DIR"/*; do
    [ -e "$d" ] || continue
    wipe "$d"
  done
fi

if [ "$DO_GO" = 1 ]; then
  echo "清空 Go 缓存…"
  OLDIFS="$IFS"; IFS='
'
  for d in $GO_DIRS; do
    IFS="$OLDIFS"
    [ -d "$d" ] && wipe "$d" contents-only
  done
  IFS="$OLDIFS"
fi

if [ "$FAIL" -ne 0 ]; then echo "完成，但有删除失败（见上）。"; exit 1; fi
echo "完成。下次 bin/run.sh 会重新下载全部分支。"
exit 0

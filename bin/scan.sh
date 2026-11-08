#!/usr/bin/env bash
# scan.sh - 扫描一个 worktree（被 run.sh source）。
# 产物（results/<name>/<branch>/<运行ID>/）：meta.json osv.json govulncheck/*.json report.{json,tsv,md}
# 成功后设置 SCAN_SUMMARY = "包数<TAB>漏洞数<TAB>KEV数<TAB>可达数<TAB>高危+严重数"

find_go_mods() {  # worktree
  find "$1" -maxdepth "$GO_MOD_MAXDEPTH" -name go.mod \
    -not -path '*/node_modules/*' -not -path '*/testdata/*' -not -path '*/vendor/*' \
    -not -path '*/third_party/*' -not -path '*/.git/*' 2>/dev/null | sort
}

scan_target() {  # name branch worktree outdir commit
  local name="$1" branch="$2" wt="$3" out="$4" commit="$5"
  local rc mods gm d rel f grc
  mkdir -p "$out/govulncheck"
  printf '{"target":"%s","branch":"%s","commit":"%s","scanned_at":"%s"}\n' \
    "$name" "$branch" "$commit" "$(date '+%Y-%m-%dT%H:%M:%S%z')" > "$out/meta.json"

  # 1) OSV-Scanner：完整依赖漏洞清单（go.mod / Cargo.lock / npm 锁文件等）
  log_info "[$name] osv-scanner scanning (timeout ${OSV_TIMEOUT}s)"
  # --no-ignore：osv-scanner 默认跳过 .gitignore 里的路径，而且会读上层目录的 .gitignore。
  # 本项目自己的 .gitignore 忽略了 worktrees/，不加这个参数时整个 worktree 都会被跳过（exit 128）。
  run_to "$OSV_TIMEOUT" "$OSV_SCANNER" scan source -r --no-ignore --format json "$wt" >"$out/osv.json" 2>"$out/osv.stderr"
  rc=$?
  case $rc in
    0|1) ;;   # 0 = 无漏洞，1 = 发现漏洞，均为正常
    124) alert ERROR "[$name] osv-scanner timed out after ${OSV_TIMEOUT}s"; return 1;;
    128) alert ERROR "[$name] osv-scanner found no supported manifests in worktree (exit 128)"; return 1;;
    *)   alert ERROR "[$name] osv-scanner failed (exit $rc): $(tail -n 3 "$out/osv.stderr" | tr '\n\t' '  ')"; return 1;;
  esac
  if ! "$PYTHON" "$SCA_PY" validate --kind osv "$out/osv.json" 2>>"$out/osv.stderr"; then
    alert ERROR "[$name] osv-scanner output is not valid JSON (see $out/osv.json)"; return 1
  fi

  # 2) govulncheck：每个 go.mod 单独跑，标注 Go 漏洞是否在代码中可达
  : > "$out/govulncheck/_status.tsv"
  if [ "$GOVULNCHECK_ENABLED" = "1" ] && [ "${NO_GOVULN:-0}" != "1" ]; then
    mods="$(find_go_mods "$wt")"
    if [ -n "$mods" ]; then
      if ! have_tool "$GOVULNCHECK" || ! have_tool go; then
        alert WARN "[$name] go or govulncheck not found in PATH: Go reachability will be 'unknown' for this branch"
      else
        while IFS= read -r gm <&4; do
          d="$(dirname "$gm")"; rel="${d#$wt}"; rel="${rel#/}"
          [ -z "$rel" ] && rel="root"
          f="$(echo "$rel" | tr '/' '_')"
          log_info "[$name] govulncheck module: $rel"
          ( cd "$d" && run_to "$GOVULN_TIMEOUT" "$GOVULNCHECK" -format json ./... ) >"$out/govulncheck/$f.json" 2>"$out/govulncheck/$f.stderr"
          grc=$?
          printf '%s\t%s\n' "$rel" "$grc" >> "$out/govulncheck/_status.tsv"
          if [ $grc -ne 0 ]; then
            rm -f "$out/govulncheck/$f.json"
            alert WARN "[$name] govulncheck failed in module '$rel' (exit $grc): $(tail -n 2 "$out/govulncheck/$f.stderr" | tr '\n\t' '  ')"
          fi
        done 4<<< "$mods"
      fi
    fi
  fi

  # 3) 聚合：按依赖包汇总 + CVSS + KEV + 可达性
  SCAN_SUMMARY="$("$PYTHON" "$SCA_PY" report \
      --osv "$out/osv.json" --govuln-dir "$out/govulncheck" --kev "${KEV_FILE:-}" \
      --exclude "$EXCLUDE_PATH_REGEX" --include-dev "$INCLUDE_DEV_DEPS" \
      --worktree "$wt" --meta "$out/meta.json" --out "$out" 2>>"$RUN_LOG")" \
    || { alert ERROR "[$name] failed to build report from scanner output"; return 1; }
  return 0
}

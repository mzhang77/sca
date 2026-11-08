#!/usr/bin/env bash
# check_env.sh - 只检查环境，不安装任何东西；缺什么会告诉你怎么装。
# 用法：bin/check_env.sh [--selftest]    --selftest 会用一个很小的 go.mod 实际跑一遍 osv-scanner 验证输出格式
BIN="$(cd "$(dirname "$0")" && pwd)"
. "$BIN/lib.sh"
bad=0
row() { printf '  %-6s %-13s %s\n' "$1" "$2" "$3"; }

echo "PATH 额外目录(EXTRA_PATH): ${EXTRA_PATH:-<空>}"
echo "Go 缓存: GOCACHE=${GOCACHE:-<Go 全局设置>}  GOMODCACHE=${GOMODCACHE:-<Go 全局设置>}"
for c in branches.conf images.conf; do
  if [ -f "$CONF_DIR/$c" ]; then echo "配置: config/$c 已存在"
  else echo "配置: 缺少 config/$c  ->  cp config/$c.example config/$c  然后按需修改"; bad=1; fi
done
if [ -f "$CONF_DIR/settings.env" ]; then echo "配置: config/settings.env 已存在"
else echo "配置: 没有 config/settings.env，使用默认设置（可选：cp config/settings.env.example config/settings.env）"; fi
echo

if have_tool git; then
  gv="$(git --version | sed -E 's/[^0-9]*([0-9]+\.[0-9]+).*/\1/')"
  if "$PYTHON" -c "import sys; sys.exit(0 if tuple(map(int,'$gv'.split('.')))>=(2,25) else 1)" 2>/dev/null; then row OK git "$(git --version)"; else row WARN git "$(git --version) - 建议 >= 2.25（partial clone / worktree）"; fi
else row MISS git "需要。macOS: xcode-select --install"; bad=1; fi

if have_tool "$PYTHON"; then
  if "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info>=(3,8) else 1)'; then row OK python3 "$("$PYTHON" --version) ($(command -v "$PYTHON"))"; else row MISS python3 "需要 >= 3.8，当前 $("$PYTHON" --version)"; bad=1; fi
else row MISS python3 "需要 >= 3.8"; bad=1; fi

if have_tool curl; then row OK curl "$(curl --version | head -1 | cut -d' ' -f1-2)"; else row MISS curl "需要（下载 CISA KEV）"; bad=1; fi

if have_tool "$OSV_SCANNER"; then
  ov="$("$OSV_SCANNER" --version 2>&1 | head -1)"
  case "$ov" in *" 2."*|*"v2."*) row OK osv-scanner "$ov";; *) row WARN osv-scanner "$ov - 本工具按 v2.x 的命令行/JSON 编写，建议升级到 v2";; esac
else
  row MISS osv-scanner "必需。安装方式二选一："
  echo "                       brew install osv-scanner"
  echo "                       go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest   （需要先有 go）"
  bad=1
fi

if have_tool go; then row OK go "$(go version)"; else
  row MISS go "可选（Go 可达性分析、清理 Go 缓存时用）。如果用 gvm 等工具装了 Go，但当前 shell 没加载："
  echo "                       把 Go 的 bin 目录写进 config/settings.env 的 EXTRA_PATH（脚本不会加载 gvm 之类的 shell 初始化）"
  echo "                       没有的话: brew install go   （这些仓库用 Go 1.27.x，go.mod 会自动切换工具链，需 Go >= 1.21）"
fi

if have_tool "$GOVULNCHECK"; then row OK govulncheck "$("$GOVULNCHECK" -version 2>&1 | head -2 | tr '\n' ' ')"; else
  row MISS govulncheck "可选（缺省不用，GOVULNCHECK_ENABLED=0）。打开可达性分析时才需要。安装："
  echo "                       go install golang.org/x/vuln/cmd/govulncheck@latest"
  echo "                       （请用最新的 Go 来安装：这些仓库用较新的 Go 语法，旧版编译出的 govulncheck 可能解析失败）"
fi
if have_tool "${TRIVY:-trivy}"; then row OK trivy "$("${TRIVY:-trivy}" --version 2>/dev/null | head -1)"; else
  row MISS trivy "镜像报告（bin/run.sh 第 2 步）需要。安装： brew install trivy"
fi
echo
if [ "${1:-}" = "--selftest" ]; then
  if ! have_tool "$OSV_SCANNER"; then echo "selftest 跳过：osv-scanner 未安装"; exit 1; fi
  T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
  printf 'module example.com/t\n\ngo 1.21\n\nrequire golang.org/x/net v0.10.0\n' > "$T/go.mod"
  "$OSV_SCANNER" scan source -r --format json "$T" > "$T/out.json" 2> "$T/err.txt"; rc=$?
  echo "selftest: osv-scanner exit=${rc}（1 表示发现漏洞，预期值）"
  "$PYTHON" "$SCA_PY" validate --kind osv "$T/out.json" && echo "selftest: 输出是合法 JSON"
  "$PYTHON" "$SCA_PY" report --osv "$T/out.json" --govuln-dir "$T/none" --kev "" --exclude "" --include-dev 0 --worktree "$T" --out "$T" >/dev/null \
    && { echo "selftest: 聚合结果："; cat "$T/report.tsv"; } || { echo "selftest: 聚合失败（把 $T/out.json 发给我排查）"; bad=1; }
fi
[ "$bad" -eq 0 ] && echo "必需工具齐全。" || echo "有必需工具缺失，见上。"
exit $bad

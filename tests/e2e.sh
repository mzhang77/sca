#!/usr/bin/env bash
# 端到端测试：本地假 origin + 桩 osv-scanner/govulncheck/caffeinate，全程不联网，不碰真实的 repos/results/logs。
# 用法：tests/e2e.sh
export PYTHONDONTWRITEBYTECODE=1
HERE="$(cd "$(dirname "$0")" && pwd)"; SRC="$(cd "$HERE/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
R="$T/root"; mkdir -p "$R/config" "$T/stubs"; cp -R "$SRC/bin" "$R/bin"
PASS=0; FAILN=0
check() { if eval "$2"; then PASS=$((PASS+1)); echo "  PASS  $1"; else FAILN=$((FAILN+1)); echo "  FAIL  $1"; fi; }

# ---- 桩工具 ----
cat > "$T/stubs/osv-scanner" <<'S'
#!/bin/sh
[ -n "$STUB_OSV_FAIL" ] && { echo "boom: simulated scanner crash" >&2; exit 127; }
for a in "$@"; do last="$a"; done
sed "s#/WT#$last#g" "$STUB_OSV_FILE"
exit 1
S
printf '#!/bin/sh\necho "$GOCACHE|$GOMODCACHE" > "%s/gov.env"\ncat "$STUB_GOV_FILE"\n' "$T" > "$T/stubs/govulncheck"
printf '#!/bin/sh\nexit 0\n' > "$T/stubs/go"
printf '#!/bin/sh\necho "$@" > "%s/caff.args"\nexit 0\n' "$T" > "$T/stubs/caffeinate"
chmod +x "$T/stubs/"*
cp "$HERE/fixtures/kev_sample.json" "$T/kev.json"
python3 - "$HERE/fixtures/osv_sample.json" "$T/osv_v2.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); pk=d["results"][0]["packages"][0]
pk["vulnerabilities"].append({"id":"GHSA-w32m-9786-jp63","aliases":["CVE-2024-45338"],"summary":"Non-linear parsing of case-insensitive content",
 "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
 "affected":[{"package":{"name":"golang.org/x/net","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.33.0"}]}]}]})
pk["groups"].append({"ids":["GHSA-w32m-9786-jp63","CVE-2024-45338"],"aliases":["CVE-2024-45338"],"max_severity":"7.5"})
json.dump(d,open(sys.argv[2],"w"))
PY
export STUB_OSV_FILE="$HERE/fixtures/osv_sample.json" STUB_GOV_FILE="$HERE/fixtures/govulncheck_sample.json"
cat > "$R/config/settings.env" <<EOF2
EXTRA_PATH="$T/stubs"
KEV_URL="file://$T/kev.json"
CLONE_TIMEOUT=120
FETCH_TIMEOUT=60
RETENTION=3
GOVULNCHECK_ENABLED=1
EOF2

# ---- 假 origin ----
O="$T/origin.git"; git init -q --bare "$O"
git -C "$O" config uploadpack.allowFilter true; git -C "$O" config uploadpack.allowAnySHA1InWant true
W="$T/work"; git init -q "$W"
g() { git -C "$W" "$@"; }
g config user.email t@t; g config user.name t; g checkout -q -b rel-1
printf 'module x\n' > "$W/go.mod"; g add .; g commit -qm c1; g remote add origin "file://$O"; g push -q origin rel-1
printf 'demo   file://%s   rel-1\n' "$O" > "$R/config/branches.conf"

run_it() { "$R/bin/run.sh" --branches-only "$@" > "$T/out.txt" 2>&1; RC=$?; sleep 1; }
ALERTS="$R/logs/alerts.log"
B="$R/results/demo/rel-1"
dirs() { ls -1d "$B"/20*/ 2>/dev/null | wc -l | tr -d ' '; }

echo "== 1. 首次运行：创建仓库/worktree，生成完整报告"
run_it
WT="$(ls -d "$R"/worktrees/*/rel-1 2>/dev/null)"
RES="$B/latest"
check "退出码 0" '[ $RC -eq 0 ]'
check "已调用 caffeinate 并绑定本脚本进程(-w)" 'grep -q -- "-i -m -s -w" "$T/caff.args" && grep -q "caffeinate started" "$R"/logs/run-*.log'
check "worktree 已创建且在 sca/rel-1" '[ "$(git -C "$WT" symbolic-ref HEAD)" = "refs/heads/sca/rel-1" ]'
check "完整报告三件套都在" '[ -s "$RES/report.tsv" ] && [ -s "$RES/report.md" ] && [ -s "$RES/report.json" ]'
check "聚合行正确(最高修复版本/CVE数/KEV/可达)" 'awk -F"\t" "\$1==\"golang.org/x/net\" && \$4==\"0.17.0\" && \$5==\"2\" && \$8==\"YES\" && \$9==\"called\"" "$RES/report.tsv" | grep -q .'
check "node_modules 下的包被排除" '! grep -q lodash "$RES/report.tsv"'
check "Rust 包有结果且可达性 n/a" 'awk -F"\t" "\$1==\"time\" && \$9==\"n/a\"" "$RES/report.tsv" | grep -q .'
SUM="$R/results/report-branches-latest.md"
check "汇总文件含总览/优先处理/聚合表" '[ -s "$SUM" ] && grep -q "## 1. 总览" "$SUM" && grep -q "## 2. 需要优先处理" "$SUM" && grep "^| demo | golang.org/x/net" "$SUM" | grep -q "CVE-2023-44487.*YES.*called"'
check "没有 NEW/ESCALATION 之类的对比告警，告警日志为空" '! grep -q "NEW\|ESCALATION" "$R"/logs/run-*.log && [ ! -s "$ALERTS" ]'
check "go/govulncheck 用的是项目内的 Go 缓存" '[ "$(cat "$T/gov.env")" = "$R/caches/go-build|$R/caches/go-mod" ]'
check "state/last_run.json 状态 ok" 'grep -q "\"status\": \"ok\"" "$R/state/last_run.json"'

echo "== 2. 上游前进 + 新增漏洞：fast-forward，并生成新的完整报告"
printf 'b\n' >> "$W/go.mod"; g commit -qam c2; g push -q origin rel-1
export STUB_OSV_FILE="$T/osv_v2.json"
run_it
check "退出码 0，worktree 已 fast-forward" '[ $RC -eq 0 ] && [ "$(git -C "$WT" rev-parse HEAD)" = "$(g rev-parse HEAD)" ]'
check "新报告包含全部 3 个当前漏洞（不区分新旧）" 'awk -F"\t" "\$1==\"golang.org/x/net\" && \$5==\"3\"" "$B/latest/report.tsv" | grep -q .'
check "产生了第 2 个扫描目录" '[ "$(dirs)" = "2" ]'

echo "== 3. worktree 有本地改动且上游前进：拒绝更新并报错，不动文件"
printf 'c\n' >> "$W/go.mod"; g commit -qam c3; g push -q origin rel-1
printf 'local edit\n' >> "$WT/go.mod"; BEFORE="$(git -C "$WT" rev-parse HEAD)"
run_it
check "退出码 1，ERROR 提到 modified tracked files" '[ $RC -eq 1 ] && grep "\[ERROR\]" "$ALERTS" | grep -q "modified tracked files"'
check "HEAD 与本地改动都原样保留" '[ "$(git -C "$WT" rev-parse HEAD)" = "$BEFORE" ] && grep -q "local edit" "$WT/go.mod"'
git -C "$WT" checkout -q -- go.mod
run_it
check "还原改动后恢复正常并 fast-forward" '[ $RC -eq 0 ] && [ "$(git -C "$WT" rev-parse HEAD)" = "$(g rev-parse HEAD)" ]'

echo "== 4. 上游强推导致分叉：拒绝并报错"
g reset -q --hard HEAD~2; printf 'diverged\n' >> "$W/go.mod"; g commit -qam d1; g push -q -f origin rel-1
BEFORE="$(git -C "$WT" rev-parse HEAD)"
run_it
check "退出码 1 且 ERROR 提到 cannot fast-forward" '[ $RC -eq 1 ] && grep "\[ERROR\]" "$ALERTS" | grep -q "cannot fast-forward"'
check "worktree 未被改动" '[ "$(git -C "$WT" rev-parse HEAD)" = "$BEFORE" ]'

echo "== 5. 扫描器崩溃：不能悄悄失败"
STUB_OSV_FAIL=1 run_it --no-sync
check "退出码 1 且 ERROR 提到 osv-scanner failed" '[ $RC -eq 1 ] && grep "\[ERROR\]" "$ALERTS" | grep -q "osv-scanner failed (exit 127)"'
check "last_run.json 状态为 errors" 'grep -q "\"status\": \"errors\"" "$R/state/last_run.json"'
check "汇总文件标注本次失败并保留上次成功的结果" 'grep -q "本次失败，下表是上次成功的结果" "$SUM" && grep -q "golang.org/x/net" "$SUM"'

echo "== 6. fetch 失败（URL 不可达）：报错"
printf 'demo   file://%s/nope.git   rel-1\n' "$T" > "$R/config/branches.conf"
run_it
check "退出码 1 且 ERROR 提到 git fetch failed" '[ $RC -eq 1 ] && grep "\[ERROR\]" "$ALERTS" | grep -q "git fetch failed"'

echo "== 7. 缺 govulncheck：降级并告警"
printf 'demo   file://%s   rel-1\n' "$O" > "$R/config/branches.conf"
mv "$T/stubs/govulncheck" "$T/stubs/govulncheck.off"
export STUB_OSV_FILE="$HERE/fixtures/osv_sample.json"
run_it --no-sync          # 第 4 步故意制造了分叉，这里只关心扫描阶段
check "WARN 提到 govulncheck 缺失，且可达性为 unknown" 'grep "\[WARN\]" "$ALERTS" | grep -q "govulncheck" && awk -F"\t" "\$1==\"golang.org/x/net\" && \$9==\"unknown\"" "$B/latest/report.tsv" | grep -q .'

echo "== 7b. GOVULNCHECK_ENABLED=0（缺省）：不跑、不告警，可达性 unknown；--govulncheck 单次打开"
mv "$T/stubs/govulncheck.off" "$T/stubs/govulncheck"
sed -i.bak 's/^GOVULNCHECK_ENABLED=1/GOVULNCHECK_ENABLED=0/' "$R/config/settings.env"
NW0="$(grep -c "govulncheck" "$ALERTS")"
run_it --no-sync
check "关闭时：退出码 0、没有新的 govulncheck 告警、可达性 unknown、没有 govulncheck 输出" '[ $RC -eq 0 ] && [ "$(grep -c "govulncheck" "$ALERTS")" -eq "$NW0" ] && awk -F"\t" "\$1==\"golang.org/x/net\" && \$9==\"unknown\"" "$B/latest/report.tsv" | grep -q . && ! ls "$B/latest/govulncheck/"*.json >/dev/null 2>&1'
run_it --no-sync --govulncheck
check "--govulncheck：本次可达性为 called" '[ $RC -eq 0 ] && awk -F"\t" "\$1==\"golang.org/x/net\" && \$9==\"called\"" "$B/latest/report.tsv" | grep -q .'
sed -i.bak 's/^GOVULNCHECK_ENABLED=0/GOVULNCHECK_ENABLED=1/' "$R/config/settings.env"

echo "== 8. 保留策略：RETENTION=3 时目录数不超过 3"
check "之前所有运行（含失败的）累计后目录数 <= 3" '[ "$(dirs)" -le 3 ]'
check "latest 软链接没有被清理掉" '[ -L "$B/latest" ] && [ -s "$B/latest/report.tsv" ]'

echo "== 9. 保留策略不分成败：RETENTION=2，连续 3 次失败后只剩最新 2 个（都是失败的）"
sed -i.bak 's/^RETENTION=3/RETENTION=2/' "$R/config/settings.env"
STUB_OSV_FAIL=1 run_it --no-sync; STUB_OSV_FAIL=1 run_it --no-sync; STUB_OSV_FAIL=1 run_it --no-sync
check "目录数恰好为 2" '[ "$(dirs)" = "2" ]'
check "这 2 个都是失败的运行（没有 report.tsv）" '[ -z "$(ls "$B"/20*/report.tsv 2>/dev/null)" ]'
check "日志记录了清理动作" 'grep -q "retention=2: removed" "$R"/logs/run-*.log'
check "汇总文件如实说明：本次失败且尚无成功结果" 'grep -q "本次失败，尚无成功结果" "$SUM"'
run_it --no-sync
check "再成功一次：仍是 2 个目录，latest 指向最新的成功扫描" '[ "$(dirs)" = "2" ] && [ -s "$B/latest/report.tsv" ]'

echo "== 10. RETENTION 非法：告警且不删除任何东西"
N0="$(dirs)"
sed -i.bak 's/^RETENTION=2/RETENTION=abc/' "$R/config/settings.env"
run_it --no-sync
check "WARN 提到 invalid RETENTION，目录数只增不减" 'grep "\[WARN\]" "$ALERTS" | grep -q "invalid RETENTION" && [ "$(dirs)" -gt "$N0" ]'

echo "== 11. 完整运行（不加 --branches-only）：先分支、后镜像，出两份报告"
sed -i.bak 's/^RETENTION=abc/RETENTION=3/' "$R/config/settings.env"
cat > "$T/stubs/trivy" <<'S'
#!/bin/sh
[ "$1" = "--version" ] && { echo "Version: 0.0.stub"; exit 0; }
for a in "$@"; do case "$prev" in --output) out="$a";; esac; prev="$a"; done
cp "$STUB_TRIVY_FILE" "$out"
S
chmod +x "$T/stubs/trivy"; export STUB_TRIVY_FILE="$HERE/fixtures/trivy_sample.json"
printf 'demoimg  docker.io/x/demo:1  demo\n' > "$R/config/images.conf"
run_it_all() { "$R/bin/run.sh" "$@" > "$T/out.txt" 2>&1; RC=$?; sleep 1; }
run_it_all --no-sync
IMGREP="$R/results/report-images-latest.md"
check "退出码 0，两份报告都生成" '[ $RC -eq 0 ] && [ -s "$SUM" ] && [ -s "$IMGREP" ]'
check "先分支后镜像（日志顺序）" 'L="$(ls "$R"/logs/run-*.log)"; [ "$(grep -n "STEP 1/2" "$L" | tail -1 | cut -d: -f1)" -lt "$(grep -n "STEP 2/2" "$L" | tail -1 | cut -d: -f1)" ]'
check "镜像报告含源码状态（源码已修复/未修复两节）" 'grep -q "## 4. 源码已修复、还没发镜像的" "$IMGREP" && grep -q "## 5. 源码也还没修复的" "$IMGREP"'
check "镜像和分支共用同一个运行ID" 'RID="$(basename "$(readlink "$B/latest")")"; [ -d "$R/results/images/demoimg/$RID" ]'
check "终端汇总同时列出分支和镜像" 'grep -q "^demo " "$T/out.txt" && grep -q "^demoimg " "$T/out.txt" && grep -q "镜像报告:" "$T/out.txt"'
STUB_OSV_FAIL=1 run_it_all --no-sync
check "分支失败时镜像照常扫描，并提示对比的是旧内容" '[ $RC -eq 1 ] && grep -q "^demoimg  *OK" "$T/out.txt" && grep "\[WARN\]" "$ALERTS" | grep -q "failed in step 1"'
run_it_all --no-sync --only demoimg
check "--only 镜像名：同时处理对应分支" '[ $RC -eq 0 ] && grep -q "^demo  *OK" "$T/out.txt" && grep -q "^demoimg  *OK" "$T/out.txt"'
run_it_all --only nope
check "--only 不存在的名称：退出码 2" '[ $RC -eq 2 ]'

echo "== 12. REQUIRED_MOUNT：设了但没挂载时直接退出 2；留空不检查"
cp "$R/config/settings.env" "$T/settings.keep"
echo 'REQUIRED_MOUNT="/no/such/mount"' >> "$R/config/settings.env"
run_it_all --no-sync
check "未挂载：退出码 2，提示 REQUIRED_MOUNT" '[ $RC -eq 2 ] && grep -q "REQUIRED_MOUNT" "$T/out.txt"'
cp "$T/settings.keep" "$R/config/settings.env"
echo 'REQUIRED_MOUNT="/"' >> "$R/config/settings.env"
run_it_all --no-sync
check "已挂载（/）：正常运行" '[ $RC -eq 0 ]'
cp "$T/settings.keep" "$R/config/settings.env"

echo "== 13. cleanup.sh：删除分支和项目内 Go 缓存，不动结果，也不碰 Go 全局缓存"
mkdir -p "$R/caches/go-mod/m/x" "$R/caches/go-build/aa" "$T/globalcache/k"; chmod 555 "$R/caches/go-mod/m/x"
"$R/bin/cleanup.sh" --dry-run > "$T/out.txt" 2>&1
check "--dry-run 不删除，列出项目内缓存" '[ -n "$(ls -A "$R/repos")" ] && [ -d "$R/caches/go-mod/m/x" ] && grep -q "$R/caches/go-mod" "$T/out.txt"'
GOCACHE="$T/globalcache" "$R/bin/cleanup.sh" -y > "$T/out.txt" 2>&1; RC=$?
check "-y：分支和项目缓存清空，results 和全局缓存都还在" '[ $RC -eq 0 ] && [ -z "$(ls -A "$R/repos")" ] && [ -z "$(ls -A "$R/worktrees")" ] && [ -d "$R/caches/go-mod" ] && [ -z "$(ls -A "$R/caches/go-mod")" ] && [ -z "$(ls -A "$R/caches/go-build")" ] && [ -d "$T/globalcache/k" ] && [ -s "$SUM" ]'

echo
echo "结果: $PASS 通过, $FAILN 失败"
[ "$FAILN" -eq 0 ]

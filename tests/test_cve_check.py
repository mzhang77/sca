#!/usr/bin/env python3
"""cve_check.py：本地假 origin 仓库 + 桩 osv-scanner（不联网），检查两个分支 / 一个分支的归类、排除、配置、失败处理和输出文件。"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)

STUB = """#!/bin/sh
# 桩 osv-scanner：输出 worktree 里 fake_osv.json 的内容（/WT 换成 worktree 路径）；不带 --all-packages 时去掉没有漏洞的包
all=0
for a in "$@"; do
  if [ "$a" = "--all-packages" ]; then
    [ -n "$STUB_NO_ALL" ] && { echo "unknown flag --all-packages" >&2; exit 2; }
    all=1
  fi
  last="$a"
done
[ -f "$last/fake_osv.json" ] || { echo "no manifests" >&2; exit 128; }
sed "s#/WT#$last#g" "$last/fake_osv.json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
if sys.argv[1] == "0":
    for r in d["results"]:
        r["packages"] = [p for p in r["packages"] if p["vulnerabilities"]]
print(json.dumps(d))' "$all"
exit 1
"""


def w(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False))


def vuln(vid, aliases, pkg, fixed):
    return {"id": vid, "aliases": aliases, "summary": "s",
            "database_specific": {"severity": "HIGH"},
            "affected": [{"package": {"name": pkg, "ecosystem": "Go"},
                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}


def osv(pkgs, path="go.mod"):
    """pkgs: [(包, 版本, [vuln...])]"""
    return {"results": [{"source": {"path": "/WT/" + path, "type": "lockfile"}, "packages": [
        {"package": {"name": p, "version": v, "ecosystem": "Go"}, "vulnerabilities": vs, "groups": []} for p, v, vs in pkgs]}]}


V1 = vuln("GO-2026-0001", ["CVE-2026-0001"], "golang.org/x/net", "0.30.0")
V2 = vuln("GHSA-aaaa-bbbb-cccc", ["CVE-2026-0002"], "golang.org/x/crypto", "0.40.0")
V3 = vuln("GO-2026-0003", ["CVE-2026-0003"], "golang.org/x/text", "0.20.0")
V5 = vuln("GO-2026-0005", ["CVE-2026-0005"], "golang.org/x/net", "0.30.0")


def git(*a, cwd):
    subprocess.run(["git"] + list(a), cwd=cwd, check=True, capture_output=True)


class CveCheck(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        r = self.root = os.path.join(self.t, "root")
        shutil.copytree(os.path.join(SRC, "bin"), os.path.join(r, "bin"))
        stubs = os.path.join(self.t, "stubs")
        w(os.path.join(stubs, "osv-scanner"), STUB)
        os.chmod(os.path.join(stubs, "osv-scanner"), 0o755)
        w(os.path.join(r, "config", "settings.env"), 'EXTRA_PATH="%s"\nRETENTION=2\n' % stubs)
        # 假 origin：master 上 x/net 已升级（0001、0005 修了），crypto 没修（0002），text 新引入了 0003；
        # 客户分支 cust：x/net 0.20.0（0001、0005），crypto 0.30.0（0002），text 0.21.0（没有 0003）；tests/ 下的清单要被排除
        o = self.origin = os.path.join(self.t, "origin", "pd")
        os.makedirs(o)
        git("init", "-q", "-b", "master", cwd=o)
        git("config", "user.email", "t@t", cwd=o)
        git("config", "user.name", "t", cwd=o)
        w(os.path.join(o, "fake_osv.json"), osv([("golang.org/x/net", "0.31.0", []), ("golang.org/x/crypto", "0.30.0", [V2]),
                                                 ("golang.org/x/text", "0.10.0", [V3])]))
        git("add", ".", cwd=o)
        git("commit", "-q", "-m", "master", cwd=o)
        git("checkout", "-q", "-b", "cust", cwd=o)
        d = osv([("golang.org/x/net", "v0.20.0", [V1, V5]), ("golang.org/x/crypto", "0.30.0", [V2]), ("golang.org/x/text", "0.21.0", [])])
        d["results"].append(osv([("x/test", "1.0", [vuln("GO-2026-0009", ["CVE-2026-0009"], "x/test", "1.1")])], "tests/go.mod")["results"][0])
        w(os.path.join(o, "fake_osv.json"), d)
        git("commit", "-q", "-am", "cust", cwd=o)
        git("checkout", "-q", "master", cwd=o)
        w(os.path.join(r, "config", "branches.conf"), "pd %s master\n" % o)
        self.cdir = os.path.join(self.t, "cust")
        w(os.path.join(self.cdir, "cves.txt"), "# 注释\nCVE-2026-0001\ncve-2026-0002  小写也行\nCVE-2026-0003\nCVE-2026-0004\n"
          "CVE-2026-0005\nCVE-2026-0009\nCVE-2026-0008\n不是编号\nCVE-2026-0001\n")
        # 旧配置里的 components 行：忽略并提示
        self.conf = os.path.join(self.cdir, "cve_check.conf")
        w(self.conf, "components pd dash\nexclude CVE-2026-0005 已确认误报\n")

    def tearDown(self):
        shutil.rmtree(self.t)

    def run_it(self, *extra, env=None):
        return subprocess.run([sys.executable, os.path.join(self.root, "bin", "cve_check.py"), os.path.join(self.cdir, "cves.txt")] + list(extra),
                              capture_output=True, text=True, env=dict(os.environ, **(env or {})))

    def latest(self):
        d = os.path.join(self.root, "results", "cve-check", "cust", "latest")
        with open(os.path.join(d, "report.tsv"), encoding="utf-8") as f:
            rows = [l.rstrip("\n").split("\t") for l in f]
        with open(os.path.join(d, "report.md"), encoding="utf-8") as f:
            md = f.read()
        return rows[0], {r[0]: r for r in rows[1:]}, md

    def test_compare(self):
        p = self.run_it("--repo", "pd", "--branch", "cust", "--base", "master")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        head, rows, md = self.latest()
        self.assertEqual(head[:5], ["CVE", "结论", "涉及的仓库", "客户分支中", "master 中"])
        self.assertEqual({k: v[1] for k, v in rows.items()}, {
            "CVE-2026-0001": "master已解决-分支未解决", "CVE-2026-0002": "都未解决", "CVE-2026-0003": "master未解决-分支已解决",
            "CVE-2026-0004": "都已解决", "CVE-2026-0005": "排除", "CVE-2026-0009": "都已解决",   # 0009 只在 tests/ 下，被排除
            "CVE-2026-0008": "都已解决"})
        self.assertEqual(rows["CVE-2026-0001"][2], "pd")
        self.assertEqual(rows["CVE-2026-0001"][3], "pd: golang.org/x/net 0.20.0")
        self.assertEqual(rows["CVE-2026-0001"][5], "0.30.0")
        s1 = md[md.index("## 1."):md.index("## 2.")]
        self.assertIn("| pd | golang.org/x/net | Go | 0.20.0（受影响） | 0.31.0 | 0.30.0 |", s1)   # master 的版本也列出来
        self.assertIn("按依赖包合并", s1)
        s3 = md[md.index("## 3."):md.index("## 4.")]
        self.assertIn("| pd | golang.org/x/text | Go | 0.21.0 | 0.10.0（受影响） |", s3)
        self.assertIn("1 行不是 CVE/GHSA/GO 编号", md)
        self.assertIn("已确认误报", md)
        self.assertIn("已忽略的配置行：components", md)
        # 临时 worktree、锁都清掉了；不碰 run.sh 用的 refs/remotes/origin/*
        self.assertFalse(os.path.exists(os.path.join(self.root, "state", "cve_check")))
        self.assertFalse(os.path.exists(os.path.join(self.root, "state", "run.lock")))
        refs = subprocess.run(["git", "-C", os.path.join(self.root, "repos", os.listdir(os.path.join(self.root, "repos"))[0]),
                               "for-each-ref", "--format=%(refname)"], capture_output=True, text=True).stdout.split()
        self.assertEqual(sorted(refs), ["refs/cve-check/cust", "refs/cve-check/master"])

    def test_single_branch(self):
        p = self.run_it("--repo", "pd", "--branch", "cust")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        head, rows, md = self.latest()
        self.assertNotIn("master 中", head)
        self.assertEqual({k: v[1] for k, v in rows.items() if v[1] != "排除"}, {
            "CVE-2026-0001": "分支未解决", "CVE-2026-0002": "分支未解决", "CVE-2026-0003": "分支已解决",
            "CVE-2026-0004": "分支已解决", "CVE-2026-0009": "分支已解决", "CVE-2026-0008": "分支已解决"})

    def test_config_targets_and_url(self):
        """配置里的 target 行；直接写 URL 时用 branches.conf 里同 URL 的名称；--all-packages 不支持时退回"""
        w(self.conf, "target %s cust master\nexclude CVE-2026-0005\n" % self.origin)
        p = self.run_it(env={"STUB_NO_ALL": "1"})
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        _, rows, md = self.latest()
        self.assertEqual(rows["CVE-2026-0001"][1], "master已解决-分支未解决")
        self.assertIn("| pd | golang.org/x/net | Go | 0.20.0（受影响） | 无漏洞（版本未知） |", md)

    def test_same_branch_target(self):
        """没写 master 分支的 target（如 tidb-operator）：两边都用这个分支，只扫一次"""
        w(self.conf, "target pd cust master\ntarget %s master\nexclude CVE-2026-0005\n" % self.origin)
        p = self.run_it()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        _, rows, md = self.latest()
        self.assertEqual(rows["CVE-2026-0001"][1], "master已解决-分支未解决")
        # 0003：pd 这一行 master 有、客户分支没有；pd(master) 这一行两边是同一个分支，算都未解决。按仓库分别归类，两类都出现
        self.assertEqual(rows["CVE-2026-0003"][1], "都未解决 / master未解决-分支已解决")
        self.assertEqual(rows["CVE-2026-0003"][2], "pd: master未解决-分支已解决; pd(master): 都未解决")
        s2, s3 = md[md.index("## 2."):md.index("## 3.")], md[md.index("## 3."):md.index("## 4.")]
        self.assertIn("| pd(master) | golang.org/x/text |", s2)
        self.assertNotIn("| pd | golang.org/x/text |", s2)
        self.assertIn("| pd | golang.org/x/text |", s3)
        self.assertIn("| pd(master) | 客户分支 = master | master |", md)
        self.assertIn("| pd(master) | golang.org/x/text | Go | 0.10.0（受影响） | 同一分支 |", md)
        self.assertEqual(len(os.listdir(os.path.join(self.root, "results", "cve-check", "cust", "latest", "scans", "pd"))), 2)

    def test_per_repo_classification(self):
        """同一个 CVE：pd 的 master 已修复，另一个只有一个分支的仓库还没修 -> pd 那一行仍然是 master已解决-分支未解决"""
        w(self.conf, "target pd cust master\ntarget %s cust\n" % self.origin)
        p = self.run_it()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        _, rows, md = self.latest()
        self.assertEqual(rows["CVE-2026-0001"][1], "master已解决-分支未解决 / 都未解决")
        s1, s2 = md[md.index("## 1."):md.index("## 2.")], md[md.index("## 2."):md.index("## 3.")]
        self.assertIn("| pd | golang.org/x/net | Go | 0.20.0（受影响） | 0.31.0 |", s1)
        self.assertIn("| pd(cust) | golang.org/x/net | Go | 0.20.0（受影响） | 同一分支 |", s2)
        self.assertNotIn("| pd | golang.org/x/net |", s2)

    def test_missing_branch_fails(self):
        p = self.run_it("--repo", "pd", "--branch", "cust", "--base", "nope")
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        _, rows, md = self.latest()
        self.assertIn("以下分支扫描失败", md)
        self.assertEqual(rows["CVE-2026-0001"][1], "master已解决-分支未解决")   # 失败的分支不算

    def test_lock_and_retention(self):
        os.makedirs(os.path.join(self.root, "state", "run.lock"))
        w(os.path.join(self.root, "state", "run.lock", "pid"), str(os.getpid()))
        self.assertEqual(self.run_it("--repo", "pd", "--branch", "cust").returncode, 3)
        shutil.rmtree(os.path.join(self.root, "state", "run.lock"))
        base = os.path.join(self.root, "results", "cve-check", "cust")
        for d in ("2026-01-01_000000", "2026-01-02_000000"):
            os.makedirs(os.path.join(base, d))
        out = os.path.join(self.t, "copy", "r.md")
        self.assertEqual(self.run_it("--repo", "pd", "--branch", "cust", "--out", out).returncode, 0)
        runs = sorted(x for x in os.listdir(base) if x != "latest")
        self.assertEqual(len(runs), 2)                          # RETENTION=2
        self.assertNotIn("2026-01-01_000000", runs)
        self.assertTrue(os.path.isfile(out) and os.path.isfile(os.path.join(self.t, "copy", "r.tsv")))

    def test_bad_args(self):
        self.assertEqual(self.run_it("--branch", "cust").returncode, 2)
        self.assertEqual(self.run_it().returncode, 2)            # 配置里没有 target，也没给 --repo
        self.assertEqual(self.run_it("--repo", "pd", "--branch", "cust", "--config", "/nope").returncode, 2)
        self.assertEqual(self.run_it("--repo", "nope", "--branch", "x").returncode, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""cve_check.py：假 results 目录 + 假配置，检查六种归类、组件过滤、排除和输出文件。"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)


def w(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False))


def img_issue(pkg, ver, vid, fix, status, eco="Go"):
    return {"eco": eco, "package": pkg, "installed": ver, "id": vid, "severity": "HIGH", "fix_to": fix,
            "status": status, "src_version": ver, "targets": ["x"]}


def br_issue(pkg, ver, vid, fix, aliases=()):
    return {"ecosystem": "Go", "package": pkg, "version": ver, "id": vid, "ids": [vid] + list(aliases),
            "cves": [x for x in [vid] + list(aliases) if x.startswith("CVE-")], "severity": "HIGH", "fix": fix}


class CveCheck(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        r = self.root = os.path.join(self.t, "root")
        shutil.copytree(os.path.join(SRC, "bin"), os.path.join(r, "bin"))
        w(os.path.join(r, "config", "images.conf"), "pd docker.io/pingcap/pd:v1 pd\n")
        w(os.path.join(r, "config", "builds.conf"), "dash dash 1 ./cmd/d\n")
        w(os.path.join(r, "config", "branches.conf"), "pd https://x/pd.git rel-1\ndash https://x/d.git rel-2\nlib https://x/l.git main\n")
        res = os.path.join(r, "results")
        old, new = "2026-11-01_000000", "2026-11-10_000000"
        # 镜像 pd：旧运行有 CVE-2026-0005（后来修了）和 OS 包 CVE-2026-0007；最新有 0001（源码已修复）和 OS 包 0006
        w(os.path.join(res, "images", "pd", old, "report.json"), {"meta": {}, "issues": [
            img_issue("golang.org/x/net", "0.1.0", "CVE-2026-0005", "0.2.0", "源码未修复"),
            img_issue("openssl", "3.0", "CVE-2026-0007", "3.1", "需重建镜像(OS包)", eco="OS(rocky)")]})
        w(os.path.join(res, "images", "pd", new, "report.json"), {"meta": {"image": "docker.io/pingcap/pd:v1", "scanned_at": "2026-11-10T00:00:00"}, "issues": [
            img_issue("golang.org/x/net", "0.1.0", "CVE-2026-0001", "0.3.0", "源码已修复(待发镜像)"),
            img_issue("openssl", "3.0", "CVE-2026-0006", "3.1", "需重建镜像(OS包)", eco="OS(rocky)")]})
        os.symlink(new, os.path.join(res, "images", "pd", "latest"))
        # 源码构建 dash：0001 和 0002
        w(os.path.join(res, "builds", "dash", new, "report.json"), {"meta": {"source": "dash", "commit": "abc"}, "issues": [
            img_issue("golang.org/x/net", "0.0.9", "CVE-2026-0001", "0.3.0", "源码未修复"),
            img_issue("golang.org/x/crypto", "0.4.0", "CVE-2026-0002", "0.5.0", "源码未修复")]})
        os.symlink(new, os.path.join(res, "builds", "dash", "latest"))
        # 分支 pd：0003 以 GHSA 为主编号、CVE 是别名
        w(os.path.join(res, "pd", "rel-1", new, "report.json"), {"meta": {"branch": "rel-1"}, "issues": [
            br_issue("go.etcd.io/etcd", "3.5.15", "GHSA-aaaa-bbbb-cccc", "3.5.33", ["CVE-2026-0003"])]})
        os.symlink(new, os.path.join(res, "pd", "rel-1", "latest"))
        # 分支 lib（配置里不选）：0004
        w(os.path.join(res, "lib", "main", new, "report.json"), {"meta": {}, "issues": [br_issue("x/y", "1.0", "CVE-2026-0004", "1.1")]})
        os.symlink(new, os.path.join(res, "lib", "main", "latest"))
        self.cdir = os.path.join(self.t, "cust")
        w(os.path.join(self.cdir, "cves.txt"), "# 注释\nCVE-2026-0001\ncve-2026-0002  小写也行\nCVE-2026-0003\nCVE-2026-0004\n"
          "CVE-2026-0005\nCVE-2026-0006\nCVE-2026-0007\nCVE-2026-0008\nCVE-2026-0009\n不是编号\nCVE-2026-0001\n")
        w(os.path.join(self.cdir, "cve_check.conf"), "components pd dash\nexclude CVE-2026-0009 已确认误报\n")

    def tearDown(self):
        shutil.rmtree(self.t)

    def run_it(self, *extra):
        p = subprocess.run([sys.executable, os.path.join(self.root, "bin", "cve_check.py"), os.path.join(self.cdir, "cves.txt")] + list(extra),
                           capture_output=True, text=True)
        return p

    def test_classify(self):
        p = self.run_it()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        out = os.path.join(self.root, "results", "cve-check-cust")
        rows = {l.split("\t")[0]: l.rstrip("\n").split("\t") for l in open(out + ".tsv", encoding="utf-8").readlines()[1:]}
        cat = {k: v[1] for k, v in rows.items()}
        self.assertEqual(cat, {
            "CVE-2026-0001": "未解决-交付物", "CVE-2026-0002": "未解决-交付物", "CVE-2026-0003": "未解决-仅分支",
            "CVE-2026-0004": "从未扫到",      # 只在没选的组件 lib 里
            "CVE-2026-0005": "已解决", "CVE-2026-0006": "仅OS包", "CVE-2026-0007": "仅OS包",
            "CVE-2026-0008": "从未扫到", "CVE-2026-0009": "排除"})
        self.assertEqual(len(rows), 9)   # 重复的编号只算一次
        self.assertEqual(rows["CVE-2026-0001"][4], "0.3.0")
        md = open(out + ".md", encoding="utf-8").read()
        self.assertIn("1 行不是 CVE/GHSA/GO 编号", md)
        self.assertIn("源码已修复（0.1.0），发新镜像", md)   # 镜像：源码已修复 -> 发新镜像
        self.assertIn("**dash**（源码构建）", md)
        self.assertIn("已确认误报", md)
        self.assertIn("go.etcd.io/etcd", md[md.index("## 2."):md.index("## 3.")])
        self.assertNotIn("openssl", md)                      # OS 包不出现在任何表里

    def test_branch_only_component_listed_in_section1(self):
        """只有分支结果的组件（lib）：CVE 因别的组件镜像命中归为交付物时，lib 的分支命中也要在第 1 节列出。"""
        res = os.path.join(self.root, "results")
        w(os.path.join(res, "lib", "main", "2026-11-10_000000", "report.json"), {"meta": {}, "issues": [
            br_issue("golang.org/x/net", "0.0.5", "CVE-2026-0001", "0.3.0"), br_issue("x/y", "1.0", "CVE-2026-0004", "1.1")]})
        w(os.path.join(self.cdir, "cve_check.conf"), "components pd dash lib\n")
        p = self.run_it()
        self.assertEqual(p.returncode, 0, p.stderr)
        md = open(os.path.join(res, "cve-check-cust.md"), encoding="utf-8").read()
        s1 = md[md.index("## 1."):md.index("## 2.")]
        self.assertIn("**lib**（分支）", s1)
        self.assertIn("升级依赖（没扫镜像，按分支源码）", s1)
        self.assertIn("lib 0.0.5", s1)                         # 1.2 按依赖包合并里也有
        self.assertNotIn("**pd**（分支）", s1)                 # pd 有镜像，它的分支命中不进第 1 节

    def test_unknown_component(self):
        w(os.path.join(self.cdir, "cve_check.conf"), "components pd nope\n")
        p = self.run_it()
        self.assertEqual(p.returncode, 2)
        self.assertIn("nope", p.stderr)

    def test_no_config_means_all(self):
        os.remove(os.path.join(self.cdir, "cve_check.conf"))
        p = self.run_it("--out", os.path.join(self.t, "r.md"))
        self.assertEqual(p.returncode, 0, p.stderr)
        cat = {l.split("\t")[0]: l.split("\t")[1] for l in open(os.path.join(self.t, "r.tsv"), encoding="utf-8").readlines()[1:]}
        self.assertEqual(cat["CVE-2026-0004"], "未解决-仅分支")   # 没配置时 lib 也算
        self.assertEqual(cat["CVE-2026-0009"], "从未扫到")


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""sca.py 的单元测试：python3 tests/test_sca.py"""
import json, os, shutil, subprocess, sys, tempfile, unittest
sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "bin"))
import sca  # noqa: E402

FX = os.path.join(HERE, "fixtures")
SCA = os.path.join(HERE, "..", "bin", "sca.py")


def run(*args):
    p = subprocess.run([sys.executable, SCA] + list(args), capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


class Basics(unittest.TestCase):
    def test_vkey_order(self):
        self.assertLess(sca.vkey("0.9.0"), sca.vkey("0.17.0"))
        self.assertLess(sca.vkey("v1.2.3-rc1"), sca.vkey("1.2.3"))
        self.assertLess(sca.vkey("go1.21.0"), sca.vkey("1.21.4"))
        self.assertLess(sca.vkey("0.0.0-20190620200207-3b0461eec859"), sca.vkey("0.1.0"))

    def test_cvss3(self):
        self.assertEqual(sca.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(sca.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"), 7.5)
        self.assertEqual(sca.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertEqual(sca.cvss3_score("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"), 6.2)
        self.assertIsNone(sca.cvss3_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"))


class SafeFix(unittest.TestCase):
    """CVE 有多段受影响区间时（grpc CVE-2026-84445：<1.82.2 和 [1.83.0, 1.83.2)），合并建议版本不能落在另一段里"""
    V1 = {"id": "GO-A", "affected": [{"package": {"name": "google.golang.org/grpc"},
          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.83.1"}]}]}]}
    V2 = {"id": "GO-B", "affected": [{"package": {"name": "google.golang.org/grpc"},
          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.82.2"}, {"introduced": "1.83.0"},
                                                   {"fixed": "1.83.2"}, {"introduced": "1.84.0-dev"},
                                                   {"fixed": "1.84.0-dev.0.20260825144003-d5a41119e0e3"}]}]}]}

    def iss(self, v, cur):
        fx, _ = sca.fix_version([v], "Go", "google.golang.org/grpc", cur)
        return {"fix": fx, "ranges": sca.affected_ranges([v], "google.golang.org/grpc")}

    def test_multi_range(self):
        for cur in ("1.79.3", "1.82.1", "1.83.1"):
            got = sca.safe_fix([self.iss(self.V1, cur), self.iss(self.V2, cur)] if cur != "1.83.1" else [self.iss(self.V2, cur)])
            self.assertEqual(got, "1.83.2", cur)

    def test_single_and_legacy(self):
        self.assertEqual(sca.safe_fix([self.iss(self.V2, "1.79.3")]), "1.82.2")
        self.assertEqual(sca.safe_fix([{"fix": "1.2.0"}, {"fix": "1.10.0"}]), "1.10.0")   # 旧数据没有 ranges：取最高
        self.assertIsNone(sca.safe_fix([{"fix": None}]))


class Report(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.t, "gov"))
        shutil.copy(os.path.join(FX, "govulncheck_sample.json"), os.path.join(self.t, "gov", "root.json"))
        with open(os.path.join(self.t, "meta.json"), "w") as f:
            json.dump({"target": "demo", "branch": "rel-1", "commit": "abc"}, f)

    def tearDown(self):
        shutil.rmtree(self.t)

    def report(self, out, kev=True, gov=True, osv="osv_sample.json"):
        os.makedirs(out, exist_ok=True)
        rc, so, se = run("report", "--osv", os.path.join(FX, osv),
                         "--govuln-dir", os.path.join(self.t, "gov") if gov else os.path.join(self.t, "none"),
                         "--kev", os.path.join(FX, "kev_sample.json") if kev else "",
                         "--exclude", r"(^|/)(node_modules|testdata)(/|$)", "--include-dev", "0",
                         "--worktree", "/WT", "--meta", os.path.join(self.t, "meta.json"), "--out", out)
        self.assertEqual(rc, 0, se)
        with open(os.path.join(out, "report.json")) as f:
            return json.load(f)

    def test_aggregation(self):
        r = self.report(os.path.join(self.t, "o1"))
        rows = {p["package"]: p for p in r["packages"]}
        self.assertEqual(set(rows), {"golang.org/x/net", "stdlib", "time"})   # lodash 被排除
        net = rows["golang.org/x/net"]
        self.assertEqual(net["fix_to"], "0.17.0")        # 0.17.0 与 0.7.0 取最高
        self.assertEqual(net["issue_count"], 2)
        self.assertEqual(net["max_cvss"], 7.5)
        self.assertTrue(net["kev"]); self.assertEqual(net["kev_cves"], ["CVE-2023-44487"])
        self.assertEqual(net["reach"], "called")
        std = rows["stdlib"]
        self.assertEqual(std["fix_to"], "1.21.4")        # 1.20.11 低于当前版本，不应选
        self.assertEqual(std["severity"], "HIGH")        # max_severity=0 -> 回退到 database_specific
        self.assertEqual(std["reach"], "imported")       # stdlib 版本不同也能匹配
        t = rows["time"]
        self.assertEqual(t["reach"], "n/a"); self.assertEqual(t["max_cvss"], 6.2)   # 由向量算出
        self.assertEqual(r["packages"][0]["package"], "golang.org/x/net")            # KEV 排最前
        tsv = open(os.path.join(self.t, "o1", "report.tsv")).read().splitlines()
        self.assertIn("golang.org/x/net\tGo\t0.10.0\t0.17.0\t2\t7.5\tHIGH\tYES\tcalled", tsv)

    def test_without_govulncheck_or_kev(self):
        r = self.report(os.path.join(self.t, "o2"), kev=False, gov=False)
        rows = {p["package"]: p for p in r["packages"]}
        self.assertEqual(rows["golang.org/x/net"]["reach"], "unknown")
        self.assertIsNone(rows["golang.org/x/net"]["kev"])


class GoOfficial(unittest.TestCase):
    """summary 第 0 节：近 N 天的 golang.org/x/* 和 stdlib 漏洞，按公布日期倒序；旧 report.json 无 published 时从 osv.json 补。"""
    def test_section0(self):
        import datetime as d
        t = tempfile.mkdtemp()
        try:
            osv = json.load(open(os.path.join(FX, "osv_sample.json")))
            today = d.date.today()
            recent = (today - d.timedelta(days=5)).isoformat() + "T00:00:00Z"
            older = (today - d.timedelta(days=20)).isoformat() + "T00:00:00Z"
            stale = (today - d.timedelta(days=400)).isoformat() + "T00:00:00Z"
            seen = []
            for r in osv["results"]:
                for pe in r["packages"]:
                    for v in pe.get("vulnerabilities") or []:
                        n = pe["package"]["name"]
                        if n == "golang.org/x/net":
                            v["published"] = recent if not seen else stale
                            seen.append(v["id"])
                        elif n == "stdlib":
                            v["published"] = older
                        else:
                            v["published"] = recent      # 非 Go 官方包，不应出现
            run_dir = os.path.join(t, "results", "demo", "rel-1", "R1")
            os.makedirs(run_dir)
            json.dump(osv, open(os.path.join(run_dir, "osv.json"), "w"))
            meta = os.path.join(t, "meta.json"); json.dump({"target": "demo", "branch": "rel-1"}, open(meta, "w"))
            rc, so, se = run("report", "--osv", os.path.join(run_dir, "osv.json"), "--govuln-dir", os.path.join(t, "none"),
                             "--kev", "", "--exclude", "", "--include-dev", "0", "--worktree", "/WT",
                             "--meta", meta, "--out", run_dir)
            self.assertEqual(rc, 0, se)
            rj = os.path.join(run_dir, "report.json")
            # 模拟旧格式：去掉 published，验证从 osv.json 回退
            rep = json.load(open(rj))
            self.assertTrue(any(i.get("published") for i in rep["issues"]))
            for i in rep["issues"]:
                i.pop("published", None)
            json.dump(rep, open(rj, "w"))
            os.symlink("R1", os.path.join(t, "results", "demo", "rel-1", "latest"))
            conf = os.path.join(t, "branches.conf"); open(conf, "w").write("demo file:///x rel-1\n")
            tg = os.path.join(t, "targets.tsv"); open(tg, "w").write("demo\trel-1\tOK\n")
            out = os.path.join(t, "summary.md")
            rc, so, se = run("summary", "--conf", conf, "--results", os.path.join(t, "results"), "--targets", tg,
                             "--run-id", "X", "--go-days", "90", "--out", out)
            self.assertEqual(rc, 0, se)
            md = open(out, encoding="utf-8").read()
            sec0 = md.split("## 0.")[1].split("## 1.")[0]
            lines = [l for l in sec0.splitlines() if l.startswith("| 20")]
            self.assertEqual([l.split(" | ")[2] for l in lines], ["golang.org/x/net", "stdlib"])   # 倒序，旧的被过滤
            self.assertIn("demo 0.10.0", lines[0])
            self.assertNotIn("| time |", sec0)
            self.assertLess(md.index("## 0."), md.index("## 1. 总览"))
        finally:
            shutil.rmtree(t)


class Validate(unittest.TestCase):
    def test_validate(self):
        t = tempfile.mkdtemp()
        try:
            bad = os.path.join(t, "bad.json")
            with open(bad, "w") as f: f.write("not json")
            self.assertEqual(run("validate", "--kind", "osv", bad)[0], 1)
            ok = os.path.join(t, "ok.json")
            with open(ok, "w") as f: f.write('{"results": null}')
            self.assertEqual(run("validate", "--kind", "osv", ok)[0], 0)
            self.assertEqual(run("validate", "--kind", "kev", ok)[0], 1)
            self.assertEqual(run("validate", "--kind", "kev", os.path.join(FX, "kev_sample.json"))[0], 0)
        finally:
            shutil.rmtree(t)


if __name__ == "__main__":
    unittest.main(verbosity=1)

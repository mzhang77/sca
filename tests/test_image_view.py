#!/usr/bin/env python3
"""image_view.py / run.sh 第 2 步的测试：python3 tests/test_image_view.py（不联网，用桩 trivy）"""
import json, os, shutil, subprocess, sys, tempfile, unittest
sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(SRC, "bin"))
import image_view as iv  # noqa: E402

FX = os.path.join(HERE, "fixtures", "trivy_sample.json")

PD_GOMOD = """module github.com/tikv/pd

go 1.25

toolchain go1.27.3

require (
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/crypto v0.58.0
	google.golang.org/grpc v1.79.3
	github.com/aws/aws-sdk-go v1.55.7
	github.com/pingcap/kvproto v0.0.0-20261001-abcdef
)

replace github.com/pingcap/kvproto => github.com/pingcap/kvproto v0.0.0-20261020-123456
replace github.com/local/thing => ../thing
"""
TOOLS_GOMOD = "module github.com/tikv/pd/tools\n\ngo 1.27.3\n\nrequire golang.org/x/net v0.55.0\n"


def make_wt(root, tools=True):
    wt = os.path.join(root, "wt")
    os.makedirs(os.path.join(wt, "tools"))
    open(os.path.join(wt, "go.mod"), "w").write(PD_GOMOD)
    if tools:
        open(os.path.join(wt, "tools", "go.mod"), "w").write(TOOLS_GOMOD)
    g = lambda *a: subprocess.run(["git", "-C", wt] + list(a), capture_output=True, check=True,
                                  env=dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t"))
    g("init", "-q"); g("add", "."); g("commit", "-qm", "a")
    first = subprocess.run(["git", "-C", wt, "rev-parse", "--short=7", "HEAD"], capture_output=True, text=True).stdout.strip()
    open(os.path.join(wt, "x"), "w").write("1"); g("add", "."); g("commit", "-qm", "b")
    return wt, first


class Versions(unittest.TestCase):
    def test_is_fixed(self):
        self.assertTrue(iv.is_fixed("0.61.0", ["0.60.0"]))
        self.assertFalse(iv.is_fixed("0.56.0", ["0.60.0"]))
        self.assertTrue(iv.is_fixed("1.27.3", ["1.26.9", "1.27.2"]))
        self.assertTrue(iv.is_fixed("1.26.9", ["1.26.9", "1.27.2"]))
        self.assertFalse(iv.is_fixed("1.26.8", ["1.26.9", "1.27.2"]))
        self.assertFalse(iv.is_fixed("1.25.12", ["1.26.9", "1.27.2"]))
        self.assertTrue(iv.is_fixed("1.28.0", ["1.26.9", "1.27.2"]))
        self.assertTrue(iv.is_fixed("v0.58.1-0.20261009181718-2f1f834330b2", ["0.58.1-0.20261009181718-2f1f834330b2"]))
        self.assertFalse(iv.is_fixed("0.58.0", ["0.58.1-0.20261009181718-2f1f834330b2"]))
        self.assertIsNone(iv.is_fixed("1.0.0", []))

    def test_min_fix(self):
        self.assertEqual(iv.min_fix_for("v1.25.12", ["1.26.9", "1.27.2"]), "1.26.9")
        self.assertEqual(iv.min_fix_for("v1.27.0", ["1.26.9", "1.27.2"]), "1.27.2")
        self.assertEqual(iv.split_fixed("1.26.9, 1.27.2"), ["1.26.9", "1.27.2"])

    def test_gomod(self):
        t = tempfile.mkdtemp()
        p = os.path.join(t, "go.mod"); open(p, "w").write(PD_GOMOD)
        gm = iv.parse_gomod(p)
        self.assertEqual(gm["module"], "github.com/tikv/pd")
        self.assertEqual(iv.go_toolchain_version(gm), ("1.27.3", "toolchain"))
        self.assertEqual(iv.gomod_version(gm, "golang.org/x/net"), "v0.61.0")
        self.assertEqual(iv.gomod_version(gm, "github.com/pingcap/kvproto"), "v0.0.0-20261020-123456")
        self.assertEqual(iv.gomod_version(gm, "github.com/local/thing"), "local")
        self.assertIsNone(iv.gomod_version(gm, "github.com/nope"))
        shutil.rmtree(t)


class Report(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.wt, self.first = make_wt(self.t)
        d = json.load(open(FX))
        d["ArtifactName"] = "docker.io/pingcap/pd:v8.5.7-20261001-%s" % self.first
        self.tv = os.path.join(self.t, "trivy.json"); json.dump(d, open(self.tv, "w"))
        self.meta = os.path.join(self.t, "meta.json")
        json.dump({"name": "pd", "image": d["ArtifactName"], "source": "pd", "branch": "rel",
                   "scanned_at": "2026-11-03T10:00:00-0500", "platform": "linux/amd64"}, open(self.meta, "w"))
        self.kev = os.path.join(self.t, "kev.json")
        json.dump({"vulnerabilities": [{"cveID": "CVE-2026-2222"}]}, open(self.kev, "w"))

    def tearDown(self):
        shutil.rmtree(self.t)

    def run_report(self, wt):
        out = os.path.join(self.t, "out")
        p = subprocess.run([sys.executable, os.path.join(SRC, "bin", "image_view.py"), "report", "--trivy", self.tv,
                            "--worktree", wt, "--meta", self.meta, "--kev", self.kev, "--out", out],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.load(open(os.path.join(out, "report.json"))), p.stdout, out

    def test_statuses(self):
        rep, so, out = self.run_report(self.wt)
        by = {(i["package"], i["id"]): i for i in rep["issues"]}
        net = by[("golang.org/x/net", "CVE-2026-78659")]
        # pd-server 的 go.mod 已是 0.61.0，但 pd-ctl（tools/go.mod）还是 0.55.0 -> 取更需要关注的“未修复”
        self.assertEqual(net["status"], iv.ST_NOT_FIXED)
        self.assertEqual(net["src_from"], "tools/go.mod")
        self.assertEqual(sorted(net["targets"]), ["pd-ctl", "pd-server"])
        self.assertEqual(by[("golang.org/x/crypto", "CVE-2026-56855")]["status"], iv.ST_FIXED)
        self.assertEqual(by[("google.golang.org/grpc", "GHSA-hrxh-6v49-42gf")]["status"], iv.ST_NOT_FIXED)
        self.assertEqual(by[("google.golang.org/grpc", "GHSA-hrxh-6v49-42gf")]["score"], 8.8)
        std = by[("stdlib", "CVE-2026-78660")]
        self.assertEqual((std["status"], std["src_version"], std["fix_to"]), (iv.ST_FIXED, "1.27.3", "1.26.9"))
        self.assertEqual(by[("github.com/old/gone", "CVE-2025-0001")]["status"], iv.ST_REMOVED)
        aws = by[("github.com/aws/aws-sdk-go", "CVE-2026-2222")]
        self.assertEqual(aws["status"], iv.ST_NO_FIX)
        self.assertTrue(aws["kev"] and aws["likely"])
        self.assertEqual(rep["issues"][0]["id"], "CVE-2026-2222")   # KEV 排第一
        ossl = by[("openssl-libs", "CVE-2026-1111")]
        self.assertEqual(ossl["status"], iv.ST_OS)
        self.assertTrue(ossl["recent"])
        self.assertFalse(ossl["likely"])   # OS 包不参与预测
        self.assertFalse(by[("github.com/old/gone", "CVE-2025-0001")]["recent"])
        self.assertEqual(rep["meta"]["relation"], "镜像落后分支 1 个 commit")
        self.assertEqual(len(rep["issues"]), 7)
        self.assertEqual(so.split("\t")[0], "6")   # 统计不含 OS 包
        self.assertEqual((rep["summary"]["os"], rep["summary"]["issues"]), (1, 6))
        md = open(os.path.join(out, "report.md")).read()
        self.assertIn("源码已修复(待发镜像)", md)
        # OS 包只出现在附录
        self.assertEqual(md.count("openssl-libs"), 1)
        self.assertGreater(md.index("openssl-libs"), md.index("## 附录：操作系统包"))

    def test_build_meta(self):
        """源码构建（kind=build）：不按镜像 tag 算落后多少 commit，报告头写构建信息，CGO 平台说明进 notes。"""
        m = json.load(open(self.meta))
        m.update({"kind": "build", "image": "源码构建 pd@abc1234", "commit": "abc1234def", "go_version": "go1.27.3",
                  "cgo": "1", "platform": "darwin/arm64", "build_note": "依赖 CGO，按本机平台 darwin/arm64 编译"})
        json.dump(m, open(self.meta, "w"))
        rep, _, out = self.run_report(self.wt)
        self.assertEqual(rep["meta"]["relation"], "按分支 HEAD 构建")
        self.assertNotIn("image_commit", rep["meta"])
        self.assertTrue(any("darwin/arm64" in n for n in rep["notes"]))
        md = open(os.path.join(out, "report.md")).read()
        self.assertIn("源码构建：从分支 HEAD 编出 Go 二进制", md)
        self.assertIn("go1.27.3", md)
        self.assertNotIn("digest", md)
        # 状态比较和镜像一样
        by = {(i["package"], i["id"]): i for i in rep["issues"]}
        self.assertEqual(by[("golang.org/x/crypto", "CVE-2026-56855")]["status"], iv.ST_FIXED)

    def test_no_worktree(self):
        rep, _, _ = self.run_report("")
        self.assertTrue(any("worktree" in n for n in rep["notes"]))
        st = {i["status"] for i in rep["issues"]}
        self.assertNotIn(iv.ST_FIXED, st)
        self.assertNotIn(iv.ST_NOT_FIXED, st)


class EndToEnd(unittest.TestCase):
    """run.sh --images-only + 桩 trivy：一个成功、一个失败，检查汇总、latest、保留数量和退出码。"""
    def test_run(self):
        t = tempfile.mkdtemp()
        try:
            root = os.path.join(t, "root"); os.makedirs(os.path.join(root, "config"))
            shutil.copytree(os.path.join(SRC, "bin"), os.path.join(root, "bin"))
            stubs = os.path.join(t, "stubs"); os.makedirs(stubs)
            open(os.path.join(stubs, "trivy"), "w").write(
                '#!/bin/sh\n[ "$1" = "--version" ] && { echo "Version: 0.0.stub"; exit 0; }\n'
                'for a in "$@"; do case "$prev" in --output) out="$a";; esac; prev="$a"; last="$a"; done\n'
                'echo "$@" >> "$STUB_ARGS"\n'
                'echo "$DOCKER_CONFIG" >> "$STUB_ARGS.dc"\n'
                'case "$last" in *broken*) echo "FATAL image not found" >&2; exit 1;; esac\n'
                'cp "$STUB_FILE" "$out"\n')
            os.chmod(os.path.join(stubs, "trivy"), 0o755)
            wt, _ = make_wt(t)
            dst = os.path.join(root, "worktrees", "tikv__pd", "rel-1"); os.makedirs(os.path.dirname(dst))
            shutil.move(wt, dst)
            open(os.path.join(root, "config", "branches.conf"), "w").write("pd https://github.com/tikv/pd.git rel-1\n")
            open(os.path.join(root, "config", "images.conf"), "w").write(
                "# c\npd docker.io/pingcap/pd:v8.5.7 pd\nbad docker.io/pingcap/broken:1 pd\n")
            open(os.path.join(root, "config", "settings.env"), "w").write("RETENTION=2\nPREVENT_SLEEP=0\nKEV_URL=\"file://%s\"\n" % os.path.join(SRC, "tests", "fixtures", "kev_sample.json"))
            env = dict(os.environ, PATH=stubs + ":" + os.environ["PATH"], STUB_FILE=FX,
                       STUB_ARGS=os.path.join(t, "args"), SCA_ROOT=root)
            for k in range(3):
                p = subprocess.run(["bash", os.path.join(root, "bin", "run.sh"), "--images-only"], env=env, capture_output=True, text=True)
                if k < 2:
                    subprocess.run(["sleep", "1.1"])
            self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
            summ = open(os.path.join(root, "results", "report-images-latest.md")).read()
            self.assertIn("本次成功", summ)
            self.assertIn("尚无成功结果", summ)
            self.assertIn("客户最可能提", summ)
            self.assertIn("google.golang.org/grpc", summ)
            self.assertLess(summ.index("## 0. Go 官方近期修复"), summ.index("## 1. 总览"))
            # OS 包只在说明之后的附录里出现，不混进 0-5 节
            app = summ.index("## 附录：操作系统包")
            self.assertLess(summ.index("## 6. 说明"), app)
            self.assertNotIn("openssl-libs", summ[:app])
            self.assertIn("openssl-libs", summ[app:])
            pdres = os.path.join(root, "results", "images", "pd")
            dirs = [d for d in os.listdir(pdres) if d != "latest"]
            self.assertEqual(len(dirs), 2)   # RETENTION=2
            self.assertTrue(os.path.isfile(os.path.join(pdres, "latest", "report.md")))
            args = open(os.path.join(t, "args")).read().splitlines()
            self.assertIn("--platform linux/amd64", args[0])
            self.assertNotIn("--skip-db-update", args[0])   # 第一个镜像更新漏洞库
            self.assertTrue(open(os.path.join(t, "args.dc")).read().strip().endswith("state/docker-anon"))
            alerts = open(os.path.join(root, "logs", "alerts.log")).read()
            self.assertIn("[bad] trivy failed", alerts)
        finally:
            shutil.rmtree(t)


if __name__ == "__main__":
    unittest.main(verbosity=2)

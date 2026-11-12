#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cve_check.py - 拿客户提交的 CVE 清单，现场扫描指定分支的源码依赖，报告每个 CVE 在客户分支 / master 上是否已解决（仅标准库，Python 3.8+）。

只扫分支源码（OSV-Scanner，和 bin/run.sh 第 1 步同样的扫描和排除规则），不扫镜像，不做源码构建。
每次运行都重新 fetch、重新扫描，不读 results/ 里以前的任何结果。

用法:
  bin/cve_check.py CVE清单 --repo 名称或仓库URL --branch 客户分支 [--base master]
  bin/cve_check.py CVE清单                         # 目标写在配置文件的 target 行里（可以多个仓库）
  选项: [--config 配置文件] [--out 报告.md]

  --repo    branches.conf 里的名称（用它的仓库 URL），或者直接写仓库 URL
  --branch  客户分支
  --base    对照的分支（一般是 master / main）。给了就做两个分支的对比，不给就只报告客户分支

CVE 清单：纯文本，一行一个编号（CVE-/GHSA-/GO- 都可以）；# 开头的行和空行忽略，一行里第一个空白之后的内容当注释。
配置文件：不指定时依次找 CVE 清单同目录的 cve_check.conf、config/cve_check.conf（每个客户一份，放在客户目录里）。
  target   名称或仓库URL  客户分支  [master分支]   要扫的仓库和分支，可以写多行（命令行给了 --repo 时忽略）
           有的仓库客户分支和 master 是同一个（如 tidb-operator），不写 master 分支即可：这一行两边都用这个分支
  exclude  CVE编号 [原因]                           不参与判断的 CVE（已确认误报、不适用等），报告里单独列出原因
  （旧配置里的 components 行不再使用，会被忽略）

结论（每个 CVE 按 仓库 + 依赖包 分别判断，同一个 CVE 在不同仓库可以结论不同，会出现在几个类别里）：
  两个分支（至少一行 target 写了 master 分支）：master 已解决、分支未解决 / 都未解决 / master 未解决、分支已解决 / 都已解决
  一个分支（都没写 master 分支）：分支未解决 / 分支已解决
  “master 已解决” = master 上这个包已经不受影响；“都已解决” = 所有仓库的两个分支都没扫到（包括从来没受影响的）。另有“排除”。

输出：results/cve-check/<清单名>/<运行ID>/ 下的 report.md、report.tsv（逐个 CVE），以及每个分支的扫描原始结果；
     latest 指向最近一次。--out 另外复制一份报告（同名 .tsv 也复制）。保留最近 RETENTION 次。
退出码：0 = 成功；1 = 有分支扫描失败（报告里标出，结论不含失败的分支）；2 = 参数或前置条件问题；3 = bin/run.sh 或另一个本脚本正在运行
"""
import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sca import vkey, norm_ver, load_json, SEV_RANK  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ID_RE = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA(-[0-9a-z]{4}){3}|GO-\d{4}-\d{4,})$", re.I)
RUN_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{6}$")

# 两个分支
C_BACKPORT = "master已解决-分支未解决"
C_BOTH = "都未解决"
C_BASE_ONLY = "master未解决-分支已解决"
C_NONE = "都已解决"
# 一个分支
C_OPEN = "分支未解决"
C_OK = "分支已解决"
C_EXCL = "排除"

SETTINGS = ("PATH", "OSV_SCANNER", "OSV_TIMEOUT", "CLONE_TIMEOUT", "FETCH_TIMEOUT", "EXCLUDE_PATH_REGEX",
            "INCLUDE_DEV_DEPS", "RETENTION", "REPOS_DIR", "STATE_DIR", "RESULTS_DIR", "LOG_DIR")

LOG_FH = None


def log(msg):
    line = "%s %s" % (dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line, flush=True)
    if LOG_FH:
        LOG_FH.write(line + "\n")
        LOG_FH.flush()


# --------------------------------------------------------------------------- 输入
class UsageError(Exception):
    pass


def norm_id(s):
    s = s.strip()
    if s.upper().startswith(("CVE-", "GO-")):
        return s.upper()
    if s.upper().startswith("GHSA-"):
        return "GHSA-" + s[5:].lower()
    return s


def read_cve_list(path):
    ids, bad = [], []
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()
    for n, line in enumerate(lines, 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        tok = s.split()[0].strip(",;")
        if ID_RE.match(tok):
            i = norm_id(tok)
            if i not in ids:
                ids.append(i)
        else:
            bad.append("%d: %s" % (n, s[:60]))
    return ids, bad


def read_config(path):
    """返回 (targets [(repo, branch, base|None)], excl {cve: 原因}, 忽略的旧配置项)"""
    targets, excl, ignored = [], {}, []
    if not path:
        return targets, excl, ignored
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()
    for n, line in enumerate(lines, 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        p = s.split(None, 1)
        key, rest = p[0].lower(), (p[1] if len(p) > 1 else "")
        if key == "target":
            q = rest.split()
            if len(q) not in (2, 3):
                raise UsageError("config %s:%d: target 的写法是：target 名称或仓库URL 客户分支 [master分支]" % (path, n))
            targets.append((q[0], q[1], q[2] if len(q) == 3 else None))
        elif key == "exclude":
            q = rest.split(None, 1)
            if q and ID_RE.match(q[0]):
                excl[norm_id(q[0])] = q[1].strip() if len(q) > 1 else ""
            else:
                raise UsageError("config %s:%d: exclude 后面要写 CVE 编号" % (path, n))
        elif key == "components":
            if "components" not in ignored:
                ignored.append("components")
        else:
            raise UsageError("config %s:%d: 不认识的配置项 '%s'（只有 target / exclude）" % (path, n, p[0]))
    return targets, excl, ignored


def branches_conf():
    """{名称: URL}"""
    out = {}
    p = os.path.join(ROOT, "config", "branches.conf")
    if os.path.isfile(p):
        with open(p, encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    q = s.split()
                    if len(q) >= 2:
                        out[q[0]] = q[1]
    return out


def looks_like_url(s):
    return "://" in s or s.startswith("git@") or s.startswith("/") or s.startswith("file:")


def resolve_repo(r, known):
    """名称或 URL -> (显示名, URL)"""
    if r in known:
        return r, known[r]
    if looks_like_url(r):
        name = re.sub(r"\.git$", "", r.rstrip("/").split("/")[-1].split(":")[-1])
        for k, u in known.items():          # URL 和 branches.conf 里的一样时用那里的名称
            if u.rstrip("/") == r.rstrip("/"):
                name = k
        return name, r
    raise UsageError("不认识的仓库 '%s'：不是 config/branches.conf 里的名称，也不像仓库 URL" % r)


def slugify(s):
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)


def repo_id(url):
    """https://github.com/tikv/pd.git -> tikv__pd（和 lib.sh 的 repo_id_from_url 一致）"""
    s = re.sub(r"^(https?://[^/]+/|git@[^:]+:)", "", url)
    s = re.sub(r"\.git$", "", s)
    s = s.replace("/", "__")
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)


# --------------------------------------------------------------------------- 设置（复用 lib.sh：settings.env、REQUIRED_MOUNT、EXTRA_PATH）
def load_settings():
    exports = " ".join(SETTINGS)
    script = ('. "$SCA_ROOT/bin/lib.sh" || exit $?; export %s; '
              'exec "$1" -c "import json, os; print(json.dumps({k: os.environ.get(k, \'\') for k in \'%s\'.split()}))"'
              % (exports, exports))
    env = dict(os.environ, SCA_ROOT=ROOT)
    p = subprocess.run(["bash", "-c", script, "bash", sys.executable], env=env, stdout=subprocess.PIPE, universal_newlines=True)
    if p.returncode != 0:
        raise SystemExit(p.returncode)
    s = json.loads(p.stdout.strip().splitlines()[-1])
    for k in ("OSV_TIMEOUT", "CLONE_TIMEOUT", "FETCH_TIMEOUT"):
        s[k] = int(s[k])
    try:
        s["RETENTION"] = int(s["RETENTION"])
    except ValueError:
        s["RETENTION"] = 0
    return s


# --------------------------------------------------------------------------- 锁（和 bin/run.sh 共用 state/run.lock）
def take_lock(state_dir):
    lk = os.path.join(state_dir, "run.lock")
    for _ in range(2):
        try:
            os.mkdir(lk)
            with open(os.path.join(lk, "pid"), "w") as f:
                f.write(str(os.getpid()))
            return lk
        except FileExistsError:
            try:
                pid = int(open(os.path.join(lk, "pid")).read().strip())
                os.kill(pid, 0)
                print("bin/run.sh 或另一个 cve_check.py 正在运行（pid %d），退出" % pid, file=sys.stderr)
                return None
            except (OSError, ValueError):
                log("清理残留的锁 %s" % lk)
                shutil.rmtree(lk, ignore_errors=True)
    return None


# --------------------------------------------------------------------------- git / 扫描
class ScanError(Exception):
    pass


def run(cmd, env, timeout, cwd=None, stdout=None, stderr=None):
    try:
        p = subprocess.run(cmd, env=env, timeout=timeout, cwd=cwd, stdout=stdout or subprocess.PIPE,
                           stderr=stderr or subprocess.STDOUT, universal_newlines=True)
        return p.returncode, (p.stdout if stdout is None else "")
    except subprocess.TimeoutExpired:
        return 124, ""
    except FileNotFoundError:
        return 127, "命令不存在: %s" % cmd[0]


class Scanner:
    def __init__(self, s, run_dir, wt_root):
        self.s = s
        self.env = dict(os.environ, PATH=s["PATH"], GIT_TERMINAL_PROMPT="0")
        self.run_dir = run_dir
        self.wt_root = wt_root
        self.gitlog = os.path.join(s["LOG_DIR"], "git-%s.log" % dt.date.today().isoformat())
        self.cache = {}
        self.ex = re.compile(s["EXCLUDE_PATH_REGEX"]) if s["EXCLUDE_PATH_REGEX"] else None
        self.include_dev = s["INCLUDE_DEV_DEPS"] == "1"

    def git(self, args, timeout, what):
        rc, out = run(["git"] + args, self.env, timeout)
        with open(self.gitlog, "a", encoding="utf-8") as f:
            f.write("[cve_check] git %s\n%s" % (" ".join(args), out))
        if rc == 124:
            raise ScanError("%s 超时（%d 秒）" % (what, timeout))
        if rc != 0:
            tail = " ".join(out.strip().splitlines()[-2:])
            raise ScanError("%s 失败（exit %d）：%s（详见 %s）" % (what, rc, tail, self.gitlog))
        return out

    def checkout(self, url, branch):
        """fetch 分支到 bare 仓库（和 run.sh 共用 repos/，只是 git 缓存），建一个临时的 detached worktree。返回 (worktree, commit)。"""
        rid = repo_id(url)
        repo = os.path.join(self.s["REPOS_DIR"], rid + ".git")
        new = not os.path.isdir(repo)
        if new:
            log("  首次使用 %s：创建 bare + blobless 仓库" % url)
            self.git(["init", "--bare", "-q", repo], 60, "git init")
            for a in (["remote", "add", "origin", url], ["config", "core.repositoryformatversion", "1"],
                      ["config", "extensions.partialClone", "origin"], ["config", "remote.origin.promisor", "true"],
                      ["config", "remote.origin.partialclonefilter", "blob:none"]):
                self.git(["-C", repo] + a, 60, "git init")
        else:
            self.git(["-C", repo, "remote", "set-url", "origin", url], 60, "git remote set-url")
        ref = "refs/cve-check/%s" % branch      # 单独的命名空间，不碰 run.sh 用的 refs/remotes/origin/*
        to = self.s["CLONE_TIMEOUT"] if new else self.s["FETCH_TIMEOUT"]
        log("  git fetch %s %s（超时 %d 秒）" % (url, branch, to))
        self.git(["-C", repo, "fetch", "--no-tags", "--refmap=", "--filter=blob:none", "origin", "+refs/heads/%s:%s" % (branch, ref)], to,
                 "git fetch %s（网络/权限问题，或者分支不存在）" % branch)
        sha = self.git(["-C", repo, "rev-parse", "--verify", ref + "^{commit}"], 60, "git rev-parse").strip()
        wt = os.path.join(self.wt_root, rid, slugify(branch))
        os.makedirs(os.path.dirname(wt), exist_ok=True)
        log("  检出 %s @ %s" % (branch, sha[:10]))
        self.git(["-C", repo, "worktree", "add", "--detach", "-q", wt, sha], self.s["CLONE_TIMEOUT"], "git worktree add")
        return repo, wt, sha

    def drop_worktree(self, repo, wt):
        run(["git", "-C", repo, "worktree", "remove", "--force", wt], self.env, 600)
        shutil.rmtree(wt, ignore_errors=True)
        run(["git", "-C", repo, "worktree", "prune"], self.env, 600)

    def osv(self, wt, out):
        base = [self.s["OSV_SCANNER"], "scan", "source", "-r", "--no-ignore"]
        # --all-packages：输出里带上没有漏洞的包，用来显示“另一个分支里这个包是什么版本”。不支持时退回不带它
        for extra in (["--all-packages"], []):
            with open(os.path.join(out, "osv.json"), "w") as fo, open(os.path.join(out, "osv.stderr"), "w") as fe:
                rc, _ = run(base + extra + ["--format", "json", wt], self.env, self.s["OSV_TIMEOUT"], stdout=fo, stderr=fe)
            if rc == 124:
                raise ScanError("osv-scanner 超时（%d 秒）" % self.s["OSV_TIMEOUT"])
            if rc == 127:
                raise ScanError("找不到 osv-scanner（%s），检查 settings.env 的 OSV_SCANNER / EXTRA_PATH" % self.s["OSV_SCANNER"])
            if rc == 128:
                raise ScanError("osv-scanner 在分支里没找到支持的依赖清单（exit 128）")
            ok = rc in (0, 1)
            if ok:
                try:
                    d = load_json(os.path.join(out, "osv.json"))
                    ok = isinstance(d, dict)
                except Exception:
                    ok = False
            if ok:
                return bool(extra)
        err = open(os.path.join(out, "osv.stderr"), encoding="utf-8", errors="replace").read().strip().splitlines()[-3:]
        raise ScanError("osv-scanner 失败（exit %d）：%s" % (rc, " ".join(err)))

    def versions(self, osv_path, wt):
        """{(生态, 包名): {版本}}：按和 report 一样的排除规则，分支里实际用到的版本（含没有漏洞的包）"""
        out = {}
        wt = os.path.abspath(wt).rstrip("/")
        for res in load_json(osv_path).get("results") or []:
            src = (res.get("source") or {}).get("path", "")
            rel = src[len(wt):].lstrip("/") if src.startswith(wt) else src
            if self.ex and self.ex.search(rel):
                continue
            for pe in res.get("packages") or []:
                p = pe.get("package") or {}
                dg = pe.get("dependencyGroups") or pe.get("dependency_groups") or []
                if not self.include_dev and dg and all(str(g).lower().startswith("dev") for g in dg):
                    continue
                out.setdefault((p.get("ecosystem", ""), p.get("name", "")), set()).add(norm_ver(p.get("version", "")))
        return out

    def scan(self, name, url, branch):
        """返回 {"ok", "error", "meta", "hits": {cve: [hit]}, "vers", "all_pkgs"}；同一次运行里同一个仓库+分支只扫一次"""
        key = (url, branch)
        if key in self.cache:
            return self.cache[key]
        out = os.path.join(self.run_dir, "scans", slugify(name), slugify(branch))
        os.makedirs(out, exist_ok=True)
        r = {"ok": False, "error": "", "meta": {"target": name, "repo": url, "branch": branch}, "hits": {}, "vers": {},
             "all_pkgs": False, "dir": out}
        self.cache[key] = r
        log("[%s] %s" % (name, branch))
        repo = wt = None
        try:
            repo, wt, sha = self.checkout(url, branch)
            r["meta"].update(commit=sha, scanned_at=dt.datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z"))
            with open(os.path.join(out, "meta.json"), "w", encoding="utf-8") as f:
                json.dump(r["meta"], f, ensure_ascii=False)
            log("  osv-scanner 扫描（超时 %d 秒）" % self.s["OSV_TIMEOUT"])
            r["all_pkgs"] = self.osv(wt, out)
            r["vers"] = self.versions(os.path.join(out, "osv.json"), wt)
            rc, msg = run([sys.executable, os.path.join(ROOT, "bin", "sca.py"), "report", "--osv", os.path.join(out, "osv.json"),
                           "--exclude", self.s["EXCLUDE_PATH_REGEX"], "--include-dev", self.s["INCLUDE_DEV_DEPS"],
                           "--worktree", wt, "--meta", os.path.join(out, "meta.json"), "--out", out], self.env, 600)
            if rc != 0:
                raise ScanError("生成报告失败：%s" % msg.strip()[-300:])
            rep = load_json(os.path.join(out, "report.json"))
            for i in rep.get("issues", []):
                h = {"pkg": i["package"], "eco": i.get("ecosystem", ""), "ver": norm_ver(i.get("version", "")),
                     "fix": norm_ver(i.get("fix") or ""), "sev": i.get("severity", "UNKNOWN")}
                for x in {norm_id(x) for x in (i.get("ids") or []) + (i.get("cves") or []) + [i.get("id", "")] if x}:
                    r["hits"].setdefault(x, []).append(h)
            r["ok"] = True
            log("  完成：%d 个漏洞" % len(rep.get("issues", [])))
        except ScanError as e:
            r["error"] = str(e)
            log("  [ERROR] %s" % e)
        finally:
            if repo and wt:
                self.drop_worktree(repo, wt)
        return r


# --------------------------------------------------------------------------- 归类
def pkg_cat(t, c, eco, pkg, compare):
    """一个目标里、一个依赖包上这个 CVE 的结论（按包判断：master 上这个包已经不受影响才算 master 已解决）"""
    b = t["br"]["ok"] and any(h["eco"] == eco and h["pkg"] == pkg for h in t["br"]["hits"].get(c, []))
    if not compare:
        return C_OPEN if b else None
    m = t["base"]["ok"] and any(h["eco"] == eco and h["pkg"] == pkg for h in t["base"]["hits"].get(c, []))
    return {(True, False): C_BACKPORT, (True, True): C_BOTH, (False, True): C_BASE_ONLY}.get((b, m))


def pkgs_of(t, c, compare):
    sides = [t["br"]] + ([t["base"]] if compare else [])
    return sorted({(h["eco"], h["pkg"]) for s in sides if s["ok"] for h in s["hits"].get(c, [])})


def classify(ids, excl, targets, compare):
    """每个 CVE 按 目标 + 依赖包 分别判断（同一个 CVE 在不同仓库、不同包上结论可以不同）。
    返回 {cve: {"cats": [出现的结论，按严重顺序], "per": [(目标, 结论)]}}；排除的、哪里都没扫到的 cats 只有一个"""
    order = [C_BACKPORT, C_BOTH, C_BASE_ONLY] if compare else [C_OPEN]
    res = {}
    for c in ids:
        if c in excl:
            res[c] = {"cats": [C_EXCL], "per": []}
            continue
        per = []
        for t in targets:
            for eco, pkg in pkgs_of(t, c, compare):
                k = pkg_cat(t, c, eco, pkg, compare)
                if k and (t["name"], k) not in per:
                    per.append((t["name"], k))
        cats = [k for k in order if any(x[1] == k for x in per)]
        res[c] = {"cats": cats or [C_NONE if compare else C_OK], "per": per}
    return res


def max_ver(vs):
    vs = [v for v in vs if v]
    return max(vs, key=vkey) if vs else ""


def sev_max(a, b):
    return a if SEV_RANK.get(a, 0) >= SEV_RANK.get(b, 0) else b


def side_cell(scan, c, eco, pkg):
    """某个分支里这个包的情况：受影响的版本，或者（没受影响时）实际用的版本"""
    if scan is None:
        return "-"
    if not scan["ok"]:
        return "扫描失败"
    hv = sorted({h["ver"] for h in scan["hits"].get(c, []) if h["eco"] == eco and h["pkg"] == pkg}, key=vkey)
    if hv:
        return "%s（受影响）" % ", ".join(hv)
    vs = sorted(scan["vers"].get((eco, pkg), set()), key=vkey)
    if vs:
        return ", ".join(vs)
    return "无此依赖" if scan["all_pkgs"] else "无漏洞（版本未知）"


def rows_for(cves, targets, compare, cat):
    """结论是 cat 的 (目标, 依赖包)，按 (目标, 生态, 包, 分支格子, master 格子) 合并 CVE -> 行"""
    g = {}
    for c in cves:
        for t in targets:
            sides = [t["br"]] + ([t["base"]] if compare else [])
            hits = [h for s in sides if s["ok"] for h in s["hits"].get(c, [])]
            for eco, pkg in pkgs_of(t, c, compare):
                if pkg_cat(t, c, eco, pkg, compare) != cat:
                    continue
                bc = side_cell(t["br"], c, eco, pkg)
                mc = ("同一分支" if t.get("same") else side_cell(t["base"], c, eco, pkg)) if compare else ""
                k = (t["name"], eco, pkg, bc, mc)
                r = g.setdefault(k, {"target": t["name"], "eco": eco, "pkg": pkg, "br": bc, "base": mc,
                                     "fix": "", "sev": "UNKNOWN", "ids": set()})
                for h in hits:
                    if h["eco"] == eco and h["pkg"] == pkg:
                        r["fix"] = max_ver([r["fix"], h["fix"]])
                        r["sev"] = sev_max(r["sev"], h["sev"])
                r["ids"].add(c)
    order = [t["name"] for t in targets]
    return sorted(g.values(), key=lambda r: (order.index(r["target"]), -SEV_RANK.get(r["sev"], 0), r["pkg"]))


# --------------------------------------------------------------------------- 输出
def md_table(head, rows):
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for r in rows:
        out.append("| " + " | ".join(str(x).replace("|", "\\|").replace("\n", " ") for x in r) + " |")
    return "\n".join(out) + "\n"


def id_key(x):
    return (x[:3], [int(n) if n.isdigit() else n for n in re.split(r"(\d+)", x)])


def ids_cell(ids):
    return ", ".join(sorted(ids, key=id_key))


def rel(p):
    ap = os.path.abspath(p)
    return os.path.relpath(ap, ROOT) if ap.startswith(ROOT + os.sep) else p


def where(c, targets, side):
    xs = []
    for t in targets:
        s = t[side]
        if s and s["ok"]:
            for h in s["hits"].get(c, []):
                x = "%s: %s %s" % (t["name"], h["pkg"], h["ver"])
                if x not in xs:
                    xs.append(x)
    return "; ".join(xs)


def render(a, ids, bad, targets, compare, excl, res, ignored):
    cats = [C_BACKPORT, C_BOTH, C_BASE_ONLY, C_NONE] if compare else [C_OPEN, C_OK]
    cnt = {k: sum(1 for c in ids if k in res[c]["cats"]) for k in cats + [C_EXCL]}
    failed = [(t["name"], s) for t in targets for s in ((t["br"],) if t.get("same") else (t["br"], t["base"])) if s and not s["ok"]]
    L = ["# 客户 CVE 核对：%s\n" % a.title]
    L.append("- 生成时间: %s（本次现场扫描，不用以前的结果）" % dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    L.append("- CVE 清单: `%s`（%d 个编号）" % (rel(a.cves), len(ids)))
    L.append("- 配置: %s" % ("`%s`" % rel(a.config) if a.config else "无（不排除任何 CVE）"))
    if ignored:
        L.append("- 不再使用、已忽略的配置行：%s" % "、".join(ignored))
    if bad:
        L.append("- **清单里有 %d 行不是 CVE/GHSA/GO 编号，已跳过**：%s" % (len(bad), "；".join(bad[:10])))
    if failed:
        L.append("- **以下分支扫描失败，结论里不含它们**：%s" % "；".join("%s %s（%s）" % (n, s["meta"]["branch"], s["error"]) for n, s in failed))
    L.append("")
    L.append("只扫分支源码里的依赖清单（go.mod、Cargo.lock、npm 锁文件等，OSV-Scanner），按 `EXCLUDE_PATH_REGEX` 排除测试、示例等不会编进交付物的清单。"
             "不扫镜像，所以 OS 包、镜像里另外复制进来的东西都不在内。“已解决”指这次没扫到，包括从来没受影响的。\n")

    L.append("## 扫描的分支\n")
    rows = []
    for t in targets:
        sides = (("客户分支 = master", t["br"]),) if t.get("same") else (("客户分支", t["br"]), ("master", t["base"]))
        for role, s in sides:
            if s is None:
                continue
            m = s["meta"]
            st = "成功" if s["ok"] else "**失败**：%s" % s["error"]
            rows.append([t["name"], role, m["branch"], (m.get("commit") or "")[:10], (m.get("scanned_at") or "")[:16].replace("T", " "),
                         st, m["repo"]])
    L.append(md_table(["目标", "角色", "分支", "commit", "扫描时间", "结果", "仓库"], rows))

    L.append("\n## 总览\n")
    meaning = {
        C_BACKPORT: "master 上扫不到，客户分支上还有：把 master 的依赖升级合到客户分支",
        C_BOTH: "master 和客户分支都还有：要先在 master（或直接在客户分支）升级",
        C_BASE_ONLY: "客户分支上扫不到，master 上还有",
        C_NONE: "两个分支都扫不到",
        C_OPEN: "客户分支上还有",
        C_OK: "客户分支上扫不到",
        C_EXCL: "配置里排除的",
    }
    L.append(md_table(["结论", "CVE 个数", "含义"], [[k, cnt[k], meaning[k]] for k in cats + [C_EXCL]]))
    L.append("\n每个 CVE 按 仓库 + 依赖包 分别判断：比如同一个 CVE 在 ticdc 的 master 上已修复、在 tidb-operator 上还没修，"
             "ticdc 那一行算“%s”，tidb-operator 那一行算“%s”。所以同一个 CVE 可能出现在几个类别里，个数加起来会多于编号数。\n"
             % ((C_BACKPORT, C_BOTH) if compare else (C_OK, C_OPEN)))

    if compare:
        head = ["目标", "依赖包", "生态", "客户分支", "master", "修复版本", "最高严重程度", "CVE"]
        mk = lambda r: [r["target"], r["pkg"], r["eco"], r["br"], r["base"], r["fix"] or "无修复版本", r["sev"], ids_cell(r["ids"])]  # noqa: E731
        sections = [(C_BACKPORT, "客户分支版本低于修复版本、master 已升级时，把客户分支升到 master 的版本（或修复版本）即可。"),
                    (C_BOTH, ""),
                    (C_BASE_ONLY, "")]
    else:
        head = ["目标", "依赖包", "生态", "客户分支版本", "修复版本", "最高严重程度", "CVE"]
        mk = lambda r: [r["target"], r["pkg"], r["eco"], r["br"], r["fix"] or "无修复版本", r["sev"], ids_cell(r["ids"])]  # noqa: E731
        sections = [(C_OPEN, "")]
    n = 0
    for cat, note in sections:
        n += 1
        cs = [c for c in ids if cat in res[c]["cats"]]
        L.append("\n## %d. %s（%d 个 CVE）\n" % (n, cat, len(cs)))
        if note and cs:
            L.append(note + "\n")
        rs = rows_for(cs, targets, compare, cat)
        L.append(md_table(head, [mk(r) for r in rs]) if rs else "无\n")
        if cat in (C_BACKPORT, C_OPEN) and rs:
            bypkg = {}
            for r in rs:
                x = bypkg.setdefault((r["eco"], r["pkg"]), {"fix": "", "ids": set(), "sev": "UNKNOWN", "where": []})
                x["fix"] = max_ver([x["fix"], r["fix"]])
                x["sev"] = sev_max(x["sev"], r["sev"])
                x["ids"] |= r["ids"]
                x["where"].append("%s %s" % (r["target"], r["br"].replace("（受影响）", "")))
            L.append("\n按依赖包合并（跨目标）：\n")
            L.append(md_table(["依赖包", "修复版本（最高）", "最高严重程度", "客户分支里的版本", "CVE"],
                              [[k[1], x["fix"] or "无修复版本", x["sev"], "<br>".join(sorted(set(x["where"]))), ids_cell(x["ids"])]
                               for k, x in sorted(bypkg.items(), key=lambda kv: (-SEV_RANK.get(kv[1]["sev"], 0), kv[0][1]))]))

    n += 1
    ok_cat = C_NONE if compare else C_OK
    xs = [c for c in ids if res[c]["cats"] == [ok_cat]]
    L.append("\n## %d. %s（%d 个）\n" % (n, ok_cat, len(xs)))
    L.append("这次扫描里没有出现。可能已经升级修复，也可能这些仓库本来就不受影响（例如 CVE 属于 OS 包、别的组件，或扫描器的库没收录），需要的话问客户具体是哪个组件、哪个包。\n")
    L.append((ids_cell(xs) if xs else "无") + "\n")
    n += 1
    xs = [c for c in ids if res[c]["cats"] == [C_EXCL]]
    L.append("\n## %d. 配置里排除的（%d 个）\n" % (n, len(xs)))
    L.append(md_table(["CVE", "原因"], [[c, excl.get(c) or "-"] for c in xs]) if xs else "无\n")

    L.append("\n## 附录：逐个 CVE\n")
    tsv = []
    for c in ids:
        fx = max_ver([h["fix"] for t in targets for s in (t["br"], t["base"]) if s and s["ok"] for h in s["hits"].get(c, [])])
        r = res[c]
        per = "; ".join("%s: %s" % x for x in r["per"]) if len(r["cats"]) > 1 else ", ".join(dict.fromkeys(x[0] for x in r["per"]))
        row = [c, " / ".join(r["cats"]), per or "-", where(c, targets, "br") or "-"]
        if compare:
            row.append(where(c, targets, "base") or "-")
        row += [fx or "-", excl.get(c, "") if r["cats"] == [C_EXCL] else ""]
        tsv.append(row)
    head = ["CVE", "结论", "涉及的仓库", "客户分支中"] + (["master 中"] if compare else []) + ["修复版本", "排除原因"]
    L.append(md_table(head, tsv))
    return "\n".join(L) + "\n", head, tsv, cnt


def prune(base, keep):
    if keep < 1 or not os.path.isdir(base):
        return
    ds = sorted(d for d in os.listdir(base) if RUN_RE.match(d) and os.path.isdir(os.path.join(base, d))
                and not os.path.islink(os.path.join(base, d)))
    for d in ds[:-keep] if len(ds) > keep else []:
        shutil.rmtree(os.path.join(base, d), ignore_errors=True)


def main():
    global LOG_FH
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cves", help="CVE 清单（纯文本，一行一个）")
    ap.add_argument("--repo", help="branches.conf 里的名称，或仓库 URL")
    ap.add_argument("--branch", help="客户分支")
    ap.add_argument("--base", help="对照的分支（master / main），不给就只报告客户分支")
    ap.add_argument("--config", default=None, help="配置文件（默认：清单同目录的 cve_check.conf，其次 config/cve_check.conf）")
    ap.add_argument("--out", default="", help="另外复制一份报告到这里（同名 .tsv 也复制）")
    a = ap.parse_args()

    if a.config is None:
        a.config = ""
        for cand in (os.path.join(os.path.dirname(os.path.abspath(a.cves)), "cve_check.conf"),
                     os.path.join(ROOT, "config", "cve_check.conf")):
            if os.path.isfile(cand):
                a.config = cand
                break
    elif not os.path.isfile(a.config):
        print("配置文件不存在: %s" % a.config, file=sys.stderr)
        return 2
    ids, bad = read_cve_list(a.cves)
    if not ids:
        print("CVE 清单里没有任何编号: %s" % a.cves, file=sys.stderr)
        return 2
    try:
        cfg_targets, excl, ignored = read_config(a.config)
    except UsageError as e:
        print(e, file=sys.stderr)
        return 2
    if a.repo or a.branch or a.base:
        if not (a.repo and a.branch):
            print("--repo 和 --branch 要一起给（--base 可选）", file=sys.stderr)
            return 2
        raw = [(a.repo, a.branch, a.base)]
    else:
        raw = cfg_targets
    if not raw:
        print("没有要扫的分支：用 --repo/--branch [--base]，或在配置文件里写 target 行", file=sys.stderr)
        return 2
    compare = any(t[2] is not None for t in raw)   # 有一行写了 master 分支就是对比；没写的行两边用同一个分支
    known = branches_conf()
    tgts, seen = [], set()
    for r, b, m in raw:
        try:
            name, url = resolve_repo(r, known)
        except UsageError as e:
            print(e, file=sys.stderr)
            return 2
        if name in seen:
            name = "%s(%s)" % (name, b)
        seen.add(name)
        tgts.append((name, url, b, m))

    s = load_settings()
    lock = take_lock(s["STATE_DIR"])
    if not lock:
        return 3
    stem = os.path.splitext(os.path.basename(a.cves))[0]
    if stem in ("cves", "cve", "list"):
        stem = os.path.basename(os.path.dirname(os.path.abspath(a.cves))) or stem
    a.title = stem
    run_id = dt.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    base_dir = os.path.join(s["RESULTS_DIR"], "cve-check", slugify(stem))
    run_dir = os.path.join(base_dir, run_id)
    wt_root = os.path.join(s["STATE_DIR"], "cve_check")
    try:
        shutil.rmtree(wt_root, ignore_errors=True)       # 以前中断留下的临时 worktree（有锁，不会有别人在用）
        os.makedirs(run_dir, exist_ok=True)
        LOG_FH = open(os.path.join(run_dir, "run.log"), "w", encoding="utf-8")
        log("===== cve_check %s：%d 个编号，%s =====" % (run_id, len(ids), "两个分支对比" if compare else "只看客户分支"))
        sc = Scanner(s, run_dir, wt_root)
        targets = []
        for name, url, b, m in tgts:
            t = {"name": name, "br": sc.scan(name, url, b), "same": compare and m is None}
            t["base"] = (t["br"] if t["same"] else sc.scan(name, url, m)) if compare else None
            targets.append(t)
        res = classify(ids, excl, targets, compare)
        md, head, tsv, cnt = render(a, ids, bad, targets, compare, excl, res, ignored)
        rp = os.path.join(run_dir, "report.md")
        with open(rp, "w", encoding="utf-8") as f:
            f.write(md)
        tp = os.path.join(run_dir, "report.tsv")
        with open(tp, "w", encoding="utf-8") as f:
            f.write("\t".join(head) + "\n")
            for r in tsv:
                f.write("\t".join(x.replace("\t", " ") for x in r) + "\n")
        lk = os.path.join(base_dir, "latest")
        if os.path.islink(lk):
            os.remove(lk)
        if not os.path.exists(lk):
            os.symlink(run_id, lk)
        if a.out:
            os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
            shutil.copyfile(rp, a.out)
            shutil.copyfile(tp, os.path.splitext(a.out)[0] + ".tsv")
        prune(base_dir, s["RETENTION"])
        failed = [s_ for t in targets for s_ in (t["br"], t["base"]) if s_ and not s_["ok"]]
        failed = list({id(x): x for x in failed}.values())
        log("%d 个编号：%s" % (len(ids), "，".join("%s %d" % (k, v) for k, v in cnt.items())))
        if failed:
            log("[ERROR] %d 个分支扫描失败（见报告开头），结论不含它们" % len(failed))
        if bad:
            log("注意：清单里有 %d 行不是编号，已跳过（见报告开头）" % len(bad))
        log("报告: %s" % rp)
        log("逐个 CVE: %s" % tp)
        if a.out:
            log("副本: %s" % a.out)
        return 1 if failed else 0
    finally:
        shutil.rmtree(wt_root, ignore_errors=True)
        shutil.rmtree(lock, ignore_errors=True)
        if LOG_FH:
            LOG_FH.close()


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""image_view.py - "客户视角"报告（仅标准库，Python 3.8+），由 bin/run.sh 调用（第 2 步）。

客户的商业扫描器扫的是交付的镜像，不是源码。这里用 Trivy 扫镜像，再把每个漏洞和对应分支的源码比较：
  源码已修复(待发镜像) / 源码未修复 / 源码已移除该依赖 / 暂无修复版本 / 无法对比 / 需重建镜像(OS 包)

OS 包（需重建镜像）不参与任何预测和统计，单独放在报告最后的附录。

子命令:
  validate  检查 Trivy 输出是否为合法 JSON
  report    trivy.json + 分支 worktree -> 单个镜像的 report.{json,tsv,md}
  summary   合并所有镜像最近一次成功的结果 -> results/report-images-latest.md
"""
import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sca import vkey, norm_ver, load_kev, load_json, SEV_RANK  # noqa: E402

# 源码对比状态（排序用：越靠前越需要关注）
ST_NOT_FIXED = "源码未修复"
ST_FIXED = "源码已修复(待发镜像)"
ST_REMOVED = "源码已移除该依赖"
ST_NO_FIX = "暂无修复版本"
ST_UNKNOWN = "无法对比"
ST_OS = "需重建镜像(OS包)"
ST_RANK = {ST_NOT_FIXED: 0, ST_UNKNOWN: 1, ST_NO_FIX: 2, ST_OS: 3, ST_FIXED: 4, ST_REMOVED: 5}

HIGH = ("HIGH", "CRITICAL")


# --------------------------------------------------------------------------- 版本比较
def split_fixed(s):
    """Trivy 的 FixedVersion 可能是 '1.26.9, 1.27.2' 这样的多个分支修复版本。"""
    return [x.strip() for x in re.split(r"[,\s]+", str(s or "")) if x.strip()]


def _line(v):
    k = vkey(v)[0]
    return k[:2]  # (major, minor)


def is_fixed(ver, fixed_list):
    """ver 是否已包含修复。fixed_list 为各维护分支的修复版本：
    同一 major.minor 线上 >= 该线的修复版本 -> 已修复；比所有修复版本都新 -> 已修复；否则未修复。"""
    if not ver or not fixed_list:
        return None
    kv = vkey(ver)
    same = [f for f in fixed_list if _line(f) == _line(ver)]
    if same:
        return any(kv >= vkey(f) for f in same)
    return kv >= max(vkey(f) for f in fixed_list)


def min_fix_for(ver, fixed_list):
    """对当前版本来说最小的修复版本：优先同一 major.minor 线，否则取大于当前版本的最小值。"""
    if not fixed_list:
        return ""
    kv = vkey(ver) if ver else None
    same = sorted((f for f in fixed_list if ver and _line(f) == _line(ver)), key=vkey)
    if same:
        return norm_ver(same[0])
    higher = sorted((f for f in fixed_list if kv is None or vkey(f) > kv), key=vkey)
    return norm_ver(higher[0] if higher else max(fixed_list, key=vkey))


# --------------------------------------------------------------------------- 源码解析
def parse_gomod(path):
    """返回 {module, go, toolchain, require{mod:ver}, replace{mod:ver|'local'}}"""
    info = {"path": path, "module": "", "go": "", "toolchain": "", "require": {}, "replace": {}}
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return info
    text = re.sub(r"//.*", "", text)
    block = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if block:
            if line == ")":
                block = None
                continue
            _gomod_stmt(info, block, line)
            continue
        m = re.match(r"^(require|replace|exclude|retract)\s*\($", line)
        if m:
            block = m.group(1)
            continue
        m = re.match(r"^(module|go|toolchain|require|replace|exclude|retract)\s+(.*)$", line)
        if m:
            kw, rest = m.groups()
            if kw == "module":
                info["module"] = rest.strip().strip('"')
            elif kw == "go":
                info["go"] = rest.strip()
            elif kw == "toolchain":
                info["toolchain"] = rest.strip()
            else:
                _gomod_stmt(info, kw, rest.strip())
    return info


def _gomod_stmt(info, kw, s):
    if kw == "require":
        p = s.split()
        if len(p) >= 2:
            info["require"][p[0]] = p[1]
    elif kw == "replace":
        if "=>" not in s:
            return
        left, right = [x.strip() for x in s.split("=>", 1)]
        lmod = left.split()[0]
        r = right.split()
        if len(r) >= 2:
            info["replace"][lmod] = r[1]
        elif r:
            info["replace"][lmod] = "local"


def gomod_version(gm, mod):
    """分支 go.mod 里某模块最终生效的版本；None = 不再依赖。"""
    if mod in gm["replace"]:
        return gm["replace"][mod]
    return gm["require"].get(mod)


def go_toolchain_version(gm):
    t = gm.get("toolchain") or ""
    if t.startswith("go"):
        return t[2:], "toolchain"
    if gm.get("go"):
        return gm["go"], "go 指令"
    return "", ""


def index_gomods(wt, maxdepth=4):
    out = {}
    if not wt or not os.path.isdir(wt):
        return out
    base_depth = wt.rstrip("/").count("/")
    skip = {"node_modules", "vendor", "testdata", "third_party", ".git"}
    for root, dirs, files in os.walk(wt):
        dirs[:] = [d for d in dirs if d not in skip]
        if root.count("/") - base_depth >= maxdepth:
            dirs[:] = []
        if "go.mod" in files:
            gm = parse_gomod(os.path.join(root, "go.mod"))
            if gm["module"]:
                gm["rel"] = os.path.relpath(os.path.join(root, "go.mod"), wt)
                # 同一 module path 出现多次时，优先离仓库根最近的
                if gm["module"] not in out or gm["rel"].count("/") < out[gm["module"]]["rel"].count("/"):
                    out[gm["module"]] = gm
    return out


def gomod_by_binary_name(wt, target, gomods, maxdepth=4):
    """二进制里没有主模块信息时（比如 PD 的 pd-ctl），按二进制名在源码里找同名目录
    （cmd/pd-server、tools/pd-ctl ...），再取离它最近的上级 go.mod。"""
    name = os.path.basename(target.rstrip("/"))
    if not name:
        return None
    by_rel = {gm["rel"]: gm for gm in gomods.values()}
    skip = {"node_modules", "vendor", "testdata", "third_party", ".git"}
    base_depth = wt.rstrip("/").count("/")
    hits = []
    for root, dirs, files in os.walk(wt):
        dirs[:] = [d for d in dirs if d not in skip]
        if root.count("/") - base_depth >= maxdepth:
            dirs[:] = []
        if os.path.basename(root) == name and root != wt:
            hits.append(root)
    for h in sorted(hits, key=lambda x: x.count("/")):
        d = h
        while True:
            rel = os.path.relpath(os.path.join(d, "go.mod"), wt)
            if rel in by_rel:
                return by_rel[rel]
            if os.path.abspath(d) == os.path.abspath(wt):
                break
            d = os.path.dirname(d)
    return None


def parse_cargo_lock(wt):
    res = {}
    p = os.path.join(wt or "", "Cargo.lock")
    if not os.path.isfile(p):
        return None
    name = None
    with open(p, encoding="utf-8") as f:
        lines = f.readlines()
    for line in lines:
        m = re.match(r'^name = "(.+)"', line)
        if m:
            name = m.group(1)
            continue
        m = re.match(r'^version = "(.+)"', line)
        if m and name:
            res.setdefault(name, []).append(m.group(1))
            name = None
    return res


def git(wt, *args):
    try:
        p = subprocess.run(["git", "-C", wt] + list(args), capture_output=True, text=True, timeout=60)
        return p.returncode, p.stdout.strip()
    except Exception:
        return 1, ""


def image_vs_branch(image, wt):
    """镜像 tag 末尾的 commit（如 v8.5.8-20261107-c1ce72e）和分支 HEAD 的关系。"""
    res = {"image_commit": "", "relation": "", "behind": None}
    tag = image.rsplit(":", 1)[-1] if ":" in image.rsplit("/", 1)[-1] else ""
    m = re.search(r"-([0-9a-f]{7,40})$", tag)
    if not m:
        res["relation"] = "标准版镜像（tag 不含 commit）"
        return res
    h = m.group(1)
    res["image_commit"] = h
    if not wt or not os.path.isdir(wt):
        res["relation"] = "无 worktree"
        return res
    rc, _ = git(wt, "cat-file", "-e", h + "^{commit}")
    if rc != 0:
        res["relation"] = "分支里找不到该 commit"
        return res
    rc, _ = git(wt, "merge-base", "--is-ancestor", h, "HEAD")
    if rc != 0:
        res["relation"] = "不在分支历史上"
        return res
    rc, out = git(wt, "rev-list", "--count", h + "..HEAD")
    n = int(out) if rc == 0 and out.isdigit() else None
    res["behind"] = n
    res["relation"] = "与分支 HEAD 一致" if n == 0 else ("镜像落后分支 %s 个 commit" % n)
    return res


# --------------------------------------------------------------------------- Trivy 解析
def best_score(v):
    cv = v.get("CVSS") or {}
    for src in ("nvd", "ghsa", "redhat"):
        s = cv.get(src) or {}
        for k in ("V3Score", "V40Score"):
            if s.get(k):
                return float(s[k]), src
    for src, s in cv.items():
        for k in ("V3Score", "V40Score", "V2Score"):
            if (s or {}).get(k):
                return float(s[k]), src
    return None, ""


def root_module(result):
    for p in result.get("Packages") or []:
        if p.get("Relationship") == "root" and p.get("Name"):
            return p["Name"]
    return ""


def parse_date(s):
    if not s:
        return None
    try:
        return dt.date.fromisoformat(str(s)[:10])
    except ValueError:
        return None


def cmd_validate(a):
    try:
        d = load_json(a.file)
    except Exception as e:
        print("invalid JSON: %s" % e, file=sys.stderr)
        return 1
    if not isinstance(d, dict) or "ArtifactName" not in d:
        print("not a Trivy JSON report (no ArtifactName)", file=sys.stderr)
        return 1
    return 0


def cmd_report(a):
    tv = load_json(a.trivy)
    meta = load_json(a.meta) if a.meta and os.path.isfile(a.meta) else {}
    kev = load_kev(a.kev)
    today = parse_date(meta.get("scanned_at")) or dt.date.today()
    wt = a.worktree if a.worktree and os.path.isdir(a.worktree) else ""
    gomods = index_gomods(wt) if wt else {}
    root_gm = None
    if wt:
        for gm in gomods.values():
            if gm["rel"] == "go.mod":
                root_gm = gm
    cargo = parse_cargo_lock(wt) if wt else None

    md = tv.get("Metadata") or {}
    osinfo = md.get("OS") or {}
    meta.update({
        "os": ("%s %s" % (osinfo.get("Family", ""), osinfo.get("Name", ""))).strip(),
        "digest": (md.get("RepoDigests") or [""])[0],
        "image_created": ((md.get("ImageConfig") or {}).get("created") or "")[:19],
    })
    meta.update(image_vs_branch(meta.get("image", ""), wt))
    if wt:
        rc, head = git(wt, "log", "-1", "--format=%h %cs")
        meta["branch_head"] = head if rc == 0 else ""

    issues = {}   # key -> issue
    binaries = []
    notes = []
    saw_rust = False
    for r in tv.get("Results") or []:
        cls, typ, target = r.get("Class", ""), r.get("Type", ""), r.get("Target", "")
        if cls == "lang-pkgs" and typ == "gobinary":
            rm = root_module(r)
            gm = gomods.get(rm) if rm else None
            how = "go.mod: %s" % gm["rel"] if gm else ""
            if not gm and wt:
                gm = gomod_by_binary_name(wt, target, gomods)
                if gm:
                    rm, how = gm["module"], "go.mod: %s（按二进制名找到源码目录）" % gm["rel"]
            if not gm and root_gm:
                gm, how = root_gm, "go.mod: go.mod（未识别主模块，按仓库根）"
            binaries.append({"binary": target, "main_module": rm or "?", "gomod": how})
        if typ in ("rustbinary", "cargo"):
            saw_rust = True
        for v in r.get("Vulnerabilities") or []:
            pkg, inst = v.get("PkgName", ""), v.get("InstalledVersion", "")
            fixed = split_fixed(v.get("FixedVersion"))
            src_ver, src_from, status = "", "", ST_UNKNOWN
            if cls == "os-pkgs":
                status, eco = ST_OS, "OS(%s)" % typ
            elif typ == "gobinary":
                eco = "Go"
                if not wt:
                    status = ST_UNKNOWN
                elif pkg == "stdlib":
                    src_ver, src_from = go_toolchain_version(gm or {})
                    status = ST_UNKNOWN if not src_ver else (ST_NO_FIX if not fixed else (ST_FIXED if is_fixed(src_ver, fixed) else ST_NOT_FIXED))
                elif gm:
                    src_ver = gomod_version(gm, pkg)
                    src_from = gm["rel"]
                    if src_ver is None:
                        status, src_ver = ST_REMOVED, ""
                    elif src_ver == "local":
                        status = ST_UNKNOWN
                    elif not fixed:
                        status = ST_NO_FIX
                    else:
                        status = ST_FIXED if is_fixed(src_ver, fixed) else ST_NOT_FIXED
            elif typ in ("rustbinary", "cargo"):
                eco = "Rust"
                if cargo is not None:
                    vers = cargo.get(pkg)
                    src_from = "Cargo.lock"
                    if not vers:
                        status = ST_REMOVED
                    else:
                        src_ver = ", ".join(sorted(set(vers), key=vkey))
                        if not fixed:
                            status = ST_NO_FIX
                        else:
                            status = ST_FIXED if all(is_fixed(x, fixed) for x in vers) else ST_NOT_FIXED
            else:
                eco = typ or cls
            if status == ST_UNKNOWN and not fixed and cls != "os-pkgs":
                status = ST_NO_FIX
            vid = v.get("VulnerabilityID", "")
            score, ssrc = best_score(v)
            sev = (v.get("Severity") or "UNKNOWN").upper()
            pub = parse_date(v.get("PublishedDate"))
            key = (eco, pkg, inst, vid)
            it = issues.get(key)
            if it is None:
                it = issues[key] = {
                    "eco": eco, "package": pkg, "installed": norm_ver(inst), "id": vid,
                    "severity": sev, "severity_source": v.get("SeveritySource", ""),
                    "score": score, "score_source": ssrc, "fixed": [norm_ver(f) for f in fixed],
                    "fix_to": min_fix_for(inst, fixed), "published": pub.isoformat() if pub else "",
                    "recent": bool(pub and (today - pub).days <= a.recent_days),
                    "kev": (None if kev is None else vid in kev),
                    "title": (v.get("Title") or "")[:120], "url": v.get("PrimaryURL", ""),
                    "targets": [], "status": status, "src_version": src_ver or "", "src_from": src_from,
                }
            if target not in it["targets"]:
                it["targets"].append(target)
            # 同一漏洞出现在多个二进制里：取最需要关注的状态
            if ST_RANK[status] < ST_RANK[it["status"]]:
                it["status"], it["src_version"], it["src_from"] = status, src_ver or "", src_from

    if meta.get("target_kind") == "rust" or "tikv" in meta.get("name", ""):
        if not saw_rust:
            notes.append("镜像中没有检出 Rust 依赖信息（二进制未用 cargo-auditable 嵌入依赖清单），客户的扫描器大概率也看不到 TiKV 的 crate 漏洞。")
    if not binaries and not saw_rust:
        notes.append("镜像中没有检出带依赖信息的 Go 二进制。")
    if not wt:
        notes.append("没有找到对应分支的 worktree，无法和源码比较（先跑一次 bin/run.sh）。")

    lst = sorted(issues.values(), key=issue_sort)
    for i in lst:
        i["likely"] = likely(i)
    summ = make_summary(lst)
    rep = {"meta": meta, "summary": summ, "binaries": binaries, "notes": notes, "issues": lst}
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "report.json"), "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=1)
    cols = ["eco", "package", "installed", "id", "severity", "score", "published", "fix_to", "status", "src_version", "src_from", "kev", "targets"]
    with open(os.path.join(a.out, "report.tsv"), "w", encoding="utf-8") as f:
        f.write("\t".join(cols) + "\n")
        for i in lst:
            f.write("\t".join(fmt_cell(i[c]) for c in cols) + "\n")
    with open(os.path.join(a.out, "report.md"), "w", encoding="utf-8") as f:
        f.write(render_image_md(rep, a.recent_days))
    print("%d\t%d\t%d\t%d\t%d" % (summ["issues"], summ["high_critical"], summ["likely"], summ["fixed_in_src"], summ["not_fixed"]))
    return 0


def likely(i):
    """客户最可能提的：在 KEV 里，或 HIGH/CRITICAL 且有修复版本。
    OS 包不算：客户自己 build 镜像，OS 包来自他们自己的基础镜像，和我们的交付镜像无关（见报告附录）。"""
    if i["status"] == ST_OS:
        return False
    return bool(i["kev"]) or (i["severity"] in HIGH and bool(i["fixed"]))


def make_summary(lst):
    """统计。除 os/os_high 外，所有计数都不含 OS 包。"""
    app = [i for i in lst if i["status"] != ST_OS]
    osi = [i for i in lst if i["status"] == ST_OS]
    return {
        "issues": len(app),
        "high_critical": sum(1 for i in app if i["severity"] in HIGH),
        "likely": sum(1 for i in app if likely(i)),
        "fixed_in_src": sum(1 for i in app if i["status"] == ST_FIXED),
        "not_fixed": sum(1 for i in app if i["status"] == ST_NOT_FIXED),
        "recent": sum(1 for i in app if i["recent"]),
        "kev": sum(1 for i in app if i["kev"]),
        "os": len(osi),
        "os_high": sum(1 for i in osi if i["severity"] in HIGH),
    }


def issue_sort(i):
    return (not i["kev"], -SEV_RANK.get(i["severity"], 0), -(i["score"] or 0),
            i["status"] == ST_OS, i["published"] and -int(i["published"].replace("-", "")) or 0, i["package"], i["id"])


def fmt_cell(v):
    if isinstance(v, list):
        return ",".join(v)
    if v is None:
        return "?"
    if isinstance(v, bool):
        return "YES" if v else "no"
    return str(v)


def md_table(head, rows):
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for r in rows:
        out.append("| " + " | ".join(str(c).replace("|", "\\|") for c in r) + " |")
    return "\n".join(out) + "\n"


def sev_cell(i):
    return i["severity"] + (" (%.1f)" % i["score"] if i["score"] else "")


def group_pkgs(issues):
    """按 (镜像版本的) 依赖包聚合：一个包一行，列出 CVE、最高严重程度、需要升级到的版本和源码状态。"""
    g = {}
    for i in issues:
        k = (i["eco"], i["package"], i["installed"])
        x = g.setdefault(k, {"eco": i["eco"], "package": i["package"], "installed": i["installed"], "ids": [],
                             "sev": "UNKNOWN", "score": None, "fix_to": "", "status": i["status"],
                             "src_version": i["src_version"], "src_from": i["src_from"], "kev": False,
                             "recent": False, "targets": []})
        x["ids"].append(i["id"])
        if SEV_RANK.get(i["severity"], 0) > SEV_RANK.get(x["sev"], 0):
            x["sev"] = i["severity"]
        if i["score"] and (x["score"] or 0) < i["score"]:
            x["score"] = i["score"]
        if i["fix_to"] and (not x["fix_to"] or vkey(i["fix_to"]) > vkey(x["fix_to"])):
            x["fix_to"] = i["fix_to"]
        if ST_RANK[i["status"]] < ST_RANK[x["status"]]:
            x["status"], x["src_version"], x["src_from"] = i["status"], i["src_version"], i["src_from"]
        x["kev"] = x["kev"] or bool(i["kev"])
        x["recent"] = x["recent"] or i["recent"]
        for t in i["targets"]:
            if t not in x["targets"]:
                x["targets"].append(t)
    rows = list(g.values())
    rows.sort(key=lambda x: (not x["kev"], -SEV_RANK.get(x["sev"], 0), -(x["score"] or 0), x["package"]))
    return rows


def ids_cell(ids, n=6):
    ids = sorted(set(ids))
    return ", ".join(ids[:n]) + (" 等%d个" % len(ids) if len(ids) > n else "")


def pkg_rows(rows, with_image=None):
    out = []
    for x in rows:
        r = ([with_image] if with_image is not None else []) + [
            x["package"], x["installed"], ids_cell(x["ids"]),
            x["sev"] + (" (%.1f)" % x["score"] if x["score"] else ""),
            "YES" if x["kev"] else "no", x["fix_to"] or "无", x["status"],
            x["src_version"] or "-"]
        out.append(r)
    return out


PKG_HEAD = ["依赖包", "镜像中版本", "漏洞", "最高严重程度", "KEV", "升级到", "源码状态", "分支版本"]

OS_APPENDIX_NOTE = ("基础镜像里的操作系统包（rpm/apk 等）。客户从我们的分支自己 build 私有镜像，OS 包来自他们自己的基础镜像"
                    "（分支里的 Dockerfile 和官方发布流水线用的基础镜像也不一样），所以这里的结果不用于预测客户会提什么，"
                    "也不计入正文的任何统计。只有客户直接使用官方发布镜像时才有参考价值。")


def render_image_md(rep, recent_days):
    m, s = rep["meta"], rep["summary"]
    L = ["# 客户视角：%s\n" % m.get("image", "")]
    L.append("- 扫描时间: %s ｜ 运行ID: %s" % (m.get("scanned_at", ""), m.get("run_id", "")))
    L.append("- 镜像: `%s`（%s）  digest: `%s`" % (m.get("image", ""), m.get("platform", ""), m.get("digest", "") or "?"))
    L.append("- 基础系统: %s ｜ 镜像创建: %s" % (m.get("os") or "?", m.get("image_created") or "?"))
    L.append("- 对比分支: %s `%s`（HEAD %s）｜ %s" % (m.get("source", ""), m.get("branch", ""), m.get("branch_head", "") or "?", m.get("relation", "")))
    L.append("- 漏洞 %d ｜ HIGH/CRITICAL %d ｜ 客户可能提 %d ｜ 源码已修复待发镜像 %d ｜ 源码未修复 %d ｜ 近%d天新公布 %d（均不含 OS 包，OS 包见附录）\n" % (
        s["issues"], s["high_critical"], s["likely"], s["fixed_in_src"], s["not_fixed"], recent_days, s["recent"]))
    for n in rep["notes"]:
        L.append("> 注意: " + n + "\n")
    if rep["binaries"]:
        L.append("## 镜像里的 Go 二进制\n")
        L.append(md_table(["二进制", "主模块", "对比用的 go.mod"], [[b["binary"], b["main_module"], b["gomod"] or "-"] for b in rep["binaries"]]))
    lang = [i for i in rep["issues"] if i["status"] != ST_OS]
    osi = [i for i in rep["issues"] if i["status"] == ST_OS]
    L.append("## 依赖包（Go / Rust，按包聚合）\n")
    L.append(md_table(PKG_HEAD, pkg_rows(group_pkgs(lang))) if lang else "无\n")
    L.append("\n## 漏洞明细（不含 OS 包）\n")
    L.append(md_table(["依赖包", "镜像中版本", "漏洞", "严重程度", "公布日期", "升级到", "源码状态", "分支版本", "所在文件"],
                      [[i["package"], i["installed"], i["id"], sev_cell(i), i["published"] or "?", i["fix_to"] or "无",
                        i["status"], i["src_version"] or "-", ", ".join(i["targets"])] for i in lang]) if lang else "无\n")
    L.append("\n## 附录：操作系统包（与预测客户关注点无关）\n")
    L.append(OS_APPENDIX_NOTE + "\n")
    L.append(md_table(PKG_HEAD[:6], [r[:6] for r in pkg_rows(group_pkgs(osi))]) if osi else "无\n")
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------- summary
def read_images_conf(path):
    out = []
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        p = line.split()
        if len(p) >= 3:
            out.append((p[0], p[1], p[2]))
    return out


def load_status(path):
    st = {}
    if path and os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines:
            p = line.rstrip("\n").split("\t")
            if len(p) >= 3:
                st[p[0]] = (p[1], p[2])
    return st


def is_go_official(pkg):
    return pkg == "stdlib" or pkg.startswith("golang.org/x/")


ST_SHORT = {ST_FIXED: "源码已修复", ST_NOT_FIXED: "源码未修复", ST_REMOVED: "源码已移除",
            ST_NO_FIX: "无修复", ST_UNKNOWN: "无法对比", ST_OS: "OS"}


def render_go_official(reps, days):
    """报告最前面：Go 官方（golang.org/x/* 和标准库）近 N 天的修复，命中了哪些镜像。按公布日期倒序。"""
    today = dt.date.today()
    rows = {}
    for name, rep in reps:
        for i in rep["issues"]:
            if i["eco"] != "Go" or not is_go_official(i["package"]):
                continue
            pub = parse_date(i["published"])
            if not pub or (today - pub).days > days:
                continue
            k = (i["published"], i["package"], i["id"])
            r = rows.setdefault(k, {"sev": i["severity"], "score": i["score"], "fix": i["fixed"],
                                    "title": i.get("title", ""), "hits": []})
            if SEV_RANK.get(i["severity"], 0) > SEV_RANK.get(r["sev"], 0):
                r["sev"] = i["severity"]
            hit = "%s %s（%s%s）" % (name, i["installed"], ST_SHORT.get(i["status"], i["status"]),
                                    (" " + i["src_version"]) if i["src_version"] else "")
            if hit not in r["hits"]:
                r["hits"].append(hit)
    out = ["## 0. Go 官方近期修复，命中镜像（近 %d 天，按公布日期倒序）\n" % days,
           "只看 Go 官方团队维护的 golang.org/x/* 和 Go 标准库。命中写法：镜像 镜像中版本（源码状态 分支版本）。"
           "公布日期取自 Trivy 漏洞库（通常是 NVD/Go 漏洞库的发布时间），和 golang-announce 公告日期可能差一两天。\n"]
    if not rows:
        out.append("无\n")
        return "\n".join(out) + "\n"
    tab = []
    for (pub, pkg, vid), r in sorted(rows.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2]), reverse=True):
        tab.append([pub, vid, pkg, r["sev"] + (" (%.1f)" % r["score"] if r["score"] else ""),
                    ", ".join(r["fix"]) or "无", r["title"][:70] or "-", "<br>".join(r["hits"])])
    out.append(md_table(["公布日期", "漏洞", "包", "严重程度", "修复版本", "说明", "命中镜像"], tab))
    return "\n".join(out) + "\n"


def cmd_summary(a):
    imgs = read_images_conf(a.conf)
    st = load_status(a.targets)
    reps = []
    L = ["# 客户视角汇总（扫交付镜像）\n",
         "生成时间: %s ｜ 运行ID: %s\n" % (dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), a.run_id),
         "用 Trivy 扫描交付给客户的镜像（%s），模拟客户的商业扫描器能看到的内容，再和对应分支的源码比较。"
         "“客户可能提”= 在 CISA KEV 里，或 HIGH/CRITICAL 且有修复版本。\n" % a.platform]
    over, os_over = [], []
    for name, image, src in imgs:
        latest = os.path.join(a.results, name, "latest", "report.json")
        status = st.get(name, ("未运行", ""))
        rep = load_json(latest) if os.path.isfile(latest) else None
        if rep and rep["meta"].get("image") != image:
            note = "（结果是旧镜像 %s 的）" % rep["meta"].get("image")
        else:
            note = ""
        if status[0] == "OK":
            stxt = "本次成功"
        elif rep:
            stxt = "本次%s，显示上次结果" % status[0]
        else:
            stxt = "本次%s，尚无成功结果" % status[0]
        if not rep:
            over.append([name, image, src, "-", "-", stxt, "-", "-", "-", "-", "-"])
            os_over.append([name, "-", "-"])
            continue
        for i in rep["issues"]:   # 旧结果里 OS 包可能被算作“客户可能提”，这里按当前口径重算
            i["likely"] = likely(i)
        m, s = rep["meta"], make_summary(rep["issues"])
        os_over.append([name, s["os"], s["os_high"]])
        reps.append((name, rep))
        over.append([name, "`%s`%s" % (image, note), "%s (%s)" % (src, m.get("branch_head", "") or "?"), m.get("relation", ""),
                     m.get("scanned_at", "")[:16].replace("T", " "), stxt, s["issues"], s["high_critical"], s["likely"],
                     s["fixed_in_src"], s["not_fixed"]])
    L.append(render_go_official(reps, a.go_days))
    L.append("## 1. 总览\n")
    L.append("以下各节（0-5）都不含操作系统包，OS 包统一放在最后的附录。\n")
    L.append(md_table(["名称", "镜像", "对比分支(HEAD)", "镜像与分支", "扫描时间", "状态", "漏洞", "HIGH+", "客户可能提", "源码已修复待发镜像", "源码未修复"], over))

    def section(title, desc, pred, os_only=False):
        rows = []
        for name, rep in reps:
            sel = [i for i in rep["issues"] if pred(i) and (i["status"] == ST_OS) == os_only]
            rows += pkg_rows(group_pkgs(sel), with_image=name)
        L.append("\n## %s\n" % title)
        if desc:
            L.append(desc + "\n")
        L.append(md_table(["镜像"] + PKG_HEAD, rows) if rows else "无\n")

    section("2. 客户最可能提的（KEV，或 HIGH/CRITICAL 且有修复版本）",
            "按依赖包聚合。“源码状态”说明发新镜像能不能解决。", lambda i: i["likely"])
    section("3. 近 %d 天新公布的（全部严重程度）" % a.recent_days,
            "客户通常只盯新出的 CVE，这一节最可能变成下一轮的要求。", lambda i: i["recent"])
    section("4. 源码已修复、还没发镜像的",
            "分支上的版本已经包含修复，只要出新镜像就能消掉。", lambda i: i["status"] == ST_FIXED)
    section("5. 源码也还没修复的（需要升级依赖）", "", lambda i: i["status"] == ST_NOT_FIXED and i["eco"] in ("Go", "Rust"))
    notes = []
    for name, rep in reps:
        for n in rep.get("notes", []):
            notes.append("- **%s**: %s" % (name, n))
    L.append("\n## 6. 说明\n")
    L.append("\n".join(notes + [
        "- 源码状态：%s = 分支版本已 >= 修复版本；%s = 分支版本仍低于修复版本；%s = 分支 go.mod 里已没有这个依赖；"
        "%s = 上游还没有修复版本；%s = 没有 worktree 或分支版本是本地 replace。" % (ST_FIXED, ST_NOT_FIXED, ST_REMOVED, ST_NO_FIX, ST_UNKNOWN),
        "- Go 依赖按“二进制的主模块”找到分支里对应的 go.mod 比较；stdlib 按分支 go.mod 的 toolchain（没有则 go 指令）比较，实际发版用的 Go 版本可能不同。",
        "- 对比的是 worktree 当前内容，bin/run.sh 每次先更新分支再扫镜像；某分支本次更新失败时，对比的是它上次的内容（日志里有 WARN）。",
        "- 严重程度用 Trivy 给出的（厂商/NVD/GHSA），CVSS 分数优先取 NVD。客户的商业扫描器数据源和更新时间可能略有不同。",
    ]) + "\n")
    L.append("\n---\n\n## 附录：操作系统包（与预测客户关注点无关）\n")
    L.append(OS_APPENDIX_NOTE + "\n")
    L.append(md_table(["名称", "OS包漏洞", "其中 HIGH+"], os_over))
    section("附录明细：操作系统包（按包聚合）", "", lambda i: True, os_only=True)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("validate"); p.add_argument("file")
    p = sp.add_parser("report")
    p.add_argument("--trivy", required=True); p.add_argument("--worktree", default="")
    p.add_argument("--meta", default=""); p.add_argument("--kev", default="")
    p.add_argument("--recent-days", type=int, default=45); p.add_argument("--out", required=True)
    p = sp.add_parser("summary")
    p.add_argument("--conf", required=True); p.add_argument("--results", required=True)
    p.add_argument("--targets", default=""); p.add_argument("--run-id", default="")
    p.add_argument("--platform", default="linux/amd64")
    p.add_argument("--go-days", type=int, default=90)
    p.add_argument("--recent-days", type=int, default=45); p.add_argument("--out", required=True)
    a = ap.parse_args()
    return {"validate": cmd_validate, "report": cmd_report, "summary": cmd_summary}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())

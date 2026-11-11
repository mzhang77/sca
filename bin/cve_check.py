#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cve_check.py - 拿客户提交的 CVE 清单，对照 results/ 里各组件最新一次的扫描结果，生成核对报告（仅标准库，Python 3.8+）。

用法:
  bin/cve_check.py CVE清单 [--config 配置文件] [--out 报告.md]

CVE 清单：纯文本，一行一个编号（CVE-/GHSA-/GO- 都可以）；# 开头的行和空行忽略，一行里第一个空白之后的内容当注释。
配置文件：不指定时依次找 CVE 清单同目录的 cve_check.conf、config/cve_check.conf；都没有就看全部组件、不排除任何 CVE。
  components 名称 名称 ...   要看的组件：images.conf / builds.conf / branches.conf 里的名称（可以写多行）
  exclude    CVE编号 [原因]  不列出的 CVE（已确认误报、不适用等），报告里单独列出原因
输出：报告 .md 和逐个 CVE 的 .tsv（默认 results/cve-check-<清单名>.md / .tsv）。

每个 CVE 归到一类（按顺序判断）：
  排除            配置里 exclude 的
  未解决-交付物   在镜像或源码构建（Trivy 扫二进制）的最新结果里，且不是 OS 包
  未解决-仅分支   只在分支（OSV 扫源码清单）的最新结果里
  已解决          最新结果里没有，但这些组件以前的扫描里出现过（OS 包除外）
  仅 OS 包        只在镜像的 OS 包里出现过（客户自己 build 镜像，不考虑）
  从未扫到        这些组件的任何一次扫描里都没有（分支报告已按 EXCLUDE_PATH_REGEX 排除了测试/示例等清单）
"""
import argparse
import datetime as dt
import glob
import os
import re
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sca import vkey, norm_ver, load_json, SEV_RANK  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ID_RE = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA(-[0-9a-z]{4}){3}|GO-\d{4}-\d{4,})$", re.I)
RUN_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{6}$")
ST_OS = "需重建镜像(OS包)"
ST_FIXED = "源码已修复(待发镜像)"

C_EXCL, C_DELIV, C_BRANCH, C_RESOLVED, C_OS, C_NEVER = "排除", "未解决-交付物", "未解决-仅分支", "已解决", "仅OS包", "从未扫到"


# --------------------------------------------------------------------------- 输入
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
    comps, excl = None, {}
    if not path:
        return comps, excl
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()
    for n, line in enumerate(lines, 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        p = s.split(None, 1)
        key, rest = p[0].lower(), (p[1] if len(p) > 1 else "")
        if key == "components":
            comps = (comps or []) + rest.split()
        elif key == "exclude":
            q = rest.split(None, 1)
            if q and ID_RE.match(q[0]):
                excl[norm_id(q[0])] = q[1].strip() if len(q) > 1 else ""
            else:
                raise SystemExit("config %s:%d: exclude 后面要写 CVE 编号" % (path, n))
        else:
            raise SystemExit("config %s:%d: 不认识的配置项 '%s'（只有 components / exclude）" % (path, n, p[0]))
    return comps, excl


def conf_lines(name):
    p = os.path.join(ROOT, "config", name)
    out = []
    if os.path.isfile(p):
        with open(p, encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    out.append(s.split())
    return out


def slugify(s):
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)


def discover_components(results):
    """[(名称, 类型, 结果目录)]：类型 image / build / branch。"""
    out = []
    for p in conf_lines("images.conf"):
        if len(p) >= 3:
            out.append((p[0], "image", os.path.join(results, "images", p[0])))
    for p in conf_lines("builds.conf"):
        if len(p) >= 4:
            out.append((p[0], "build", os.path.join(results, "builds", p[0])))
    for p in conf_lines("branches.conf"):
        if len(p) >= 3:
            out.append((p[0], "branch", os.path.join(results, p[0], slugify(p[2]))))
    return out


# --------------------------------------------------------------------------- 扫描结果
def run_dirs(base, kind):
    """该组件全部运行目录（历史用）。分支取 results/<名称>/ 下所有分支的运行目录（换过分支的旧结果也算历史）。"""
    if kind == "branch":
        return [d for d in glob.glob(os.path.join(os.path.dirname(base), "*", "*")) if RUN_RE.match(os.path.basename(d))]
    return [d for d in glob.glob(os.path.join(base, "*")) if RUN_RE.match(os.path.basename(d))]


def issue_ids(i, kind):
    if kind == "branch":
        return {norm_id(x) for x in (i.get("ids") or []) + (i.get("cves") or []) + [i.get("id", "")] if x}
    return {norm_id(i.get("id", ""))}


def load_latest(comps):
    """{cve: [hit...]} 只看最新结果；返回 (hits, meta 列表)"""
    hits, metas = {}, []
    for name, kind, base in comps:
        p = os.path.join(base, "latest", "report.json")
        if not os.path.isfile(p):
            metas.append((name, kind, None))
            continue
        rep = load_json(p)
        metas.append((name, kind, rep.get("meta", {})))
        for i in rep.get("issues", []):
            is_os = kind != "branch" and i.get("status") == ST_OS
            if kind == "branch":
                h = {"comp": name, "kind": kind, "os": False, "pkg": i["package"], "eco": i.get("ecosystem", ""),
                     "ver": norm_ver(i.get("version", "")), "fix": norm_ver(i.get("fix") or ""), "status": "",
                     "src_ver": "", "sev": i.get("severity", "UNKNOWN"), "targets": []}
            else:
                h = {"comp": name, "kind": kind, "os": is_os, "pkg": i["package"], "eco": i.get("eco", ""),
                     "ver": i.get("installed", ""), "fix": i.get("fix_to", ""), "status": i.get("status", ""),
                     "src_ver": norm_ver(i.get("src_version", "")), "sev": i.get("severity", "UNKNOWN"),
                     "targets": i.get("targets", [])}
            for x in issue_ids(i, kind):
                hits.setdefault(x, []).append(h)
    return hits, metas


def load_history(comps, wanted):
    """{cve: {"app": bool, "os": bool}}：这些组件全部历史运行里出现过的（只统计 wanted 里的编号）。"""
    seen = {}
    for name, kind, base in comps:
        for d in run_dirs(base, kind):
            p = os.path.join(d, "report.json")
            if not os.path.isfile(p):
                continue
            try:
                rep = load_json(p)
            except Exception:
                continue
            for i in rep.get("issues", []):
                is_os = kind != "branch" and i.get("status") == ST_OS
                for x in issue_ids(i, kind) & wanted:
                    s = seen.setdefault(x, {"app": False, "os": False})
                    s["os" if is_os else "app"] = True
    return seen


# --------------------------------------------------------------------------- 归类
def classify(ids, excl, latest, hist):
    res = {}
    for c in ids:
        hs = latest.get(c, [])
        app = [h for h in hs if not h["os"]]
        if c in excl:
            cat = C_EXCL
        elif any(h["kind"] in ("image", "build") for h in app):
            cat = C_DELIV
        elif app:
            cat = C_BRANCH
        elif hist.get(c, {}).get("app"):
            cat = C_RESOLVED
        elif any(h["os"] for h in hs) or hist.get(c, {}).get("os"):
            cat = C_OS
        else:
            cat = C_NEVER
        res[c] = (cat, app)
    return res


def max_ver(vs):
    vs = [v for v in vs if v]
    return max(vs, key=vkey) if vs else ""


def sev_max(a, b):
    return a if SEV_RANK.get(a, 0) >= SEV_RANK.get(b, 0) else b


def group(res, cat, kinds, extra=None):
    """按 (组件, 类型, 依赖包, 当前版本) 合并 -> 行。extra(h) 为真的命中也算进来（不管类型）。"""
    g = {}
    for c, (k, hs) in res.items():
        if k != cat:
            continue
        for h in hs:
            if h["kind"] not in kinds and not (extra and extra(h)):
                continue
            key = (h["comp"], h["kind"], h["pkg"], h["ver"])
            r = g.setdefault(key, {"comp": h["comp"], "kind": h["kind"], "pkg": h["pkg"], "eco": h["eco"], "ver": h["ver"],
                                   "fix": "", "ids": set(), "status": h["status"], "src_ver": h["src_ver"], "sev": "UNKNOWN",
                                   "targets": set()})
            r["ids"].add(c)
            r["fix"] = max_ver([r["fix"], h["fix"]])
            r["sev"] = sev_max(r["sev"], h["sev"])
            r["targets"].update(h["targets"])
            if h["status"] and h["status"] != ST_FIXED:
                r["status"], r["src_ver"] = h["status"], h["src_ver"]
    return list(g.values())


# --------------------------------------------------------------------------- 输出
def md_table(head, rows):
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for r in rows:
        out.append("| " + " | ".join(str(x).replace("|", "\\|").replace("\n", " ") for x in r) + " |")
    return "\n".join(out) + "\n"


def ids_cell(ids):
    return ", ".join(sorted(ids, key=lambda x: (x[:3], [int(n) if n.isdigit() else n for n in re.split(r"(\d+)", x)])))


def rel(p):
    ap = os.path.abspath(p)
    return os.path.relpath(ap, ROOT) if ap.startswith(ROOT + os.sep) else p


def kind_label(k):
    return {"image": "镜像", "build": "源码构建", "branch": "分支"}.get(k, k)


def what_to_do(r):
    if r["kind"] == "image" and r["status"] == ST_FIXED:
        return "源码已修复（%s），发新镜像" % (r["src_ver"] or "?")
    if r["kind"] == "image" and r["status"]:
        return r["status"] + ("（分支 %s）" % r["src_ver"] if r["src_ver"] else "")
    if r["kind"] == "build":
        return "升级依赖（分支就是这个版本）"
    if r["kind"] == "branch":
        return "升级依赖（没扫镜像，按分支源码）"
    return "升级依赖"


def render(a, ids, bad, comps, metas, excl, res):
    cnt = {k: 0 for k in (C_DELIV, C_BRANCH, C_RESOLVED, C_OS, C_NEVER, C_EXCL)}
    for c in ids:
        cnt[res[c][0]] += 1
    L = ["# 客户 CVE 核对：%s\n" % a.title]
    L.append("- 生成时间: %s" % dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    L.append("- CVE 清单: `%s`（%d 个编号）" % (rel(a.cves), len(ids)))
    L.append("- 配置: %s" % ("`%s`" % rel(a.config) if a.config else "无（看全部组件，不排除）"))
    L.append("- 对照的组件: %s" % "、".join("%s(%s)" % (n, kind_label(k)) for n, k, _ in comps))
    if bad:
        L.append("- **清单里有 %d 行不是 CVE/GHSA/GO 编号，已跳过**：%s" % (len(bad), "；".join(bad[:10])))
    L.append("\n只看非 OS 包：OS 包来自客户自己的基础镜像，不考虑。镜像里直接复制进来、我们没扫的东西（如 tidb-backup-manager 镜像里的 tidb-lightning、dumpling）也不在内。\n")

    L.append("## 总览\n")
    L.append(md_table(["结论", "个数", "含义"], [
        [C_DELIV, cnt[C_DELIV], "镜像或源码构建（Trivy 扫二进制）里能看到，客户扫镜像会看到"],
        [C_BRANCH, cnt[C_BRANCH], "只在分支的源码清单（go.mod、lock 文件）里，我们扫的二进制里没有"],
        [C_RESOLVED, cnt[C_RESOLVED], "以前的扫描里有，最新结果里没有了"],
        [C_OS, cnt[C_OS], "只在 OS 包里出现过，不考虑"],
        [C_NEVER, cnt[C_NEVER], "所选组件的任何一次扫描里都没有（可能在没选、没扫的组件或镜像里，或扫描器的库没收录）"],
        [C_EXCL, cnt[C_EXCL], "配置里排除的"],
    ]))

    L.append("\n## 扫描结果来源（每个组件最新一次）\n")
    rows = []
    for name, kind, m in metas:
        if m is None:
            rows.append([name, kind_label(kind), "-", "**没有结果**"])
            continue
        if kind == "image":
            what = "`%s`" % m.get("image", "")
        elif kind == "build":
            what = "%s 分支 HEAD %s" % (m.get("source", ""), (m.get("commit") or "")[:7])
        else:
            what = "%s @ %s" % (m.get("branch", ""), (m.get("commit") or "")[:7])
        rows.append([name, kind_label(kind), (m.get("scanned_at") or "")[:16].replace("T", " "), what])
    L.append(md_table(["组件", "类型", "扫描时间", "镜像 / 分支"], rows))

    # 1. 交付物
    # 没有镜像/源码构建结果的组件（如 ng-monitoring）：它的分支命中也列进第 1 节，否则会被别的组件的镜像命中“盖住”
    has_bin = {n for n, k, _ in comps if k in ("image", "build")}
    branch_only_comp = lambda h: h["kind"] == "branch" and h["comp"] not in has_bin  # noqa: E731
    deliv = group(res, C_DELIV, ("image", "build"), extra=branch_only_comp)
    L.append("\n## 1. 未解决：镜像 / 源码构建里能看到（%d 个 CVE）\n" % cnt[C_DELIV])
    if deliv:
        L.append("### 1.1 按组件\n")
        L.append("同一个 CVE 可能出现在多个组件里。“处理”：镜像的源码已修复就发新镜像，否则要在分支上升级依赖。"
                 "没有扫镜像或源码构建的组件（类型写“分支”）列的是分支源码清单里的版本。\n")
        for comp, kind, _ in comps:
            rs = sorted([r for r in deliv if r["comp"] == comp and r["kind"] == kind], key=lambda r: (-SEV_RANK.get(r["sev"], 0), r["pkg"]))
            if not rs:
                continue
            L.append("**%s**（%s）\n" % (comp, kind_label(kind)))
            L.append(md_table(["依赖包", "当前版本", "升级到", "最高严重程度", "处理", "CVE"],
                              [[r["pkg"], r["ver"], r["fix"] or "无修复版本", r["sev"], what_to_do(r), ids_cell(r["ids"])] for r in rs]))
        L.append("### 1.2 按依赖包（跨组件合并）\n")
        bypkg = {}
        for r in deliv:
            x = bypkg.setdefault(r["pkg"], {"fix": "", "ids": set(), "where": [], "sev": "UNKNOWN"})
            x["fix"] = max_ver([x["fix"], r["fix"]])
            x["ids"] |= r["ids"]
            x["sev"] = sev_max(x["sev"], r["sev"])
            x["where"].append("%s %s" % (r["comp"], r["ver"]))
        L.append(md_table(["依赖包", "升级到（各组件里最高的）", "最高严重程度", "组件 当前版本", "CVE"],
                          [[p, x["fix"] or "无修复版本", x["sev"], "<br>".join(sorted(set(x["where"]))), ids_cell(x["ids"])]
                           for p, x in sorted(bypkg.items(), key=lambda kv: (-SEV_RANK.get(kv[1]["sev"], 0), kv[0]))]))
    else:
        L.append("无\n")

    # 2. 仅分支
    br = group(res, C_BRANCH, ("branch",))
    L.append("\n## 2. 未解决：只在分支源码里（%d 个 CVE）\n" % cnt[C_BRANCH])
    L.append("我们扫的二进制里没有，客户只扫镜像的话一般看不到；客户扫源码或用了我们没扫的组件时会看到。\n")
    if br:
        order = [(n, k) for n, k, _ in comps]
        rs = sorted(br, key=lambda r: (order.index((r["comp"], r["kind"])), r["pkg"]))
        L.append(md_table(["分支", "依赖包", "生态", "当前版本", "升级到", "最高严重程度", "CVE"],
                          [[r["comp"], r["pkg"], r["eco"], r["ver"], r["fix"] or "无修复版本", r["sev"], ids_cell(r["ids"])] for r in rs]))
    else:
        L.append("无\n")

    # 3. 其他
    L.append("\n## 3. 不需要处理 / 无法判断的\n")
    for title, cat in (("3.1 已解决（以前扫到过，最新结果里没有）", C_RESOLVED),
                       ("3.2 只在 OS 包里（不考虑）", C_OS),
                       ("3.3 所选组件里从未扫到（需要问客户是哪个组件、哪个包）", C_NEVER)):
        xs = [c for c in ids if res[c][0] == cat]
        L.append("**%s：%d 个**\n" % (title, len(xs)))
        L.append((ids_cell(xs) if xs else "无") + "\n")
    xs = [c for c in ids if res[c][0] == C_EXCL]
    L.append("**3.4 配置里排除的：%d 个**\n" % len(xs))
    L.append(md_table(["CVE", "原因"], [[c, excl.get(c) or "-"] for c in xs]) if xs else "无\n")

    L.append("\n## 附录：逐个 CVE\n")
    rows = []
    for c in ids:
        cat, hs = res[c]
        comps_ = sorted({"%s(%s)" % (h["comp"], kind_label(h["kind"])) for h in hs})
        pk = sorted({h["pkg"] for h in hs})
        fx = max_ver([h["fix"] for h in hs])
        rows.append([c, cat, ", ".join(comps_) or "-", ", ".join(pk) or "-", fx or "-"])
    L.append(md_table(["CVE", "结论", "组件", "依赖包", "升级到"], rows))
    return "\n".join(L) + "\n", rows, cnt


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cves", help="CVE 清单（纯文本，一行一个）")
    ap.add_argument("--config", default=None, help="配置文件（默认：清单同目录的 cve_check.conf，其次 config/cve_check.conf）")
    ap.add_argument("--results", default=os.path.join(ROOT, "results"))
    ap.add_argument("--out", default="", help="报告路径（默认 results/cve-check-<清单名>.md，同时写 .tsv）")
    a = ap.parse_args()

    if a.config is None:
        for cand in (os.path.join(os.path.dirname(os.path.abspath(a.cves)), "cve_check.conf"),
                     os.path.join(ROOT, "config", "cve_check.conf")):
            if os.path.isfile(cand):
                a.config = cand
                break
    ids, bad = read_cve_list(a.cves)
    if not ids:
        print("CVE 清单里没有任何编号: %s" % a.cves, file=sys.stderr)
        return 2
    want, excl = read_config(a.config)
    comps = discover_components(a.results)
    if want is not None:
        names = {n for n, _, _ in comps}
        unknown = [w for w in want if w not in names]
        if unknown:
            print("配置里的组件不在 images.conf / builds.conf / branches.conf 里: %s" % ", ".join(unknown), file=sys.stderr)
            return 2
        comps = [c for c in comps if c[0] in want]
    latest, metas = load_latest(comps)
    hist = load_history(comps, set(ids))
    res = classify(ids, excl, latest, hist)
    stem = os.path.splitext(os.path.basename(a.cves))[0]
    if stem in ("cves", "cve", "list"):
        stem = os.path.basename(os.path.dirname(os.path.abspath(a.cves))) or stem
    a.title = stem
    md, rows, cnt = render(a, ids, bad, comps, metas, excl, res)

    out = a.out or os.path.join(a.results, "cve-check-%s.md" % stem)
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(md)
    tsv = os.path.splitext(out)[0] + ".tsv"
    with open(tsv, "w", encoding="utf-8") as f:
        f.write("CVE\t结论\t组件\t依赖包\t升级到\n")
        for r in rows:
            f.write("\t".join(r) + "\n")
    missing = [n for n, _, m in metas if m is None]
    print("%d 个编号：%s" % (len(ids), "，".join("%s %d" % (k, v) for k, v in cnt.items())))
    if missing:
        print("注意：这些组件还没有扫描结果：%s" % ", ".join(missing))
    if bad:
        print("注意：清单里有 %d 行不是编号，已跳过（见报告开头）" % len(bad))
    print("报告: %s" % out)
    print("逐个 CVE: %s" % tsv)
    return 0


if __name__ == "__main__":
    sys.exit(main())

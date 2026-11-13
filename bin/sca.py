#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sca.py - JSON 处理辅助脚本（仅标准库，Python 3.8+），由 bin/run.sh 调用。

子命令:
  validate  检查扫描器输出 / KEV 文件是否为合法 JSON
  report    osv-scanner (+ govulncheck + CISA KEV) -> 按依赖包聚合的报告
  summary   合并所有目标最近一次成功的结果 -> results/report-branches-latest.md
  runstate  写 state/last_run.json
"""
import argparse
import datetime
import json
import math
import os
import re
import sys

SEV_RANK = {"UNKNOWN": 0, "NONE": 0, "LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
# Go 可达性：called = 漏洞函数被调用；imported = 包被引入但漏洞函数未被调用；required = 仅 module 被依赖
REACH_RANK = {"called": 3, "imported": 2, "required": 1, "unknown": 0, "n/a": 0}


# --------------------------------------------------------------------------- 基础工具
def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def norm_ver(v):
    v = str(v or "").strip()
    return re.sub(r"^(go|v)", "", v)


def vkey(v):
    """宽松的 semver 排序键（Go / crates.io / npm 都够用）。预发布版本小于同号正式版。"""
    v = norm_ver(v).split("+")[0]
    core, _, pre = v.partition("-")
    nums = []
    for p in core.split("."):
        m = re.match(r"\d+", p)
        nums.append(int(m.group()) if m else 0)
    while len(nums) < 3:
        nums.append(0)
    return (tuple(nums), 0 if pre else 1, pre)


def _roundup(x):
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vec):
    """由 CVSS v3.x 向量计算基础分；其它版本返回 None。"""
    try:
        if not re.match(r"^CVSS:3\.[01]/", vec):
            return None
        m = dict(p.split(":") for p in vec.split("/")[1:])
        changed = m["S"] == "C"
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        iss = 1 - (1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]])
        if changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        expl = 8.22 * av * ac * pr * ui
        if impact <= 0:
            return 0.0
        if changed:
            return _roundup(min(1.08 * (impact + expl), 10))
        return _roundup(min(impact + expl, 10))
    except Exception:
        return None


def sev_label(score):
    if score is None:
        return ""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return ""


def iter_json_stream(text):
    """govulncheck -format json 输出的是多个连续的 JSON 对象。"""
    dec = json.JSONDecoder()
    i, n = 0, len(text)
    while True:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            return
        obj, j = dec.raw_decode(text, i)
        yield obj
        i = j


# --------------------------------------------------------------------------- govulncheck / KEV
def parse_govulncheck(gdir):
    """返回 (是否至少有一个 module 成功跑完, {(module, version): {漏洞ID或别名: 可达级别}})"""
    reach, ran = {}, False
    if not gdir or not os.path.isdir(gdir):
        return False, reach
    for fn in sorted(os.listdir(gdir)):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(gdir, fn), encoding="utf-8") as f:
                objs = list(iter_json_stream(f.read()))
        except Exception:
            continue
        ran = True
        aliases = {}
        for o in objs:
            if "osv" in o and o["osv"].get("id"):
                aliases[o["osv"]["id"]] = [o["osv"]["id"]] + list(o["osv"].get("aliases") or [])
        for o in objs:
            f = o.get("finding")
            if not f or not f.get("trace"):
                continue
            t0 = f["trace"][0]          # trace[0] 是漏洞符号本身
            level = "called" if t0.get("function") else ("imported" if t0.get("package") else "required")
            slot = reach.setdefault((t0.get("module", ""), norm_ver(t0.get("version", ""))), {})
            for i in aliases.get(f.get("osv"), [f.get("osv")]):
                if REACH_RANK[level] > REACH_RANK.get(slot.get(i, "unknown"), 0):
                    slot[i] = level
    return ran, reach


def lookup_reach(eco, name, ver, ids, ran, reach):
    if eco != "Go":
        return "n/a"
    if not ran:
        return "unknown"
    best = "unknown"
    for (mod, v), slot in reach.items():
        if mod != name:
            continue
        if name != "stdlib" and v != norm_ver(ver):   # stdlib 的版本是实际工具链版本，与 go.mod 的 go 指令可能不同
            continue
        for i in ids:
            lv = slot.get(i)
            if lv and REACH_RANK[lv] > REACH_RANK[best]:
                best = lv
    return best


def load_kev(path):
    if not path or not os.path.isfile(path):
        return None
    try:
        d = load_json(path)
        return {v["cveID"]: v for v in d.get("vulnerabilities", []) if v.get("cveID")}
    except Exception:
        return None


# --------------------------------------------------------------------------- report
def fix_version(vulns, eco, name, cur):
    """返回 (最近的、高于当前版本的修复版本或 None, OSV 是否给出过任何 fixed 事件)。
    没有任何 fixed 事件 = 真正"无已知修复"；有 fixed 但都不高于当前版本 = 数据不一致，不算无修复。"""
    fixed, fixed_any = set(), set()
    for v in vulns:
        for aff in v.get("affected") or []:
            p = aff.get("package") or {}
            same = str(p.get("name", "")).lower() == name.lower()
            for r in aff.get("ranges") or []:
                if r.get("type") not in ("SEMVER", "ECOSYSTEM"):
                    continue
                for ev in r.get("events") or []:
                    if "fixed" in ev:
                        fixed_any.add(ev["fixed"])
                        if same:
                            fixed.add(ev["fixed"])
    pool = fixed or fixed_any
    cands = [f for f in pool if vkey(f) > vkey(cur)]
    return (min(cands, key=vkey) if cands else None), bool(pool)


def affected_ranges(vulns, name):
    """OSV 里这个包的受影响区间 [[introduced, fixed 或 "", last_affected 或 ""], ...]。
    同一个漏洞可能有好几段（例如 <1.82.2 和 [1.83.0, 1.83.2)），只看"下一个 fixed"会挑到另一段里的版本。"""
    out = []
    for v in vulns:
        for aff in v.get("affected") or []:
            if str((aff.get("package") or {}).get("name", "")).lower() != name.lower():
                continue
            for r in aff.get("ranges") or []:
                if r.get("type") not in ("SEMVER", "ECOSYSTEM"):
                    continue
                cur = None
                for ev in r.get("events") or []:
                    if "introduced" in ev:
                        if cur is not None:
                            out.append(cur)
                        cur = [norm_ver(ev["introduced"]), "", ""]
                    elif cur is not None and ("fixed" in ev or "last_affected" in ev):
                        if "fixed" in ev:
                            cur[1] = norm_ver(ev["fixed"])
                        else:
                            cur[2] = norm_ver(ev["last_affected"])
                        out.append(cur)
                        cur = None
                if cur is not None:
                    out.append(cur)
    return [list(x) for x in dict.fromkeys(tuple(x) for x in out)]


def in_ranges(ver, ranges):
    k = vkey(ver)
    for intro, fixed, last in ranges:
        if intro not in ("", "0") and k < vkey(intro):
            continue
        if fixed and k >= vkey(fixed):
            continue
        if last and k > vkey(last):
            continue
        return True
    return False


def safe_fix(issues):
    """几个漏洞一起修时建议升级到的版本：不低于每个漏洞各自的修复版本、且不落在任何一个漏洞受影响区间里的最低版本。
    issues: [{"fix": str, "ranges": [...]}]。没有 ranges（旧数据）时退回取最高。"""
    fixes = [norm_ver(i.get("fix")) for i in issues if i.get("fix")]
    if not fixes:
        return None
    floor = max(fixes, key=vkey)
    ranges = [r for i in issues if i.get("fix") for r in (i.get("ranges") or [])]   # 无修复的漏洞单独提示，不参与
    if not ranges:
        return floor
    cands = {floor} | {r[1] for r in ranges if r[1]}
    # 预发布 / 伪版本（如 1.84.0-dev.0.2026...）不拿来当建议版本
    cands = sorted((c for c in cands if c == floor or (vkey(c) > vkey(floor) and vkey(c)[1] == 1)), key=vkey)
    for c in cands:
        if not in_ranges(c, ranges):
            return c
    return floor


def package_issues(pe, eco, name, ver, kev, ran, reach):
    vulns = [v for v in (pe.get("vulnerabilities") or []) if v.get("id")]
    uf = {}

    def find(x):
        while uf.setdefault(x, x) != x:
            uf[x] = uf[uf[x]]
            x = uf[x]
        return x

    for v in vulns:
        ids = [v["id"]] + list(v.get("aliases") or [])
        find(ids[0])
        for i in ids[1:]:
            uf[find(i)] = find(ids[0])
    groups = {}
    for v in vulns:
        groups.setdefault(find(v["id"]), []).append(v)

    out = []
    for gv in groups.values():
        ids = set()
        for v in gv:
            ids.add(v["id"])
            ids.update(v.get("aliases") or [])
        cves = sorted(i for i in ids if i.startswith("CVE-"))
        issue_id = cves[0] if cves else sorted(ids)[0]

        scores = []
        for g in pe.get("groups") or []:
            if set(g.get("ids") or []) & ids:
                try:
                    scores.append(float(g.get("max_severity")))
                except (TypeError, ValueError):
                    pass
        if not [s for s in scores if s > 0]:
            scores = []
            for v in gv:
                for s in v.get("severity") or []:
                    sc = cvss3_score(str(s.get("score", "")))
                    if sc is not None:
                        scores.append(sc)
        scores = [s for s in scores if s > 0]
        score = max(scores) if scores else None
        label = sev_label(score)
        if not label:
            label = "UNKNOWN"
            for v in gv:
                l = str((v.get("database_specific") or {}).get("severity")
                        or (v.get("ecosystem_specific") or {}).get("severity") or "").upper()
                if l in SEV_RANK and SEV_RANK[l] > SEV_RANK[label]:
                    label = "MEDIUM" if l == "MODERATE" else l

        kev_hit = sorted(c for c in cves if kev is not None and c in kev)
        fix, has_fix_info = fix_version(gv, eco, name, ver)
        out.append({
            "ecosystem": eco, "package": name, "version": ver,
            "id": issue_id, "ids": sorted(ids), "cves": cves,
            "summary": (next((v.get("summary") for v in gv if v.get("summary")), "") or "")[:120],
            "score": score, "severity": label,
            "kev": (None if kev is None else bool(kev_hit)), "kev_cves": kev_hit,
            "reach": lookup_reach(eco, name, ver, ids, ran, reach),
            "fix": fix, "no_fix_info": not has_fix_info, "ranges": affected_ranges(gv, name),
            "published": min((str(v.get("published") or "")[:10] for v in gv if v.get("published")), default=""),
        })
    return out


def fmt_score(s):
    return "" if s is None else "%.1f" % s


def cmd_report(a):
    osv = load_json(a.osv)
    kev = load_kev(a.kev)
    ran, reach = parse_govulncheck(a.govuln_dir)
    ex = re.compile(a.exclude) if a.exclude else None
    meta = load_json(a.meta) if a.meta and os.path.isfile(a.meta) else {}
    wt = os.path.abspath(a.worktree).rstrip("/") if a.worktree else ""
    include_dev = str(a.include_dev) == "1"

    pkgs = {}
    for res in osv.get("results") or []:
        src = (res.get("source") or {}).get("path", "")
        rel = src[len(wt):].lstrip("/") if wt and src.startswith(wt) else src
        if ex and ex.search(rel):
            continue
        for pe in res.get("packages") or []:
            p = pe.get("package") or {}
            eco, name, ver = p.get("ecosystem", ""), p.get("name", ""), p.get("version", "")
            dg = pe.get("dependencyGroups") or pe.get("dependency_groups") or []
            if not include_dev and dg and all(str(g).lower().startswith("dev") for g in dg):
                continue
            entry = pkgs.setdefault((eco, name, ver), {"issues": {}, "sources": set()})
            entry["sources"].add(rel)
            for iss in package_issues(pe, eco, name, ver, kev, ran, reach):
                old = entry["issues"].get(iss["id"])
                if old is None or (iss["score"] or 0) > (old["score"] or 0):
                    entry["issues"][iss["id"]] = iss

    rows, issues = [], []
    for (eco, name, ver), e in pkgs.items():
        iss = list(e["issues"].values())
        if not iss:
            continue
        fixes = [i["fix"] for i in iss if i["fix"]]
        scores = [i["score"] for i in iss if i["score"] is not None]
        sev = max((i["severity"] for i in iss), key=lambda s: SEV_RANK.get(s, 0))
        reach_best = max((i["reach"] for i in iss), key=lambda r: REACH_RANK.get(r, 0))
        rows.append({
            "package": name, "ecosystem": eco, "version": ver,
            "fix_to": safe_fix(iss) if fixes else None,
            "unfixed": sum(1 for i in iss if i.get("no_fix_info")),
            "issue_count": len(iss),
            "cves": sorted(c for i in iss for c in i["cves"]),
            "max_cvss": max(scores) if scores else None, "severity": sev,
            "kev": (None if kev is None else any(i["kev"] for i in iss)),
            "kev_cves": sorted(c for i in iss for c in i["kev_cves"]),
            "reach": reach_best,
            "sources": sorted(e["sources"]),
        })
        issues.extend(iss)
    rows.sort(key=lambda r: (not r["kev"], -REACH_RANK.get(r["reach"], 0), -(r["max_cvss"] or 0),
                             -r["issue_count"], r["package"]))
    issues.sort(key=lambda i: (not i["kev"], -REACH_RANK.get(i["reach"], 0), -(i["score"] or 0), i["package"], i["id"]))

    summary = {
        "packages": len(rows), "issues": len(issues),
        "kev": sum(1 for i in issues if i["kev"]),
        "reachable": sum(1 for i in issues if i["reach"] == "called"),
        "high_critical": sum(1 for i in issues if SEV_RANK.get(i["severity"], 0) >= 3),
        "govulncheck_ran": ran, "kev_available": kev is not None,
    }
    report = {"meta": meta, "summary": summary, "packages": rows, "issues": issues}
    with open(os.path.join(a.out, "report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=1)

    def kev_s(v):
        return "?" if v is None else ("YES" if v else "no")

    def fix_s(r):
        s = r["fix_to"] or "无已知修复"
        return s + (" (另有%d个无修复)" % r["unfixed"] if r["fix_to"] and r["unfixed"] else "")

    hdr = ["依赖包", "生态", "当前版本", "建议升级到", "CVE数", "最高CVSS", "严重程度", "KEV", "可达性"]
    table = [[r["package"], r["ecosystem"], r["version"], fix_s(r), str(r["issue_count"]),
              fmt_score(r["max_cvss"]), r["severity"], kev_s(r["kev"]), r["reach"]] for r in rows]
    with open(os.path.join(a.out, "report.tsv"), "w", encoding="utf-8") as f:
        f.write("\t".join(hdr) + "\n")
        for t in table:
            f.write("\t".join(t) + "\n")
    with open(os.path.join(a.out, "report.md"), "w", encoding="utf-8") as f:
        f.write("# %s @ %s\n\n" % (meta.get("target", "?"), meta.get("branch", "?")))
        f.write("- commit: `%s`\n- 扫描时间: %s\n" % (meta.get("commit", "?"), meta.get("scanned_at", "?")))
        f.write("- 有漏洞的依赖包 %d 个；漏洞 %d 个；KEV %d；Go 可达 %d；高危/严重 %d\n" % (
            summary["packages"], summary["issues"], summary["kev"], summary["reachable"], summary["high_critical"]))
        if not ran:
            f.write("- 注意：本次没有可用的 govulncheck 结果，Go 漏洞可达性均为 unknown\n")
        if kev is None:
            f.write("- 注意：本次没有可用的 CISA KEV 数据，KEV 列为 ?\n")
        f.write("\n| " + " | ".join(hdr) + " |\n|" + "---|" * len(hdr) + "\n")
        for t in table:
            f.write("| " + " | ".join(c.replace("|", "\\|") for c in t) + " |\n")
    print("%d\t%d\t%d\t%d\t%d" % (summary["packages"], summary["issues"], summary["kev"],
                                  summary["reachable"], summary["high_critical"]))
    return 0



# --------------------------------------------------------------------------- summary
def cmd_summary(a):
    """把 branches.conf 里所有目标最近一次成功的结果合并成一个 Markdown 汇总。"""
    import datetime

    def slug(x):
        return re.sub(r"[^A-Za-z0-9._-]", "_", x)

    def esc(x):
        return str(x).replace("|", "\\|")

    def kev_s(v):
        return "?" if v is None else ("YES" if v else "no")

    def fix_s(r):
        s = r["fix_to"] or "无已知修复"
        return s + (" (另有%d个无修复)" % r["unfixed"] if r["fix_to"] and r["unfixed"] else "")

    status = {}
    if a.targets and os.path.isfile(a.targets):
        with open(a.targets, encoding="utf-8") as f:
            for line in f:
                p = line.rstrip("\n").split("\t")
                if len(p) >= 3:
                    status[p[0]] = p[2]
    targets = []
    with open(a.conf, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                p = line.split()
                if len(p) >= 3:
                    targets.append((p[0], p[2]))

    overview, priority, details, reps = [], [], [], []
    for name, branch in targets:
        rp = os.path.join(a.results, name, slug(branch), "latest", "report.json")
        rep = None
        if os.path.isfile(rp):
            try:
                rep = load_json(rp)
            except Exception:
                rep = None
        st = status.get(name, "")
        if st == "OK":
            note = "本次成功"
        elif st.startswith("FAILED"):
            note = "本次失败，下表是上次成功的结果" if rep else "本次失败，尚无成功结果"
        else:
            note = "本次未运行，下表是上次成功的结果" if rep else "尚未扫描"
        if not rep:
            overview.append([name, branch, "-", "-", note, "-", "-", "-", "-", "-", "-"])
            continue
        reps.append((name, rep, os.path.dirname(os.path.realpath(rp))))
        m, sm = rep.get("meta", {}), rep["summary"]
        unscored = sum(1 for i in rep["issues"] if i["score"] is None)
        overview.append([name, branch, (m.get("commit") or "")[:10], (m.get("scanned_at") or "")[:19].replace("T", " "),
                         note, str(sm["packages"]), str(sm["issues"]), str(sm["kev"]), str(sm["reachable"]),
                         str(sm["high_critical"]), str(unscored)])
        for i in rep["issues"]:
            if i["kev"] or i["reach"] == "called":
                priority.append((name, i))
        hdr = ["依赖包", "生态", "当前版本", "建议升级到", "CVE数", "最高CVSS", "严重程度", "KEV", "可达性"]
        rows = [[r["package"], r["ecosystem"], r["version"], fix_s(r), str(r["issue_count"]),
                 fmt_score(r["max_cvss"]), r["severity"], kev_s(r["kev"]), r["reach"]] for r in rep["packages"]]
        details.append((name, branch, note, hdr, rows))

    priority.sort(key=lambda x: (not x[1]["kev"], -REACH_RANK.get(x[1]["reach"], 0), -(x[1]["score"] or 0),
                                 x[0], x[1]["package"], x[1]["id"]))
    out = ["# 依赖漏洞汇总", "",
           "生成时间: %s ｜ 运行ID: %s" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), a.run_id), "",
           "这是每个被跟踪分支**当前**的全部依赖漏洞。数据来自各分支最近一次成功的扫描。", ""]
    out += render_go_official(reps, a.go_days)
    out += ["## 1. 总览", "",
           "| 目标 | 分支 | commit | 扫描时间 | 状态 | 有漏洞的包 | 漏洞数 | KEV | Go可达 | 高危/严重 | 未评分 |",
           "|" + "---|" * 11]
    out += ["| " + " | ".join(esc(c) for c in r) + " |" for r in overview]
    out += ["", "“未评分”= OSV 里还没有 CVSS 评分的漏洞（新披露的 CVE 常见），严重程度显示 UNKNOWN，不代表低危。", "",
            "## 2. 需要优先处理（在 CISA KEV 里，或 Go 代码中可达）", ""]
    if priority:
        out += ["| 目标 | 依赖包 | 当前版本 | 漏洞 | 严重程度(CVSS) | KEV | 可达性 | 建议升级到 |", "|" + "---|" * 8]
        for name, i in priority:
            sc = " (%.1f)" % i["score"] if i["score"] is not None else ""
            out.append("| " + " | ".join(esc(c) for c in [name, i["package"], i["version"], i["id"],
                       i["severity"] + sc, kev_s(i["kev"]), i["reach"], i["fix"] or "无已知修复"]) + " |")
    else:
        out.append("没有。")
    out += ["", "## 3. 各分支按依赖包聚合", "",
            "排序：KEV 优先，其次 Go 可达，再按 CVSS。建议升级到 = 该包所有 CVE 的最高修复版本。"
            "可达性：called=漏洞函数被调用 / imported=包被引入但未调用 / required=仅模块被依赖 / unknown=无 govulncheck 结果 / n/a=非 Go。", ""]
    for name, branch, note, hdr, rows in details:
        out += ["### %s  (%s)" % (name, branch), "", "状态: %s" % note, ""]
        if rows:
            out += ["| " + " | ".join(hdr) + " |", "|" + "---|" * len(hdr)]
            out += ["| " + " | ".join(esc(c) for c in r) + " |" for r in rows]
        else:
            out.append("没有发现依赖漏洞。")
        out.append("")
    tmp = a.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    os.replace(tmp, a.out)
    return 0


# --------------------------------------------------------------------------- 第 0 节：Go 官方近期修复
def is_go_official(pkg):
    return pkg == "stdlib" or pkg.startswith("golang.org/x/")


def published_from_osv(path):
    """旧的 report.json 没有 published 字段时，从同目录的 osv.json 补：{漏洞ID或别名: 最早公布日期}"""
    out = {}
    try:
        j = load_json(path)
    except Exception:
        return out
    for r in j.get("results") or []:
        for pe in r.get("packages") or []:
            for v in pe.get("vulnerabilities") or []:
                d = str(v.get("published") or "")[:10]
                if not d:
                    continue
                for i in [v.get("id")] + list(v.get("aliases") or []):
                    if i and (i not in out or d < out[i]):
                        out[i] = d
    return out


def render_go_official(reps, days, today=None):
    """reps: [(目标名, report.json 内容, 结果目录)]。近 days 天公布、命中各分支的 golang.org/x/* 和标准库漏洞，按公布日期倒序。"""
    today = today or datetime.date.today()
    rows = {}
    for name, rep, rdir in reps:
        fallback = None
        for i in rep.get("issues") or []:
            if i.get("ecosystem") != "Go" or not is_go_official(i.get("package", "")):
                continue
            pub = i.get("published")
            if not pub:
                if fallback is None:
                    fallback = published_from_osv(os.path.join(rdir, "osv.json"))
                pub = min((fallback[x] for x in i.get("ids") or [i["id"]] if x in fallback), default="")
            try:
                age = (today - datetime.date.fromisoformat(pub)).days
            except ValueError:
                continue
            if age > days:
                continue
            k = (pub, i["package"], i["id"])
            r = rows.setdefault(k, {"sev": i["severity"], "score": i["score"], "kev": False,
                                    "fix": set(), "title": i.get("summary") or "", "hits": []})
            if SEV_RANK.get(i["severity"], 0) > SEV_RANK.get(r["sev"], 0):
                r["sev"] = i["severity"]
            if (i["score"] or 0) > (r["score"] or 0):
                r["score"] = i["score"]
            r["kev"] = r["kev"] or bool(i.get("kev"))
            if i.get("fix"):
                r["fix"].add(i["fix"])
            hit = "%s %s" % (name, i["version"])
            if hit not in r["hits"]:
                r["hits"].append(hit)
    out = ["## 0. Go 官方近期修复，命中分支（近 %d 天，按公布日期倒序）" % days, "",
           "只看 Go 官方团队维护的 golang.org/x/* 和 Go 标准库。命中写法：目标 分支中的版本。"
           "公布日期取自 OSV（同一漏洞有多个编号时取最早的），和 golang-announce 公告日期可能差一两天。"
           "修复版本 = 各分支“高于当前版本的最小修复版本”的合集。客户扫的是镜像，镜像里的情况见 report-images-latest.md 第 0 节。", ""]
    if not rows:
        return out + ["无", ""]
    out += ["| 公布日期 | 漏洞 | 包 | 严重程度 | KEV | 修复版本 | 说明 | 命中分支 |", "|" + "---|" * 8]
    for (pub, pkg, vid), r in sorted(rows.items(), key=lambda kv: kv[0], reverse=True):
        cells = [pub, vid, pkg, r["sev"] + (" (%.1f)" % r["score"] if r["score"] else ""),
                 "YES" if r["kev"] else "", ", ".join(sorted(r["fix"], key=vkey)) or "无已知修复",
                 r["title"][:70].replace("|", "/").replace("\n", " ") or "-", "<br>".join(r["hits"])]
        out.append("| " + " | ".join(cells) + " |")
    return out + [""]


# --------------------------------------------------------------------------- runstate / validate
def cmd_runstate(a):
    targets = []
    if os.path.isfile(a.targets):
        with open(a.targets, encoding="utf-8") as f:
            for line in f:
                p = ["" if x == "-" else x for x in line.rstrip("\n").split("\t")]
                p += [""] * (6 - len(p))
                targets.append({"name": p[0], "branch": p[1], "status": p[2], "commit": p[3],
                                "issues": int(p[4]) if p[4].isdigit() else None, "message": p[5]})
    state = {"run_id": a.run_id, "status": a.status, "started": a.started, "finished": a.finished,
             "errors": int(a.errors), "warnings": int(a.warnings), "targets": targets}
    tmp = a.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=1)
    os.replace(tmp, a.out)
    return 0


def cmd_validate(a):
    try:
        d = load_json(a.file)
    except Exception as e:
        print("invalid JSON in %s: %s" % (a.file, e), file=sys.stderr)
        return 1
    if not isinstance(d, dict):
        print("unexpected JSON shape (not an object)", file=sys.stderr)
        return 1
    if a.kind == "kev" and not (isinstance(d.get("vulnerabilities"), list) and d["vulnerabilities"]):
        print("KEV file has no 'vulnerabilities'", file=sys.stderr)
        return 1
    if a.kind == "osv" and d.get("results") not in (None, []) and not isinstance(d.get("results"), list):
        print("OSV output has unexpected 'results'", file=sys.stderr)
        return 1
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)

    p = sp.add_parser("validate"); p.add_argument("--kind", choices=["osv", "kev"], required=True); p.add_argument("file")
    p.set_defaults(fn=cmd_validate)

    p = sp.add_parser("report")
    p.add_argument("--osv", required=True); p.add_argument("--govuln-dir", default="")
    p.add_argument("--kev", default=""); p.add_argument("--exclude", default="")
    p.add_argument("--include-dev", default="0"); p.add_argument("--worktree", default="")
    p.add_argument("--meta", default=""); p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_report)

    p = sp.add_parser("summary")
    for k in ("conf", "results", "targets", "run-id", "out"):
        p.add_argument("--" + k, required=True)
    p.add_argument("--go-days", type=int, default=90)
    p.set_defaults(fn=cmd_summary)

    p = sp.add_parser("runstate")
    for k in ("out", "status", "run-id", "started", "finished", "errors", "warnings", "targets"):
        p.add_argument("--" + k, required=True)
    p.set_defaults(fn=cmd_runstate)

    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())

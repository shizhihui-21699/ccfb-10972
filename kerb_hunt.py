#!/usr/bin/env python3
"""
kerb_hunt.py — hunt Kerberos anomalies in exported DC Security EVTX logs.

Focus: 4768 (TGT request), 4769 (TGS request), 4771 (pre-auth failed).

Detections (thresholds are CLI-tunable):
  1. RC4 burst      — one account requests many RC4(0x17)-encrypted service
                      tickets inside a short window (kerberoasting)
  2. Long TGT       — a TGT keeps being used far beyond the normal 10 h
                      domain lifetime (inferred from 4768 -> 4769 activity)
  3. New host       — an account authenticates from a host/IP never seen
                      for it before AND requests a high-privilege service
                      (DC-targeting or remote-admin service classes)
  4. Spray          — many 4771 pre-auth failures for distinct accounts
                      from one source IP inside a short window

Outputs (into --out dir):
  timeline.csv   all Kerberos events, normalized
  baseline.json  per-account / per-service baseline
  alerts.json    machine-readable alerts
  alerts.md      human report: alerts + evidence + attack timeline

Usage:
    python3 kerb_hunt.py security.evtx -o hunt_out
"""

import argparse
import collections
import csv
import datetime
import json
import os
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evtx

KERB_EIDS = (4768, 4769, 4771)

ENC_NAMES = {
    0x01: "DES-CBC-CRC", 0x03: "DES-CBC-MD5",
    0x11: "AES128-CTS-HMAC-SHA1-96", 0x12: "AES256-CTS-HMAC-SHA1-96",
    0x17: "RC4-HMAC", 0x18: "RC4-HMAC-EXP",
}
STATUS_NAMES = {
    0x0: "success",
    0x6: "KDC_ERR_C_PRINCIPAL_UNKNOWN (user not found)",
    0x17: "KDC_ERR_KEY_EXPIRED (password expired)",
    0x18: "KDC_ERR_PREAUTH_FAILED (wrong password)",
    0x25: "KDC_ERR_PREAUTH_REQUIRED",
}
# service classes that mean remote administration / sensitive access
ADMIN_CLASSES = {"wsman", "termsrv", "rpc", "winrm", "ssh", "powershell"}
# service classes that are sensitive when they target a DC directly
DC_CLASSES = {"cifs", "ldap", "host", "rpc", "dns", "wsman", "termsrv",
              "http", "ifs"}


# ---------------------------------------------------------------------------
# parsing / normalization
# ---------------------------------------------------------------------------
def _local(tag):
    return tag.rsplit("}", 1)[-1]


def parse_time(s):
    s = s.strip().rstrip("Z")
    if "." in s:
        main, frac = s.split(".", 1)
        frac = (frac + "000000")[:6]
    else:
        main, frac = s, "0"
    dt = datetime.datetime.strptime(main, "%Y-%m-%dT%H:%M:%S")
    return dt.replace(microsecond=int(frac), tzinfo=datetime.timezone.utc)


def to_int(s):
    if s is None:
        return None
    s = s.strip()
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return None


def parse_event_xml(xml):
    root = ET.fromstring(xml)
    sys_el = data_el = None
    for c in root:
        n = _local(c.tag)
        if n == "System":
            sys_el = c
        elif n in ("EventData", "UserData"):
            data_el = c
    out = {"data": {}}
    for c in sys_el:
        n = _local(c.tag)
        if n == "EventID":
            out["eid"] = int(c.text)
        elif n == "TimeCreated":
            out["time"] = parse_time(c.get("SystemTime"))
        elif n == "EventRecordID":
            out["record_id"] = int(c.text)
        elif n == "Computer":
            out["computer"] = c.text or ""
    if data_el is not None:
        for d in data_el:
            if _local(d.tag) == "Data" and d.get("Name"):
                out["data"][d.get("Name")] = d.text or ""
    return out


def normalize(ev):
    d = ev["data"]
    ip = (d.get("IpAddress") or "").replace("::ffff:", "")
    return {
        "time": ev["time"],
        "eid": ev["eid"],
        "record_id": ev["record_id"],
        "computer": ev["computer"],
        "user": d.get("TargetUserName", ""),
        "service": d.get("ServiceName", ""),
        "ip": ip,
        "enc": to_int(d.get("TicketEncryptionType")),
        "status": to_int(d.get("Status")),
        "options": d.get("TicketOptions", ""),
    }


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# detections
# ---------------------------------------------------------------------------
def detect_rc4_bursts(events, threshold, window_sec):
    """Clusters of RC4-encrypted 4769s per account (kerberoasting)."""
    by_user = collections.defaultdict(list)
    for e in events:
        if e["eid"] == 4769 and e["enc"] == 0x17:
            by_user[e["user"]].append(e)
    alerts = []
    for user, evs in sorted(by_user.items()):
        evs.sort(key=lambda e: e["time"])
        # cluster consecutive RC4 requests with inter-arrival <= window
        cluster = [evs[0]]
        for e in evs[1:]:
            if (e["time"] - cluster[-1]["time"]).total_seconds() <= window_sec:
                cluster.append(e)
            else:
                if len(cluster) >= threshold:
                    alerts.append((user, cluster))
                cluster = [e]
        if len(cluster) >= threshold:
            alerts.append((user, cluster))
    out = []
    for user, cl in alerts:
        spns = sorted({e["service"] for e in cl})
        ips = sorted({e["ip"] for e in cl})
        # was this account AES-only before the burst?
        prior = [e for e in events
                 if e["eid"] == 4769 and e["user"] == user
                 and e["time"] < cl[0]["time"]]
        prior_rc4 = any(e["enc"] == 0x17 for e in prior)
        note = "" if prior_rc4 else \
            "该账户此前从未使用 RC4（全部 AES），疑似加密降级。"
        out.append({
            "type": "rc4_burst",
            "severity": "high",
            "title": "疑似 Kerberoasting：账户 %s 短时大量 RC4 票据请求"
                     % user,
            "summary": (
                "%s ~ %s（%d 秒）内账户 %s 从 %s 请求了 %d 张 RC4-HMAC "
                "(0x17) 加密的服务票据，涉及 %d 个不同 SPN。%s"
                % (iso(cl[0]["time"]), iso(cl[-1]["time"]),
                   (cl[-1]["time"] - cl[0]["time"]).total_seconds(),
                   user, "/".join(ips), len(cl), len(spns), note)),
            "account": user,
            "source_ips": ips,
            "spn_count": len(spns),
            "sample_spns": spns[:10],
            "evidence": cl,
            "recommendation": "排查来源主机是否运行 Rubeus/Impacket 等工具；"
                              "重置该账户口令；检查被请求 SPN 对应服务账户"
                              "的口令强度（RC4 票据可离线爆破）。",
        })
    return out


def detect_long_tgt(events, max_hours, gap_sec):
    """TGT used far beyond the normal domain lifetime (default max 10 h).

    For each 4768 (TGT issued at t0), chain subsequent 4769s of the same
    account while consecutive requests are <= gap_sec apart (a TGT in
    active use produces regular TGS traffic). If the chain extends past
    max_hours, the ticket outlived the domain limit. The gap rule also
    makes the check robust to missing data (e.g. skipped corrupt chunks):
    a long silence breaks the chain instead of inflating the span.
    """
    by_user_4768 = collections.defaultdict(list)
    by_user_4769 = collections.defaultdict(list)
    for e in events:
        if e["eid"] == 4768 and e["status"] == 0:
            by_user_4768[e["user"]].append(e)
        elif e["eid"] == 4769:
            by_user_4769[e["user"]].append(e)
    out = []
    for user, tgts in sorted(by_user_4768.items()):
        tgts.sort(key=lambda e: e["time"])
        uses = sorted(by_user_4769.get(user, []), key=lambda e: e["time"])
        for i, tgt in enumerate(tgts):
            t0 = tgt["time"]
            t1 = tgts[i + 1]["time"] if i + 1 < len(tgts) else None
            session = [e for e in uses
                       if t0 <= e["time"] and (t1 is None or e["time"] < t1)]
            chain = []
            chain_end = t0
            for e in session:
                if (e["time"] - chain_end).total_seconds() <= gap_sec:
                    chain.append(e)
                    chain_end = e["time"]
                else:
                    break
            if not chain:
                continue
            hours = (chain_end - t0).total_seconds() / 3600.0
            if hours > max_hours:
                out.append({
                    "type": "long_tgt",
                    "severity": "medium",
                    "title": "票据有效期异常：账户 %s 的 TGT 被持续使用 "
                             "%.1f 小时" % (user, hours),
                    "summary": (
                        "账户 %s 于 %s 从 %s 获取 TGT 后，直到 %s 仍在使用"
                        "该 TGT 请求服务票据（连续活动跨度 %.1f 小时，域默"
                        "认上限 10 小时），期间未重新认证。疑似伪造/窃取的"
                        "长期票据（如 Golden Ticket）。" % (
                            user, iso(t0), tgt["ip"], iso(chain_end),
                            hours)),
                    "account": user,
                    "source_ips": sorted({tgt["ip"]} |
                                         {e["ip"] for e in chain}),
                    "span_hours": round(hours, 1),
                    "evidence": [tgt] + chain,
                    "recommendation": "检查该账户 TGT 的加密类型与来源主机；"
                                      "若确认伪造票据，需两次重置 krbtgt "
                                      "账户口令。",
                })
    return out


def detect_new_host_highpriv(events, min_history, established_sec,
                             new_ip_sec):
    """Established account, first-seen host/IP, high-privilege service.

    An account is "established" once its first-ever event is older than
    `established_sec`; an IP is "new" if first seen for this account within
    `new_ip_sec` before the event. Both windows are computed from
    first-seen timestamps (not a running set), so the 4768 logon from the
    new host doesn't whitelist the IP for the 4769s that follow it.
    """
    dc_names = set()
    first_seen_user = {}
    first_seen_ip = {}
    for e in events:
        if e["computer"]:
            dc_names.add(e["computer"].lower())
            dc_names.add(e["computer"].split(".")[0].lower())
        u = e["user"]
        if u:
            if u not in first_seen_user or e["time"] < first_seen_user[u]:
                first_seen_user[u] = e["time"]
            key = (u, e["ip"])
            if e["ip"] and (key not in first_seen_ip
                            or e["time"] < first_seen_ip[key]):
                first_seen_ip[key] = e["time"]

    def sensitive(service):
        if not service or "/" not in service:
            return False
        cls, _, host = service.partition("/")
        cls = cls.lower()
        host_short = host.split(".")[0].lower()
        if cls in ADMIN_CLASSES:
            return True
        return cls in DC_CLASSES and host_short in dc_names

    global_first_ip = {}
    for e in events:
        if e["ip"] and (e["ip"] not in global_first_ip
                        or e["time"] < global_first_ip[e["ip"]]):
            global_first_ip[e["ip"]] = e["time"]

    hist_count = collections.Counter()
    alerts = {}
    for e in sorted(events, key=lambda x: x["time"]):
        if e["eid"] not in (4768, 4769):
            continue
        user, ip = e["user"], e["ip"]
        if user and ip:
            established = (e["time"] - first_seen_user[user]
                           ).total_seconds() >= established_sec
            ip_age = (e["time"] - first_seen_ip[(user, ip)]
                      ).total_seconds()
            if (established and hist_count[user] >= min_history
                    and ip_age <= new_ip_sec
                    and e["eid"] == 4769 and sensitive(e["service"])):
                key = (user, ip)
                globally_new = (global_first_ip[ip] >=
                                first_seen_ip[(user, ip)])
                if key not in alerts:
                    alerts[key] = {
                        "type": "new_host_highpriv",
                        "severity": "high" if globally_new else "medium",
                        "title": "新主机突访高权限服务：账户 %s 来自陌生地址 "
                                 "%s" % (user, ip),
                        "account": user,
                        "source_ips": [ip],
                        "evidence": [],
                        "services": set(),
                        "recommendation": "核实该来源主机归属；检查账户凭据"
                                          "是否被盗用（Pass-the-Hash / 被窃"
                                          "票据重放）；必要时强制改密。",
                    }
                alerts[key]["evidence"].append(e)
                alerts[key]["services"].add(e["service"])
                if globally_new:
                    alerts[key]["severity"] = "high"
            hist_count[user] += 1
    out = []
    for (user, ip), a in alerts.items():
        evs = a["evidence"]
        known = sorted({k[1] for k in first_seen_ip
                        if k[0] == user and k[1] != ip})
        a["summary"] = (
            "账户 %s 的历史来源地址为 %s，%s 起突然从陌生地址 %s 请求高权限"
            "服务：%s。%s" % (
                user, ", ".join(known[:5]) or "(无)", iso(evs[0]["time"]),
                ip, ", ".join(sorted(a["services"])),
                "该地址在整个日志中从未出现过。" if a["severity"] == "high"
                else "该地址此前被其他账户使用过。"))
        a["services"] = sorted(a["services"])
        out.append(a)
    return out


def detect_spray(events, threshold, window_sec):
    """Many 4771 pre-auth failures for distinct accounts from one IP."""
    by_ip = collections.defaultdict(list)
    for e in events:
        if e["eid"] == 4771 and e["status"] in (0x18, 0x17, 0x6):
            by_ip[e["ip"]].append(e)
    out = []
    for ip, evs in sorted(by_ip.items()):
        evs.sort(key=lambda e: e["time"])
        cluster = [evs[0]]
        clusters = []
        for e in evs[1:]:
            if (e["time"] - cluster[-1]["time"]).total_seconds() <= window_sec:
                cluster.append(e)
            else:
                clusters.append(cluster)
                cluster = [e]
        clusters.append(cluster)
        for cl in clusters:
            users = sorted({e["user"] for e in cl})
            if len(users) >= threshold:
                out.append({
                    "type": "password_spray",
                    "severity": "high",
                    "title": "疑似口令喷洒：%s 对 %d 个账户预认证失败" % (
                        ip, len(users)),
                    "summary": (
                        "%s ~ %s 内，来源 %s 对 %d 个不同账户产生 %d 条 "
                        "Kerberos 预认证失败（4771，状态 %s）。典型口令喷洒"
                        "特征。" % (
                            iso(cl[0]["time"]), iso(cl[-1]["time"]), ip,
                            len(users), len(cl),
                            STATUS_NAMES.get(cl[0]["status"], "?"))),
                    "source_ips": [ip],
                    "account_count": len(users),
                    "accounts": users,
                    "evidence": cl,
                    "recommendation": "封禁/限速来源地址；检查喷射窗口之后"
                                      "是否有任一目标账户登录成功（4768 "
                                      "成功或 4624）；强制受影响账户改密。",
                })
    return out


# ---------------------------------------------------------------------------
# baseline
# ---------------------------------------------------------------------------
def build_baseline(events):
    per_user = {}
    per_service = collections.defaultdict(
        lambda: {"accounts": set(), "count": 0})
    for e in events:
        u = per_user.setdefault(e["user"], {
            "ips": set(), "services": set(),
            "enc_types": collections.Counter(),
            "events": 0, "failures": 0,
            "first_seen": None, "last_seen": None})
        u["events"] += 1
        if e["ip"]:
            u["ips"].add(e["ip"])
        if e["service"]:
            u["services"].add(e["service"])
            s = per_service[e["service"]]
            s["accounts"].add(e["user"])
            s["count"] += 1
        if e["enc"] is not None:
            u["enc_types"][ENC_NAMES.get(e["enc"],
                                         "0x%x" % e["enc"])] += 1
        if e["eid"] == 4771:
            u["failures"] += 1
        if u["first_seen"] is None or e["time"] < u["first_seen"]:
            u["first_seen"] = e["time"]
        if u["last_seen"] is None or e["time"] > u["last_seen"]:
            u["last_seen"] = e["time"]
    return {
        "accounts": {
            u: {"ips": sorted(v["ips"]),
                "services": sorted(v["services"]),
                "enc_types": dict(v["enc_types"]),
                "events": v["events"],
                "failures": v["failures"],
                "first_seen": iso(v["first_seen"]),
                "last_seen": iso(v["last_seen"])}
            for u, v in sorted(per_user.items())},
        "services": {
            s: {"accounts": sorted(v["accounts"]), "count": v["count"]}
            for s, v in sorted(per_service.items())},
    }


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------
SEV_ORDER = {"high": 0, "medium": 1, "low": 2}


def ev_line(e):
    return "%s  %-4d  %-12s  %-40s  %-15s  enc=%-4s st=%s" % (
        iso(e["time"]), e["eid"], e["user"][:12], e["service"][:40],
        e["ip"], ("0x%x" % e["enc"]) if e["enc"] is not None else "-",
        ("0x%x" % e["status"]) if e["status"] is not None else "-")


def write_report(path, alerts, warnings, events, args):
    lines = []
    lines.append("# Kerberos 安全检测报告")
    lines.append("")
    lines.append("- 日志文件：`%s`" % args.evtx)
    lines.append("- 解析到 Kerberos 事件（4768/4769/4771）：%d 条" % len(events))
    if events:
        lines.append("- 时间范围：%s ~ %s" % (iso(events[0]["time"]),
                                               iso(events[-1]["time"])))
    lines.append("- 阈值：RC4 突发 ≥%d 次/%d 秒；TGT 使用 >%.1f 小时；"
                 "喷洒 ≥%d 账户/%d 秒" % (
                     args.rc4_burst, args.rc4_window, args.max_tgt_hours,
                     args.spray_accounts, args.spray_window))
    if warnings:
        lines.append("")
        lines.append("## 解析警告（已跳过，未中断）")
        lines.append("")
        for w in warnings:
            lines.append("- %s" % w)
    lines.append("")
    lines.append("## 告警（%d 条）" % len(alerts))
    for i, a in enumerate(alerts, 1):
        lines.append("")
        lines.append("### %d. [%s] %s" % (i, a["severity"].upper(),
                                          a["title"]))
        lines.append("")
        lines.append(a["summary"])
        lines.append("")
        lines.append("**处置建议**：%s" % a["recommendation"])
        lines.append("")
        lines.append("证据（前 12 条，共 %d 条）：" % len(a["evidence"]))
        lines.append("")
        lines.append("```")
        for e in a["evidence"][:12]:
            lines.append(ev_line(e))
        if len(a["evidence"]) > 12:
            lines.append("... 其余 %d 条略" % (len(a["evidence"]) - 12))
        lines.append("```")
    # attack timeline: every event referenced by any alert
    lines.append("")
    lines.append("## 攻击时间线（告警涉及事件，按时间排序）")
    lines.append("")
    tagged = {}
    for a in alerts:
        for e in a["evidence"]:
            tagged.setdefault(e["record_id"], (e, set()))[1].add(a["type"])
    lines.append("```")
    for e, tags in sorted(tagged.values(),
                          key=lambda x: x[0]["time"]):
        lines.append("%s  [%s]" % (ev_line(e), ",".join(sorted(tags))))
    lines.append("```")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("evtx")
    ap.add_argument("-o", "--out", default="hunt_out")
    ap.add_argument("--rc4-burst", type=int, default=20,
                    help="RC4 TGS requests per account per window (def 20)")
    ap.add_argument("--rc4-window", type=int, default=600,
                    help="RC4 burst window, seconds (def 600)")
    ap.add_argument("--max-tgt-hours", type=float, default=12.0,
                    help="max plausible TGT usage span in hours (def 12)")
    ap.add_argument("--max-gap-hours", type=float, default=3.0,
                    help="max gap between TGS requests to count as one "
                         "TGT session, hours (def 3)")
    ap.add_argument("--spray-accounts", type=int, default=10,
                    help="distinct failed accounts per IP per window (def 10)")
    ap.add_argument("--spray-window", type=int, default=300,
                    help="spray window, seconds (def 300)")
    ap.add_argument("--min-history", type=int, default=5,
                    help="min prior events before new-host detection (def 5)")
    ap.add_argument("--established-hours", type=float, default=24.0,
                    help="account must be this old for new-host alerts "
                         "(def 24)")
    ap.add_argument("--new-ip-hours", type=float, default=24.0,
                    help="an IP counts as new for this long after first "
                         "seen (def 24)")
    args = ap.parse_args()

    f = evtx.EvtxFile(args.evtx)
    events = []
    parse_errors = 0
    for _rid, _ts, xml in f:
        try:
            ev = parse_event_xml(xml)
        except Exception:
            parse_errors += 1
            continue
        if ev.get("eid") in KERB_EIDS:
            events.append(normalize(ev))
    events.sort(key=lambda e: e["time"])
    warnings = list(f.warnings)
    if parse_errors:
        warnings.append("%d events dropped: XML parse failed" % parse_errors)

    if not events:
        print("no Kerberos events (4768/4769/4771) found", file=sys.stderr)
        sys.exit(1)

    alerts = []
    alerts += detect_rc4_bursts(events, args.rc4_burst, args.rc4_window)
    alerts += detect_long_tgt(events, args.max_tgt_hours,
                              args.max_gap_hours * 3600)
    alerts += detect_new_host_highpriv(events, args.min_history,
                                       args.established_hours * 3600,
                                       args.new_ip_hours * 3600)
    alerts += detect_spray(events, args.spray_accounts, args.spray_window)
    alerts.sort(key=lambda a: (SEV_ORDER.get(a["severity"], 9),
                               a["evidence"][0]["time"]))

    # strip event objects -> record ids for JSON
    alerts_json = []
    for a in alerts:
        b = {k: v for k, v in a.items() if k != "evidence"}
        b["evidence_records"] = [e["record_id"] for e in a["evidence"]]
        b["first_seen"] = iso(a["evidence"][0]["time"])
        b["last_seen"] = iso(a["evidence"][-1]["time"])
        alerts_json.append(b)

    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "timeline.csv"), "w", newline="",
              encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["time", "event_id", "record_id", "computer", "account",
                    "service", "ip", "enc_type", "status", "ticket_options"])
        for e in events:
            w.writerow([iso(e["time"]), e["eid"], e["record_id"],
                        e["computer"], e["user"], e["service"], e["ip"],
                        ENC_NAMES.get(e["enc"], e["enc"]),
                        STATUS_NAMES.get(e["status"], e["status"]),
                        e["options"]])
    with open(os.path.join(args.out, "baseline.json"), "w",
              encoding="utf-8") as fh:
        json.dump(build_baseline(events), fh, ensure_ascii=False, indent=2)
    with open(os.path.join(args.out, "alerts.json"), "w",
              encoding="utf-8") as fh:
        json.dump(alerts_json, fh, ensure_ascii=False, indent=2)
    write_report(os.path.join(args.out, "alerts.md"), alerts, warnings,
                 events, args)

    # console summary
    print("解析：%d 条 Kerberos 事件（%s ~ %s）"
          % (len(events), iso(events[0]["time"]), iso(events[-1]["time"])))
    for w in warnings:
        print("警告：%s" % w)
    print("告警：%d 条" % len(alerts))
    for a in alerts:
        print("  [%s] %s" % (a["severity"].upper(), a["title"]))
    print("输出目录：%s（timeline.csv / baseline.json / alerts.json / "
          "alerts.md）" % args.out)


if __name__ == "__main__":
    main()

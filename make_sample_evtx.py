#!/usr/bin/env python3
"""
make_sample_evtx.py — build a format-accurate Security-log EVTX sample.

Writes a real EVTX binary (file header, 64 KB chunks with valid CRCs,
chunk string table stored after the records, BinXML template definitions
+ substitution values) containing a week of synthetic Kerberos activity
plus planted anomalies:

  1. Kerberoasting: one account bursts many RC4 (0x17) TGS requests
  2. Abnormally long-lived TGT (used ~26 h, normal domain max is 10 h)
  3. First-seen host suddenly requesting high-privilege services on the DC
  4. Password spray: many 4771 pre-auth failures from one source IP

One chunk is deliberately corrupted (bad CRC) so the parser's
skip-and-continue behaviour can be verified.

Usage:
    python3 make_sample_evtx.py --out samples/security_sample.evtx
"""

import argparse
import datetime
import random
import struct
import zlib

import evtx  # for VT_* constants and dt_to_filetime

UTC = datetime.timezone.utc
DC = "DC01.corp.local"
PROVIDER_GUID = "{54849625-5478-4994-A5BA-3E3B0328C30D}"

# ---------------------------------------------------------------------------
# BinXML skeleton builder
# ---------------------------------------------------------------------------

def E(name, attrs=None, children=None, text=None, empty=False):
    return ("el", name, attrs or [], children or [], text, empty)


def SUB(idx, vtype):
    return ("sub", idx, vtype)


def TXT(s):
    return ("txt", s)


def LIT(s):
    return ("lit", s)


def _lit_string(s):
    """Literal StringType value inside a template skeleton:
    token 0x05, type 0x01, u16 char count, UTF-16LE chars (no NUL)."""
    enc = s.encode("utf-16le")
    return b"\x05" + bytes([evtx.VT_STRING]) \
        + struct.pack("<H", len(enc) // 2) + enc


def _ser_attr_value(av):
    if av[0] == "lit":
        return _lit_string(av[1])
    if av[0] == "sub":
        return b"\x0d" + struct.pack("<H", av[1]) + bytes([av[2]])
    raise ValueError(av)


def ser_node(node, n2o):
    kind = node[0]
    if kind == "sub":
        return b"\x0d" + struct.pack("<H", node[1]) + bytes([node[2]])
    if kind == "txt":
        return _lit_string(node[1])
    _, name, attrs, children, text, empty = node
    attr_bytes = b""
    for i, (an, av) in enumerate(attrs):
        more = i < len(attrs) - 1
        attr_bytes += bytes([0x46 if more else 0x06]) \
            + struct.pack("<I", n2o[an]) + _ser_attr_value(av)
    if text is not None:
        children = children + [text]
    body = b"".join(ser_node(c, n2o) for c in children)
    if empty:
        content = attr_bytes + b"\x03"
    else:
        content = attr_bytes + b"\x02" + body + b"\x04"
    tok = 0x41 if attrs else 0x01
    # element data size: name ref + [attr list size] + content
    size = 4 + (4 if attrs else 0) + len(content)
    out = bytes([tok]) + b"\xff\xff" + struct.pack("<I", size) \
        + struct.pack("<I", n2o[name])
    if attrs:
        out += struct.pack("<I", len(attr_bytes))
    return out + content


def event_skeleton(data_fields):
    """BinXML skeleton of a classic Security event: fixed System
    substitutions 0..10, then one substitution per EventData field."""
    sys_children = [
        E("Provider", attrs=[
            ("Name", LIT("Microsoft-Windows-Security-Auditing")),
            ("Guid", LIT(PROVIDER_GUID))], empty=True),
        E("EventID", text=SUB(0, evtx.VT_UINT16)),
        E("Version", text=SUB(1, evtx.VT_UINT8)),
        E("Level", text=SUB(2, evtx.VT_UINT8)),
        E("Task", text=SUB(3, evtx.VT_UINT16)),
        E("Opcode", text=SUB(4, evtx.VT_UINT8)),
        E("Keywords", text=SUB(5, evtx.VT_HEX64)),
        E("TimeCreated", attrs=[("SystemTime", SUB(6, evtx.VT_FILETIME))],
          empty=True),
        E("EventRecordID", text=SUB(7, evtx.VT_UINT64)),
        E("Correlation", empty=True),
        E("Execution", attrs=[("ProcessID", SUB(8, evtx.VT_UINT32)),
                              ("ThreadID", SUB(9, evtx.VT_UINT32))],
          empty=True),
        E("Channel", text=TXT("Security")),
        E("Computer", text=SUB(10, evtx.VT_STRING)),
        E("Security", empty=True),
    ]
    data_children = [
        E("Data", attrs=[("Name", LIT(fname))], text=SUB(11 + i, vt))
        for i, (fname, vt) in enumerate(data_fields)
    ]
    return E("Event",
             attrs=[("xmlns", LIT(
                 "http://schemas.microsoft.com/win/2004/08/events/event"))],
             children=[E("System", children=sys_children),
                       E("EventData", children=data_children)])


# ---------------------------------------------------------------------------
# EVTX writer
# ---------------------------------------------------------------------------

def name_hash(s):
    h = 0
    b = s.encode("utf-16le")
    for i in range(0, len(b), 2):
        h = (h * 0x1003F + (b[i] | (b[i + 1] << 8))) & 0xFFFF
    return h


def name_entry(n):
    enc = n.encode("utf-16le")
    return b"\x00\x00\x00\x00" \
        + struct.pack("<HH", name_hash(n), len(n)) + enc + b"\x00\x00"


def collect_names(skeletons):
    names = set()

    def walk(node):
        if node[0] == "el":
            names.add(node[1])
            for an, _av in node[2]:
                names.add(an)
            for c in node[3]:
                walk(c)
            if node[4] is not None:
                walk(node[4])
    for sk in skeletons:
        walk(sk)
    return sorted(names)


def encode_value(vt, v):
    if vt == evtx.VT_STRING:
        return str(v).encode("utf-16le") + b"\x00\x00"
    if vt == evtx.VT_UINT8:
        return struct.pack("<B", v)
    if vt == evtx.VT_UINT16:
        return struct.pack("<H", v)
    if vt == evtx.VT_UINT32:
        return struct.pack("<I", v)
    if vt == evtx.VT_UINT64:
        return struct.pack("<Q", v)
    if vt == evtx.VT_HEX32:
        return struct.pack("<I", v)
    if vt == evtx.VT_HEX64:
        return struct.pack("<Q", v)
    if vt == evtx.VT_FILETIME:
        return struct.pack("<Q", v)
    raise ValueError("unsupported value type 0x%x" % vt)


def build_record(rec_id, filetime, tmpl_id, values, rec_chunk_off,
                 inline_def, tmpl_off, skeleton):
    frag = b"\x0f\x01\x01\x00"
    inst = b"\x0c\x01" + struct.pack("<I", tmpl_id)
    if inline_def:
        toff = rec_chunk_off + 24 + len(frag) + 2 + 4 + 4
        inst += struct.pack("<I", toff)
        # template definition header: next_template_offset (0), guid, size
        inst += struct.pack("<I", 0) + bytes(16) \
            + struct.pack("<I", len(skeleton)) + skeleton
    else:
        inst += struct.pack("<I", tmpl_off)
    vals = struct.pack("<I", len(values))
    for vt, raw in values:
        vals += struct.pack("<HBB", len(raw), vt, 0)
    for vt, raw in values:
        vals += raw
    binxml = frag + inst + vals + b"\x00"
    size = 24 + len(binxml) + 4
    return struct.pack("<II", 0x2A2A, size) \
        + struct.pack("<Q", rec_id) + struct.pack("<Q", filetime) \
        + binxml + struct.pack("<I", size)


def build_file_header(nchunks, next_rec_id):
    h = bytearray(evtx.FILE_HEADER_SIZE)
    h[0:8] = b"ElfFile\x00"
    struct.pack_into("<Q", h, 8, 0)
    struct.pack_into("<Q", h, 16, nchunks - 1)
    struct.pack_into("<Q", h, 24, next_rec_id)
    struct.pack_into("<I", h, 32, evtx.FILE_HEADER_SIZE)
    struct.pack_into("<H", h, 36, 1)   # minor version
    struct.pack_into("<H", h, 38, 3)   # major version
    struct.pack_into("<H", h, 40, evtx.FILE_HEADER_SIZE)
    struct.pack_into("<H", h, 42, nchunks)
    struct.pack_into("<I", h, 124, zlib.crc32(bytes(h[0:120])) & 0xFFFFFFFF)
    return bytes(h)


def write_evtx(path, events, rnd, corrupt_chunk=1):
    skeletons = {eid: event_skeleton(SCHEMAS[eid]) for eid in SCHEMAS}
    names = collect_names(skeletons.values())
    string_tab = b"".join(name_entry(n) for n in names)

    # pre-compute per-event substitution values (sizes are chunk-independent)
    items = []
    rec_id = 0
    for ev in events:
        rec_id += 1
        items.append((ev, rec_id, event_values(ev, rec_id, rnd)))

    # skeleton serialized length (name offsets are always 4 bytes, so the
    # length does not depend on where the string table lands in a chunk)
    dummy_n2o = {n: 0 for n in names}
    skel_len = {eid: len(b"\x0f\x01\x01\x00" + ser_node(sk, dummy_n2o)
                         + b"\x00")
                for eid, sk in skeletons.items()}

    def rec_size(vals, inline, eid):
        binxml_len = 4 + 10 + (24 + skel_len[eid] if inline else 0) \
            + 4 + len(vals) * 4 + sum(len(raw) for _, raw in vals) + 1
        return 24 + binxml_len + 4

    # pack records into chunks; layout per chunk:
    # [512-byte header][records...][string table][zero padding]
    capacity = evtx.CHUNK_SIZE - evtx.CHUNK_HEADER_SIZE - len(string_tab)
    chunks, cur, cur_size, seen = [], [], 0, set()
    for it in items:
        ev = it[0]
        tid = TMPL_IDS[ev["eid"]]
        inline = tid not in seen
        sz = rec_size(it[2], inline, ev["eid"])
        if cur and cur_size + sz > capacity:
            chunks.append(cur)
            cur, cur_size, seen = [], 0, set()
            inline = True
            sz = rec_size(it[2], inline, ev["eid"])
        seen.add(tid)
        cur.append(it)
        cur_size += sz
    if cur:
        chunks.append(cur)

    blob = build_file_header(len(chunks), rec_id + 1)
    chunk_file_offs = []
    for chunk_items in chunks:
        chunk_file_off = len(blob)
        chunk_file_offs.append(chunk_file_off)

        # this chunk's string table sits right after its records
        seen = set()
        rec_sizes = []
        for (ev, _rid, vals) in chunk_items:
            tid = TMPL_IDS[ev["eid"]]
            inline = tid not in seen
            seen.add(tid)
            rec_sizes.append(rec_size(vals, inline, ev["eid"]))
        st_start = evtx.CHUNK_HEADER_SIZE + sum(rec_sizes)
        n2o, off = {}, st_start
        for n in names:
            n2o[n] = off
            off += len(name_entry(n))
        skel_bytes = {eid: b"\x0f\x01\x01\x00" + ser_node(sk, n2o) + b"\x00"
                      for eid, sk in skeletons.items()}

        # build records
        records, tmpl_offs = [], {}
        rec_file_offs = []
        pos = evtx.CHUNK_HEADER_SIZE
        seen = set()
        for (ev, rid, vals) in chunk_items:
            eid = ev["eid"]
            tid = TMPL_IDS[eid]
            inline = tid not in seen
            rec = build_record(rid, evtx.dt_to_filetime(ev["dt"]), tid,
                               vals, pos, inline, tmpl_offs.get(tid, 0),
                               skel_bytes[eid])
            if inline:
                tmpl_offs[tid] = pos + 24 + 4 + 2 + 4 + 4
            seen.add(tid)
            records.append(rec)
            rec_file_offs.append(chunk_file_off + pos)
            pos += len(rec)

        body = b"".join(records) + string_tab
        free = evtx.CHUNK_HEADER_SIZE + len(body)
        ids = [rid for (_ev, rid, _v) in chunk_items]

        hdr = bytearray(evtx.CHUNK_HEADER_SIZE)
        hdr[0:8] = b"ElfChnk\x00"
        struct.pack_into("<Q", hdr, 8, rec_file_offs[0])
        struct.pack_into("<Q", hdr, 16, rec_file_offs[-1])
        struct.pack_into("<Q", hdr, 24, ids[0])
        struct.pack_into("<Q", hdr, 32, ids[-1])
        struct.pack_into("<I", hdr, 40, evtx.CHUNK_HEADER_SIZE)
        struct.pack_into("<I", hdr, 44,
                         rec_file_offs[-1] - chunk_file_off)
        struct.pack_into("<I", hdr, 48, free)
        struct.pack_into("<I", hdr, 52, zlib.crc32(body) & 0xFFFFFFFF)
        s_offs = [0] * 64
        for i, n in enumerate(names[:64]):
            s_offs[i] = n2o[n]
        struct.pack_into("<64I", hdr, 128, *s_offs)
        t_offs = [0] * 32
        for i, (_tid, o) in enumerate(sorted(tmpl_offs.items())[:32]):
            t_offs[i] = o
        struct.pack_into("<32I", hdr, 384, *t_offs)
        crc = zlib.crc32(bytes(hdr[0:120]) + bytes(hdr[128:512])) & 0xFFFFFFFF
        struct.pack_into("<I", hdr, 120, crc)

        chunk = bytes(hdr) + body
        blob += chunk + b"\x00" * (evtx.CHUNK_SIZE - len(chunk))

    # corrupt one chunk on purpose (bad data CRC -> parser must skip it)
    if corrupt_chunk is not None and 0 <= corrupt_chunk < len(chunks):
        b = bytearray(blob)
        base = chunk_file_offs[corrupt_chunk] + evtx.CHUNK_HEADER_SIZE + 200
        for i in range(base, base + 64):
            b[i] ^= 0xFF
        blob = bytes(b)

    with open(path, "wb") as fh:
        fh.write(blob)
    return len(chunks), rec_id


# ---------------------------------------------------------------------------
# Event schema
# ---------------------------------------------------------------------------
FIELDS_4768 = [("TargetUserName", evtx.VT_STRING),
               ("TargetSid", evtx.VT_STRING),
               ("ServiceName", evtx.VT_STRING),
               ("TicketOptions", evtx.VT_HEX32),
               ("Status", evtx.VT_HEX32),
               ("TicketEncryptionType", evtx.VT_HEX32),
               ("PreAuthType", evtx.VT_UINT16),
               ("IpAddress", evtx.VT_STRING),
               ("IpPort", evtx.VT_UINT16)]
FIELDS_4769 = [("TargetUserName", evtx.VT_STRING),
               ("TargetSid", evtx.VT_STRING),
               ("ServiceName", evtx.VT_STRING),
               ("TicketOptions", evtx.VT_HEX32),
               ("Status", evtx.VT_HEX32),
               ("TicketEncryptionType", evtx.VT_HEX32),
               ("IpAddress", evtx.VT_STRING),
               ("IpPort", evtx.VT_UINT16)]
FIELDS_4771 = [("TargetUserName", evtx.VT_STRING),
               ("TargetSid", evtx.VT_STRING),
               ("ServiceName", evtx.VT_STRING),
               ("TicketOptions", evtx.VT_HEX32),
               ("Status", evtx.VT_HEX32),
               ("FailureCode", evtx.VT_HEX32),
               ("PreAuthType", evtx.VT_UINT16),
               ("IpAddress", evtx.VT_STRING),
               ("IpPort", evtx.VT_UINT16)]

SCHEMAS = {4768: FIELDS_4768, 4769: FIELDS_4769, 4771: FIELDS_4771}
TASKS = {4768: 14339, 4769: 14337, 4771: 14340}
TMPL_IDS = {4768: 1, 4769: 2, 4771: 3}
KEYWORDS_OK = 0x8020000000000000
KEYWORDS_FAIL = 0x8010000000000000


def event_values(ev, rec_id, rnd):
    ft = evtx.dt_to_filetime(ev["dt"])
    kw = KEYWORDS_FAIL if ev["eid"] == 4771 else KEYWORDS_OK
    vals = [
        (evtx.VT_UINT16, ev["eid"]),
        (evtx.VT_UINT8, 0),                      # Version
        (evtx.VT_UINT8, 0),                      # Level
        (evtx.VT_UINT16, TASKS[ev["eid"]]),
        (evtx.VT_UINT8, 0),                      # Opcode
        (evtx.VT_HEX64, kw),
        (evtx.VT_FILETIME, ft),
        (evtx.VT_UINT64, rec_id),
        (evtx.VT_UINT32, 500 + rnd.randint(0, 50)),
        (evtx.VT_UINT32, 600 + rnd.randint(0, 200)),
        (evtx.VT_STRING, DC),
    ]
    for fname, vt in SCHEMAS[ev["eid"]]:
        vals.append((vt, ev["fields"][fname]))
    return [(vt, encode_value(vt, v)) for vt, v in vals]


# ---------------------------------------------------------------------------
# Scenario
# ---------------------------------------------------------------------------
USERS = {
    "alice": "10.0.0.11",
    "bob": "10.0.0.12",
    "carol": "10.0.0.13",
    "dave": "10.0.0.14",
    "svc_backup": "10.0.0.31",
    "admin_w": "10.0.0.5",
}
NORMAL_SPNS = ["cifs/fs01.corp.local", "HTTP/intranet.corp.local",
               "HOST/wks01.corp.local", "ldap/DC01.corp.local",
               "cifs/print01.corp.local"]


def dt(y, mo, d, h, mi, s=0):
    return datetime.datetime(y, mo, d, h, mi, s, tzinfo=UTC)


def gen_events(seed):
    rnd = random.Random(seed)
    events = []

    def add(when, eid, user, service, ip, enc=0x12, status=0x0,
            options=0x40810010, preauth=2, failure=0x0):
        fields = {
            "TargetUserName": user,
            "TargetSid": "S-1-5-21-3623811015-3361044348-30300820-%d"
                         % (1100 + abs(hash(user)) % 800),
            "ServiceName": service,
            "TicketOptions": options,
            "Status": status,
            "TicketEncryptionType": enc,
            "PreAuthType": preauth,
            "FailureCode": failure,
            "IpAddress": ip,
            "IpPort": rnd.randint(49000, 65000),
        }
        events.append({"dt": when, "eid": eid, "fields": fields})

    # ---- baseline: 2026-11-02 .. 2026-11-08 ----
    day0 = datetime.date(2026, 11, 2)
    for i in range(7):
        day = day0 + datetime.timedelta(days=i)
        for user, ip in USERS.items():
            if user == "svc_backup":
                if day == datetime.date(2026, 11, 8):
                    continue  # that night's TGT is the long-lifetime anomaly
                t0 = dt(day.year, day.month, day.day, 1, 0) \
                    + datetime.timedelta(seconds=rnd.randint(0, 300))
                add(t0, 4768, user, "krbtgt", ip)
                for k in range(rnd.randint(2, 4)):
                    add(t0 + datetime.timedelta(minutes=5 + 30 * k),
                        4769, user, "cifs/backup01.corp.local", ip)
                continue
            if rnd.random() < 0.15:
                continue  # day off
            t0 = dt(day.year, day.month, day.day, 8, 0) \
                + datetime.timedelta(seconds=rnd.randint(0, 1800))
            if rnd.random() < 0.10:  # occasional typo
                add(t0 - datetime.timedelta(minutes=1), 4771, user,
                    "krbtgt", ip, status=0x18, failure=0x18)
            add(t0, 4768, user, "krbtgt", ip)
            t = t0
            for _ in range(rnd.randint(8, 14)):
                t += datetime.timedelta(minutes=rnd.randint(15, 60))
                add(t, 4769, user, rnd.choice(NORMAL_SPNS), ip)

    # ---- attack day: 2026-11-09 ----
    # normal background that morning
    for user in ("bob", "carol", "admin_w"):
        ip = USERS[user]
        t0 = dt(2026, 11, 9, 8, 0) \
            + datetime.timedelta(seconds=rnd.randint(0, 1800))
        add(t0, 4768, user, "krbtgt", ip)
        t = t0
        for _ in range(rnd.randint(3, 6)):
            t += datetime.timedelta(minutes=rnd.randint(20, 90))
            add(t, 4769, user, rnd.choice(NORMAL_SPNS), ip)

    # anomaly 1: kerberoasting — alice's account from a new host bursts
    # RC4-encrypted TGS requests for dozens of service SPNs
    t0 = dt(2026, 11, 9, 9, 30, 12)
    add(t0, 4768, "alice", "krbtgt", "10.0.0.66")
    roast_spns = []
    for k in range(20):
        roast_spns.append("MSSQLSvc/sql%02d.corp.local:1433" % (k + 1))
    for k in range(20):
        roast_spns.append("HTTP/web%02d.corp.local" % (k + 1))
    for k in range(20):
        roast_spns.append("svc_app%02d/app%02d.corp.local" % (k + 1, k + 1))
    for k, spn in enumerate(roast_spns):
        add(t0 + datetime.timedelta(seconds=48 + 4 * k), 4769, "alice",
            spn, "10.0.0.66", enc=0x17)

    # anomaly 2: svc_backup TGT stays in use ~26 h (normal max 10 h)
    t0 = dt(2026, 11, 8, 1, 0, 0)
    add(t0, 4768, "svc_backup", "krbtgt", USERS["svc_backup"],
        options=0x40810010)
    for k in range(26):
        add(t0 + datetime.timedelta(hours=1 + k), 4769, "svc_backup",
            "cifs/backup01.corp.local", USERS["svc_backup"])

    # anomaly 3: dave from a never-seen host requests services on the DC
    t0 = dt(2026, 11, 9, 22, 14, 50)
    add(t0, 4768, "dave", "krbtgt", "10.0.9.99")
    add(t0 + datetime.timedelta(seconds=13), 4769, "dave",
        "CIFS/DC01.corp.local", "10.0.9.99")
    add(t0 + datetime.timedelta(seconds=30), 4769, "dave",
        "LDAP/DC01.corp.local", "10.0.9.99")
    add(t0 + datetime.timedelta(seconds=71), 4769, "dave",
        "cifs/DC01.corp.local", "10.0.9.99")

    # anomaly 4: password spray — 4771 for 30 accounts from one IP
    t0 = dt(2026, 11, 9, 3, 12, 0)
    for k in range(30):
        add(t0 + datetime.timedelta(seconds=3 * k), 4771,
            "user%02d" % k, "krbtgt", "10.0.9.100",
            status=0x18, failure=0x18)

    events.sort(key=lambda e: e["dt"])
    return events, rnd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="samples/security_sample.evtx")
    ap.add_argument("--seed", type=int, default=20261109)
    ap.add_argument("--corrupt-chunk", type=int, default=1,
                    help="chunk index to corrupt (-1 = none)")
    args = ap.parse_args()

    import os
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    events, rnd = gen_events(args.seed)
    nchunks, nrecs = write_evtx(
        args.out, events, rnd,
        corrupt_chunk=None if args.corrupt_chunk < 0 else args.corrupt_chunk)
    print("wrote %s: %d events, %d chunks (chunk %d deliberately corrupted)"
          % (args.out, nrecs, nchunks, args.corrupt_chunk))


if __name__ == "__main__":
    main()

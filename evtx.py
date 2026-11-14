#!/usr/bin/env python3
"""
evtx.py — pure-python EVTX (Windows Event Log) binary parser. No dependencies.

Parses the on-disk format directly:
  * file header ("ElfFile")
  * 64 KB chunks ("ElfChnk") with CRC validation — corrupted chunks are
    skipped (warning recorded), parsing continues with the next chunk
  * BinXML: fragment headers, elements/attributes, template instances,
    template definitions (inline in the record, or referenced through the
    chunk template-offset table), substitution values (all common types)
  * element/attribute names from the chunk string table, or inline

Layout reference: libevtx "Windows XML Event Log (EVTX) format" spec.

Usage:
    import evtx
    f = evtx.EvtxFile("security.evtx")
    for record_id, timestamp, xml in f:
        ...
    print(f.warnings)   # corrupted chunks / broken records land here

CLI:  python3 evtx.py file.evtx          # dump XML of every event
"""

import datetime
import struct
import zlib

__all__ = ["EvtxFile", "iter_events", "CorruptChunkError",
           "filetime_to_dt", "dt_to_filetime"]

CHUNK_SIZE = 0x10000
FILE_HEADER_SIZE = 0x1000
CHUNK_HEADER_SIZE = 0x200

_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def filetime_to_dt(ft):
    return _EPOCH + datetime.timedelta(microseconds=ft // 10)


def dt_to_filetime(dt):
    return int((dt - _EPOCH).total_seconds() * 10_000_000)


class CorruptChunkError(Exception):
    pass


# ---------------------------------------------------------------------------
# BinXML value types
# ---------------------------------------------------------------------------
VT_NULL, VT_STRING, VT_ANSI = 0x00, 0x01, 0x02
VT_INT8, VT_UINT8, VT_INT16, VT_UINT16 = 0x03, 0x04, 0x05, 0x06
VT_INT32, VT_UINT32, VT_INT64, VT_UINT64 = 0x07, 0x08, 0x09, 0x0A
VT_REAL32, VT_REAL64, VT_BOOL, VT_BINARY = 0x0B, 0x0C, 0x0D, 0x0E
VT_GUID, VT_SIZET, VT_FILETIME, VT_SYSTIME = 0x0F, 0x10, 0x11, 0x12
VT_SID, VT_HEX32, VT_HEX64 = 0x13, 0x14, 0x15
VT_BXML, VT_WSTRARRAY = 0x21, 0x81

_FIXED_SIZES = {
    VT_INT8: 1, VT_UINT8: 1, VT_INT16: 2, VT_UINT16: 2,
    VT_INT32: 4, VT_UINT32: 4, VT_INT64: 8, VT_UINT64: 8,
    VT_REAL32: 4, VT_REAL64: 8, VT_BOOL: 4, VT_GUID: 16,
    VT_FILETIME: 8, VT_SYSTIME: 16, VT_HEX32: 4, VT_HEX64: 8,
}


def _xesc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _xesc_attr(s):
    return _xesc(s).replace('"', "&quot;")


def _guid_str(b):
    d1, d2, d3 = struct.unpack_from("<IHH", b, 0)
    r = b[8:16]
    return "{%08X-%04X-%04X-%02X%02X-%s}" % (
        d1, d2, d3, r[0], r[1], r[2:].hex().upper())


def _sid_str(b):
    if len(b) < 8:
        return b.hex()
    rev, nsub = b[0], b[1]
    auth = int.from_bytes(b[2:8], "big")
    subs, off = [], 8
    for _ in range(nsub):
        if off + 4 > len(b):
            break
        subs.append(struct.unpack_from("<I", b, off)[0])
        off += 4
    return "S-%d-%d" % (rev, auth) + "".join("-%d" % s for s in subs)


def _iso_filetime(ft):
    dt = filetime_to_dt(ft)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%07dZ" % (ft % 10_000_000)


def format_value(vtype, raw):
    """Render a typed BinXML value as the text Windows would put in the XML."""
    t = vtype & 0x7F
    if vtype & 0x80:  # array flag
        if t == VT_STRING:
            s = raw.decode("utf-16le", "replace").rstrip("\x00")
            return "; ".join(x for x in s.split("\x00") if x)
        return raw.hex()
    if t == VT_NULL:
        return ""
    if t == VT_STRING:
        return raw.decode("utf-16le", "replace").rstrip("\x00")
    if t == VT_ANSI:
        return raw.decode("cp1252", "replace").rstrip("\x00")
    if t == VT_INT8:
        return str(struct.unpack("<b", raw[:1])[0])
    if t == VT_UINT8:
        return str(raw[0])
    if t == VT_INT16:
        return str(struct.unpack("<h", raw[:2])[0])
    if t == VT_UINT16:
        return str(struct.unpack("<H", raw[:2])[0])
    if t == VT_INT32:
        return str(struct.unpack("<i", raw[:4])[0])
    if t == VT_UINT32:
        return str(struct.unpack("<I", raw[:4])[0])
    if t == VT_INT64:
        return str(struct.unpack("<q", raw[:8])[0])
    if t == VT_UINT64:
        return str(struct.unpack("<Q", raw[:8])[0])
    if t == VT_REAL32:
        return repr(struct.unpack("<f", raw[:4])[0])
    if t == VT_REAL64:
        return repr(struct.unpack("<d", raw[:8])[0])
    if t == VT_BOOL:
        return "true" if struct.unpack("<I", raw[:4])[0] else "false"
    if t == VT_BINARY:
        return raw.hex().upper()
    if t == VT_GUID:
        return _guid_str(raw)
    if t == VT_SIZET:
        return str(struct.unpack("<Q", raw[:8].ljust(8, b"\x00"))[0])
    if t == VT_FILETIME:
        return _iso_filetime(struct.unpack("<Q", raw[:8])[0])
    if t == VT_SYSTIME:
        y, mo, _dow, d, h, mi, s, ms = struct.unpack("<8H", raw[:16])
        return "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ" % (y, mo, d, h, mi, s, ms)
    if t == VT_SID:
        return _sid_str(raw)
    if t == VT_HEX32:
        return "0x%08X" % struct.unpack("<I", raw[:4])[0]
    if t == VT_HEX64:
        return "0x%016X" % struct.unpack("<Q", raw[:8])[0]
    return raw.hex()


def _read_template_value(data, p, vtype):
    """Read a literal value inside a template skeleton. Returns (raw, consumed).

    Literal strings in skeletons are u16 char-count prefixed (not NUL
    terminated); fixed-size types use their natural width.
    """
    t = vtype & 0x7F
    if t in _FIXED_SIZES:
        n = _FIXED_SIZES[t]
        return data[p:p + n], n
    if t == VT_STRING:
        n = struct.unpack_from("<H", data, p)[0]
        return data[p + 2:p + 2 + 2 * n], 2 + 2 * n
    if t == VT_ANSI:
        n = struct.unpack_from("<H", data, p)[0]
        return data[p + 2:p + 2 + n], 2 + n
    # binary / sid / unknown in a skeleton: fall back to remaining length
    return data[p:], len(data) - p


# ---------------------------------------------------------------------------
# Chunk
# ---------------------------------------------------------------------------
class Chunk:
    def __init__(self, data, file_offset, index):
        self.data = data
        self.file_offset = file_offset
        self.index = index
        self.names = {}            # chunk offset -> name string (cache)
        self.template_offsets = {} # chunk offset -> (skeleton, skeleton_base)

    def parse_header(self):
        d = self.data
        if len(d) < CHUNK_HEADER_SIZE or d[:8] != b"ElfChnk\x00":
            raise CorruptChunkError("bad chunk magic")
        stored = struct.unpack_from("<I", d, 120)[0]
        calc = zlib.crc32(d[0:120] + d[128:512]) & 0xFFFFFFFF
        if stored != calc:
            raise CorruptChunkError(
                "header CRC mismatch (stored 0x%08X, computed 0x%08X)"
                % (stored, calc))
        self.first_rec = struct.unpack_from("<Q", d, 24)[0]
        self.last_rec = struct.unpack_from("<Q", d, 32)[0]
        self.last_rec_data_off = struct.unpack_from("<I", d, 44)[0]
        self.free_off = struct.unpack_from("<I", d, 48)[0]
        # event-records data CRC (offset 52) covers the region after the
        # 512-byte header up to the free-space offset
        data_crc = struct.unpack_from("<I", d, 52)[0]
        if CHUNK_HEADER_SIZE <= self.free_off <= len(d):
            calc_data = zlib.crc32(d[CHUNK_HEADER_SIZE:self.free_off]) \
                & 0xFFFFFFFF
            if data_crc != calc_data:
                raise CorruptChunkError(
                    "event data CRC mismatch (stored 0x%08X, computed "
                    "0x%08X)" % (data_crc, calc_data))
        self.string_offsets = struct.unpack_from("<64I", d, 128)
        self.template_table = struct.unpack_from("<32I", d, 384)

    def lookup_name(self, off):
        if off in self.names:
            return self.names[off]
        d = self.data
        # name entry: [4-byte prefix][hash u16][char count u16][utf16][u16 0]
        # be tolerant: also try without the 4-byte prefix
        for prefix in (4, 0):
            try:
                n = struct.unpack_from("<H", d, off + prefix + 2)[0]
                if 0 < n < 1024 and off + prefix + 4 + 2 * n + 2 <= len(d):
                    s = d[off + prefix + 4:off + prefix + 4 + 2 * n]
                    term = d[off + prefix + 4 + 2 * n:
                             off + prefix + 4 + 2 * n + 2]
                    if term == b"\x00\x00":
                        name = s.decode("utf-16le")
                        self.names[off] = name
                        return name
            except Exception:
                pass
        raise ValueError("bad name entry at chunk offset 0x%x" % off)

    def template_at(self, off):
        """Fetch a template definition stored at chunk offset `off`.

        Definition header: next_template_offset u32, guid 16, data_size u32,
        then the BinXML skeleton (fragment header included).
        """
        if off in self.template_offsets:
            return self.template_offsets[off]
        d = self.data
        if off + 24 > len(d):
            raise ValueError("template offset 0x%x out of chunk" % off)
        dlen = struct.unpack_from("<I", d, off + 20)[0]
        if off + 24 + dlen > len(d):
            raise ValueError("template at 0x%x overruns chunk" % off)
        entry = (d[off + 24:off + 24 + dlen], off + 24)
        self.template_offsets[off] = entry
        return entry

    def records(self):
        """Yield (record_id, filetime, binxml, binxml_chunk_offset)."""
        d = self.data
        free = self.free_off if CHUNK_HEADER_SIZE <= self.free_off <= len(d) \
            else len(d)
        last_off = self.last_rec_data_off
        pos = CHUNK_HEADER_SIZE
        while pos + 24 <= free:
            sig = struct.unpack_from("<I", d, pos)[0]
            if sig != 0x2A2A:
                # resync: scan for the next record signature
                nxt = d.find(b"\x2a\x2a\x00\x00", pos + 1, free)
                if nxt < 0:
                    break
                pos = nxt
                continue
            size = struct.unpack_from("<I", d, pos + 4)[0]
            if size < 28 or pos + size > len(d):
                pos += 4
                continue
            rec_id = struct.unpack_from("<Q", d, pos + 8)[0]
            ts = struct.unpack_from("<Q", d, pos + 16)[0]
            yield rec_id, ts, d[pos + 24:pos + size - 4], pos + 24
            if pos == last_off:
                break  # last record per the chunk header; stop before the
                # string table / free space that follows the records
            pos += size


# ---------------------------------------------------------------------------
# BinXML renderer
# ---------------------------------------------------------------------------
class BinXmlRenderer:
    """Renders BinXML (a record, or a template skeleton) to XML text.

    `base` is the chunk-relative offset of data[0]; name references and
    template offsets in the stream are chunk-relative, so we need it.
    """

    def __init__(self, chunk, base):
        self.chunk = chunk
        self.base = base

    def render(self, data, values=None):
        self.data = data
        self.pos = 0
        self.values = values
        out = []
        self._level(out)
        return "".join(out)

    def _u2(self, p):
        return struct.unpack_from("<H", self.data, p)[0]

    def _u4(self, p):
        return struct.unpack_from("<I", self.data, p)[0]

    def _level(self, out):
        d = self.data
        while self.pos < len(d):
            tok = d[self.pos]
            if tok == 0x00:            # end of stream
                self.pos += 1
                return
            if tok == 0x04:            # close element: caller consumes
                return
            if tok == 0x0F:            # fragment header
                self.pos += 4
                continue
            if tok in (0x01, 0x41):    # open start element
                self._element(out)
                continue
            if tok == 0x05:            # literal value
                vt = d[self.pos + 1]
                raw, used = _read_template_value(d, self.pos + 2, vt)
                out.append(_xesc(format_value(vt, raw)))
                self.pos += 2 + used
                continue
            if tok in (0x0D, 0x0E):    # substitution (normal / conditional)
                idx = self._u2(self.pos + 1)
                vt = d[self.pos + 3]
                out.append(_xesc(self._subst(idx, vt)))
                self.pos += 4
                continue
            if tok == 0x0C:            # template instance
                self._template_instance(out)
                continue
            raise ValueError("unknown BinXML token 0x%02X at offset %d"
                             % (tok, self.pos))

    def _subst(self, idx, vt):
        if self.values is None or idx >= len(self.values):
            return ""
        real_vt, raw = self.values[idx]
        return format_value(real_vt if real_vt is not None else vt, raw)

    def _name(self, pos):
        """Read an element/attribute name. Returns (name, bytes_consumed)."""
        abspos = self.base + pos
        off = self._u4(pos)
        if off == abspos + 4:
            # name stored inline right after the reference:
            # [next_string u32][hash u16][char count u16][utf16][nul u16]
            n = self._u2(pos + 10)
            s = self.data[pos + 12:pos + 12 + 2 * n].decode("utf-16le")
            return s, 12 + 2 * n + 2
        return self.chunk.lookup_name(off), 4

    def _element(self, out):
        d = self.data
        tok = d[self.pos]
        has_attrs = tok == 0x41
        size = self._u4(self.pos + 3)
        region = self.pos + 7
        name, nlen = self._name(region)
        p = region + nlen
        attrs = []
        if has_attrs:
            # attribute list data size (u32) precedes the attributes
            p += 4
            while True:
                atok = d[p]
                if atok not in (0x06, 0x46):
                    raise ValueError("expected attribute token, got 0x%02X"
                                     % atok)
                more = atok == 0x46
                aname, alen = self._name(p + 1)
                p += 1 + alen
                vtok = d[p]
                if vtok == 0x05:
                    vt = d[p + 1]
                    raw, used = _read_template_value(d, p + 2, vt)
                    aval = format_value(vt, raw)
                    p += 2 + used
                elif vtok in (0x0D, 0x0E):
                    idx = self._u2(p + 1)
                    aval = self._subst(idx, d[p + 3])
                    p += 4
                else:
                    raise ValueError("bad attribute value token 0x%02X"
                                     % vtok)
                attrs.append((aname, aval))
                if not more:
                    break
        closetok = d[p]
        p += 1
        attr_s = "".join(' %s="%s"' % (n, _xesc_attr(v)) for n, v in attrs)
        if closetok == 0x03:           # empty element
            out.append("<%s%s/>" % (name, attr_s))
            self.pos = p
            return
        if closetok != 0x02:
            raise ValueError("expected close-start token, got 0x%02X"
                             % closetok)
        out.append("<%s%s>" % (name, attr_s))
        self.pos = p
        self._level(out)
        if self.pos >= len(d) or d[self.pos] != 0x04:
            raise ValueError("missing close-element for <%s>" % name)
        self.pos += 1
        out.append("</%s>" % name)

    def _template_instance(self, out):
        d = self.data
        p = self.pos
        tmpl_off = self._u4(p + 6)
        p += 10
        if tmpl_off == self.base + p:
            # template definition is inline, right here:
            # next_template_offset u32, guid 16, data_size u32, skeleton
            dlen = self._u4(p + 20)
            skel = d[p + 24:p + 24 + dlen]
            skel_base = self.base + p + 24
            self.chunk.template_offsets[tmpl_off] = (skel, skel_base)
            p += 24 + dlen
        else:
            skel, skel_base = self.chunk.template_at(tmpl_off)
        nvals = self._u4(p)
        p += 4
        descs = []
        for _ in range(nvals):
            size = self._u2(p)
            vt = d[p + 2]
            descs.append((size, vt))
            p += 4
        values = []
        for size, vt in descs:
            values.append((vt, d[p:p + size]))
            p += size
        out.append(BinXmlRenderer(self.chunk, skel_base).render(skel, values))
        self.pos = p


# ---------------------------------------------------------------------------
# File
# ---------------------------------------------------------------------------
class EvtxFile:
    def __init__(self, path):
        self.path = path
        self.warnings = []

    def __iter__(self):
        with open(self.path, "rb") as fh:
            data = fh.read()
        if data[:8] != b"ElfFile\x00":
            raise ValueError("not an EVTX file (bad 'ElfFile' magic)")
        off = FILE_HEADER_SIZE
        index = 0
        while off + CHUNK_HEADER_SIZE <= len(data):
            cdata = data[off:off + CHUNK_SIZE]
            chunk = Chunk(cdata, off, index)
            try:
                chunk.parse_header()
            except CorruptChunkError as e:
                self.warnings.append(
                    "chunk %d (file offset 0x%x): %s — chunk skipped"
                    % (index, off, e))
                off += CHUNK_SIZE
                index += 1
                continue
            for rec_id, ts, binxml, base in chunk.records():
                try:
                    xml = BinXmlRenderer(chunk, base).render(binxml)
                    yield rec_id, filetime_to_dt(ts), xml
                except Exception as e:
                    self.warnings.append(
                        "record %d (chunk %d): BinXML parse failed: %s — "
                        "record skipped" % (rec_id, index, e))
            off += CHUNK_SIZE
            index += 1


def iter_events(path):
    yield from EvtxFile(path)


if __name__ == "__main__":
    import sys
    f = EvtxFile(sys.argv[1])
    n = 0
    for _rid, _ts, xml in f:
        sys.stdout.write(xml + "\n")
        n += 1
    for w in f.warnings:
        sys.stderr.write("warning: %s\n" % w)
    sys.stderr.write("%d events\n" % n)

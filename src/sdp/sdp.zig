//! SDP for WebRTC offer/answer (RFC 8866, RFC 8829 JSEP, RFC 8843 BUNDLE).
//!
//! Parsing keeps every line in order so a description serialises back byte for byte, and
//! offers typed accessors (ICE credentials, fingerprint, setup, codecs, SSRCs...) on top.
//! Writing builds our own descriptions from `Description`. Media kinds are free-form, so an
//! `application` m-line (data channels) parses today and can be generated later.

const std = @import("std");

pub const Line = struct {
    type: u8,
    value: []const u8,
};

pub const Direction = enum {
    sendrecv,
    sendonly,
    recvonly,
    inactive,

    pub fn reverse(d: Direction) Direction {
        return switch (d) {
            .sendonly => .recvonly,
            .recvonly => .sendonly,
            else => d,
        };
    }
};

pub const Setup = enum {
    actpass,
    active,
    passive,
    holdconn,
};

pub const Codec = struct {
    pt: u8,
    name: []const u8,
    clock: u32,
    channels: u8 = 1,
    fmtp: []const u8 = "",

    /// Value of `key` in "a=fmtp" ("k=v;k=v").
    pub fn param(c: Codec, key: []const u8) ?[]const u8 {
        var it = std.mem.tokenizeScalar(u8, c.fmtp, ';');
        while (it.next()) |kv| {
            const t = std.mem.trim(u8, kv, " ");
            const eq = std.mem.indexOfScalar(u8, t, '=') orelse continue;
            if (std.ascii.eqlIgnoreCase(t[0..eq], key)) return t[eq + 1 ..];
        }
        return null;
    }
};

pub const Media = struct {
    kind: []const u8,
    port: u16,
    proto: []const u8,
    /// Format list after the protocol (payload types for RTP).
    formats: []const u8,
    /// Lines after the m= line, in order.
    lines: []const Line,

    /// First "a=name" or "a=name:value"; returns the value ("" for flags).
    pub fn attr(m: *const Media, name: []const u8) ?[]const u8 {
        return findAttr(m.lines, name);
    }

    pub fn attrs(m: *const Media, name: []const u8) AttrIterator {
        return .{ .lines = m.lines, .name = name };
    }

    pub fn mid(m: *const Media) ?[]const u8 {
        return m.attr("mid");
    }

    pub fn direction(m: *const Media) Direction {
        inline for (comptime std.meta.fieldNames(Direction)) |f| {
            if (m.attr(f) != null) return @field(Direction, f);
        }
        return .sendrecv;
    }

    pub fn rtcpMux(m: *const Media) bool {
        return m.attr("rtcp-mux") != null;
    }

    pub fn payloadTypes(m: *const Media) std.mem.TokenIterator(u8, .scalar) {
        return std.mem.tokenizeScalar(u8, m.formats, ' ');
    }

    /// Codec description for payload type `pt` from a=rtpmap and a=fmtp.
    pub fn codec(m: *const Media, pt: u8) ?Codec {
        var it = m.attrs("rtpmap");
        const map = while (it.next()) |v| {
            if (ptPrefix(v)) |p| if (p.pt == pt) break p.rest;
        } else return null;
        var parts = std.mem.splitScalar(u8, map, '/');
        var c: Codec = .{ .pt = pt, .name = parts.next() orelse return null, .clock = 0 };
        c.clock = std.fmt.parseInt(u32, parts.next() orelse "0", 10) catch 0;
        if (parts.next()) |ch| c.channels = std.fmt.parseInt(u8, ch, 10) catch 1;
        var f = m.attrs("fmtp");
        while (f.next()) |v| if (ptPrefix(v)) |p| if (p.pt == pt) {
            c.fmtp = p.rest;
        };
        return c;
    }

    pub fn hasFeedback(m: *const Media, pt: u8, fb: []const u8) bool {
        var it = m.attrs("rtcp-fb");
        while (it.next()) |v| if (ptPrefix(v)) |p| if ((p.pt == pt or p.wildcard) and std.mem.eql(u8, p.rest, fb)) return true;
        return false;
    }

    /// SSRCs announced with a=ssrc (first of each, in order, without duplicates).
    pub fn ssrcs(m: *const Media, out: []u32) []u32 {
        var n: usize = 0;
        var it = m.attrs("ssrc");
        while (it.next()) |v| {
            const sp = std.mem.indexOfScalar(u8, v, ' ') orelse v.len;
            const s = std.fmt.parseInt(u32, v[0..sp], 10) catch continue;
            if (std.mem.indexOfScalar(u32, out[0..n], s) != null) continue;
            if (n == out.len) break;
            out[n] = s;
            n += 1;
        }
        return out[0..n];
    }

    /// The header extension id for `uri`, if negotiated.
    pub fn extmapId(m: *const Media, uri: []const u8) ?u8 {
        var it = m.attrs("extmap");
        while (it.next()) |v| {
            var t = std.mem.tokenizeScalar(u8, v, ' ');
            const id_text = t.next() orelse continue;
            const slash = std.mem.indexOfScalar(u8, id_text, '/') orelse id_text.len;
            if (std.mem.eql(u8, t.next() orelse "", uri)) return std.fmt.parseInt(u8, id_text[0..slash], 10) catch null;
        }
        return null;
    }
};

fn ptPrefix(v: []const u8) ?struct { pt: u8, wildcard: bool, rest: []const u8 } {
    const sp = std.mem.indexOfScalar(u8, v, ' ') orelse return null;
    if (std.mem.eql(u8, v[0..sp], "*")) return .{ .pt = 0, .wildcard = true, .rest = v[sp + 1 ..] };
    const pt = std.fmt.parseInt(u8, v[0..sp], 10) catch return null;
    return .{ .pt = pt, .wildcard = false, .rest = v[sp + 1 ..] };
}

fn findAttr(lines: []const Line, name: []const u8) ?[]const u8 {
    var it: AttrIterator = .{ .lines = lines, .name = name };
    return it.next();
}

pub const AttrIterator = struct {
    lines: []const Line,
    name: []const u8,
    i: usize = 0,

    pub fn next(it: *AttrIterator) ?[]const u8 {
        while (it.i < it.lines.len) {
            const l = it.lines[it.i];
            it.i += 1;
            if (l.type != 'a' or !std.mem.startsWith(u8, l.value, it.name)) continue;
            const rest = l.value[it.name.len..];
            if (rest.len == 0) return "";
            if (rest[0] == ':') return rest[1..];
        }
        return null;
    }
};

/// A parsed session description. Owns a copy of the text.
pub const Session = struct {
    arena: std.heap.ArenaAllocator,
    /// Lines before the first m= line.
    lines: []const Line,
    media: []const Media,

    pub fn parse(gpa: std.mem.Allocator, text: []const u8) !Session {
        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        const a = arena.allocator();
        const copy = try a.dupe(u8, text);
        var session_lines: std.ArrayList(Line) = .empty;
        var media: std.ArrayList(Media) = .empty;
        var current: std.ArrayList(Line) = .empty;
        var it = std.mem.splitScalar(u8, copy, '\n');
        var saw_version = false;
        while (it.next()) |raw| {
            const line = std.mem.trimEnd(u8, raw, "\r");
            if (line.len == 0) continue;
            if (line.len < 2 or line[1] != '=') return error.BadSdpLine;
            const l: Line = .{ .type = line[0], .value = line[2..] };
            if (!saw_version) {
                if (l.type != 'v') return error.MissingVersion;
                saw_version = true;
            }
            if (l.type == 'm') {
                if (media.items.len > 0) media.items[media.items.len - 1].lines = try current.toOwnedSlice(a);
                var t = std.mem.tokenizeScalar(u8, l.value, ' ');
                const kind = t.next() orelse return error.BadMediaLine;
                const port = std.fmt.parseInt(u16, t.next() orelse return error.BadMediaLine, 10) catch return error.BadMediaLine;
                const proto = t.next() orelse return error.BadMediaLine;
                try media.append(a, .{ .kind = kind, .port = port, .proto = proto, .formats = t.rest(), .lines = &.{} });
            } else if (media.items.len > 0) {
                try current.append(a, l);
            } else {
                try session_lines.append(a, l);
            }
        }
        if (!saw_version) return error.MissingVersion;
        if (media.items.len > 0) media.items[media.items.len - 1].lines = try current.toOwnedSlice(a);
        return .{ .arena = arena, .lines = try session_lines.toOwnedSlice(a), .media = try media.toOwnedSlice(a) };
    }

    pub fn deinit(s: *Session) void {
        s.arena.deinit();
    }

    pub fn attr(s: *const Session, name: []const u8) ?[]const u8 {
        return findAttr(s.lines, name);
    }

    /// Media-level attribute with session-level fallback (ICE and fingerprint may be either).
    pub fn mediaAttr(s: *const Session, m: *const Media, name: []const u8) ?[]const u8 {
        return m.attr(name) orelse s.attr(name);
    }

    pub fn bundleMids(s: *const Session) std.mem.TokenIterator(u8, .scalar) {
        const g = s.attr("group") orelse "";
        const rest = if (std.mem.startsWith(u8, g, "BUNDLE")) g["BUNDLE".len..] else "";
        return std.mem.tokenizeScalar(u8, rest, ' ');
    }

    /// Writes the description back in SDP form with CRLF line endings.
    pub fn write(s: *const Session, w: *std.Io.Writer) std.Io.Writer.Error!void {
        for (s.lines) |l| try w.print("{c}={s}\r\n", .{ l.type, l.value });
        for (s.media) |m| {
            try w.print("m={s} {d} {s}", .{ m.kind, m.port, m.proto });
            if (m.formats.len > 0) try w.print(" {s}", .{m.formats});
            try w.writeAll("\r\n");
            for (m.lines) |l| try w.print("{c}={s}\r\n", .{ l.type, l.value });
        }
    }
};

/// Splits "sha-256 AB:CD:..." into algorithm and value.
pub fn splitFingerprint(v: []const u8) ?struct { algorithm: []const u8, value: []const u8 } {
    const sp = std.mem.indexOfScalar(u8, v, ' ') orelse return null;
    return .{ .algorithm = v[0..sp], .value = std.mem.trim(u8, v[sp + 1 ..], " ") };
}

// ---- writing our own descriptions --------------------------------------------------------

pub const LocalCodec = struct {
    pt: u8,
    name: []const u8,
    clock: u32,
    channels: u8 = 1,
    fmtp: []const u8 = "",
    feedback: []const []const u8 = &.{},
};

pub const Extmap = struct { id: u8, uri: []const u8 };

pub const LocalMedia = struct {
    kind: []const u8, // "audio" | "video" (| "application" later)
    mid: []const u8,
    direction: Direction = .sendrecv,
    codecs: []const LocalCodec,
    extmaps: []const Extmap = &.{},
    /// 0 when not sending.
    ssrc: u32 = 0,
    cname: []const u8 = "",
    stream_id: []const u8 = "",
    track_id: []const u8 = "",
    rtcp_rsize: bool = false,
    /// A rejected m-line in an answer (port 0).
    rejected: bool = false,
    /// For rejecting non-RTP sections (e.g. "UDP/DTLS/SCTP" + "webrtc-datachannel"): echo
    /// the offer's protocol and format list and write only the minimal lines.
    raw_proto: ?[]const u8 = null,
    raw_formats: []const u8 = "",
};

pub const Description = struct {
    session_id: u64,
    version: u32 = 2,
    ice_ufrag: []const u8,
    ice_pwd: []const u8,
    fingerprint: []const u8, // "AB:CD:..." (sha-256)
    setup: Setup,
    media: []const LocalMedia,
    /// "candidate:..." lines written into every bundled m-line's first section.
    candidates: []const []const u8 = &.{},
    end_of_candidates: bool = false,
};

pub fn write(d: Description, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.print("v=0\r\no=- {d} {d} IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n", .{ d.session_id, d.version });
    try w.writeAll("a=group:BUNDLE");
    for (d.media) |m| if (!m.rejected) try w.print(" {s}", .{m.mid});
    try w.writeAll("\r\na=msid-semantic: WMS");
    for (d.media) |m| if (m.stream_id.len > 0) {
        try w.print(" {s}", .{m.stream_id});
        break;
    };
    try w.writeAll("\r\n");
    var candidates_written = false;
    for (d.media) |m| {
        if (m.raw_proto) |proto| {
            try w.print("m={s} 0 {s} {s}\r\nc=IN IP4 0.0.0.0\r\na=mid:{s}\r\n", .{ m.kind, proto, m.raw_formats, m.mid });
            continue;
        }
        try w.print("m={s} {d} UDP/TLS/RTP/SAVPF", .{ m.kind, @as(u16, if (m.rejected) 0 else 9) });
        for (m.codecs) |c| try w.print(" {d}", .{c.pt});
        try w.writeAll("\r\nc=IN IP4 0.0.0.0\r\na=rtcp:9 IN IP4 0.0.0.0\r\n");
        try w.print("a=ice-ufrag:{s}\r\na=ice-pwd:{s}\r\na=ice-options:trickle\r\n", .{ d.ice_ufrag, d.ice_pwd });
        try w.print("a=fingerprint:sha-256 {s}\r\na=setup:{t}\r\na=mid:{s}\r\n", .{ d.fingerprint, d.setup, m.mid });
        for (m.extmaps) |e| try w.print("a=extmap:{d} {s}\r\n", .{ e.id, e.uri });
        try w.print("a={t}\r\n", .{if (m.rejected) Direction.inactive else m.direction});
        if (m.ssrc != 0 and m.stream_id.len > 0) try w.print("a=msid:{s} {s}\r\n", .{ m.stream_id, m.track_id });
        try w.writeAll("a=rtcp-mux\r\n");
        if (m.rtcp_rsize) try w.writeAll("a=rtcp-rsize\r\n");
        for (m.codecs) |c| {
            try w.print("a=rtpmap:{d} {s}/{d}", .{ c.pt, c.name, c.clock });
            if (c.channels > 1) try w.print("/{d}", .{c.channels});
            try w.writeAll("\r\n");
            for (c.feedback) |fb| try w.print("a=rtcp-fb:{d} {s}\r\n", .{ c.pt, fb });
            if (c.fmtp.len > 0) try w.print("a=fmtp:{d} {s}\r\n", .{ c.pt, c.fmtp });
        }
        if (m.ssrc != 0) {
            try w.print("a=ssrc:{d} cname:{s}\r\n", .{ m.ssrc, m.cname });
            if (m.stream_id.len > 0) try w.print("a=ssrc:{d} msid:{s} {s}\r\n", .{ m.ssrc, m.stream_id, m.track_id });
        }
        if (!m.rejected and !candidates_written) {
            candidates_written = true;
            for (d.candidates) |c| try w.print("a={s}\r\n", .{c});
            if (d.end_of_candidates) try w.writeAll("a=end-of-candidates\r\n");
        }
    }
}

// ---- tests --------------------------------------------------------------------------------

const testing = std.testing;

/// A Chrome 13x offer (audio + video, unified plan, max-bundle), as RTCPeerConnection
/// produces it after addTrack(audio) and addTrack(video).
pub const chrome_offer =
    "v=0\r\n" ++
    "o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n" ++
    "s=-\r\n" ++
    "t=0 0\r\n" ++
    "a=group:BUNDLE 0 1\r\n" ++
    "a=extmap-allow-mixed\r\n" ++
    "a=msid-semantic: WMS 3f1e6a2c-9d4b-4f7e-8a1c-5b2d7e9f0a13\r\n" ++
    "m=audio 9 UDP/TLS/RTP/SAVPF 111 63 9 0 8 13 110 126\r\n" ++
    "c=IN IP4 0.0.0.0\r\n" ++
    "a=rtcp:9 IN IP4 0.0.0.0\r\n" ++
    "a=candidate:1467250027 1 udp 2122260223 192.168.1.20 49846 typ host generation 0 network-id 1 network-cost 10\r\n" ++
    "a=ice-ufrag:Zx3k\r\n" ++
    "a=ice-pwd:Yq0g7m1o2H9vS4bT6nR8pL3c\r\n" ++
    "a=ice-options:trickle\r\n" ++
    "a=fingerprint:sha-256 7B:8B:F0:65:5F:78:E2:51:3B:AC:6F:F3:3F:46:1B:35:DC:B8:5F:64:1A:24:C2:43:F0:A1:58:D0:A1:2C:19:08\r\n" ++
    "a=setup:actpass\r\n" ++
    "a=mid:0\r\n" ++
    "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n" ++
    "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n" ++
    "a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n" ++
    "a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n" ++
    "a=sendrecv\r\n" ++
    "a=msid:3f1e6a2c-9d4b-4f7e-8a1c-5b2d7e9f0a13 a7c3e1f0-2b4d-4c6e-9f8a-1d3b5c7e9f02\r\n" ++
    "a=rtcp-mux\r\n" ++
    "a=rtcp-rsize\r\n" ++
    "a=rtpmap:111 opus/48000/2\r\n" ++
    "a=rtcp-fb:111 transport-cc\r\n" ++
    "a=fmtp:111 minptime=10;useinbandfec=1\r\n" ++
    "a=rtpmap:63 red/48000/2\r\n" ++
    "a=fmtp:63 111/111\r\n" ++
    "a=rtpmap:9 G722/8000\r\n" ++
    "a=rtpmap:0 PCMU/8000\r\n" ++
    "a=rtpmap:8 PCMA/8000\r\n" ++
    "a=rtpmap:13 CN/8000\r\n" ++
    "a=rtpmap:110 telephone-event/48000\r\n" ++
    "a=rtpmap:126 telephone-event/8000\r\n" ++
    "a=ssrc:2711883041 cname:p0kD3e8hQ2wM1vZt\r\n" ++
    "a=ssrc:2711883041 msid:3f1e6a2c-9d4b-4f7e-8a1c-5b2d7e9f0a13 a7c3e1f0-2b4d-4c6e-9f8a-1d3b5c7e9f02\r\n" ++
    "m=video 9 UDP/TLS/RTP/SAVPF 96 97 102 103 104 105 106 107 108 109 127 125 39 40 116 117 118\r\n" ++
    "c=IN IP4 0.0.0.0\r\n" ++
    "a=rtcp:9 IN IP4 0.0.0.0\r\n" ++
    "a=ice-ufrag:Zx3k\r\n" ++
    "a=ice-pwd:Yq0g7m1o2H9vS4bT6nR8pL3c\r\n" ++
    "a=ice-options:trickle\r\n" ++
    "a=fingerprint:sha-256 7B:8B:F0:65:5F:78:E2:51:3B:AC:6F:F3:3F:46:1B:35:DC:B8:5F:64:1A:24:C2:43:F0:A1:58:D0:A1:2C:19:08\r\n" ++
    "a=setup:actpass\r\n" ++
    "a=mid:1\r\n" ++
    "a=extmap:14 urn:ietf:params:rtp-hdrext:toffset\r\n" ++
    "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n" ++
    "a=extmap:13 urn:3gpp:video-orientation\r\n" ++
    "a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n" ++
    "a=extmap:5 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay\r\n" ++
    "a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n" ++
    "a=extmap:10 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n" ++
    "a=extmap:11 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id\r\n" ++
    "a=sendrecv\r\n" ++
    "a=msid:3f1e6a2c-9d4b-4f7e-8a1c-5b2d7e9f0a13 c94d1e2f-7a3b-4e5c-8d9f-0b1a2c3d4e5f\r\n" ++
    "a=rtcp-mux\r\n" ++
    "a=rtcp-rsize\r\n" ++
    "a=rtpmap:96 VP8/90000\r\n" ++
    "a=rtcp-fb:96 goog-remb\r\n" ++
    "a=rtcp-fb:96 transport-cc\r\n" ++
    "a=rtcp-fb:96 ccm fir\r\n" ++
    "a=rtcp-fb:96 nack\r\n" ++
    "a=rtcp-fb:96 nack pli\r\n" ++
    "a=rtpmap:97 rtx/90000\r\n" ++
    "a=fmtp:97 apt=96\r\n" ++
    "a=rtpmap:102 H264/90000\r\n" ++
    "a=rtcp-fb:102 goog-remb\r\n" ++
    "a=rtcp-fb:102 transport-cc\r\n" ++
    "a=rtcp-fb:102 ccm fir\r\n" ++
    "a=rtcp-fb:102 nack\r\n" ++
    "a=rtcp-fb:102 nack pli\r\n" ++
    "a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f\r\n" ++
    "a=rtpmap:103 rtx/90000\r\n" ++
    "a=fmtp:103 apt=102\r\n" ++
    "a=rtpmap:104 H264/90000\r\n" ++
    "a=rtcp-fb:104 goog-remb\r\n" ++
    "a=rtcp-fb:104 transport-cc\r\n" ++
    "a=rtcp-fb:104 ccm fir\r\n" ++
    "a=rtcp-fb:104 nack\r\n" ++
    "a=rtcp-fb:104 nack pli\r\n" ++
    "a=fmtp:104 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f\r\n" ++
    "a=rtpmap:105 rtx/90000\r\n" ++
    "a=fmtp:105 apt=104\r\n" ++
    "a=rtpmap:106 H264/90000\r\n" ++
    "a=rtcp-fb:106 goog-remb\r\n" ++
    "a=rtcp-fb:106 transport-cc\r\n" ++
    "a=rtcp-fb:106 ccm fir\r\n" ++
    "a=rtcp-fb:106 nack\r\n" ++
    "a=rtcp-fb:106 nack pli\r\n" ++
    "a=fmtp:106 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n" ++
    "a=rtpmap:107 rtx/90000\r\n" ++
    "a=fmtp:107 apt=106\r\n" ++
    "a=rtpmap:108 H264/90000\r\n" ++
    "a=rtcp-fb:108 goog-remb\r\n" ++
    "a=rtcp-fb:108 transport-cc\r\n" ++
    "a=rtcp-fb:108 ccm fir\r\n" ++
    "a=rtcp-fb:108 nack\r\n" ++
    "a=rtcp-fb:108 nack pli\r\n" ++
    "a=fmtp:108 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e01f\r\n" ++
    "a=rtpmap:109 rtx/90000\r\n" ++
    "a=fmtp:109 apt=108\r\n" ++
    "a=rtpmap:127 H264/90000\r\n" ++
    "a=rtcp-fb:127 goog-remb\r\n" ++
    "a=rtcp-fb:127 transport-cc\r\n" ++
    "a=rtcp-fb:127 ccm fir\r\n" ++
    "a=rtcp-fb:127 nack\r\n" ++
    "a=rtcp-fb:127 nack pli\r\n" ++
    "a=fmtp:127 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=4d001f\r\n" ++
    "a=rtpmap:125 rtx/90000\r\n" ++
    "a=fmtp:125 apt=127\r\n" ++
    "a=rtpmap:39 AV1/90000\r\n" ++
    "a=rtcp-fb:39 goog-remb\r\n" ++
    "a=rtcp-fb:39 transport-cc\r\n" ++
    "a=rtcp-fb:39 ccm fir\r\n" ++
    "a=rtcp-fb:39 nack\r\n" ++
    "a=rtcp-fb:39 nack pli\r\n" ++
    "a=fmtp:39 level-idx=5;profile=0;tier=0\r\n" ++
    "a=rtpmap:40 rtx/90000\r\n" ++
    "a=fmtp:40 apt=39\r\n" ++
    "a=rtpmap:116 red/90000\r\n" ++
    "a=rtpmap:117 rtx/90000\r\n" ++
    "a=fmtp:117 apt=116\r\n" ++
    "a=rtpmap:118 ulpfec/90000\r\n" ++
    "a=ssrc-group:FID 1838571023 3311274602\r\n" ++
    "a=ssrc:1838571023 cname:p0kD3e8hQ2wM1vZt\r\n" ++
    "a=ssrc:1838571023 msid:3f1e6a2c-9d4b-4f7e-8a1c-5b2d7e9f0a13 c94d1e2f-7a3b-4e5c-8d9f-0b1a2c3d4e5f\r\n" ++
    "a=ssrc:3311274602 cname:p0kD3e8hQ2wM1vZt\r\n" ++
    "a=ssrc:3311274602 msid:3f1e6a2c-9d4b-4f7e-8a1c-5b2d7e9f0a13 c94d1e2f-7a3b-4e5c-8d9f-0b1a2c3d4e5f\r\n";

/// Chrome's answer to an audio+video offer (setup:active, so Chrome is the DTLS client).
pub const chrome_answer =
    "v=0\r\n" ++
    "o=- 8127369146582337001 2 IN IP4 127.0.0.1\r\n" ++
    "s=-\r\n" ++
    "t=0 0\r\n" ++
    "a=group:BUNDLE 0 1\r\n" ++
    "a=extmap-allow-mixed\r\n" ++
    "a=msid-semantic: WMS\r\n" ++
    "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
    "c=IN IP4 0.0.0.0\r\n" ++
    "a=rtcp:9 IN IP4 0.0.0.0\r\n" ++
    "a=ice-ufrag:q8Yt\r\n" ++
    "a=ice-pwd:MkH0rO9w2c1aB6sD3fG5jL7n\r\n" ++
    "a=ice-options:trickle\r\n" ++
    "a=fingerprint:sha-256 1A:2B:3C:4D:5E:6F:70:81:92:A3:B4:C5:D6:E7:F8:09:1A:2B:3C:4D:5E:6F:70:81:92:A3:B4:C5:D6:E7:F8:09\r\n" ++
    "a=setup:active\r\n" ++
    "a=mid:0\r\n" ++
    "a=recvonly\r\n" ++
    "a=rtcp-mux\r\n" ++
    "a=rtpmap:111 opus/48000/2\r\n" ++
    "a=fmtp:111 minptime=10;useinbandfec=1\r\n" ++
    "m=video 9 UDP/TLS/RTP/SAVPF 102\r\n" ++
    "c=IN IP4 0.0.0.0\r\n" ++
    "a=rtcp:9 IN IP4 0.0.0.0\r\n" ++
    "a=ice-ufrag:q8Yt\r\n" ++
    "a=ice-pwd:MkH0rO9w2c1aB6sD3fG5jL7n\r\n" ++
    "a=ice-options:trickle\r\n" ++
    "a=fingerprint:sha-256 1A:2B:3C:4D:5E:6F:70:81:92:A3:B4:C5:D6:E7:F8:09:1A:2B:3C:4D:5E:6F:70:81:92:A3:B4:C5:D6:E7:F8:09\r\n" ++
    "a=setup:active\r\n" ++
    "a=mid:1\r\n" ++
    "a=recvonly\r\n" ++
    "a=rtcp-mux\r\n" ++
    "a=rtcp-rsize\r\n" ++
    "a=rtpmap:102 H264/90000\r\n" ++
    "a=rtcp-fb:102 goog-remb\r\n" ++
    "a=rtcp-fb:102 ccm fir\r\n" ++
    "a=rtcp-fb:102 nack\r\n" ++
    "a=rtcp-fb:102 nack pli\r\n" ++
    "a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n";

test "Chrome offer parses and round-trips byte for byte" {
    var s = try Session.parse(testing.allocator, chrome_offer);
    defer s.deinit();
    try testing.expectEqual(@as(usize, 2), s.media.len);
    var mids = s.bundleMids();
    try testing.expectEqualStrings("0", mids.next().?);
    try testing.expectEqualStrings("1", mids.next().?);

    const audio = &s.media[0];
    try testing.expectEqualStrings("audio", audio.kind);
    try testing.expectEqualStrings("Zx3k", s.mediaAttr(audio, "ice-ufrag").?);
    try testing.expectEqualStrings("Yq0g7m1o2H9vS4bT6nR8pL3c", s.mediaAttr(audio, "ice-pwd").?);
    try testing.expectEqualStrings("actpass", audio.attr("setup").?);
    try testing.expect(audio.rtcpMux());
    try testing.expectEqual(Direction.sendrecv, audio.direction());
    const opus = audio.codec(111).?;
    try testing.expectEqualStrings("opus", opus.name);
    try testing.expectEqual(@as(u32, 48000), opus.clock);
    try testing.expectEqual(@as(u8, 2), opus.channels);
    try testing.expectEqualStrings("1", opus.param("useinbandfec").?);
    try testing.expectEqual(@as(?u8, 4), audio.extmapId("urn:ietf:params:rtp-hdrext:sdes:mid"));
    const fp = splitFingerprint(audio.attr("fingerprint").?).?;
    try testing.expectEqualStrings("sha-256", fp.algorithm);
    var ssrc_buf: [4]u32 = undefined;
    try testing.expectEqualSlices(u32, &.{2711883041}, audio.ssrcs(&ssrc_buf));

    const video = &s.media[1];
    const h264 = video.codec(106).?;
    try testing.expectEqualStrings("H264", h264.name);
    try testing.expectEqualStrings("42e01f", h264.param("profile-level-id").?);
    try testing.expect(video.hasFeedback(106, "nack pli"));
    try testing.expectEqualSlices(u32, &.{ 1838571023, 3311274602 }, video.ssrcs(&ssrc_buf));

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try s.write(&out.writer);
    try testing.expectEqualStrings(chrome_offer, out.written());
}

test "Chrome answer round-trips" {
    var s = try Session.parse(testing.allocator, chrome_answer);
    defer s.deinit();
    try testing.expectEqualStrings("active", s.media[1].attr("setup").?);
    try testing.expectEqual(Direction.recvonly, s.media[0].direction());
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try s.write(&out.writer);
    try testing.expectEqualStrings(chrome_answer, out.written());
}

test "written description parses back" {
    const desc: Description = .{
        .session_id = 42,
        .ice_ufrag = "abcd1234",
        .ice_pwd = "0123456789abcdefghijklmn",
        .fingerprint = "7B:8B:F0:65:5F:78:E2:51:3B:AC:6F:F3:3F:46:1B:35:DC:B8:5F:64:1A:24:C2:43:F0:A1:58:D0:A1:2C:19:08",
        .setup = .actpass,
        .media = &.{
            .{ .kind = "audio", .mid = "0", .codecs = &.{.{ .pt = 111, .name = "opus", .clock = 48000, .channels = 2, .fmtp = "minptime=10;useinbandfec=1" }}, .ssrc = 1234, .cname = "c", .stream_id = "s", .track_id = "a" },
            .{ .kind = "video", .mid = "1", .codecs = &.{.{ .pt = 102, .name = "H264", .clock = 90000, .fmtp = "packetization-mode=1;profile-level-id=42e01f", .feedback = &.{ "nack", "nack pli" } }}, .ssrc = 5678, .cname = "c", .stream_id = "s", .track_id = "v", .rtcp_rsize = true },
        },
        .candidates = &.{"candidate:1000 1 udp 2130706431 192.168.1.5 50000 typ host generation 0"},
    };
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try write(desc, &out.writer);
    var s = try Session.parse(testing.allocator, out.written());
    defer s.deinit();
    try testing.expectEqual(@as(usize, 2), s.media.len);
    try testing.expectEqualStrings("abcd1234", s.mediaAttr(&s.media[1], "ice-ufrag").?);
    try testing.expect(s.media[1].hasFeedback(102, "nack pli"));
    try testing.expectEqualStrings("1000 1 udp 2130706431 192.168.1.5 50000 typ host generation 0", s.media[0].attr("candidate").?);
}

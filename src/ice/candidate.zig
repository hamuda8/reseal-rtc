//! ICE candidates (RFC 8445 5.1, RFC 8839 5.1): priorities and the SDP "candidate:" syntax.

const std = @import("std");
const Address = @import("../net.zig").Address;

pub const Type = enum {
    host,
    srflx,
    prflx,
    relay,

    /// Recommended type preferences (RFC 8445 5.1.2.2).
    pub fn preference(t: Type) u32 {
        return switch (t) {
            .host => 126,
            .prflx => 110,
            .srflx => 100,
            .relay => 0,
        };
    }
};

pub fn priority(t: Type, local_pref: u16, component: u8) u32 {
    return (t.preference() << 24) | (@as(u32, local_pref) << 8) | (256 - @as(u32, component));
}

/// RFC 8445 6.1.2.3; `g` is the controlling side's candidate priority.
pub fn pairPriority(g: u32, d: u32) u64 {
    const lo: u64 = @min(g, d);
    const hi: u64 = @max(g, d);
    return (lo << 32) + 2 * hi + @intFromBool(g > d);
}

pub const Candidate = struct {
    foundation: [32]u8 = @splat(0),
    foundation_len: u8 = 0,
    component: u8 = 1,
    priority: u32,
    address: Address,
    type: Type,
    related: ?Address = null,
    /// mDNS host names (".local") are not resolved: such candidates are kept unusable and the
    /// peer is reached through the peer-reflexive candidate its checks reveal.
    unresolved: bool = false,

    pub fn foundationText(c: *const Candidate) []const u8 {
        return c.foundation[0..c.foundation_len];
    }

    pub fn setFoundation(c: *Candidate, f: []const u8) void {
        const n = @min(f.len, c.foundation.len);
        @memcpy(c.foundation[0..n], f[0..n]);
        c.foundation_len = @intCast(n);
    }

    /// Parses "candidate:..." (with or without the leading "a="). TCP candidates are rejected.
    pub fn parse(line: []const u8) !Candidate {
        var text = std.mem.trim(u8, line, " \r\n");
        if (std.mem.startsWith(u8, text, "a=")) text = text[2..];
        if (!std.mem.startsWith(u8, text, "candidate:")) return error.NotACandidate;
        var it = std.mem.tokenizeScalar(u8, text["candidate:".len..], ' ');
        const foundation = it.next() orelse return error.BadCandidate;
        const component = std.fmt.parseInt(u8, it.next() orelse return error.BadCandidate, 10) catch return error.BadCandidate;
        const transport = it.next() orelse return error.BadCandidate;
        if (!std.ascii.eqlIgnoreCase(transport, "udp")) return error.UnsupportedTransport;
        const prio = std.fmt.parseInt(u32, it.next() orelse return error.BadCandidate, 10) catch return error.BadCandidate;
        const host = it.next() orelse return error.BadCandidate;
        const port = std.fmt.parseInt(u16, it.next() orelse return error.BadCandidate, 10) catch return error.BadCandidate;
        if (!std.mem.eql(u8, it.next() orelse "", "typ")) return error.BadCandidate;
        const typ = std.meta.stringToEnum(Type, it.next() orelse "") orelse return error.BadCandidate;
        var c: Candidate = .{ .component = component, .priority = prio, .address = .{}, .type = typ };
        c.setFoundation(foundation);
        if (Address.parseIp(host, port)) |a| {
            c.address = a;
        } else |_| {
            c.unresolved = true;
            c.address.port = port;
        }
        var raddr: ?[]const u8 = null;
        var rport: u16 = 0;
        while (it.next()) |key| {
            const val = it.next() orelse break;
            if (std.mem.eql(u8, key, "raddr")) raddr = val;
            if (std.mem.eql(u8, key, "rport")) rport = std.fmt.parseInt(u16, val, 10) catch 0;
        }
        if (raddr) |r| c.related = Address.parseIp(r, rport) catch null;
        return c;
    }

    /// Writes "candidate:..." as browsers expect it in RTCIceCandidateInit.candidate.
    pub fn format(c: Candidate, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("candidate:{s} {d} udp {d} ", .{ c.foundationText(), c.component, c.priority });
        try c.address.formatIp(w);
        try w.print(" {d} typ {t}", .{ c.address.port, c.type });
        if (c.related) |r| {
            try w.writeAll(" raddr ");
            try r.formatIp(w);
            try w.print(" rport {d}", .{r.port});
        }
        try w.writeAll(" generation 0");
    }
};

const testing = std.testing;

test "parse Chrome candidates" {
    const host = try Candidate.parse("candidate:1467250027 1 udp 2122260223 192.168.1.20 49846 typ host generation 0 ufrag 4ZcD network-id 1 network-cost 10");
    try testing.expectEqual(Type.host, host.type);
    try testing.expectEqual(@as(u32, 2122260223), host.priority);
    try testing.expect(host.address.eql(Address.ip4(.{ 192, 168, 1, 20 }, 49846)));
    try testing.expectEqualStrings("1467250027", host.foundationText());

    const srflx = try Candidate.parse("a=candidate:842163049 1 udp 1686052607 203.0.113.7 61000 typ srflx raddr 192.168.1.20 rport 49846 generation 0");
    try testing.expectEqual(Type.srflx, srflx.type);
    try testing.expect(srflx.related.?.eql(Address.ip4(.{ 192, 168, 1, 20 }, 49846)));

    const mdns = try Candidate.parse("candidate:2399212829 1 udp 2113937151 0b1f6c2e-8f7a-4a51-9a4c-6f0d1d7f2b1e.local 53412 typ host generation 0");
    try testing.expect(mdns.unresolved);

    try testing.expectError(error.UnsupportedTransport, Candidate.parse("candidate:1 1 tcp 1518280447 192.168.1.20 9 typ host tcptype active"));
}

test "format round trip and priorities" {
    var c: Candidate = .{ .priority = priority(.srflx, 65535, 1), .address = Address.ip4(.{ 203, 0, 113, 7 }, 61000), .type = .srflx, .related = Address.ip4(.{ 10, 0, 0, 2 }, 5000) };
    c.setFoundation("2");
    var buf: [256]u8 = undefined;
    const s = try std.fmt.bufPrint(&buf, "{f}", .{c});
    try testing.expectEqualStrings("candidate:2 1 udp 1694498815 203.0.113.7 61000 typ srflx raddr 10.0.0.2 rport 5000 generation 0", s);
    const back = try Candidate.parse(s);
    try testing.expect(back.address.eql(c.address));
    try testing.expectEqual(c.priority, back.priority);
    try testing.expectEqual(@as(u32, 2130706431), priority(.host, 65535, 1));
    try testing.expect(pairPriority(10, 20) < pairPriority(20, 10));
}

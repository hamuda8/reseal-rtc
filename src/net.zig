//! Addresses and the socket interface the app supplies.
//!
//! The engine is sans-IO: it never opens sockets or reads clocks by itself. The app (or the
//! std.Io driver in `driver.zig`) hands it received datagrams and the current time, and the
//! engine sends through `Socket`s.

const std = @import("std");

/// An IP address and UDP port with value semantics (comparable with `eql`).
pub const Address = struct {
    family: Family = .ip4,
    /// IPv4 uses the first 4 bytes.
    ip: [16]u8 = @splat(0),
    port: u16 = 0,

    pub const Family = enum { ip4, ip6 };

    pub fn ip4(bytes: [4]u8, port: u16) Address {
        var a: Address = .{ .family = .ip4, .port = port };
        a.ip[0..4].* = bytes;
        return a;
    }

    pub fn ip6(bytes: [16]u8, port: u16) Address {
        return .{ .family = .ip6, .ip = bytes, .port = port };
    }

    pub fn ipBytes(a: *const Address) []const u8 {
        return if (a.family == .ip4) a.ip[0..4] else a.ip[0..16];
    }

    pub fn eql(a: Address, b: Address) bool {
        return a.family == b.family and a.port == b.port and std.mem.eql(u8, a.ipBytes(), b.ipBytes());
    }

    pub fn sameIp(a: Address, b: Address) bool {
        return a.family == b.family and std.mem.eql(u8, a.ipBytes(), b.ipBytes());
    }

    /// Parses an IP literal without port ("192.0.2.1", "2001:db8::1").
    pub fn parseIp(text: []const u8, port: u16) !Address {
        const std_addr = std.Io.net.IpAddress.parse(text, port) catch return error.InvalidAddress;
        return fromStd(std_addr);
    }

    pub fn fromStd(a: std.Io.net.IpAddress) Address {
        return switch (a) {
            .ip4 => |v| ip4(v.bytes, v.port),
            .ip6 => |v| blk: {
                // IPv4-mapped addresses are folded back to IPv4 so they compare equal.
                const prefix = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
                if (std.mem.eql(u8, v.bytes[0..12], &prefix)) break :blk ip4(v.bytes[12..16].*, v.port);
                break :blk ip6(v.bytes, v.port);
            },
        };
    }

    pub fn toStd(a: Address) std.Io.net.IpAddress {
        return switch (a.family) {
            .ip4 => .{ .ip4 = .{ .bytes = a.ip[0..4].*, .port = a.port } },
            .ip6 => .{ .ip6 = .{ .bytes = a.ip, .port = a.port } },
        };
    }

    pub fn isLoopback(a: Address) bool {
        return switch (a.family) {
            .ip4 => a.ip[0] == 127,
            .ip6 => std.mem.eql(u8, &a.ip, &[16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }),
        };
    }

    pub fn isUnspecified(a: Address) bool {
        for (a.ipBytes()) |b| if (b != 0) return false;
        return true;
    }

    /// Writes the IP without the port.
    pub fn formatIp(a: Address, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (a.family) {
            .ip4 => try w.print("{d}.{d}.{d}.{d}", .{ a.ip[0], a.ip[1], a.ip[2], a.ip[3] }),
            .ip6 => {
                const std_addr: std.Io.net.Ip6Address = .{ .bytes = a.ip, .port = 0 };
                // std prints "[ip]:port"; strip the brackets and port.
                var buf: [64]u8 = undefined;
                var fw: std.Io.Writer = .fixed(&buf);
                std_addr.format(&fw) catch return error.WriteFailed;
                const s = fw.buffered();
                const close = std.mem.lastIndexOfScalar(u8, s, ']') orelse s.len;
                try w.writeAll(s[@intFromBool(s.len > 0 and s[0] == '[')..close]);
            },
        }
    }

    pub fn format(a: Address, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (a.family == .ip6) try w.writeByte('[');
        try a.formatIp(w);
        if (a.family == .ip6) try w.writeByte(']');
        try w.print(":{d}", .{a.port});
    }
};

/// A UDP socket the engine sends through. The app keeps ownership; the engine only calls `send`.
/// Received datagrams come back in through `PeerConnection.receive(socket_index, ...)`.
pub const Socket = struct {
    ctx: *anyopaque,
    sendFn: *const fn (ctx: *anyopaque, to: Address, data: []const u8) void,
    /// The address this socket is bound to; used as the host candidate. Must be a concrete
    /// interface address (not 0.0.0.0) for it to be useful to the remote peer.
    local: Address,
    /// Set for a stream connection (TCP or TLS) to one TURN server: it carries only that
    /// server's traffic (TURN messages framed on the stream, RFC 8656 §12.5), never makes a
    /// host candidate, and `send` ignores its `to`.
    remote: ?Address = null,

    pub fn send(s: Socket, to: Address, data: []const u8) void {
        s.sendFn(s.ctx, to, data);
    }
};

test "address parse, format and std round trip" {
    const a = try Address.parseIp("192.0.2.1", 32853);
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("192.0.2.1:32853", try std.fmt.bufPrint(&buf, "{f}", .{a}));
    try std.testing.expect(a.eql(Address.fromStd(a.toStd())));
    const b = try Address.parseIp("2001:db8::1", 9);
    var w: std.Io.Writer = .fixed(&buf);
    try b.formatIp(&w);
    try std.testing.expectEqualStrings("2001:db8::1", w.buffered());
}

//! STUN messages (RFC 8489): parsing, building, MESSAGE-INTEGRITY (HMAC-SHA1) and
//! FINGERPRINT (CRC32). Also carries the TURN (RFC 8656) and ICE (RFC 8445) attributes.

const std = @import("std");
const Address = @import("../net.zig").Address;

const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
const Md5 = std.crypto.hash.Md5;
const Crc32 = std.hash.Crc32;

pub const magic_cookie: u32 = 0x2112A442;
pub const header_len = 20;
const fingerprint_xor: u32 = 0x5354554e;

pub const Class = enum(u2) { request = 0, indication = 1, success = 2, failure = 3 };

pub const Method = enum(u12) {
    binding = 0x001,
    allocate = 0x003,
    refresh = 0x004,
    send = 0x006,
    data = 0x007,
    create_permission = 0x008,
    channel_bind = 0x009,
    _,
};

/// Attribute types we read or write. Unknown comprehension-optional ones (>= 0x8000) are ignored.
pub const attr = struct {
    pub const mapped_address: u16 = 0x0001;
    pub const username: u16 = 0x0006;
    pub const message_integrity: u16 = 0x0008;
    pub const error_code: u16 = 0x0009;
    pub const unknown_attributes: u16 = 0x000A;
    pub const channel_number: u16 = 0x000C;
    pub const lifetime: u16 = 0x000D;
    pub const xor_peer_address: u16 = 0x0012;
    pub const data: u16 = 0x0013;
    pub const realm: u16 = 0x0014;
    pub const nonce: u16 = 0x0015;
    pub const xor_relayed_address: u16 = 0x0016;
    pub const requested_transport: u16 = 0x0019;
    pub const dont_fragment: u16 = 0x001A;
    pub const xor_mapped_address: u16 = 0x0020;
    pub const priority: u16 = 0x0024;
    pub const use_candidate: u16 = 0x0025;
    pub const software: u16 = 0x8022;
    pub const fingerprint: u16 = 0x8028;
    pub const ice_controlled: u16 = 0x8029;
    pub const ice_controlling: u16 = 0x802A;
};

pub fn messageType(method: Method, class: Class) u16 {
    const m: u16 = @backingInt(method);
    const c: u16 = @backingInt(class);
    return (m & 0x000F) | ((m & 0x0070) << 1) | ((m & 0x0F80) << 2) | ((c & 1) << 4) | ((c & 2) << 7);
}

fn splitType(t: u16) struct { Method, Class } {
    const m = (t & 0x000F) | ((t >> 1) & 0x0070) | ((t >> 2) & 0x0F80);
    const c = ((t >> 4) & 1) | ((t >> 7) & 2);
    return .{ @fromBackingInt(@intCast(m)), @fromBackingInt(@intCast(c)) };
}

/// Cheap check used by the demultiplexer (RFC 7983: first byte 0..3) plus the magic cookie.
pub fn isStun(data: []const u8) bool {
    return data.len >= header_len and data[0] < 4 and
        std.mem.readInt(u32, data[4..8], .big) == magic_cookie and
        std.mem.readInt(u16, data[2..4], .big) + header_len == data.len;
}

/// Long-term credential key (RFC 8489 9.2.2): MD5(username ":" realm ":" password).
/// SASLprep is skipped: TURN REST credentials are ASCII.
pub fn longTermKey(username: []const u8, realm: []const u8, password: []const u8) [16]u8 {
    var h = Md5.init(.{});
    h.update(username);
    h.update(":");
    h.update(realm);
    h.update(":");
    h.update(password);
    var out: [16]u8 = undefined;
    h.final(&out);
    return out;
}

/// A parsed, validated view over a received datagram. Attribute values point into `raw`.
pub const Message = struct {
    method: Method,
    class: Class,
    txid: [12]u8,
    raw: []const u8,

    pub fn parse(raw: []const u8) !Message {
        if (!isStun(raw)) return error.NotStun;
        const method, const class = splitType(std.mem.readInt(u16, raw[0..2], .big));
        // Walk the attributes once so later lookups can trust the framing.
        var it: Iterator = .{ .raw = raw };
        while (try it.next()) |_| {}
        return .{ .method = method, .class = class, .txid = raw[8..20].*, .raw = raw };
    }

    pub fn iterator(m: Message) Iterator {
        return .{ .raw = m.raw };
    }

    /// The first attribute of type `t` (before MESSAGE-INTEGRITY, per RFC 8489 14.5, except
    /// FINGERPRINT which comes after it).
    pub fn get(m: Message, t: u16) ?[]const u8 {
        var it = m.iterator();
        while (it.next() catch null) |a| {
            if (a.type == t) return a.value;
            if (a.type == attr.message_integrity and t != attr.fingerprint) return null;
        }
        return null;
    }

    pub fn has(m: Message, t: u16) bool {
        return m.get(t) != null;
    }

    pub fn getU32(m: Message, t: u16) ?u32 {
        const v = m.get(t) orelse return null;
        if (v.len < 4) return null;
        return std.mem.readInt(u32, v[0..4], .big);
    }

    pub fn getU64(m: Message, t: u16) ?u64 {
        const v = m.get(t) orelse return null;
        if (v.len < 8) return null;
        return std.mem.readInt(u64, v[0..8], .big);
    }

    pub fn xorAddress(m: Message, t: u16) ?Address {
        const v = m.get(t) orelse return null;
        return decodeXorAddress(v, m.txid) catch null;
    }

    pub fn mappedAddress(m: Message) ?Address {
        if (m.xorAddress(attr.xor_mapped_address)) |a| return a;
        const v = m.get(attr.mapped_address) orelse return null;
        return decodeAddress(v) catch null;
    }

    pub fn errorCode(m: Message) ?u16 {
        const v = m.get(attr.error_code) orelse return null;
        if (v.len < 4) return null;
        return @as(u16, v[2] & 7) * 100 + v[3];
    }

    /// Verifies MESSAGE-INTEGRITY with `key` (the password for ICE, the long-term key for TURN).
    pub fn checkIntegrity(m: Message, key: []const u8) bool {
        var it = m.iterator();
        while (it.next() catch null) |a| {
            if (a.type != attr.message_integrity) continue;
            if (a.value.len != 20) return false;
            const end = a.offset; // start of the MI attribute header
            var hdr: [header_len]u8 = m.raw[0..header_len].*;
            std.mem.writeInt(u16, hdr[2..4], @intCast(end - header_len + 24), .big);
            var mac = HmacSha1.init(key);
            mac.update(&hdr);
            mac.update(m.raw[header_len..end]);
            var out: [20]u8 = undefined;
            mac.final(&out);
            return std.crypto.timing_safe.eql([20]u8, out, a.value[0..20].*);
        }
        return false;
    }

    /// True if there is no FINGERPRINT or it matches; false if it is present and wrong.
    pub fn checkFingerprint(m: Message) bool {
        var it = m.iterator();
        while (it.next() catch null) |a| {
            if (a.type != attr.fingerprint) continue;
            if (a.value.len != 4) return false;
            return std.mem.readInt(u32, a.value[0..4], .big) == fingerprintOf(m.raw[0..a.offset]);
        }
        return true;
    }

    pub fn hasFingerprint(m: Message) bool {
        var it = m.iterator();
        while (it.next() catch null) |a| if (a.type == attr.fingerprint) return true;
        return false;
    }
};

pub const Attribute = struct { type: u16, value: []const u8, offset: usize };

pub const Iterator = struct {
    raw: []const u8,
    pos: usize = header_len,

    pub fn next(it: *Iterator) !?Attribute {
        if (it.pos == it.raw.len) return null;
        if (it.pos + 4 > it.raw.len) return error.Truncated;
        const t = std.mem.readInt(u16, it.raw[it.pos..][0..2], .big);
        const len = std.mem.readInt(u16, it.raw[it.pos + 2 ..][0..2], .big);
        const start = it.pos + 4;
        if (start + len > it.raw.len) return error.Truncated;
        const a: Attribute = .{ .type = t, .value = it.raw[start .. start + len], .offset = it.pos };
        it.pos = @min(it.raw.len, start + std.mem.alignForward(usize, len, 4));
        return a;
    }
};

/// CRC32 over `prefix` as if its length field already counted the 8-byte FINGERPRINT.
fn fingerprintOf(prefix: []const u8) u32 {
    var hdr: [header_len]u8 = prefix[0..header_len].*;
    std.mem.writeInt(u16, hdr[2..4], @intCast(prefix.len - header_len + 8), .big);
    var crc = Crc32.init();
    crc.update(&hdr);
    crc.update(prefix[header_len..]);
    return crc.final() ^ fingerprint_xor;
}

pub fn decodeAddress(v: []const u8) !Address {
    if (v.len < 8) return error.BadAddress;
    const port = std.mem.readInt(u16, v[2..4], .big);
    return switch (v[1]) {
        0x01 => Address.ip4(v[4..8].*, port),
        0x02 => if (v.len >= 20) Address.ip6(v[4..20].*, port) else error.BadAddress,
        else => error.BadAddress,
    };
}

pub fn decodeXorAddress(v: []const u8, txid: [12]u8) !Address {
    var a = try decodeAddress(v);
    a.port ^= @truncate(magic_cookie >> 16);
    const mask = xorMask(txid);
    for (a.ip[0..if (a.family == .ip4) 4 else 16], 0..) |*b, i| b.* ^= mask[i];
    return a;
}

fn xorMask(txid: [12]u8) [16]u8 {
    var mask: [16]u8 = undefined;
    std.mem.writeInt(u32, mask[0..4], magic_cookie, .big);
    mask[4..16].* = txid;
    return mask;
}

/// Writes a message into a caller buffer. Attributes are appended in call order; the header
/// length is kept current so integrity/fingerprint see the right value.
pub const Builder = struct {
    buf: []u8,
    len: usize,

    pub fn init(buf: []u8, method: Method, class: Class, txid: [12]u8) Builder {
        std.mem.writeInt(u16, buf[0..2], messageType(method, class), .big);
        std.mem.writeInt(u16, buf[2..4], 0, .big);
        std.mem.writeInt(u32, buf[4..8], magic_cookie, .big);
        buf[8..20].* = txid;
        return .{ .buf = buf, .len = header_len };
    }

    fn txidOf(b: *const Builder) [12]u8 {
        return b.buf[8..20].*;
    }

    pub fn add(b: *Builder, t: u16, value: []const u8) !void {
        const padded = std.mem.alignForward(usize, value.len, 4);
        if (b.len + 4 + padded > b.buf.len) return error.NoSpaceLeft;
        std.mem.writeInt(u16, b.buf[b.len..][0..2], t, .big);
        std.mem.writeInt(u16, b.buf[b.len + 2 ..][0..2], @intCast(value.len), .big);
        @memcpy(b.buf[b.len + 4 ..][0..value.len], value);
        @memset(b.buf[b.len + 4 + value.len ..][0 .. padded - value.len], 0);
        b.len += 4 + padded;
        std.mem.writeInt(u16, b.buf[2..4], @intCast(b.len - header_len), .big);
    }

    pub fn addU32(b: *Builder, t: u16, v: u32) !void {
        var tmp: [4]u8 = undefined;
        std.mem.writeInt(u32, &tmp, v, .big);
        try b.add(t, &tmp);
    }

    pub fn addU64(b: *Builder, t: u16, v: u64) !void {
        var tmp: [8]u8 = undefined;
        std.mem.writeInt(u64, &tmp, v, .big);
        try b.add(t, &tmp);
    }

    pub fn addXorAddress(b: *Builder, t: u16, a: Address) !void {
        var tmp: [20]u8 = undefined;
        tmp[0] = 0;
        tmp[1] = if (a.family == .ip4) 0x01 else 0x02;
        std.mem.writeInt(u16, tmp[2..4], a.port ^ @as(u16, @truncate(magic_cookie >> 16)), .big);
        const n: usize = if (a.family == .ip4) 4 else 16;
        const mask = xorMask(b.txidOf());
        for (0..n) |i| tmp[4 + i] = a.ip[i] ^ mask[i];
        try b.add(t, tmp[0 .. 4 + n]);
    }

    pub fn addErrorCode(b: *Builder, code: u16, reason: []const u8) !void {
        var tmp: [128]u8 = undefined;
        tmp[0..2].* = .{ 0, 0 };
        tmp[2] = @intCast(code / 100);
        tmp[3] = @intCast(code % 100);
        const n = @min(reason.len, tmp.len - 4);
        @memcpy(tmp[4..][0..n], reason[0..n]);
        try b.add(attr.error_code, tmp[0 .. 4 + n]);
    }

    pub fn addIntegrity(b: *Builder, key: []const u8) !void {
        if (b.len + 24 > b.buf.len) return error.NoSpaceLeft;
        std.mem.writeInt(u16, b.buf[2..4], @intCast(b.len - header_len + 24), .big);
        var out: [20]u8 = undefined;
        HmacSha1.create(&out, b.buf[0..b.len], key);
        try b.add(attr.message_integrity, &out);
    }

    pub fn addFingerprint(b: *Builder) !void {
        try b.addU32(attr.fingerprint, 0);
        const v = fingerprintOf(b.buf[0 .. b.len - 8]);
        std.mem.writeInt(u32, b.buf[b.len - 4 ..][0..4], v, .big);
    }

    pub fn bytes(b: *const Builder) []u8 {
        return b.buf[0..b.len];
    }
};

// ---- tests: RFC 5769 sample messages -----------------------------------------------------

const testing = std.testing;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

const rfc5769_request = hex("000100582112a442b7e7a701bc34d686fa87dfae" ++
    "802200105354554e20746573742063" ++ "6c69656e74" ++
    "002400046e0001ff" ++ "80290008932ff9b151263b36" ++
    "000600096576746a3a68367659202020" ++
    "000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2" ++ "80280004e57a3bcf");

const rfc5769_response4 = hex("0101003c2112a442b7e7a701bc34d686fa87dfae" ++
    "8022000b7465737420766563746f7220" ++ "002000080001a147e112a643" ++
    "000800142b91f599fd9e90c38c7489f92af9ba53f06be7d7" ++ "80280004c07d4c96");

const rfc5769_response6_full = hex("010100482112a442b7e7a701bc34d686fa87dfae" ++
    "8022000b7465737420766563746f7220" ++
    "002000140002a1470113a9faa5d3f179bc25f4b5bed2b9d9" ++
    "00080014a382954e4be67bf11784c97c8292c275bfe3ed41" ++ "80280004c8fb0b4c");

const rfc5769_long_term = hex("000100602112a442" ++ "78ad3433c6ad72c029da412e" ++
    "00060012e3839ee38388e383aae38383e382afe382b90000" ++
    "0015001c662f2f3439396b39353464364f4c33346f4c39465354767936347341" ++
    "0014000b6578616d706c652e6f726700" ++
    "00080014f67024656dd64a3e02b8e0712e85c9a28ca89666");

const ice_password = "VOkJxbRl1RmTxUk/WvJxBt";

test "RFC 5769 2.1 sample request: parse, integrity, fingerprint" {
    const m = try Message.parse(&rfc5769_request);
    try testing.expectEqual(Method.binding, m.method);
    try testing.expectEqual(Class.request, m.class);
    try testing.expectEqualStrings("evtj:h6vY", m.get(attr.username).?);
    try testing.expectEqualStrings("STUN test client", m.get(attr.software).?);
    try testing.expectEqual(@as(u32, 0x6e0001ff), m.getU32(attr.priority).?);
    try testing.expectEqual(@as(u64, 0x932ff9b151263b36), m.getU64(attr.ice_controlled).?);
    try testing.expect(m.checkIntegrity(ice_password));
    try testing.expect(!m.checkIntegrity("wrong"));
    try testing.expect(m.hasFingerprint() and m.checkFingerprint());
}

test "RFC 5769 2.1 sample request: rebuilt byte for byte" {
    var buf: [256]u8 = undefined;
    var b = Builder.init(&buf, .binding, .request, rfc5769_request[8..20].*);
    try b.add(attr.software, "STUN test client");
    try b.addU32(attr.priority, 0x6e0001ff);
    try b.addU64(attr.ice_controlled, 0x932ff9b151263b36);
    // The RFC pads USERNAME with spaces rather than zeros; reproduce that to compare bytes.
    try b.add(attr.username, "evtj:h6vY");
    @memset(b.buf[b.len - 3 .. b.len], ' ');
    try b.addIntegrity(ice_password);
    try b.addFingerprint();
    try testing.expectEqualSlices(u8, &rfc5769_request, b.bytes());
}

test "RFC 5769 2.2 IPv4 response" {
    const m = try Message.parse(&rfc5769_response4);
    try testing.expectEqual(Class.success, m.class);
    try testing.expect(m.mappedAddress().?.eql(Address.ip4(.{ 192, 0, 2, 1 }, 32853)));
    try testing.expect(m.checkIntegrity(ice_password));
    try testing.expect(m.checkFingerprint());

    var buf: [256]u8 = undefined;
    var b = Builder.init(&buf, .binding, .success, m.txid);
    try b.add(attr.software, "test vector");
    b.buf[b.len - 1] = ' ';
    try b.addXorAddress(attr.xor_mapped_address, Address.ip4(.{ 192, 0, 2, 1 }, 32853));
    try b.addIntegrity(ice_password);
    try b.addFingerprint();
    try testing.expectEqualSlices(u8, &rfc5769_response4, b.bytes());
}

test "RFC 5769 2.3 IPv6 response" {
    const m = try Message.parse(&rfc5769_response6_full);
    const want = try Address.parseIp("2001:db8:1234:5678:11:2233:4455:6677", 32853);
    try testing.expect(m.mappedAddress().?.eql(want));
    try testing.expect(m.checkIntegrity(ice_password));
    try testing.expect(m.checkFingerprint());
}

test "RFC 5769 2.4 long-term authentication" {
    const m = try Message.parse(&rfc5769_long_term);
    try testing.expectEqualStrings("example.org", m.get(attr.realm).?);
    try testing.expectEqualStrings("f//499k954d6OL34oL9FSTvy64sA", m.get(attr.nonce).?);
    // Username is 6 katakana characters; password "TheMatrIX" after SASLprep.
    const key = longTermKey(m.get(attr.username).?, "example.org", "TheMatrIX");
    try testing.expect(m.checkIntegrity(&key));
}

test "message type encoding" {
    try testing.expectEqual(@as(u16, 0x0001), messageType(.binding, .request));
    try testing.expectEqual(@as(u16, 0x0101), messageType(.binding, .success));
    try testing.expectEqual(@as(u16, 0x0113), messageType(.allocate, .failure));
    try testing.expectEqual(@as(u16, 0x0016), messageType(.send, .indication));
    const m, const c = splitType(0x0119);
    try testing.expectEqual(Method.channel_bind, m);
    try testing.expectEqual(Class.failure, c);
}

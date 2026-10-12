//! DTLS handshake messages (RFC 6347 4.2): the 12-byte fragment header, reassembly of
//! fragmented / reordered messages, and parsing of the hello messages and their extensions.

const std = @import("std");
const bytes = @import("bytes.zig");

pub const header_len = 12;

pub const Type = enum(u8) {
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    hello_verify_request = 3,
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,
    _,
};

pub const cipher_ecdhe_ecdsa_aes128_gcm_sha256: u16 = 0xC02B;
pub const group_secp256r1: u16 = 23;
pub const group_x25519: u16 = 29;
pub const sig_ecdsa_secp256r1_sha256: u16 = 0x0403;

pub const ext = struct {
    pub const supported_groups: u16 = 10;
    pub const ec_point_formats: u16 = 11;
    pub const signature_algorithms: u16 = 13;
    pub const use_srtp: u16 = 14;
    pub const extended_master_secret: u16 = 23;
    pub const renegotiation_info: u16 = 0xff01;
};

pub const FragmentHeader = struct {
    type: Type,
    length: u32,
    seq: u16,
    offset: u32,
    frag_len: u32,

    pub fn parse(data: []const u8) !struct { FragmentHeader, []const u8 } {
        if (data.len < header_len) return error.Truncated;
        const h: FragmentHeader = .{
            .type = @enumFromInt(data[0]),
            .length = std.mem.readInt(u24, data[1..4], .big),
            .seq = std.mem.readInt(u16, data[4..6], .big),
            .offset = std.mem.readInt(u24, data[6..9], .big),
            .frag_len = std.mem.readInt(u24, data[9..12], .big),
        };
        if (header_len + h.frag_len > data.len or h.offset + h.frag_len > h.length) return error.Truncated;
        return .{ h, data[header_len..][0..h.frag_len] };
    }

    pub fn write(h: FragmentHeader, out: *[header_len]u8) void {
        out[0] = @intFromEnum(h.type);
        std.mem.writeInt(u24, out[1..4], @intCast(h.length), .big);
        std.mem.writeInt(u16, out[4..6], h.seq, .big);
        std.mem.writeInt(u24, out[6..9], @intCast(h.offset), .big);
        std.mem.writeInt(u24, out[9..12], @intCast(h.frag_len), .big);
    }
};

/// A whole message as it is hashed into the transcript: header with offset 0 and
/// fragment length = length, then the body.
pub fn wholeMessage(gpa: std.mem.Allocator, t: Type, seq: u16, body: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, header_len + body.len);
    const h: FragmentHeader = .{ .type = t, .length = @intCast(body.len), .seq = seq, .offset = 0, .frag_len = @intCast(body.len) };
    h.write(out[0..header_len]);
    @memcpy(out[header_len..], body);
    return out;
}

pub const Message = struct {
    type: Type,
    seq: u16,
    /// Whole message (header + body), owned by the caller after `pop`.
    raw: []u8,

    pub fn body(m: Message) []const u8 {
        return m.raw[header_len..];
    }
};

/// Collects fragments until messages are complete, then hands them out strictly in
/// message_seq order.
pub const Reassembler = struct {
    next_seq: u16 = 0,
    slots: [max_ahead]?Slot = @splat(null),

    const max_ahead = 16;
    const max_message = 1 << 16;

    const Slot = struct {
        type: Type,
        raw: []u8,
        have: std.DynamicBitSetUnmanaged,
        missing: usize,
    };

    pub const AddResult = enum { stored, old, dropped };

    pub fn deinit(r: *Reassembler, gpa: std.mem.Allocator) void {
        for (&r.slots) |*s| if (s.*) |*slot| {
            gpa.free(slot.raw);
            slot.have.deinit(gpa);
            s.* = null;
        };
    }

    pub fn add(r: *Reassembler, gpa: std.mem.Allocator, h: FragmentHeader, frag: []const u8) !AddResult {
        if (h.seq < r.next_seq) return .old;
        const ahead = h.seq - r.next_seq;
        if (ahead >= max_ahead or h.length > max_message) return .dropped;
        const idx = h.seq % max_ahead;
        if (r.slots[idx] == null) {
            const raw = try gpa.alloc(u8, header_len + h.length);
            errdefer gpa.free(raw);
            const whole: FragmentHeader = .{ .type = h.type, .length = h.length, .seq = h.seq, .offset = 0, .frag_len = h.length };
            whole.write(raw[0..header_len]);
            r.slots[idx] = .{ .type = h.type, .raw = raw, .have = try .initEmpty(gpa, h.length), .missing = h.length };
        }
        const slot = &(r.slots[idx].?);
        if (slot.type != h.type or slot.raw.len != header_len + h.length) return .dropped;
        for (0..h.frag_len) |i| {
            const at = h.offset + i;
            if (!slot.have.isSet(at)) {
                slot.have.set(at);
                slot.missing -= 1;
                slot.raw[header_len + at] = frag[i];
            }
        }
        return .stored;
    }

    /// The next complete message in order, if any.
    pub fn pop(r: *Reassembler, gpa: std.mem.Allocator) ?Message {
        const idx = r.next_seq % max_ahead;
        const slot = &(r.slots[idx] orelse return null);
        if (slot.missing != 0) return null;
        const m: Message = .{ .type = slot.type, .seq = r.next_seq, .raw = slot.raw };
        slot.have.deinit(gpa);
        r.slots[idx] = null;
        r.next_seq +%= 1;
        return m;
    }
};

/// The parts of a ClientHello or ServerHello the handshake looks at.
pub const Hello = struct {
    random: [32]u8,
    session_id: []const u8,
    cookie: []const u8 = "", // ClientHello only
    cipher_suites: []const u8 = "", // ClientHello: list of u16
    cipher_suite: u16 = 0, // ServerHello
    extensions: Extensions = .{},

    pub fn parseClient(body: []const u8) !Hello {
        var r = bytes.Reader.init(body);
        _ = try r.int(u16); // client_version
        var h: Hello = .{ .random = (try r.bytes(32))[0..32].*, .session_id = try r.vec(1) };
        h.cookie = try r.vec(1);
        h.cipher_suites = try r.vec(2);
        _ = try r.vec(1); // compression methods
        if (!r.done()) h.extensions = try Extensions.parse(try r.vec(2));
        return h;
    }

    pub fn parseServer(body: []const u8) !Hello {
        var r = bytes.Reader.init(body);
        const version = try r.int(u16);
        if (version != 0xFEFD) return error.UnsupportedVersion;
        var h: Hello = .{ .random = (try r.bytes(32))[0..32].*, .session_id = try r.vec(1) };
        h.cipher_suite = try r.int(u16);
        if (try r.int(u8) != 0) return error.BadCompression;
        if (!r.done()) h.extensions = try Extensions.parse(try r.vec(2));
        return h;
    }

    pub fn offersSuite(h: Hello, suite: u16) bool {
        var i: usize = 0;
        while (i + 2 <= h.cipher_suites.len) : (i += 2) {
            if (std.mem.readInt(u16, h.cipher_suites[i..][0..2], .big) == suite) return true;
        }
        return false;
    }
};

pub const Extensions = struct {
    srtp_profiles: []const u8 = "", // list of u16
    groups: []const u8 = "", // list of u16
    sig_algs: []const u8 = "", // list of u16
    point_formats: bool = false,
    extended_master_secret: bool = false,
    renegotiation_info: bool = false,

    pub fn parse(data: []const u8) !Extensions {
        var e: Extensions = .{};
        var r = bytes.Reader.init(data);
        while (!r.done()) {
            const t = try r.int(u16);
            var v = bytes.Reader.init(try r.vec(2));
            switch (t) {
                ext.use_srtp => {
                    e.srtp_profiles = try v.vec(2);
                    _ = try v.vec(1); // MKI, unused by WebRTC
                },
                ext.supported_groups => e.groups = try v.vec(2),
                ext.signature_algorithms => e.sig_algs = try v.vec(2),
                ext.ec_point_formats => e.point_formats = true,
                ext.extended_master_secret => e.extended_master_secret = true,
                ext.renegotiation_info => e.renegotiation_info = true,
                else => {},
            }
        }
        return e;
    }
};

pub fn listHas(list: []const u8, v: u16) bool {
    var i: usize = 0;
    while (i + 2 <= list.len) : (i += 2) {
        if (std.mem.readInt(u16, list[i..][0..2], .big) == v) return true;
    }
    return false;
}

test "reassembly out of order and fragmented" {
    const gpa = std.testing.allocator;
    var r: Reassembler = .{};
    defer r.deinit(gpa);
    const body = "0123456789";
    // message 1 arrives first, then message 0 in two fragments, the second first.
    _ = try r.add(gpa, .{ .type = .server_hello_done, .length = 0, .seq = 1, .offset = 0, .frag_len = 0 }, "");
    try std.testing.expect(r.pop(gpa) == null);
    _ = try r.add(gpa, .{ .type = .certificate, .length = 10, .seq = 0, .offset = 6, .frag_len = 4 }, body[6..]);
    try std.testing.expect(r.pop(gpa) == null);
    _ = try r.add(gpa, .{ .type = .certificate, .length = 10, .seq = 0, .offset = 0, .frag_len = 7 }, body[0..7]);
    const m0 = r.pop(gpa).?;
    defer gpa.free(m0.raw);
    try std.testing.expectEqualStrings(body, m0.body());
    const m1 = r.pop(gpa).?;
    defer gpa.free(m1.raw);
    try std.testing.expectEqual(Type.server_hello_done, m1.type);
    try std.testing.expectEqual(Reassembler.AddResult.old, try r.add(gpa, .{ .type = .certificate, .length = 10, .seq = 0, .offset = 0, .frag_len = 0 }, ""));
}

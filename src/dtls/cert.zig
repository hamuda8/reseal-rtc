//! The DTLS certificate: a self-signed ECDSA P-256 X.509 certificate, as browsers make for
//! RTCPeerConnection. Its identity is not a name but its SHA-256 fingerprint, which travels in
//! the SDP (a=fingerprint) and is checked against what the peer presents in the handshake.
//!
//! The DER writer is adapted from zig-core/http/tls/cert.zig.

const std = @import("std");

pub const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
pub const KeyPair = Ecdsa.KeyPair;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Fingerprint = [32]u8;

pub const Certificate = struct {
    der: []u8,
    key: KeyPair,
    fingerprint: Fingerprint,

    /// A fresh key and certificate valid from a day ago for `valid_days` (clock skew tolerant).
    pub fn generate(gpa: std.mem.Allocator, io: std.Io, valid_days: u32) !Certificate {
        const key = KeyPair.generate(io);
        const now = std.Io.Timestamp.now(io, .real).toSeconds();
        const der = try selfSigned(gpa, io, key, "WebRTC", now - 86400, now + @as(i64, valid_days) * 86400);
        return .{ .der = der, .key = key, .fingerprint = fingerprintOf(der) };
    }

    pub fn deinit(c: *Certificate, gpa: std.mem.Allocator) void {
        gpa.free(c.der);
        c.* = undefined;
    }

    /// "sha-256 AB:CD:..." value for a=fingerprint.
    pub fn fingerprintText(c: *const Certificate, buf: *[95]u8) []const u8 {
        return formatFingerprint(c.fingerprint, buf);
    }
};

pub fn fingerprintOf(der: []const u8) Fingerprint {
    var out: Fingerprint = undefined;
    Sha256.hash(der, &out, .{});
    return out;
}

pub fn formatFingerprint(fp: Fingerprint, buf: *[95]u8) []const u8 {
    const digits = "0123456789ABCDEF";
    for (fp, 0..) |b, i| {
        buf[i * 3] = digits[b >> 4];
        buf[i * 3 + 1] = digits[b & 15];
        if (i < 31) buf[i * 3 + 2] = ':';
    }
    return buf[0..95];
}

/// Parses "AB:CD:..." (the part after "sha-256 ").
pub fn parseFingerprint(text: []const u8) !Fingerprint {
    const t = std.mem.trim(u8, text, " \t\r\n");
    if (t.len != 95) return error.BadFingerprint;
    var out: Fingerprint = undefined;
    for (&out, 0..) |*b, i| {
        if (i < 31 and t[i * 3 + 2] != ':') return error.BadFingerprint;
        b.* = std.fmt.parseInt(u8, t[i * 3 ..][0..2], 16) catch return error.BadFingerprint;
    }
    return out;
}

/// The P-256 public key from a peer certificate (DER). Other key types are rejected: every
/// browser defaults to ECDSA P-256 for WebRTC.
pub fn peerPublicKey(der: []const u8) !Ecdsa.PublicKey {
    const parsed = std.crypto.Certificate.parse(.{ .buffer = der, .index = 0 }) catch return error.BadCertificate;
    switch (parsed.pub_key_algo) {
        .X9_62_id_ecPublicKey => |curve| if (curve != .X9_62_prime256v1) return error.UnsupportedCertificate,
        else => return error.UnsupportedCertificate,
    }
    return Ecdsa.PublicKey.fromSec1(parsed.pubKey()) catch error.BadCertificate;
}

// ---- DER writing ---------------------------------------------------------------------

const oid_ec_public_key = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
const oid_prime256v1 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
const oid_ecdsa_sha256 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
const oid_common_name = [_]u8{ 0x55, 0x04, 0x03 };

/// Builds DER by nesting: `begin` a constructed value, write its contents, `end` it.
const Der = struct {
    gpa: std.mem.Allocator,
    buf: std.ArrayList(u8) = .empty,
    open: std.ArrayList(usize) = .empty,

    fn deinit(d: *Der) void {
        d.buf.deinit(d.gpa);
        d.open.deinit(d.gpa);
    }

    fn begin(d: *Der, tag: u8) !void {
        try d.buf.append(d.gpa, tag);
        try d.open.append(d.gpa, d.buf.items.len);
    }

    /// Closes the innermost value, inserting its length before the contents.
    fn end(d: *Der) !void {
        const start = d.open.pop() orelse return error.NothingOpen;
        var hdr: [4]u8 = undefined;
        try d.buf.insertSlice(d.gpa, start, lengthBytes(d.buf.items.len - start, &hdr));
    }

    fn value(d: *Der, tag: u8, bytes: []const u8) !void {
        try d.buf.append(d.gpa, tag);
        var hdr: [4]u8 = undefined;
        try d.buf.appendSlice(d.gpa, lengthBytes(bytes.len, &hdr));
        try d.buf.appendSlice(d.gpa, bytes);
    }

    /// A non-negative INTEGER from big-endian bytes.
    fn uint(d: *Der, be: []const u8) !void {
        var b = be;
        while (b.len > 1 and b[0] == 0) b = b[1..];
        if (b[0] & 0x80 != 0) {
            try d.begin(0x02);
            try d.buf.append(d.gpa, 0);
            try d.buf.appendSlice(d.gpa, b);
            try d.end();
        } else try d.value(0x02, b);
    }

    fn bitString(d: *Der, bytes: []const u8) !void {
        try d.begin(0x03);
        try d.buf.append(d.gpa, 0);
        try d.buf.appendSlice(d.gpa, bytes);
        try d.end();
    }

    /// Name ::= SEQUENCE { SET { SEQUENCE { commonName, UTF8String } } }
    fn commonName(d: *Der, cn: []const u8) !void {
        try d.begin(0x30);
        try d.begin(0x31);
        try d.begin(0x30);
        try d.value(0x06, &oid_common_name);
        try d.value(0x0C, cn);
        try d.end();
        try d.end();
        try d.end();
    }

    fn ecdsaAlgorithm(d: *Der) !void {
        try d.begin(0x30);
        try d.value(0x06, &oid_ecdsa_sha256);
        try d.end();
    }

    /// UTCTime ("YYMMDDHHMMSSZ"), or GeneralizedTime from 2050 on.
    fn time(d: *Der, unix: i64) !void {
        const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(unix) };
        const yd = es.getEpochDay().calculateYearDay();
        const md = yd.calculateMonthDay();
        const ds = es.getDaySeconds();
        var buf: [16]u8 = undefined;
        const year: u32 = yd.year;
        const args = .{ md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute() };
        if (year < 2050) {
            try d.value(0x17, try std.fmt.bufPrint(&buf, "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{year % 100} ++ args));
        } else {
            try d.value(0x18, try std.fmt.bufPrint(&buf, "{d:0>4}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{year} ++ args));
        }
    }
};

fn lengthBytes(len: usize, buf: *[4]u8) []const u8 {
    if (len < 0x80) {
        buf[0] = @intCast(len);
        return buf[0..1];
    }
    if (len <= 0xff) {
        buf[0..2].* = .{ 0x81, @intCast(len) };
        return buf[0..2];
    }
    if (len <= 0xffff) {
        buf[0..3].* = .{ 0x82, @intCast(len >> 8), @truncate(len) };
        return buf[0..3];
    }
    buf.* = .{ 0x83, @intCast(len >> 16), @truncate(len >> 8), @truncate(len) };
    return buf;
}

/// A self-signed v3 certificate (DER) with subject and issuer CN=`cn`.
pub fn selfSigned(gpa: std.mem.Allocator, io: std.Io, key: KeyPair, cn: []const u8, not_before: i64, not_after: i64) ![]u8 {
    var tbs: Der = .{ .gpa = gpa };
    defer tbs.deinit();
    try tbs.begin(0x30);
    try tbs.begin(0xA0); // [0] version
    try tbs.uint(&.{2}); // v3
    try tbs.end();
    var serial: [8]u8 = undefined;
    io.random(&serial);
    serial[0] &= 0x7f;
    try tbs.uint(&serial);
    try tbs.ecdsaAlgorithm();
    try tbs.commonName(cn);
    try tbs.begin(0x30);
    try tbs.time(not_before);
    try tbs.time(not_after);
    try tbs.end();
    try tbs.commonName(cn);
    // SubjectPublicKeyInfo
    try tbs.begin(0x30);
    try tbs.begin(0x30);
    try tbs.value(0x06, &oid_ec_public_key);
    try tbs.value(0x06, &oid_prime256v1);
    try tbs.end();
    try tbs.bitString(&key.public_key.toUncompressedSec1());
    try tbs.end();
    try tbs.end();

    var cert: Der = .{ .gpa = gpa };
    defer cert.open.deinit(gpa);
    errdefer cert.buf.deinit(gpa);
    const sig = try key.sign(tbs.buf.items, null);
    var sig_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    try cert.begin(0x30);
    try cert.buf.appendSlice(gpa, tbs.buf.items);
    try cert.ecdsaAlgorithm();
    try cert.bitString(sig.toDer(&sig_buf));
    try cert.end();
    return cert.buf.toOwnedSlice(gpa);
}

const testing = std.testing;

test "generated certificate parses, self-verifies and round-trips its fingerprint" {
    var c = try Certificate.generate(testing.allocator, testing.io, 30);
    defer c.deinit(testing.allocator);
    const parsed = try std.crypto.Certificate.parse(.{ .buffer = c.der, .index = 0 });
    try testing.expectEqualStrings("WebRTC", parsed.commonName());
    try parsed.verify(parsed, std.Io.Timestamp.now(testing.io, .real).toSeconds());
    const pk = try peerPublicKey(c.der);
    try testing.expectEqualSlices(u8, &c.key.public_key.toUncompressedSec1(), &pk.toUncompressedSec1());
    var buf: [95]u8 = undefined;
    const text = c.fingerprintText(&buf);
    try testing.expectEqual(c.fingerprint, try parseFingerprint(text));
}

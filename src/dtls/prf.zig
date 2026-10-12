//! The TLS 1.2 PRF (RFC 5246 section 5) with SHA-256, and the secrets DTLS 1.2 derives with it:
//! master secret (incl. extended master secret, RFC 7627), key block, Finished verify_data and
//! the keying-material exporter (RFC 5705) that DTLS-SRTP uses.

const std = @import("std");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// P_SHA256(secret, label || seed) truncated to `out.len`.
pub fn prf(out: []u8, secret: []const u8, label: []const u8, seed: []const []const u8) void {
    // A(1) = HMAC(secret, label || seed); A(i) = HMAC(secret, A(i-1)).
    var a: [32]u8 = undefined;
    var mac = HmacSha256.init(secret);
    mac.update(label);
    for (seed) |s| mac.update(s);
    mac.final(&a);
    var pos: usize = 0;
    while (pos < out.len) {
        var block: [32]u8 = undefined;
        mac = HmacSha256.init(secret);
        mac.update(&a);
        mac.update(label);
        for (seed) |s| mac.update(s);
        mac.final(&block);
        const n = @min(32, out.len - pos);
        @memcpy(out[pos..][0..n], block[0..n]);
        pos += n;
        HmacSha256.create(&a, &a, secret);
    }
}

pub fn masterSecret(pre_master: []const u8, client_random: [32]u8, server_random: [32]u8) [48]u8 {
    var out: [48]u8 = undefined;
    prf(&out, pre_master, "master secret", &.{ &client_random, &server_random });
    return out;
}

/// RFC 7627: the session hash covers the handshake up to and including ClientKeyExchange.
pub fn extendedMasterSecret(pre_master: []const u8, session_hash: [32]u8) [48]u8 {
    var out: [48]u8 = undefined;
    prf(&out, pre_master, "extended master secret", &.{&session_hash});
    return out;
}

/// Keys for TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: no MAC keys, 16-byte keys, 4-byte salts.
pub const KeyBlock = struct {
    client_key: [16]u8,
    server_key: [16]u8,
    client_iv: [4]u8,
    server_iv: [4]u8,
};

pub fn keyBlock(master: [48]u8, client_random: [32]u8, server_random: [32]u8) KeyBlock {
    var out: [40]u8 = undefined;
    prf(&out, &master, "key expansion", &.{ &server_random, &client_random });
    return .{
        .client_key = out[0..16].*,
        .server_key = out[16..32].*,
        .client_iv = out[32..36].*,
        .server_iv = out[36..40].*,
    };
}

pub fn verifyData(master: [48]u8, is_client: bool, transcript_hash: [32]u8) [12]u8 {
    var out: [12]u8 = undefined;
    prf(&out, &master, if (is_client) "client finished" else "server finished", &.{&transcript_hash});
    return out;
}

/// RFC 5705 exporter without context (what RFC 5764 uses with "EXTRACTOR-dtls_srtp").
pub fn exporter(out: []u8, master: [48]u8, label: []const u8, client_random: [32]u8, server_random: [32]u8) void {
    prf(out, &master, label, &.{ &client_random, &server_random });
}

const testing = std.testing;

test "TLS 1.2 PRF SHA-256 test vector" {
    // The widely used vector posted to the IETF TLS list (also in Go's and NSS's test suites).
    var secret: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret, "9bbe436ba940f017b17652849a71db35");
    var seed: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, "a0ba9f936cda311827a6f796ffd5198c");
    var want: [100]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a" ++
        "6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab" ++
        "4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701" ++
        "87347b66");
    var out: [100]u8 = undefined;
    prf(&out, &secret, "test label", &.{&seed});
    try testing.expectEqualSlices(u8, &want, &out);
}

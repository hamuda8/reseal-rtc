//! Two PeerConnections in one process over an in-memory UDP network: offer/answer, ICE,
//! DTLS, SRTP, and Opus + H.264 frames in both directions, with and without packet loss.

const std = @import("std");
const peer = @import("../peer.zig");
const net = @import("../net.zig");
const IceAgent = @import("../ice/Agent.zig");

const testing = std.testing;
const PeerConnection = peer.PeerConnection;

const Net = struct {
    gpa: std.mem.Allocator,
    queue: std.ArrayList(Packet) = .empty,
    /// Drop roughly 1 in `loss` SRTP packets (0 = none). Handshake traffic is kept.
    loss: u32 = 0,
    counter: u32 = 0,
    dropped: u32 = 0,

    const Packet = struct { to: u8, from: net.Address, data: []u8 };

    const addrs = [2]net.Address{ net.Address.ip4(.{ 10, 0, 0, 1 }, 40000), net.Address.ip4(.{ 10, 0, 0, 2 }, 40002) };

    const Port = struct { n: *Net, idx: u8 };

    fn send(ctx: *anyopaque, to: net.Address, data: []const u8) void {
        const port: *Port = @ptrCast(@alignCast(ctx));
        const n = port.n;
        const target: u8 = if (to.eql(addrs[0])) 0 else if (to.eql(addrs[1])) 1 else return;
        if (n.loss != 0 and data.len > 0 and data[0] >= 128) {
            n.counter += 1;
            if ((n.counter *% 2654435761) >> 8 & 0xffff < 0x10000 / n.loss) {
                n.dropped += 1;
                return;
            }
        }
        n.queue.append(n.gpa, .{ .to = target, .from = addrs[port.idx], .data = n.gpa.dupe(u8, data) catch unreachable }) catch unreachable;
    }

    fn deinit(n: *Net) void {
        for (n.queue.items) |p| n.gpa.free(p.data);
        n.queue.deinit(n.gpa);
    }
};

const Side = struct {
    gpa: std.mem.Allocator,
    pc: *PeerConnection = undefined,
    candidates: std.ArrayList([]u8) = .empty,
    audio: std.ArrayList([]u8) = .empty,
    video: std.ArrayList([]u8) = .empty,
    keyframe_requests: u32 = 0,
    bitrate: u32 = 0,
    bitrate_min: u32 = std.math.maxInt(u32),
    connected: bool = false,

    fn onEvent(ctx: *anyopaque, e: peer.Event) void {
        const s: *Side = @ptrCast(@alignCast(ctx));
        switch (e) {
            .local_candidate => |c| s.candidates.append(s.gpa, s.gpa.dupe(u8, c) catch unreachable) catch unreachable,
            .connection_state => |st| s.connected = st == .connected,
            .audio_frame => |f| s.audio.append(s.gpa, s.gpa.dupe(u8, f.data) catch unreachable) catch unreachable,
            .video_frame => |f| if (!f.corrupt) s.video.append(s.gpa, s.gpa.dupe(u8, f.data) catch unreachable) catch unreachable,
            .keyframe_requested => s.keyframe_requests += 1,
            .send_bitrate => |b| {
                s.bitrate = b.bps;
                s.bitrate_min = @min(s.bitrate_min, b.bps);
            },
            else => {},
        }
    }

    fn deinit(s: *Side) void {
        for ([_]*std.ArrayList([]u8){ &s.candidates, &s.audio, &s.video }) |l| {
            for (l.items) |x| s.gpa.free(x);
            l.deinit(s.gpa);
        }
    }
};

fn pump(n: *Net, pcs: [2]*PeerConnection, now: u64) void {
    while (n.queue.items.len > 0) {
        const p = n.queue.orderedRemove(0);
        defer n.gpa.free(p.data);
        pcs[p.to].receive(0, p.from, p.data, now);
    }
    pcs[0].poll(now);
    pcs[1].poll(now);
}

/// A synthetic access unit: SPS + PPS + a large IDR (forces STAP-A and FU-A), Annex-B.
fn testFrame(buf: []u8, seed: u8, size: usize) []u8 {
    const head = [_]u8{ 0, 0, 0, 1, 0x67, 0x42, 0xe0, 0x1f, 0, 0, 0, 1, 0x68, 0xce, 0x3c, 0x80, 0, 0, 0, 1, 0x65 };
    @memcpy(buf[0..head.len], &head);
    for (buf[head.len..][0..size], 0..) |*b, i| b.* = @truncate((i * 31 + seed) | 1); // no zero runs
    return buf[0 .. head.len + size];
}

fn run(loss: u32, srtp_profiles: []const @import("../media/srtp.zig").Profile) !void {
    const gpa = testing.allocator;
    var n: Net = .{ .gpa = gpa };
    defer n.deinit();
    var ports = [2]Net.Port{ .{ .n = &n, .idx = 0 }, .{ .n = &n, .idx = 1 } };
    var sides = [2]Side{ .{ .gpa = gpa }, .{ .gpa = gpa } };
    defer for (&sides) |*s| s.deinit();

    var pcs: [2]*PeerConnection = undefined;
    for (0..2) |i| {
        const sockets = [_]net.Socket{.{ .ctx = &ports[i], .sendFn = Net.send, .local = Net.addrs[i] }};
        pcs[i] = try PeerConnection.create(gpa, testing.io, .{
            .sockets = &sockets,
            .srtp_profiles = srtp_profiles,
            .handler = .{ .ctx = &sides[i], .onEvent = Side.onEvent },
        });
        sides[i].pc = pcs[i];
    }
    defer for (pcs) |pc| pc.destroy();

    var now: u64 = 1_000;
    const offer = try pcs[0].createOffer(gpa, now);
    defer gpa.free(offer);
    try pcs[1].setRemoteDescription(.offer, offer, now);
    const answer = try pcs[1].createAnswer(gpa, now);
    defer gpa.free(answer);
    try pcs[0].setRemoteDescription(.answer, answer, now);
    // Trickle the answerer's candidates too (they are also in the answer; duplicates are fine).
    for (sides[1].candidates.items) |c| try pcs[0].addIceCandidate(c);

    while (now < 10_000 and !(sides[0].connected and sides[1].connected)) : (now += 5) pump(&n, pcs, now);
    try testing.expect(sides[0].connected and sides[1].connected);
    n.loss = loss;

    var frame_buf: [8000]u8 = undefined;
    const opus_silence = [_]u8{ 0xF8, 0xFF, 0xFE };
    var frames_sent: u32 = 0;
    var ts: u32 = 0;
    // 2 seconds of 20 ms audio and 10 fps video in both directions.
    var tick: u32 = 0;
    while (tick < 100) : (tick += 1) {
        for (pcs) |pc| try pc.sendAudio(&opus_silence);
        if (tick % 5 == 0) {
            const f = testFrame(&frame_buf, @truncate(frames_sent), 5000);
            for (pcs) |pc| try pc.sendVideo(f, ts);
            frames_sent += 1;
            ts += 9000;
        }
        for (0..4) |_| {
            now += 5;
            pump(&n, pcs, now);
        }
    }
    // Let NACK retransmissions and jitter buffers settle.
    for (0..200) |_| {
        now += 5;
        pump(&n, pcs, now);
    }

    if (loss != 0) {
        std.debug.print("loss test: dropped {d}, video frames {d}/{d} and {d}/{d}, audio {d} and {d}\n", .{ n.dropped, sides[0].video.items.len, frames_sent, sides[1].video.items.len, frames_sent, sides[0].audio.items.len, sides[1].audio.items.len });
        try testing.expect(n.dropped > 20);
    }
    for (&sides, 0..) |*s, i| {
        const st = pcs[i].stats();
        if (loss == 0) {
            try testing.expectEqual(@as(usize, 100), s.audio.items.len);
            try testing.expectEqual(@as(usize, frames_sent), s.video.items.len);
        } else {
            // Audio has no retransmission; video recovers through NACK.
            try testing.expect(s.audio.items.len >= 80);
            try testing.expect(s.video.items.len >= frames_sent - 2);
        }
        try testing.expectEqualSlices(u8, &opus_silence, s.audio.items[0]);
        const want = testFrame(&frame_buf, 0, 5000);
        try testing.expectEqualSlices(u8, want, s.video.items[0]);
        try testing.expectEqual(@as(u64, 0), st.srtp_errors);
        try testing.expectEqual(peer.ConnectionState.connected, st.connection);
    }
}

test "loopback: ICE + DTLS + SRTP (GCM) + Opus/H.264 both ways" {
    try run(0, &.{ .aead_aes128_gcm, .aes128_cm_sha1_80 });
}

test "loopback: AES-CM-80 profile" {
    try run(0, &.{.aes128_cm_sha1_80});
}

test "loopback: 5% media loss recovered by NACK" {
    try run(20, &.{ .aead_aes128_gcm, .aes128_cm_sha1_80 });
}

fn noSend(_: *anyopaque, _: net.Address, _: []const u8) void {}

test "answer to a Chrome offer: codec choice, setup, rejected data-channel m-line" {
    const gpa = testing.allocator;
    const sdp = @import("../sdp/sdp.zig");
    var dummy: u8 = 0;
    const sockets = [_]net.Socket{.{ .ctx = &dummy, .sendFn = noSend, .local = net.Address.ip4(.{ 192, 168, 1, 5 }, 50000) }};
    var side: Side = .{ .gpa = gpa };
    defer side.deinit();
    const pc = try PeerConnection.create(gpa, testing.io, .{ .sockets = &sockets, .handler = .{ .ctx = &side, .onEvent = Side.onEvent } });
    defer pc.destroy();
    const offer = sdp.chrome_offer ++ "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:2\r\na=sctp-port:5000\r\n";
    try pc.setRemoteDescription(.offer, offer, 0);
    const answer = try pc.createAnswer(gpa, 0);
    defer gpa.free(answer);
    var s = try sdp.Session.parse(gpa, answer);
    defer s.deinit();
    try testing.expectEqual(@as(usize, 3), s.media.len);
    try testing.expectEqualStrings("BUNDLE 0 1", s.attr("group").?);
    try testing.expectEqualStrings("active", s.media[0].attr("setup").?);
    try testing.expectEqualStrings("111", s.media[0].formats);
    try testing.expectEqualStrings("106", s.media[1].formats); // constrained baseline, mode 1
    try testing.expectEqual(@as(u16, 0), s.media[2].port);
    try testing.expectEqualStrings("application", s.media[2].kind);
    try testing.expectEqualStrings("2", s.media[2].mid().?);
    try testing.expectEqualStrings("1000 1 udp 2130706431 192.168.1.5 50000 typ host generation 0", s.media[0].attr("candidate").?);
}

test "loopback: renegotiation keeps roles and media flowing" {
    const gpa = testing.allocator;
    var n: Net = .{ .gpa = gpa };
    defer n.deinit();
    var ports = [2]Net.Port{ .{ .n = &n, .idx = 0 }, .{ .n = &n, .idx = 1 } };
    var sides = [2]Side{ .{ .gpa = gpa }, .{ .gpa = gpa } };
    defer for (&sides) |*s| s.deinit();
    var pcs: [2]*PeerConnection = undefined;
    for (0..2) |i| {
        const sockets = [_]net.Socket{.{ .ctx = &ports[i], .sendFn = Net.send, .local = Net.addrs[i] }};
        pcs[i] = try PeerConnection.create(gpa, testing.io, .{ .sockets = &sockets, .handler = .{ .ctx = &sides[i], .onEvent = Side.onEvent } });
    }
    defer for (pcs) |pc| pc.destroy();
    var now: u64 = 1000;
    const offer = try pcs[0].createOffer(gpa, now);
    defer gpa.free(offer);
    try pcs[1].setRemoteDescription(.offer, offer, now);
    const answer = try pcs[1].createAnswer(gpa, now);
    defer gpa.free(answer);
    try pcs[0].setRemoteDescription(.answer, answer, now);
    while (now < 10_000 and !(sides[0].connected and sides[1].connected)) : (now += 5) pump(&n, pcs, now);
    try testing.expect(sides[0].connected and sides[1].connected);

    // Now the original answerer re-offers (as perfect negotiation does when a track is added).
    const reoffer = try pcs[1].createOffer(gpa, now);
    defer gpa.free(reoffer);
    try testing.expect(std.mem.indexOf(u8, reoffer, "a=setup:active") != null); // not actpass
    try pcs[0].setRemoteDescription(.offer, reoffer, now);
    const reanswer = try pcs[0].createAnswer(gpa, now);
    defer gpa.free(reanswer);
    try testing.expect(std.mem.indexOf(u8, reanswer, "a=setup:passive") != null);
    try pcs[1].setRemoteDescription(.answer, reanswer, now);

    for (0..10) |_| {
        try pcs[0].sendAudio(&.{ 0xF8, 0xFF, 0xFE });
        for (0..4) |_| {
            now += 5;
            pump(&n, pcs, now);
        }
    }
    for (0..40) |_| {
        now += 5;
        pump(&n, pcs, now);
    }
    try testing.expectEqual(@as(usize, 10), sides[1].audio.items.len);
    try testing.expect(sides[0].connected and sides[1].connected);
}

test "loopback: send bitrate falls under video loss and recovers" {
    const gpa = testing.allocator;
    var n: Net = .{ .gpa = gpa };
    defer n.deinit();
    var ports = [2]Net.Port{ .{ .n = &n, .idx = 0 }, .{ .n = &n, .idx = 1 } };
    var sides = [2]Side{ .{ .gpa = gpa }, .{ .gpa = gpa } };
    defer for (&sides) |*s| s.deinit();
    var pcs: [2]*PeerConnection = undefined;
    for (0..2) |i| {
        const sockets = [_]net.Socket{.{ .ctx = &ports[i], .sendFn = Net.send, .local = Net.addrs[i] }};
        pcs[i] = try PeerConnection.create(gpa, testing.io, .{ .sockets = &sockets, .handler = .{ .ctx = &sides[i], .onEvent = Side.onEvent } });
    }
    defer for (pcs) |pc| pc.destroy();
    var now: u64 = 1000;
    const offer = try pcs[0].createOffer(gpa, now);
    defer gpa.free(offer);
    try pcs[1].setRemoteDescription(.offer, offer, now);
    const answer = try pcs[1].createAnswer(gpa, now);
    defer gpa.free(answer);
    try pcs[0].setRemoteDescription(.answer, answer, now);
    while (now < 10_000 and !(sides[0].connected and sides[1].connected)) : (now += 5) pump(&n, pcs, now);
    try testing.expectEqual(@as(u32, 600_000), sides[0].bitrate);

    var frame_buf: [8000]u8 = undefined;
    var ts: u32 = 0;
    const phase = struct {
        fn run(nn: *Net, p: [2]*PeerConnection, t: *u64, stamp: *u32, buf: []u8, seconds: u32) !void {
            for (0..seconds * 10) |_| {
                try p[0].sendVideo(testFrame(buf, 1, 3000), stamp.*);
                stamp.* +%= 9000;
                for (0..20) |_| {
                    t.* += 5;
                    pump(nn, p, t.*);
                }
            }
        }
    }.run;
    pcs[0].debug_drop_video_percent = 20;
    try phase(&n, pcs, &now, &ts, &frame_buf, 8);
    const lossy = sides[0].bitrate;
    try testing.expect(lossy < 450_000);
    pcs[0].debug_drop_video_percent = 0;
    try phase(&n, pcs, &now, &ts, &frame_buf, 20);
    try testing.expect(sides[0].bitrate > lossy * 2);
}

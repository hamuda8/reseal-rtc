//! ICE through TURN: the direct path between the agents is blocked, so the only working pair
//! is agent 0's relayed candidate <-> agent 1's host candidate, via an in-process TURN server.

const std = @import("std");
const net = @import("../net.zig");
const stun = @import("../ice/stun.zig");
const IceAgent = @import("../ice/Agent.zig");

const testing = std.testing;
const Address = net.Address;

const host0 = Address.ip4(.{ 10, 0, 0, 1 }, 1000);
const host1 = Address.ip4(.{ 10, 0, 0, 2 }, 2000);
const turn_addr = Address.ip4(.{ 10, 0, 0, 9 }, 3478);
const relay_addr = Address.ip4(.{ 10, 0, 0, 9 }, 50000);

const Datagram = struct { from: Address, to: Address, data: []u8 };

/// Minimal TURN server: one allocation, long-term auth, permissions, Send/Data indications
/// and channels. Enough to relay ICE checks and application data.
const Turn = struct {
    gpa: std.mem.Allocator,
    key: [16]u8,
    client: ?Address = null,
    permitted: std.ArrayList(Address) = .empty,
    channels: std.ArrayList(struct { number: u16, peer: Address }) = .empty,
    relayed_packets: usize = 0,

    fn deinit(t: *Turn) void {
        t.permitted.deinit(t.gpa);
        t.channels.deinit(t.gpa);
    }

    fn permittedIp(t: *const Turn, a: Address) bool {
        for (t.permitted.items) |p| if (p.sameIp(a)) return true;
        return false;
    }

    /// A datagram to the TURN server's control address.
    fn fromClient(t: *Turn, n: *Net, from: Address, data: []const u8) void {
        var buf: [1600]u8 = undefined;
        if (data[0] >= 0x40 and data[0] <= 0x7F) {
            const number = std.mem.readInt(u16, data[0..2], .big);
            const len = std.mem.readInt(u16, data[2..4], .big);
            for (t.channels.items) |c| if (c.number == number) {
                t.relayed_packets += 1;
                n.push(relay_addr, c.peer, data[4..][0..len]);
            };
            return;
        }
        const m = stun.Message.parse(data) catch return;
        if (m.method == .send and m.class == .indication) {
            const peer = m.xorAddress(stun.attr.xor_peer_address) orelse return;
            if (!t.permittedIp(peer)) return;
            t.relayed_packets += 1;
            n.push(relay_addr, peer, m.get(stun.attr.data) orelse return);
            return;
        }
        if (m.class != .request) return;
        if (!m.has(stun.attr.message_integrity)) {
            var b = stun.Builder.init(&buf, m.method, .failure, m.txid);
            b.addErrorCode(401, "Unauthorized") catch return;
            b.add(stun.attr.realm, "reseal") catch return;
            b.add(stun.attr.nonce, "n0nce") catch return;
            n.push(turn_addr, from, b.bytes());
            return;
        }
        if (!m.checkIntegrity(&t.key)) return;
        var b = stun.Builder.init(&buf, m.method, .success, m.txid);
        switch (m.method) {
            .allocate => {
                t.client = from;
                b.addXorAddress(stun.attr.xor_relayed_address, relay_addr) catch return;
                b.addXorAddress(stun.attr.xor_mapped_address, from) catch return;
                b.addU32(stun.attr.lifetime, 600) catch return;
            },
            .create_permission => t.permitted.append(t.gpa, m.xorAddress(stun.attr.xor_peer_address).?) catch return,
            .channel_bind => t.channels.append(t.gpa, .{ .number = @intCast(m.getU32(stun.attr.channel_number).? >> 16), .peer = m.xorAddress(stun.attr.xor_peer_address).? }) catch return,
            else => {},
        }
        b.addIntegrity(&t.key) catch return;
        n.push(turn_addr, from, b.bytes());
    }

    /// A datagram from a peer to the relayed address.
    fn fromPeer(t: *Turn, n: *Net, from: Address, data: []const u8) void {
        if (!t.permittedIp(from)) return;
        const client = t.client orelse return;
        t.relayed_packets += 1;
        var buf: [1600]u8 = undefined;
        for (t.channels.items) |c| if (c.peer.eql(from)) {
            std.mem.writeInt(u16, buf[0..2], c.number, .big);
            std.mem.writeInt(u16, buf[2..4], @intCast(data.len), .big);
            @memcpy(buf[4..][0..data.len], data);
            n.push(turn_addr, client, buf[0 .. 4 + data.len]);
            return;
        };
        var b = stun.Builder.init(&buf, .data, .indication, @splat(7));
        b.addXorAddress(stun.attr.xor_peer_address, from) catch return;
        b.add(stun.attr.data, data) catch return;
        n.push(turn_addr, client, b.bytes());
    }
};

const Net = struct {
    gpa: std.mem.Allocator,
    queue: std.ArrayList(Datagram) = .empty,
    blocked_direct: usize = 0,

    fn push(n: *Net, from: Address, to: Address, data: []const u8) void {
        n.queue.append(n.gpa, .{ .from = from, .to = to, .data = n.gpa.dupe(u8, data) catch unreachable }) catch unreachable;
    }

    fn deinit(n: *Net) void {
        for (n.queue.items) |d| n.gpa.free(d.data);
        n.queue.deinit(n.gpa);
    }
};

const Port = struct { n: *Net, local: Address };

fn sendFn(ctx: *anyopaque, to: Address, data: []const u8) void {
    const p: *Port = @ptrCast(@alignCast(ctx));
    // Agent 0 sits behind a firewall: no direct traffic with agent 1 either way.
    if ((p.local.eql(host0) and to.eql(host1)) or (p.local.eql(host1) and to.eql(host0))) {
        p.n.blocked_direct += 1;
        return;
    }
    p.n.push(p.local, to, data);
}

const Obs = struct {
    gpa: std.mem.Allocator,
    candidates: std.ArrayList(IceAgent.Candidate) = .empty,
    fn onCandidate(ctx: *anyopaque, c: *const IceAgent.Candidate) void {
        const o: *Obs = @ptrCast(@alignCast(ctx));
        o.candidates.append(o.gpa, c.*) catch unreachable;
    }
    fn onDone(_: *anyopaque) void {}
    fn onState(_: *anyopaque, _: IceAgent.State) void {}
};

test "ICE connects through a TURN relay when the direct path is blocked" {
    const gpa = testing.allocator;
    var n: Net = .{ .gpa = gpa };
    defer n.deinit();
    var turn: Turn = .{ .gpa = gpa, .key = stun.longTermKey("1700000000:alice", "reseal", "s3cret") };
    defer turn.deinit();
    var ports = [2]Port{ .{ .n = &n, .local = host0 }, .{ .n = &n, .local = host1 } };
    var obs = [2]Obs{ .{ .gpa = gpa }, .{ .gpa = gpa } };
    defer for (&obs) |*o| o.candidates.deinit(gpa);

    const servers = [_]IceAgent.Server{.{ .address = turn_addr, .turn = true, .username = "1700000000:alice", .password = "s3cret" }};
    const s0 = [_]net.Socket{.{ .ctx = &ports[0], .sendFn = sendFn, .local = host0 }};
    const s1 = [_]net.Socket{.{ .ctx = &ports[1], .sendFn = sendFn, .local = host1 }};
    var a0 = try IceAgent.init(gpa, testing.io, .{ .role = .controlling, .servers = &servers }, &s0, .{ .ctx = &obs[0], .candidate = Obs.onCandidate, .gathering_done = Obs.onDone, .state = Obs.onState });
    defer a0.deinit();
    var a1 = try IceAgent.init(gpa, testing.io, .{ .role = .controlled }, &s1, .{ .ctx = &obs[1], .candidate = Obs.onCandidate, .gathering_done = Obs.onDone, .state = Obs.onState });
    defer a1.deinit();
    try a0.setRemoteCredentials(a1.localUfrag(), a1.localPwd());
    try a1.setRemoteCredentials(a0.localUfrag(), a0.localPwd());
    try a0.gather(0);
    try a1.gather(0);

    var exchanged = [2]usize{ 0, 0 };
    var app_received: usize = 0;
    var now: u64 = 0;
    while (now < 5000) : (now += 10) {
        // Trickle new candidates both ways.
        for (obs[0].candidates.items[exchanged[0]..]) |c| try a1.addRemoteCandidate(c);
        exchanged[0] = obs[0].candidates.items.len;
        for (obs[1].candidates.items[exchanged[1]..]) |c| try a0.addRemoteCandidate(c);
        exchanged[1] = obs[1].candidates.items.len;

        while (n.queue.items.len > 0) {
            const d = n.queue.orderedRemove(0);
            defer gpa.free(d.data);
            if (d.to.eql(turn_addr)) {
                turn.fromClient(&n, d.from, d.data);
            } else if (d.to.eql(relay_addr)) {
                turn.fromPeer(&n, d.from, d.data);
            } else if (d.to.eql(host0)) {
                if (a0.receive(0, d.from, d.data, now)) |_| app_received += 1;
            } else if (d.to.eql(host1)) {
                if (a1.receive(0, d.from, d.data, now)) |_| app_received += 1;
            }
        }
        a0.poll(now);
        a1.poll(now);
        if (a0.state == .connected and a1.state == .connected and now > 1000) break;
    }
    try testing.expectEqual(IceAgent.State.connected, a0.state);
    try testing.expectEqual(IceAgent.State.connected, a1.state);
    const sel = a0.selectedPair().?;
    try testing.expectEqual(@import("../ice/candidate.zig").Type.relay, sel.local.type);
    try testing.expect(sel.local.address.eql(relay_addr));
    try testing.expect(n.blocked_direct > 0);

    // Application data both ways over the relay.
    try a0.send("via-turn");
    try a1.send("back");
    for (0..4) |_| {
        while (n.queue.items.len > 0) {
            const d = n.queue.orderedRemove(0);
            defer gpa.free(d.data);
            if (d.to.eql(turn_addr)) turn.fromClient(&n, d.from, d.data) else if (d.to.eql(relay_addr)) turn.fromPeer(&n, d.from, d.data) else if (d.to.eql(host0)) {
                if (a0.receive(0, d.from, d.data, now)) |x| {
                    try testing.expectEqualStrings("back", x);
                    app_received += 1;
                }
            } else if (d.to.eql(host1)) {
                if (a1.receive(0, d.from, d.data, now)) |x| {
                    try testing.expectEqualStrings("via-turn", x);
                    app_received += 1;
                }
            }
        }
    }
    try testing.expectEqual(@as(usize, 2), app_received);
    try testing.expect(turn.relayed_packets > 4);
}

test "server-reflexive candidate from a STUN server" {
    const gpa = testing.allocator;
    var n: Net = .{ .gpa = gpa };
    defer n.deinit();
    var port: Port = .{ .n = &n, .local = host0 };
    var obs: Obs = .{ .gpa = gpa };
    defer obs.candidates.deinit(gpa);
    const stun_server = Address.ip4(.{ 198, 51, 100, 7 }, 3478);
    const public = Address.ip4(.{ 203, 0, 113, 50 }, 61000);
    const servers = [_]IceAgent.Server{.{ .address = stun_server }};
    const s0 = [_]net.Socket{.{ .ctx = &port, .sendFn = sendFn, .local = host0 }};
    var a = try IceAgent.init(gpa, testing.io, .{ .role = .controlling, .servers = &servers }, &s0, .{ .ctx = &obs, .candidate = Obs.onCandidate, .gathering_done = Obs.onDone, .state = Obs.onState });
    defer a.deinit();
    try a.gather(0);
    try testing.expectEqual(@as(usize, 1), n.queue.items.len); // the Binding request
    const req = try stun.Message.parse(n.queue.items[0].data);
    var buf: [128]u8 = undefined;
    var b = stun.Builder.init(&buf, .binding, .success, req.txid);
    try b.addXorAddress(stun.attr.xor_mapped_address, public);
    try b.addFingerprint();
    _ = a.receive(0, stun_server, b.bytes(), 10);
    try testing.expectEqual(@as(usize, 2), obs.candidates.items.len);
    const srflx = obs.candidates.items[1];
    try testing.expectEqual(@import("../ice/candidate.zig").Type.srflx, srflx.type);
    try testing.expect(srflx.address.eql(public));
    try testing.expect(srflx.related.?.eql(host0));
    try testing.expect(a.gathering_complete);
}

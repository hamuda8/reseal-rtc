//! TURN client over UDP (RFC 8656): Allocate with long-term credentials, Refresh,
//! CreatePermission, ChannelBind, Send/Data indications and ChannelData.
//!
//! Sans-IO like the rest: `handle` takes datagrams that came from the TURN server, `poll`
//! drives retransmissions and refreshes, and output goes through `Output`.

const std = @import("std");
const stun = @import("stun.zig");
const Address = @import("../net.zig").Address;

pub const Output = struct {
    ctx: *anyopaque,
    /// Send `data` to the TURN server from the client's socket.
    send: *const fn (ctx: *anyopaque, socket: u8, to: Address, data: []const u8) void,
};

pub const State = enum { idle, allocating, allocated, failed, closed };

pub const Event = union(enum) {
    none,
    allocated,
    failed,
    /// Data relayed from a peer.
    data: struct { peer: Address, payload: []const u8 },
};

const Kind = enum { allocate, refresh, permission, channel_bind };

const Tx = struct {
    txid: [12]u8,
    kind: Kind,
    peer: Address = .{},
    channel: u16 = 0,
    lifetime: u32 = 600,
    next_at: u64,
    attempts: u8 = 0,
    msg: [512]u8 = undefined,
    len: usize = 0,
};

const Permission = struct { peer: Address, refresh_at: u64, installed: bool, pending: bool };
const Channel = struct { number: u16, peer: Address, bound: bool, pending: bool, refresh_at: u64 };

const rto_ms = 500;
const max_attempts = 6;

gpa: std.mem.Allocator,
io: std.Io,
out: Output,
server: Address,
socket: u8,
username: []u8,
password: []u8,

state: State = .idle,
failure: ?anyerror = null,
realm: std.ArrayList(u8) = .empty,
nonce: std.ArrayList(u8) = .empty,
key: [16]u8 = undefined,
authenticated: bool = false,

relayed: Address = .{},
mapped: Address = .{},
refresh_at: u64 = 0,

perms: std.ArrayList(Permission) = .empty,
channels: std.ArrayList(Channel) = .empty,
next_channel: u16 = 0x4000,
txs: std.ArrayList(Tx) = .empty,
now: u64 = 0,

const Client = @This();

pub fn init(gpa: std.mem.Allocator, io: std.Io, out: Output, socket: u8, server: Address, username: []const u8, password: []const u8) !Client {
    const u = try gpa.dupe(u8, username);
    errdefer gpa.free(u);
    return .{ .gpa = gpa, .io = io, .out = out, .server = server, .socket = socket, .username = u, .password = try gpa.dupe(u8, password) };
}

pub fn deinit(c: *Client) void {
    c.gpa.free(c.username);
    c.gpa.free(c.password);
    c.realm.deinit(c.gpa);
    c.nonce.deinit(c.gpa);
    c.perms.deinit(c.gpa);
    c.channels.deinit(c.gpa);
    c.txs.deinit(c.gpa);
}

pub fn start(c: *Client, now: u64) void {
    c.now = now;
    if (c.state != .idle) return;
    c.state = .allocating;
    c.request(.{ .kind = .allocate, .txid = undefined, .next_at = now }) catch |err| c.fail(err);
}

/// Releases the allocation (Refresh with LIFETIME 0); best effort.
pub fn close(c: *Client) void {
    if (c.state == .allocated) c.request(.{ .kind = .refresh, .lifetime = 0, .txid = undefined, .next_at = c.now }) catch {};
    c.state = .closed;
}

/// True for datagrams this client should handle (from its server, on its socket).
pub fn owns(c: *const Client, socket: u8, from: Address) bool {
    return socket == c.socket and from.eql(c.server);
}

fn fail(c: *Client, err: anyerror) void {
    c.failure = err;
    c.state = .failed;
}

fn newTxid(c: *Client) [12]u8 {
    var t: [12]u8 = undefined;
    c.io.random(&t);
    return t;
}

/// Builds and sends a request (adding auth once we have a realm and nonce) and tracks it.
fn request(c: *Client, template: Tx) !void {
    var tx = template;
    tx.txid = c.newTxid();
    const method: stun.Method = switch (tx.kind) {
        .allocate => .allocate,
        .refresh => .refresh,
        .permission => .create_permission,
        .channel_bind => .channel_bind,
    };
    var b = stun.Builder.init(&tx.msg, method, .request, tx.txid);
    switch (tx.kind) {
        .allocate => {
            try b.addU32(stun.attr.requested_transport, 17 << 24); // UDP
            try b.addU32(stun.attr.lifetime, 600);
        },
        .refresh => try b.addU32(stun.attr.lifetime, tx.lifetime),
        .permission => try b.addXorAddress(stun.attr.xor_peer_address, tx.peer),
        .channel_bind => {
            try b.addU32(stun.attr.channel_number, @as(u32, tx.channel) << 16);
            try b.addXorAddress(stun.attr.xor_peer_address, tx.peer);
        },
    }
    if (c.authenticated) {
        try b.add(stun.attr.username, c.username);
        try b.add(stun.attr.realm, c.realm.items);
        try b.add(stun.attr.nonce, c.nonce.items);
        try b.addIntegrity(&c.key);
    }
    try b.addFingerprint();
    tx.len = b.len;
    tx.next_at = c.now + rto_ms;
    tx.attempts = 1;
    c.out.send(c.out.ctx, c.socket, c.server, tx.msg[0..tx.len]);
    try c.txs.append(c.gpa, tx);
}

pub fn nextTimeout(c: *const Client) ?u64 {
    var t: ?u64 = null;
    for (c.txs.items) |tx| t = if (t) |v| @min(v, tx.next_at) else tx.next_at;
    if (c.state == .allocated) {
        t = if (t) |v| @min(v, c.refresh_at) else c.refresh_at;
        for (c.perms.items) |p| t = @min(t.?, p.refresh_at);
        for (c.channels.items) |ch| t = @min(t.?, ch.refresh_at);
    }
    return t;
}

pub fn poll(c: *Client, now: u64) Event {
    c.now = now;
    var i: usize = 0;
    while (i < c.txs.items.len) {
        const tx = &c.txs.items[i];
        if (now >= tx.next_at) {
            if (tx.attempts >= max_attempts) {
                const kind = tx.kind;
                _ = c.txs.swapRemove(i);
                if (kind == .allocate or kind == .refresh) {
                    c.fail(error.TurnTimeout);
                    return .failed;
                }
                continue;
            }
            tx.attempts += 1;
            tx.next_at = now + (@as(u64, rto_ms) << @intCast(tx.attempts - 1));
            c.out.send(c.out.ctx, c.socket, c.server, tx.msg[0..tx.len]);
        }
        i += 1;
    }
    if (c.state != .allocated) return .none;
    if (now >= c.refresh_at) {
        c.refresh_at = now + 60_000; // retried through the transaction if it fails
        c.request(.{ .kind = .refresh, .txid = undefined, .next_at = now }) catch {};
    }
    for (c.perms.items) |*p| if (now >= p.refresh_at and !p.pending) {
        p.pending = true;
        p.refresh_at = now + 240_000;
        c.request(.{ .kind = .permission, .peer = p.peer, .txid = undefined, .next_at = now }) catch {};
    };
    for (c.channels.items) |*ch| if (now >= ch.refresh_at and !ch.pending) {
        ch.pending = true;
        ch.refresh_at = now + 480_000;
        c.request(.{ .kind = .channel_bind, .peer = ch.peer, .channel = ch.number, .txid = undefined, .next_at = now }) catch {};
    };
    return .none;
}

fn ipOnly(a: Address) Address {
    var p = a;
    p.port = 0;
    return p;
}

/// Makes sure the server will relay to and from `peer` (permissions are per IP).
pub fn permit(c: *Client, peer: Address) void {
    if (c.state != .allocated) return;
    for (c.perms.items) |p| if (p.peer.sameIp(peer)) return;
    c.perms.append(c.gpa, .{ .peer = ipOnly(peer), .refresh_at = c.now + 240_000, .installed = false, .pending = true }) catch return;
    c.request(.{ .kind = .permission, .peer = ipOnly(peer), .txid = undefined, .next_at = c.now }) catch {};
}

/// Relays `payload` to `peer`: ChannelData when a channel is bound, else a Send indication
/// (and a ChannelBind is started so later packets use the 4-byte header).
pub fn send(c: *Client, peer: Address, payload: []const u8) void {
    if (c.state != .allocated) return;
    c.permit(peer);
    var buf: [1600]u8 = undefined;
    const channel: ?Channel = for (c.channels.items) |ch| {
        if (ch.peer.eql(peer)) break ch;
    } else null;
    if (channel) |ch| {
        if (ch.bound and payload.len + 4 <= buf.len) {
            std.mem.writeInt(u16, buf[0..2], ch.number, .big);
            std.mem.writeInt(u16, buf[2..4], @intCast(payload.len), .big);
            @memcpy(buf[4..][0..payload.len], payload);
            c.out.send(c.out.ctx, c.socket, c.server, buf[0 .. 4 + payload.len]);
            return;
        }
    } else if (c.next_channel <= 0x4FFF) {
        const number = c.next_channel;
        c.next_channel += 1;
        c.channels.append(c.gpa, .{ .number = number, .peer = peer, .bound = false, .pending = true, .refresh_at = c.now + 480_000 }) catch {};
        c.request(.{ .kind = .channel_bind, .peer = peer, .channel = number, .txid = undefined, .next_at = c.now }) catch {};
    }
    var b = stun.Builder.init(&buf, .send, .indication, c.newTxid());
    b.addXorAddress(stun.attr.xor_peer_address, peer) catch return;
    b.add(stun.attr.data, payload) catch return;
    c.out.send(c.out.ctx, c.socket, c.server, b.bytes());
}

/// Handles a datagram from the TURN server.
pub fn handle(c: *Client, data: []const u8, now: u64) Event {
    c.now = now;
    if (data.len >= 4 and data[0] >= 0x40 and data[0] <= 0x7F) {
        const number = std.mem.readInt(u16, data[0..2], .big);
        const len = std.mem.readInt(u16, data[2..4], .big);
        if (4 + len > data.len) return .none;
        for (c.channels.items) |ch| if (ch.number == number and ch.bound)
            return .{ .data = .{ .peer = ch.peer, .payload = data[4..][0..len] } };
        return .none;
    }
    const m = stun.Message.parse(data) catch return .none;
    if (m.method == .data and m.class == .indication) {
        const peer = m.xorAddress(stun.attr.xor_peer_address) orelse return .none;
        const payload = m.get(stun.attr.data) orelse return .none;
        return .{ .data = .{ .peer = peer, .payload = payload } };
    }
    if (m.class != .success and m.class != .failure) return .none;
    const idx = for (c.txs.items, 0..) |tx, i| {
        if (std.mem.eql(u8, &tx.txid, &m.txid)) break i;
    } else return .none;
    const tx = c.txs.swapRemove(idx);
    if (c.authenticated and !m.checkIntegrity(&c.key) and m.class == .success) return .none;

    if (m.class == .failure) {
        const code = m.errorCode() orelse 0;
        // 401 on the first request carries the realm and nonce; 438 means a new nonce.
        if ((code == 401 and !c.authenticated) or code == 438) {
            const realm = m.get(stun.attr.realm) orelse return c.failWith(error.TurnNoRealm);
            const nonce = m.get(stun.attr.nonce) orelse return c.failWith(error.TurnNoNonce);
            c.realm.clearRetainingCapacity();
            c.realm.appendSlice(c.gpa, realm) catch return c.failWith(error.OutOfMemory);
            c.nonce.clearRetainingCapacity();
            c.nonce.appendSlice(c.gpa, nonce) catch return c.failWith(error.OutOfMemory);
            c.key = stun.longTermKey(c.username, realm, c.password);
            c.authenticated = true;
            c.request(tx) catch |err| return c.failWith(err);
            return .none;
        }
        switch (tx.kind) {
            .allocate => return c.failWith(if (code == 401) error.TurnUnauthorized else error.TurnAllocateFailed),
            .refresh => if (tx.lifetime != 0) return c.failWith(error.TurnRefreshFailed),
            .permission, .channel_bind => {},
        }
        return .none;
    }

    switch (tx.kind) {
        .allocate => {
            c.relayed = m.xorAddress(stun.attr.xor_relayed_address) orelse return c.failWith(error.TurnNoRelayedAddress);
            c.mapped = m.xorAddress(stun.attr.xor_mapped_address) orelse .{};
            const lifetime = m.getU32(stun.attr.lifetime) orelse 600;
            c.refresh_at = now + @as(u64, @max(lifetime, 120) - 60) * 1000;
            c.state = .allocated;
            return .allocated;
        },
        .refresh => {
            const lifetime = m.getU32(stun.attr.lifetime) orelse 600;
            c.refresh_at = now + @as(u64, @max(lifetime, 120) - 60) * 1000;
        },
        .permission => for (c.perms.items) |*p| if (p.peer.sameIp(tx.peer)) {
            p.installed = true;
            p.pending = false;
        },
        .channel_bind => for (c.channels.items) |*ch| if (ch.number == tx.channel) {
            ch.bound = true;
            ch.pending = false;
        },
    }
    return .none;
}

fn failWith(c: *Client, err: anyerror) Event {
    c.fail(err);
    return .failed;
}

// ---- tests: a minimal in-process TURN server ------------------------------------------------

const testing = std.testing;

const FakeServer = struct {
    address: Address = Address.ip4(.{ 198, 51, 100, 1 }, 3478),
    relay: Address = Address.ip4(.{ 198, 51, 100, 1 }, 50000),
    client: Address = Address.ip4(.{ 10, 0, 0, 2 }, 40000),
    realm: []const u8 = "reseal",
    nonce: []const u8 = "abcd",
    key: [16]u8,
    to_client: std.ArrayList([]u8) = .empty,
    to_peers: std.ArrayList(struct { peer: Address, data: []u8 }) = .empty,
    permitted: std.ArrayList(Address) = .empty,
    channel: ?struct { number: u16, peer: Address } = null,
    gpa: std.mem.Allocator,

    fn deinit(s: *FakeServer) void {
        for (s.to_client.items) |d| s.gpa.free(d);
        for (s.to_peers.items) |d| s.gpa.free(d.data);
        s.to_client.deinit(s.gpa);
        s.to_peers.deinit(s.gpa);
        s.permitted.deinit(s.gpa);
    }

    fn reply(s: *FakeServer, b: *stun.Builder, with_integrity: bool) void {
        if (with_integrity) b.addIntegrity(&s.key) catch unreachable;
        s.to_client.append(s.gpa, s.gpa.dupe(u8, b.bytes()) catch unreachable) catch unreachable;
    }

    fn receive(s: *FakeServer, data: []const u8) void {
        var buf: [1600]u8 = undefined;
        if (data[0] >= 0x40 and data[0] <= 0x7F) {
            const ch = s.channel.?;
            std.debug.assert(std.mem.readInt(u16, data[0..2], .big) == ch.number);
            s.to_peers.append(s.gpa, .{ .peer = ch.peer, .data = s.gpa.dupe(u8, data[4..]) catch unreachable }) catch unreachable;
            return;
        }
        const m = stun.Message.parse(data) catch unreachable;
        if (m.method == .send) {
            const peer = m.xorAddress(stun.attr.xor_peer_address).?;
            for (s.permitted.items) |p| if (p.sameIp(peer)) {
                s.to_peers.append(s.gpa, .{ .peer = peer, .data = s.gpa.dupe(u8, m.get(stun.attr.data).?) catch unreachable }) catch unreachable;
            };
            return;
        }
        if (!m.has(stun.attr.message_integrity)) {
            var b = stun.Builder.init(&buf, m.method, .failure, m.txid);
            b.addErrorCode(401, "Unauthorized") catch unreachable;
            b.add(stun.attr.realm, s.realm) catch unreachable;
            b.add(stun.attr.nonce, s.nonce) catch unreachable;
            return s.reply(&b, false);
        }
        std.debug.assert(m.checkIntegrity(&s.key));
        var b = stun.Builder.init(&buf, m.method, .success, m.txid);
        switch (m.method) {
            .allocate => {
                b.addXorAddress(stun.attr.xor_relayed_address, s.relay) catch unreachable;
                b.addXorAddress(stun.attr.xor_mapped_address, s.client) catch unreachable;
                b.addU32(stun.attr.lifetime, 600) catch unreachable;
            },
            .create_permission => s.permitted.append(s.gpa, m.xorAddress(stun.attr.xor_peer_address).?) catch unreachable,
            .channel_bind => s.channel = .{ .number = @intCast(m.getU32(stun.attr.channel_number).? >> 16), .peer = m.xorAddress(stun.attr.xor_peer_address).? },
            else => {},
        }
        s.reply(&b, true);
    }

    fn fromPeer(s: *FakeServer, peer: Address, data: []const u8) void {
        var buf: [1600]u8 = undefined;
        if (s.channel) |ch| if (ch.peer.eql(peer)) {
            std.mem.writeInt(u16, buf[0..2], ch.number, .big);
            std.mem.writeInt(u16, buf[2..4], @intCast(data.len), .big);
            @memcpy(buf[4..][0..data.len], data);
            s.to_client.append(s.gpa, s.gpa.dupe(u8, buf[0 .. 4 + data.len]) catch unreachable) catch unreachable;
            return;
        };
        var b = stun.Builder.init(&buf, .data, .indication, @splat(1));
        b.addXorAddress(stun.attr.xor_peer_address, peer) catch unreachable;
        b.add(stun.attr.data, data) catch unreachable;
        s.reply(&b, false);
    }

    fn sendFn(ctx: *anyopaque, socket: u8, to: Address, data: []const u8) void {
        const s: *FakeServer = @ptrCast(@alignCast(ctx));
        std.debug.assert(socket == 0 and to.eql(s.address));
        s.receive(data);
    }

    fn deliver(s: *FakeServer, c: *Client) std.ArrayList(Event) {
        var events: std.ArrayList(Event) = .empty;
        while (s.to_client.items.len > 0) {
            const d = s.to_client.orderedRemove(0);
            defer s.gpa.free(d);
            const e = c.handle(d, 0);
            // Copy payloads out: they point into `d`.
            switch (e) {
                .data => |x| events.append(s.gpa, .{ .data = .{ .peer = x.peer, .payload = s.gpa.dupe(u8, x.payload) catch unreachable } }) catch unreachable,
                else => events.append(s.gpa, e) catch unreachable,
            }
        }
        return events;
    }
};

test "TURN allocate with long-term auth, permissions, send indication, channel data" {
    const gpa = testing.allocator;
    var server: FakeServer = .{ .gpa = gpa, .key = stun.longTermKey("1700000000:u1", "reseal", "secret") };
    defer server.deinit();
    var c = try Client.init(gpa, testing.io, .{ .ctx = &server, .send = FakeServer.sendFn }, 0, server.address, "1700000000:u1", "secret");
    defer c.deinit();

    c.start(0);
    var ev = server.deliver(&c); // 401, then the authenticated retry succeeds
    ev.deinit(gpa);
    ev = server.deliver(&c);
    ev.deinit(gpa);
    try testing.expectEqual(State.allocated, c.state);
    try testing.expect(c.relayed.eql(server.relay));
    try testing.expect(c.mapped.eql(server.client));

    const peer = Address.ip4(.{ 203, 0, 113, 9 }, 5000);
    c.send(peer, "first"); // CreatePermission + ChannelBind requests, then a Send indication
    ev = server.deliver(&c);
    ev.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), server.to_peers.items.len);
    try testing.expectEqualStrings("first", server.to_peers.items[0].data);
    try testing.expect(c.channels.items[0].bound);

    c.send(peer, "second"); // now over the channel
    try testing.expectEqualStrings("second", server.to_peers.items[1].data);

    server.fromPeer(peer, "reply");
    ev = server.deliver(&c);
    defer {
        for (ev.items) |e| if (e == .data) gpa.free(e.data.payload);
        ev.deinit(gpa);
    }
    try testing.expectEqualStrings("reply", ev.items[0].data.payload);
    try testing.expect(ev.items[0].data.peer.eql(peer));
}

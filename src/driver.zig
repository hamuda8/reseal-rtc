//! Optional std.Io glue: UDP sockets from std.Io.net, a monotonic millisecond clock, ICE
//! server URL resolution, and a `Driver` that runs a PeerConnection's receive and timer loops
//! as concurrent tasks. Apps with their own event loop can skip this and call
//! `PeerConnection.receive` / `poll` themselves.

const std = @import("std");
const net = @import("net.zig");
const IceAgent = @import("ice/Agent.zig");
const PeerConnection = @import("peer.zig").PeerConnection;

const Io = std.Io;

/// Monotonic milliseconds, the time base every engine call expects.
pub fn nowMs(io: Io) u64 {
    return @intCast(Io.Clock.Timestamp.now(io, .awake).raw.toMilliseconds());
}

pub const UdpSocket = struct {
    io: Io,
    sock: Io.net.Socket,
    local: net.Address,

    /// Binds to a concrete interface address (port 0 picks one). The bound address becomes
    /// the host candidate, so it should not be 0.0.0.0.
    pub fn open(io: Io, local: net.Address) !UdpSocket {
        const std_addr = local.toStd();
        const s = try std_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
        var bound = net.Address.fromStd(s.address);
        if (bound.isUnspecified() and !local.isUnspecified()) bound = .{ .family = local.family, .ip = local.ip, .port = bound.port };
        return .{ .io = io, .sock = s, .local = bound };
    }

    pub fn close(u: *UdpSocket) void {
        u.sock.close(u.io);
    }

    pub fn socket(u: *UdpSocket) net.Socket {
        return .{ .ctx = u, .sendFn = sendFn, .local = u.local };
    }

    fn sendFn(ctx: *anyopaque, to: net.Address, data: []const u8) void {
        const u: *UdpSocket = @ptrCast(@alignCast(ctx));
        const dest = to.toStd();
        u.sock.send(u.io, &dest, data) catch {};
    }
};

/// RTCIceServer as the signalling server hands it out.
pub const IceServerUrls = struct {
    urls: []const []const u8,
    username: []const u8 = "",
    credential: []const u8 = "",
};

/// Turns "stun:host:port" / "turn:host:port?transport=udp" URLs into resolved servers.
/// TURN over TCP/TLS ("turns:", transport=tcp) is skipped: only UDP is implemented.
/// The returned slice and its strings are allocated with `gpa` (free with `freeServers`).
pub fn resolveIceServers(io: Io, gpa: std.mem.Allocator, list: []const IceServerUrls) ![]IceAgent.Server {
    var out: std.ArrayList(IceAgent.Server) = .empty;
    errdefer freeServers(gpa, out.items);
    for (list) |entry| for (entry.urls) |url| {
        const turn = std.mem.startsWith(u8, url, "turn:");
        if (!turn and !std.mem.startsWith(u8, url, "stun:")) continue;
        var rest = url[5..];
        if (std.mem.indexOfScalar(u8, rest, '?')) |q| {
            if (std.mem.indexOf(u8, rest[q..], "transport=tcp") != null) continue;
            rest = rest[0..q];
        }
        var host = rest;
        var port: u16 = 3478;
        if (std.mem.startsWith(u8, rest, "[")) {
            const close_br = std.mem.indexOfScalar(u8, rest, ']') orelse continue;
            host = rest[1..close_br];
            if (close_br + 2 <= rest.len and rest[close_br + 1] == ':') port = std.fmt.parseInt(u16, rest[close_br + 2 ..], 10) catch 3478;
        } else if (std.mem.lastIndexOfScalar(u8, rest, ':')) |c| {
            host = rest[0..c];
            port = std.fmt.parseInt(u16, rest[c + 1 ..], 10) catch 3478;
        }
        const address = resolve(io, host, port) catch continue;
        const user = try gpa.dupe(u8, if (turn) entry.username else "");
        errdefer gpa.free(user);
        const pass = try gpa.dupe(u8, if (turn) entry.credential else "");
        errdefer gpa.free(pass);
        try out.append(gpa, .{ .address = address, .turn = turn, .username = user, .password = pass });
    };
    return out.toOwnedSlice(gpa);
}

pub fn freeServers(gpa: std.mem.Allocator, servers: []const IceAgent.Server) void {
    for (servers) |s| {
        gpa.free(s.username);
        gpa.free(s.password);
    }
    gpa.free(servers);
}

/// An IP literal or a host name (first IPv4 answer preferred).
/// The address this machine would use to reach the Internet (the default route's interface),
/// found by "connecting" a UDP socket, which sends nothing. Null without a route. (Zig 0.17's
/// Windows backend rejects connected UDP sockets; phones and Linux are fine.)
pub fn defaultLocalAddress(io: Io, family: net.Address.Family) ?net.Address {
    const probe: Io.net.IpAddress = switch (family) {
        .ip4 => .{ .ip4 = .{ .bytes = .{ 8, 8, 8, 8 }, .port = 53 } },
        .ip6 => .{ .ip6 = .{ .bytes = .{ 0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88 }, .port = 53 } },
    };
    const s = probe.connect(io, .{ .mode = .dgram, .protocol = .udp }) catch return null;
    defer s.close(io);
    var a = net.Address.fromStd(s.socket.address);
    if (a.isUnspecified()) return null;
    a.port = 0;
    return a;
}

pub fn resolve(io: Io, host: []const u8, port: u16) !net.Address {
    if (net.Address.parseIp(host, port)) |a| return a else |_| {}
    const name = try Io.net.HostName.init(host);
    var buf: [16]Io.net.HostName.LookupResult = undefined;
    var queue: Io.Queue(Io.net.HostName.LookupResult) = .init(&buf);
    try name.lookup(io, &queue, .{ .port = port });
    var first: ?net.Address = null;
    while (queue.getOne(io)) |r| switch (r) {
        .address => |a| {
            const addr = net.Address.fromStd(a);
            if (addr.family == .ip4) return addr;
            if (first == null) first = addr;
        },
        .canonical_name => {},
    } else |_| {}
    return first orelse error.UnknownHostName;
}

/// Runs one PeerConnection over std.Io: a receive task per socket and a timer task. Calls
/// into the PeerConnection from other tasks (sendAudio, setRemoteDescription...) must hold
/// the driver's lock: use `lock`/`unlock`.
pub const Driver = struct {
    io: Io,
    pc: *PeerConnection,
    sockets: []UdpSocket,
    mutex: Io.Mutex = .init,
    group: Io.Group = .init,
    /// Called with the lock held after every receive and poll: a place to act on what the
    /// handler saw (renegotiate, restart ICE) without re-entering the PeerConnection.
    on_tick: ?struct { ctx: *anyopaque, f: *const fn (ctx: *anyopaque) void } = null,

    pub fn init(io: Io, pc: *PeerConnection, sockets: []UdpSocket) Driver {
        return .{ .io = io, .pc = pc, .sockets = sockets };
    }

    pub fn start(d: *Driver) !void {
        for (0..d.sockets.len) |i| try d.group.concurrent(d.io, receiveLoop, .{ d, @as(u8, @intCast(i)) });
        try d.group.concurrent(d.io, timerLoop, .{d});
    }

    pub fn stop(d: *Driver) void {
        d.group.cancel(d.io);
    }

    pub fn lock(d: *Driver) void {
        d.mutex.lockUncancelable(d.io);
    }

    pub fn unlock(d: *Driver) void {
        d.mutex.unlock(d.io);
    }

    fn receiveLoop(d: *Driver, index: u8) Io.Cancelable!void {
        var buf: [2048]u8 = undefined;
        while (true) {
            const msg = d.sockets[index].sock.receive(d.io, &buf) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                // Windows reports ICMP port-unreachable as a reset on UDP sockets.
                else => continue,
            };
            try d.mutex.lock(d.io);
            defer d.mutex.unlock(d.io);
            d.pc.receive(index, net.Address.fromStd(msg.from), msg.data, nowMs(d.io));
            if (d.on_tick) |h| h.f(h.ctx);
        }
    }

    fn timerLoop(d: *Driver) Io.Cancelable!void {
        while (true) {
            var wait_ms: u64 = 20;
            {
                try d.mutex.lock(d.io);
                defer d.mutex.unlock(d.io);
                const now = nowMs(d.io);
                d.pc.poll(now);
                if (d.on_tick) |h| h.f(h.ctx);
                if (d.pc.nextTimeout()) |t| wait_ms = std.math.clamp(t -| now, 1, 20);
            }
            try d.io.sleep(.fromMilliseconds(@intCast(wait_ms)), .awake);
        }
    }
};

const testing = std.testing;
const peer = @import("peer.zig");

const Recorder = struct {
    connected: std.atomic.Value(bool) = .init(false),
    audio: std.atomic.Value(u32) = .init(0),

    fn onEvent(ctx: *anyopaque, e: peer.Event) void {
        const r: *Recorder = @ptrCast(@alignCast(ctx));
        switch (e) {
            .connection_state => |s| r.connected.store(s == .connected, .release),
            .audio_frame => _ = r.audio.fetchAdd(1, .monotonic),
            else => {},
        }
    }
};

test "two PeerConnections over real UDP sockets on 127.0.0.1" {
    const io = testing.io;
    const gpa = testing.allocator;
    var socks: [2]UdpSocket = undefined;
    for (&socks) |*s| s.* = try UdpSocket.open(io, net.Address.ip4(.{ 127, 0, 0, 1 }, 0));
    defer for (&socks) |*s| s.close();
    var rec = [2]Recorder{ .{}, .{} };
    var pcs: [2]*PeerConnection = undefined;
    for (0..2) |i| {
        const sockets = [_]net.Socket{socks[i].socket()};
        pcs[i] = try PeerConnection.create(gpa, io, .{ .sockets = &sockets, .video = false, .handler = .{ .ctx = &rec[i], .onEvent = Recorder.onEvent } });
    }
    defer for (pcs) |pc| pc.destroy();
    var drivers = [2]Driver{ .init(io, pcs[0], socks[0..1]), .init(io, pcs[1], socks[1..2]) };

    // Signalling before the loops start, so no locking is needed yet.
    const offer = try pcs[0].createOffer(gpa, nowMs(io));
    defer gpa.free(offer);
    try pcs[1].setRemoteDescription(.offer, offer, nowMs(io));
    const answer = try pcs[1].createAnswer(gpa, nowMs(io));
    defer gpa.free(answer);
    try pcs[0].setRemoteDescription(.answer, answer, nowMs(io));

    for (&drivers) |*d| try d.start();
    defer for (&drivers) |*d| d.stop();

    var waited: u32 = 0;
    while (waited < 5000 and !(rec[0].connected.load(.acquire) and rec[1].connected.load(.acquire))) : (waited += 10)
        try io.sleep(.fromMilliseconds(10), .awake);
    if (!(rec[0].connected.load(.acquire) and rec[1].connected.load(.acquire))) {
        for (0..2) |i| {
            const st = pcs[i].stats();
            std.debug.print("pc{d} local {f} ice {t} conn {t} pairs {d} remotes {d}\n", .{ i, socks[i].local, st.ice, st.connection, pcs[i].transport.ice.pairs.items.len, pcs[i].transport.ice.remotes.items.len });
        }
    }
    try testing.expect(rec[0].connected.load(.acquire) and rec[1].connected.load(.acquire));

    for (0..10) |_| {
        drivers[0].lock();
        pcs[0].sendAudio(&.{ 0xF8, 0xFF, 0xFE }) catch {};
        drivers[0].unlock();
        try io.sleep(.fromMilliseconds(20), .awake);
    }
    waited = 0;
    while (waited < 2000 and rec[1].audio.load(.monotonic) < 10) : (waited += 10) try io.sleep(.fromMilliseconds(10), .awake);
    try testing.expectEqual(@as(u32, 10), rec[1].audio.load(.monotonic));
}

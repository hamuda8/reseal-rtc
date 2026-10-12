//! Interop harness: a reseal-rtc PeerConnection that a real browser connects to.
//!
//!   rtc-interop <answer|offer> <lan-ip> <http-port> [gcm|cm]
//!
//! Serves a page on http://127.0.0.1:<port>/ that creates an RTCPeerConnection with fake
//! camera/microphone. In "answer" mode the browser offers and we answer (we are ICE
//! controlled and DTLS client); in "offer" mode we offer (ICE controlling, DTLS server).
//! Once connected we send Opus packets and H.264 frames from a toy encoder, and count what
//! the browser sends us. GET /status returns our side's results as JSON; the page keeps its
//! getStats() results in window.result for the driver script (run.mjs).

const std = @import("std");
const rtc = @import("reseal_rtc");
const h264enc = @import("h264enc.zig");

const Io = std.Io;

const State = struct {
    connection: rtc.peer.ConnectionState = .new,
    ice: rtc.peer.IceState = .new,
    audio_frames: u64 = 0,
    audio_bytes: u64 = 0,
    video_frames: u64 = 0,
    video_keyframes: u64 = 0,
    video_corrupt: u64 = 0,
    video_bytes: u64 = 0,
    first_video_nals: [8]u8 = @splat(0),
    first_video_nal_count: usize = 0,
    keyframe_requests: u64 = 0,
    remote_bitrate: u64 = 0,
    want_keyframe: bool = true,
    log: std.ArrayList(u8) = .empty,
    gpa: std.mem.Allocator,

    fn note(s: *State, comptime fmt: []const u8, args: anytype) void {
        var buf: [256]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, fmt, args) catch return;
        std.debug.print("[zig] {s}\n", .{line});
        s.log.appendSlice(s.gpa, line) catch {};
        s.log.appendSlice(s.gpa, "; ") catch {};
    }

    fn onEvent(ctx: *anyopaque, e: rtc.peer.Event) void {
        const s: *State = @ptrCast(@alignCast(ctx));
        switch (e) {
            .local_candidate => |c| s.note("local {s}", .{c}),
            .gathering_done => s.note("gathering done", .{}),
            .ice_state => |st| {
                s.ice = st;
                s.note("ice {t}", .{st});
            },
            .connection_state => |st| {
                s.connection = st;
                s.note("connection {t}", .{st});
            },
            .audio_frame => |f| {
                s.audio_frames += 1;
                s.audio_bytes += f.data.len;
            },
            .video_frame => |f| {
                s.video_frames += 1;
                s.video_bytes += f.data.len;
                if (f.keyframe) s.video_keyframes += 1;
                if (f.corrupt) s.video_corrupt += 1;
                if (s.first_video_nal_count == 0) {
                    var it: rtc.h264.AnnexBIterator = .{ .data = f.data };
                    while (it.next()) |nal| {
                        if (s.first_video_nal_count == s.first_video_nals.len) break;
                        s.first_video_nals[s.first_video_nal_count] = nal[0] & 0x1f;
                        s.first_video_nal_count += 1;
                    }
                    s.note("first video frame {d} bytes keyframe={}", .{ f.data.len, f.keyframe });
                }
            },
            .keyframe_requested => {
                s.keyframe_requests += 1;
                s.want_keyframe = true;
            },
            .remote_bitrate => |b| s.remote_bitrate = b,
        }
    }
};

const App = struct {
    io: Io,
    gpa: std.mem.Allocator,
    mode: enum { answer, offer },
    pc: *rtc.PeerConnection,
    driver: *rtc.driver.Driver,
    state: *State,
};

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 4) {
        std.debug.print("usage: rtc-interop <answer|offer> <lan-ip> <http-port> [gcm|cm]\n", .{});
        return error.BadArgs;
    }
    const mode: @FieldType(App, "mode") = if (std.mem.eql(u8, args[1], "offer")) .offer else .answer;
    const lan = try rtc.Address.parseIp(args[2], 0);
    const port = try std.fmt.parseInt(u16, args[3], 10);
    const profiles: []const rtc.srtp.Profile = if (args.len > 4 and std.mem.eql(u8, args[4], "cm"))
        &.{.aes128_cm_sha1_80}
    else
        &.{ .aead_aes128_gcm, .aes128_cm_sha1_80 };

    var udp = try rtc.driver.UdpSocket.open(io, lan);
    defer udp.close();
    var state: State = .{ .gpa = gpa };
    defer state.log.deinit(gpa);
    const sockets = [_]rtc.Socket{udp.socket()};
    const pc = try rtc.PeerConnection.create(gpa, io, .{
        .sockets = &sockets,
        .srtp_profiles = profiles,
        .handler = .{ .ctx = &state, .onEvent = State.onEvent },
    });
    defer pc.destroy();
    var socks = [_]rtc.driver.UdpSocket{udp};
    var driver = rtc.driver.Driver.init(io, pc, &socks);
    try driver.start();
    defer driver.stop();

    var app: App = .{ .io = io, .gpa = gpa, .mode = mode, .pc = pc, .driver = &driver, .state = &state };
    var tasks: Io.Group = .init;
    defer tasks.cancel(io);
    try tasks.concurrent(io, mediaLoop, .{&app});

    const listen_addr: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
    var server = try listen_addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    std.debug.print("[zig] mode={t} udp={f} http=127.0.0.1:{d}\n", .{ mode, udp.local, port });
    while (true) {
        const stream = server.accept(io) catch continue;
        handle(&app, stream) catch |err| std.debug.print("[zig] http error {t}\n", .{err});
        stream.close(io);
    }
}

/// Sends 20 ms Opus packets and 10 fps video once the connection is up.
fn mediaLoop(app: *App) Io.Cancelable!void {
    var enc = h264enc.Encoder.init(128, 96);
    defer enc.deinit(app.gpa);
    // Opus CELT fullband 20 ms silence frame.
    const silence = [_]u8{ 0xF8, 0xFF, 0xFE };
    var tick: u32 = 0;
    var frame_no: u32 = 0;
    while (true) {
        try app.io.sleep(.fromMilliseconds(20), .awake);
        app.driver.lock();
        defer app.driver.unlock();
        if (app.pc.connectionState() != .connected) continue;
        app.pc.sendAudio(&silence) catch {};
        tick += 1;
        if (tick % 5 == 0) {
            const key = app.state.want_keyframe or frame_no % 30 == 0;
            app.state.want_keyframe = false;
            const au = enc.encode(app.gpa, key, @truncate(frame_no * 3)) catch continue;
            app.pc.sendVideo(au, frame_no *% 9000) catch {};
            frame_no += 1;
        }
    }
}

fn handle(app: *App, stream: Io.net.Stream) !void {
    var rbuf: [64 * 1024]u8 = undefined;
    var wbuf: [64 * 1024]u8 = undefined;
    var reader = stream.reader(app.io, &rbuf);
    var writer = stream.writer(app.io, &wbuf);
    const r = &reader.interface;
    const w = &writer.interface;

    const request_line = std.mem.trimEnd(u8, try r.takeDelimiterInclusive('\n'), "\r\n");
    var parts = std.mem.tokenizeScalar(u8, request_line, ' ');
    const method = parts.next() orelse return;
    const target = parts.next() orelse return;
    var method_buf: [8]u8 = undefined;
    const m = method_buf[0..@min(method.len, 8)];
    @memcpy(m, method[0..m.len]);
    var path_buf: [64]u8 = undefined;
    const path_full = target[0..@min(target.len, 64)];
    @memcpy(path_buf[0..path_full.len], path_full);
    const path = path_buf[0 .. std.mem.indexOfScalar(u8, path_full, '?') orelse path_full.len];

    var content_length: usize = 0;
    while (true) {
        const line = std.mem.trimEnd(u8, try r.takeDelimiterInclusive('\n'), "\r\n");
        if (line.len == 0) break;
        if (std.ascii.startsWithIgnoreCase(line, "content-length:"))
            content_length = std.fmt.parseInt(usize, std.mem.trim(u8, line["content-length:".len..], " "), 10) catch 0;
    }
    const body = try app.gpa.dupe(u8, try r.take(content_length));
    defer app.gpa.free(body);

    const now = rtc.driver.nowMs(app.io);
    if (std.mem.eql(u8, path, "/")) {
        return respond(w, "text/html", page);
    } else if (std.mem.eql(u8, path, "/offer") and std.mem.eql(u8, m, "POST")) {
        // Browser offers, we answer.
        app.driver.lock();
        defer app.driver.unlock();
        app.state.note("got offer ({d} bytes)", .{body.len});
        try app.pc.setRemoteDescription(.offer, body, now);
        const answer = try app.pc.createAnswer(app.gpa, now);
        defer app.gpa.free(answer);
        std.debug.print("[zig] answer:\n{s}\n", .{answer});
        return respond(w, "application/sdp", answer);
    } else if (std.mem.eql(u8, path, "/offer")) {
        app.driver.lock();
        defer app.driver.unlock();
        const offer = try app.pc.createOffer(app.gpa, now);
        defer app.gpa.free(offer);
        std.debug.print("[zig] offer:\n{s}\n", .{offer});
        return respond(w, "application/sdp", offer);
    } else if (std.mem.eql(u8, path, "/answer")) {
        app.driver.lock();
        defer app.driver.unlock();
        app.state.note("got answer ({d} bytes)", .{body.len});
        std.debug.print("[zig] browser answer:\n{s}\n", .{body});
        try app.pc.setRemoteDescription(.answer, body, now);
        return respond(w, "text/plain", "ok");
    } else if (std.mem.eql(u8, path, "/status")) {
        app.driver.lock();
        defer app.driver.unlock();
        const st = app.pc.stats();
        const s = app.state;
        var out: Io.Writer.Allocating = .init(app.gpa);
        defer out.deinit();
        const ow = &out.writer;
        try ow.print("{{\"mode\":\"{t}\",\"ice\":\"{t}\",\"connection\":\"{t}\",\"dtls_role\":\"{s}\",\"srtp_profile\":\"{s}\",", .{
            app.mode,                                                                st.ice, st.connection,
            if (app.pc.transport.isDtlsClient()) "client" else "server", if (st.srtp_profile) |p| @tagName(p) else "none",
        });
        try ow.print("\"audio_sent\":{d},\"video_sent\":{d},\"audio_received_packets\":{d},\"video_received_packets\":{d},", .{ st.audio_sent, st.video_sent, st.audio_received, st.video_received });
        try ow.print("\"audio_frames\":{d},\"video_frames\":{d},\"video_keyframes\":{d},\"video_corrupt\":{d},\"srtp_errors\":{d},", .{ s.audio_frames, s.video_frames, s.video_keyframes, s.video_corrupt, st.srtp_errors });
        try ow.print("\"keyframe_requests\":{d},\"remote_bitrate\":{d},\"first_video_nal_types\":[", .{ s.keyframe_requests, s.remote_bitrate });
        for (s.first_video_nals[0..s.first_video_nal_count], 0..) |t, i| try ow.print("{s}{d}", .{ if (i == 0) "" else ",", t });
        try ow.writeAll("],\"selected\":\"");
        if (st.local_candidate) |c| try ow.print("{f} -> {f}", .{ c.address, st.remote_candidate.?.address });
        try ow.writeAll("\",\"log\":\"");
        for (s.log.items) |c| try ow.writeByte(if (c == '"' or c == '\\') '\'' else c);
        try ow.writeAll("\"}");
        return respond(w, "application/json", out.written());
    }
    try w.writeAll("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    try w.flush();
}

fn respond(w: *Io.Writer, content_type: []const u8, body: []const u8) !void {
    try w.print("HTTP/1.1 200 OK\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", .{ content_type, body.len });
    try w.writeAll(body);
    try w.flush();
}

const page = @embedFile("page.html");

test {
    _ = h264enc;
}

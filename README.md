# reseal-rtc

The WebRTC wire protocol in Zig: ICE, STUN/TURN, DTLS 1.2, DTLS-SRTP, RTP/RTCP and SDP
offer/answer, with no dependencies beyond the Zig standard library (Zig 0.17). It lets a
native app (Android, iOS, desktop) hold a call with a browser's `RTCPeerConnection` without
libwebrtc. It carries encoded media only: Opus packets and H.264 access units go in and come
out; capture, encoding, decoding and playback stay in the app (MediaCodec, VideoToolbox,
audio units...).

It has been run against Chrome 154 (headless, fake camera and microphone) in both roles:
ICE connected, DTLS handshake done, SRTP both ways, and each side decoded the other's audio
and video (see "Proof" below).

## Using it

```zig
// build.zig.zon: .reseal_rtc = .{ .url = "git+https://github.com/hamuda8/reseal-rtc#<commit>", .hash = "..." }
const rtc = b.dependency("reseal_rtc", .{}).module("reseal_rtc");
```

```zig
const rtc = @import("reseal_rtc");

// 1. Sockets: one UDP socket per local interface address you want to offer as a host
//    candidate. Use rtc.driver.UdpSocket (std.Io.net) or implement rtc.Socket yourself.
var udp = try rtc.driver.UdpSocket.open(io, try rtc.Address.parseIp("192.168.1.20", 0));
const sockets = [_]rtc.Socket{udp.socket()};

// 2. ICE servers as Reseal's server hands them out (call.iceServers).
const servers = try rtc.driver.resolveIceServers(io, gpa, &.{
    .{ .urls = &.{"stun:stun.wreseal.com:3478"} },
    .{ .urls = &.{"turn:turn.wreseal.com:3478?transport=udp"}, .username = user, .credential = cred },
});

// 3. The connection. Events arrive on the handler (same thread as your calls into pc).
const pc = try rtc.PeerConnection.create(gpa, io, .{
    .sockets = &sockets,
    .servers = servers,
    .handler = .{ .ctx = &call, .onEvent = Call.onEvent },
});
defer pc.destroy();

// 4. Run it: rtc.driver.Driver runs a receive task per socket and a timer task.
var socks = [_]rtc.driver.UdpSocket{udp};
var loop = rtc.driver.Driver.init(io, pc, &socks);
try loop.start();
defer loop.stop();

// 5. Signalling (under loop.lock()/unlock() once the loop runs).
const offer = try pc.createOffer(gpa, rtc.driver.nowMs(io));        // or:
try pc.setRemoteDescription(.offer, remote_sdp, now);              // then
const answer = try pc.createAnswer(gpa, now);
try pc.addIceCandidate("candidate:1467250027 1 udp 2122260223 192.168.1.30 49846 typ host");

// 6. Media.
try pc.sendAudio(opus_packet);                 // RTP timestamp advances by the packet's duration
try pc.sendVideo(annexb_access_unit, ts_90k);  // H.264, packetization-mode 1
```

### Public API (`src/peer.zig`)

```zig
PeerConnection.create(gpa: Allocator, io: std.Io, config: Config) !*PeerConnection
PeerConnection.destroy(pc) void
PeerConnection.createOffer(pc, gpa: Allocator, now_ms: u64) ![]u8          // SDP, owned by gpa
PeerConnection.createAnswer(pc, gpa: Allocator, now_ms: u64) ![]u8
PeerConnection.localDescription(pc, gpa: Allocator) ![]u8                 // with candidates so far
PeerConnection.setRemoteDescription(pc, kind: SdpType, sdp: []const u8, now_ms: u64) !void
PeerConnection.addIceCandidate(pc, line: []const u8) !void                // "candidate:..." or ""
PeerConnection.receive(pc, socket_index: u8, from: Address, datagram: []const u8, now_ms: u64) void
PeerConnection.poll(pc, now_ms: u64) void
PeerConnection.nextTimeout(pc) ?u64                                       // when to call poll next
PeerConnection.sendAudio(pc, opus_packet: []const u8) !void
PeerConnection.sendVideo(pc, annexb: []const u8, timestamp_90khz: u32) !void
PeerConnection.requestKeyframe(pc) void                                   // sends PLI
PeerConnection.connectionState(pc) ConnectionState                        // new/connecting/connected/failed/closed
PeerConnection.stats(pc) Stats
PeerConnection.fingerprint(pc) [32]u8                                     // our DTLS certificate's SHA-256
PeerConnection.close(pc) void                                             // RTCP BYE, close_notify

Config = struct {
    sockets: []const Socket,
    servers: []const IceAgent.Server = &.{},
    audio: bool = true, video: bool = true,
    certificate: ?*const dtls_cert.Certificate = null,   // generated (ECDSA P-256) if null
    srtp_profiles: []const srtp.Profile = &.{ .aead_aes128_gcm, .aes128_cm_sha1_80 },
    max_video_bitrate: u64 = 2_500_000,                  // advertised with REMB
    audio_jitter_ms: u64 = 80, video_jitter_ms: u64 = 250,
    handler: Handler,
}
Handler = struct { ctx: *anyopaque, onEvent: *const fn (ctx: *anyopaque, event: Event) void }
Event = union(enum) {
    local_candidate: []const u8,  // send as {candidate, sdpMid: "0", sdpMLineIndex: 0}
    gathering_done,
    ice_state: IceAgent.State,
    connection_state: ConnectionState,
    audio_frame: struct { ssrc: u32, timestamp: u32, data: []const u8 },          // one Opus packet
    video_frame: struct { ssrc: u32, timestamp: u32, data: []const u8,           // Annex-B
                          keyframe: bool, corrupt: bool },
    keyframe_requested,           // peer sent PLI/FIR: make the encoder emit an IDR
    remote_bitrate: u64,          // peer's REMB for our video
}
```

Slices in events are only valid during the callback.

### Sockets

The engine is sans-IO. It sends through `rtc.Socket`:

```zig
Socket = struct {
    ctx: *anyopaque,
    sendFn: *const fn (ctx: *anyopaque, to: Address, data: []const u8) void,
    local: Address,   // the bound interface address; becomes the host candidate
}
```

and the app hands every received datagram to `pc.receive(socket_index, from, bytes, now)`
and calls `pc.poll(now)` when `pc.nextTimeout()` is due (or every 10-20 ms). Time is a
monotonic millisecond counter (`rtc.driver.nowMs(io)`). `rtc.driver` provides all of this
over `std.Io.net` (UDP works there, including Windows), but an app with its own loop (an
Android Looper, a Darwin dispatch source) can implement `Socket` directly. Bind to concrete
interface addresses, not 0.0.0.0: the bound address is what the peer is told. Use one set of
sockets per PeerConnection (a 10-person mesh is 9 PeerConnections, 9 sockets).

### Codecs

* Audio: Opus, 48 kHz RTP clock (RFC 7587). Give `sendAudio` one encoded Opus packet
  (typically 20 ms); received packets come out as `audio_frame` in order, after an 80 ms
  jitter buffer, ready for the Opus decoder. Lost packets are simply missing (use the
  decoder's PLC/FEC).
* Video: H.264 Constrained Baseline, packetization-mode 1 (RFC 6184: single NAL, STAP-A,
  FU-A), profile-level-id 42e01f. Give `sendVideo` an access unit in Annex-B form (start
  codes), with SPS/PPS before each IDR (MediaCodec emits them as codec config: prepend them to
  keyframes). VideoToolbox produces AVCC (length prefixes) and keeps SPS/PPS in the format
  description: convert to Annex-B before calling. Received frames come out as Annex-B for
  `MediaCodec.queueInputBuffer` or (after conversion) `VTDecompressionSession`. On
  `keyframe_requested`, request a sync frame from the encoder. `corrupt` frames are delivered
  but the engine already asked the sender for a keyframe (PLI).

### Platforms

Compiles for aarch64-linux-android, aarch64-macos, x86_64-linux and Windows as is. For
aarch64-ios, Zig 0.17's default panic handler pulls in `std.Io.Threaded` process-spawning code
that does not compile for iOS (a std issue, independent of this library); an iOS app must
declare its own `pub const panic` in its root file, which iOS apps do anyway. With that, the
whole module, `driver` included, compiles for iOS in Debug and ReleaseFast.

### Signalling with Reseal

Reseal's `call.signal` messages carry `{ description: { type, sdp }, sig }` and
`{ candidate: { candidate, sdpMid, sdpMLineIndex } }`. Map them to `setRemoteDescription` /
`addIceCandidate`, and send our `local_candidate` events as
`{ candidate: line, sdpMid: "0", sdpMLineIndex: 0 }` (with BUNDLE every m-line shares the
transport). The SDP signature scheme (`reseal/call/v1|...`) is unchanged: sign and verify
the SDP text as the web client does. Renegotiation offers (perfect negotiation adds a video
track mid-call) are accepted; ICE restart is not implemented yet.

## Layers

```
src/
  net.zig            Address, Socket interface
  driver.zig         std.Io glue: UdpSocket, nowMs, resolveIceServers, Driver run loop
  ice/
    stun.zig         STUN (RFC 8489) parse/build, MESSAGE-INTEGRITY, FINGERPRINT, long-term key
    candidate.zig    candidate syntax (RFC 8839), priorities
    turn.zig         TURN client (RFC 8656) over UDP
    Agent.zig        ICE agent (RFC 8445) + consent freshness (RFC 7675)
  dtls/
    Conn.zig         DTLS 1.2 client/server state machine (RFC 6347)
    record.zig       record layer, AES-128-GCM, replay window
    handshake.zig    handshake framing, reassembly, hello parsing
    prf.zig          TLS 1.2 PRF, master secret (incl. RFC 7627), exporter (RFC 5705)
    cert.zig         self-signed P-256 certificate, fingerprints
    bytes.zig        TLS vector readers/writers
  transport/
    PeerTransport.zig  ICE + DTLS over one association, RFC 7983 demultiplexing
  media/
    srtp.zig         SRTP/SRTCP: AES_CM_128_HMAC_SHA1_80, AEAD_AES_128_GCM (RFC 3711, 7714)
    rtp.zig, rtcp.zig  RTP header, RTCP SR/RR/SDES/BYE/NACK/PLI/FIR/REMB
    h264.zig, opus.zig packetizers
    JitterBuffer.zig reordering, frame assembly, loss detection for NACK
  sdp/sdp.zig        lossless SDP parser + writer for offer/answer
  data/data.zig      data channels: plan only (SCTP over DTLS + DCEP)
  peer.zig           PeerConnection
tools/interop/       browser interop harness (not part of the module)
```

### What each layer does, and its limits

| Layer | Implemented | Not yet |
|---|---|---|
| STUN | All RFC 8489 framing used by ICE/TURN, MESSAGE-INTEGRITY (HMAC-SHA1), FINGERPRINT | MESSAGE-INTEGRITY-SHA256, SASLprep |
| TURN | UDP allocations with long-term credentials (401/438 nonce handling), Refresh, CreatePermission, ChannelBind, Send/Data indications, ChannelData, release | TURN over TCP/TLS (`turns:`), IPv6 relays, mobility |
| ICE | Full agent: host/srflx/relay gathering, trickle in/out, pairs and priorities, paced checks with retransmission, triggered checks, peer-reflexive candidates, role-conflict resolution (487), regular nomination when controlling, USE-CANDIDATE when controlled, consent freshness with disconnected/failed states | ICE restart, ICE-lite mode, mDNS resolution of `.local` candidates (handled through peer-reflexive learning), TCP candidates, frozen/foundation scheduling (one stream needs none) |
| DTLS | 1.2 client and server, ECDHE (P-256 or X25519) + ECDSA P-256, AES-128-GCM, mutual certificates checked against SDP fingerprints, use_srtp, extended master secret, renegotiation_info, HelloVerifyRequest as client, fragmentation and reassembly, flight retransmission with backoff, replay window, alerts, exporter | DTLS 1.3, server cookies (HelloVerifyRequest as server), resumption, RSA certificates |
| SRTP | Both profiles browsers use, ROC tracking, 128-entry replay window, SRTCP | MKI, AES-256 profiles, key rollover |
| RTP/RTCP | SR/RR with loss and jitter, SDES CNAME, BYE, NACK both ways (retransmit from a 512-packet history), PLI/FIR both ways, REMB both ways | transport-cc, RTX (retransmission uses the original SSRC, as without `a=rtpmap rtx`), RED/FEC, simulcast, header extensions on send |
| Media | Opus and H.264 packetizers/depacketizer, jitter buffer with frame assembly and loss skipping | bandwidth estimation and rate control (app picks the bitrate; REMB is reported), audio level, VP8/VP9/AV1 |
| SDP | Lossless parse/serialise (byte-exact round trip of Chrome SDP), BUNDLE, rtcp-mux, ICE/DTLS attributes, codecs, fmtp, rtcp-fb, extmap, ssrc; answers mirror the offer (unsupported m-lines rejected with port 0) | generating `m=application` |
| Data channels | Plan in `src/data/data.zig` | Everything |

## Proof

`zig build test` runs 48 tests, including:

* RFC 5769 STUN sample messages (request, IPv4 and IPv6 responses, long-term auth), parsed
  and rebuilt byte for byte (HMAC-SHA1 integrity and CRC32 fingerprint included).
* RFC 3711 Appendix B.2 (AES-CM keystream) and B.3 (key derivation), RFC 7714 16.1 (SRTP
  AEAD_AES_128_GCM) and 17.1 (SRTCP) vectors.
* The TLS 1.2 PRF (SHA-256) test vector.
* DTLS client/server handshakes with mutual fingerprints, under loss and with 300-byte MTU
  fragmentation; wrong-fingerprint rejection.
* H.264 STAP-A/FU-A round trips; SDP round trips of a real Chrome offer and answer.
* ICE between two agents (prflx discovery, nomination, consent expiry), ICE through an
  in-process TURN server with the direct path blocked, srflx gathering.
* Loopback: two PeerConnections complete ICE + DTLS + SRTP and exchange Opus and H.264 in
  both directions with each SRTP profile, under 5 % loss (video fully recovered by NACK),
  across renegotiation, and over real UDP sockets on 127.0.0.1 with the std.Io driver.

Browser interop (needs Chrome and Node 22):

```
zig build interop
node tools/interop/run.mjs answer      # Chrome offers, we answer (we: ICE controlled, DTLS client)
node tools/interop/run.mjs offer       # we offer (we: ICE controlling, DTLS server)
node tools/interop/run.mjs offer cm    # force AES_CM_128_HMAC_SHA1_80
```

The harness starts `rtc-interop` (HTTP signalling on 127.0.0.1, UDP on the LAN address
since Chrome does not gather loopback candidates), starts headless Chrome with fake devices,
drives the page over the DevTools protocol, and checks both sides' statistics. It sends
video from a toy H.264 encoder (I_PCM/P_Skip, `tools/interop/h264enc.zig`), so Chrome
actually decodes pictures produced here.

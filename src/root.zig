//! reseal-rtc: the WebRTC wire protocol in Zig, with no dependencies beyond std.
//!
//! Layers (see README.md): ice/ (STUN, TURN, ICE), dtls/ (DTLS 1.2 + DTLS-SRTP), transport/
//! (ICE + DTLS over one UDP association), media/ (SRTP, RTP/RTCP, packetizers, jitter buffer),
//! sdp/ (offer/answer), data/ (SCTP data channels: planned), and peer.zig which composes them.
//! Most apps only need `PeerConnection`, `Event`, `Socket`/`Address`, and `driver`.

// ---- the app-facing API -------------------------------------------------------------------

pub const peer = @import("peer.zig");
pub const PeerConnection = peer.PeerConnection;
pub const Config = peer.Config;
pub const Event = peer.Event;
pub const Handler = peer.Handler;
pub const Stats = peer.Stats;

pub const net = @import("net.zig");
pub const Address = net.Address;
pub const Socket = net.Socket;

/// std.Io glue: UDP sockets, clock, ICE server URL resolution, run loop.
pub const driver = @import("driver.zig");

// ---- layers, for apps that compose their own pipeline or want the codecs' helpers ----------

pub const stun = @import("ice/stun.zig");
pub const candidate = @import("ice/candidate.zig");
pub const TurnClient = @import("ice/turn.zig");
pub const IceAgent = @import("ice/Agent.zig");

pub const DtlsConn = @import("dtls/Conn.zig");
pub const dtls_cert = @import("dtls/cert.zig");
pub const dtls_prf = @import("dtls/prf.zig");

pub const PeerTransport = @import("transport/PeerTransport.zig");

pub const srtp = @import("media/srtp.zig");
pub const rtp = @import("media/rtp.zig");
pub const rtcp = @import("media/rtcp.zig");
pub const h264 = @import("media/h264.zig");
pub const opus = @import("media/opus.zig");
pub const JitterBuffer = @import("media/JitterBuffer.zig");

pub const sdp = @import("sdp/sdp.zig");
pub const data = @import("data/data.zig");

test {
    _ = peer;
    _ = net;
    _ = driver;
    _ = stun;
    _ = candidate;
    _ = TurnClient;
    _ = IceAgent;
    _ = DtlsConn;
    _ = dtls_cert;
    _ = dtls_prf;
    _ = @import("dtls/bytes.zig");
    _ = @import("dtls/record.zig");
    _ = @import("dtls/handshake.zig");
    _ = PeerTransport;
    _ = srtp;
    _ = rtp;
    _ = rtcp;
    _ = h264;
    _ = opus;
    _ = JitterBuffer;
    _ = sdp;
    _ = data;
    _ = @import("tests/loopback.zig");
    _ = @import("tests/relay.zig");
}

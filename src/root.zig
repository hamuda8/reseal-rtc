//! reseal-rtc: the WebRTC wire protocol in Zig, with no dependencies beyond std.
//!
//! Layers (see README.md): ice/ (STUN, TURN, ICE), dtls/ (DTLS 1.2 + DTLS-SRTP), transport/
//! (ICE + DTLS over one UDP association), media/ (SRTP, RTP/RTCP, packetizers, jitter buffer),
//! sdp/ (offer/answer), data/ (SCTP data channels, not yet), and peer.zig which composes them.

pub const net = @import("net.zig");
pub const Address = net.Address;
pub const Socket = net.Socket;

pub const stun = @import("ice/stun.zig");
pub const srtp = @import("media/srtp.zig");
pub const dtls_prf = @import("dtls/prf.zig");
pub const dtls_cert = @import("dtls/cert.zig");
pub const DtlsConn = @import("dtls/Conn.zig");

test {
    _ = net;
    _ = stun;
    _ = srtp;
    _ = dtls_prf;
    _ = dtls_cert;
    _ = DtlsConn;
    _ = @import("dtls/bytes.zig");
    _ = @import("dtls/record.zig");
    _ = @import("dtls/handshake.zig");
}

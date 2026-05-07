//
//  LWIPStack+LoopbackAddress.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/26/26.
//

import Foundation

private let logger = AnywhereLogger(category: "LWIPStack")

extension LWIPStack {

    // MARK: - Loopback Address (10.7.0.1)
    //
    // Implements SideStore/StosVPN-compatible loopback behavior at the raw IP
    // packet level. When a TCP or UDP packet arrives destined for 10.7.0.1,
    // the source and destination IP addresses are swapped and the modified
    // packet is injected back into the tunnel — LWIP never sees it.
    //
    // This creates a bidirectional loopback channel:
    //
    //   Forward (device → loopback):
    //     Input:  src=<device_ip>:SPORT  dst=10.7.0.1:DPORT
    //     Output: src=10.7.0.1:SPORT     dst=<device_ip>:DPORT
    //   (OS delivers to any local listener on DPORT)
    //
    //   Return (local server → device):
    //     Input:  src=<device_ip>:DPORT  dst=10.7.0.1:SPORT
    //     Output: src=10.7.0.1:DPORT     dst=<device_ip>:SPORT
    //   (OS delivers to the original client at SPORT)
    //
    // Setting loopback_address to 10.7.0.1 achieves the same behaviour as
    // SideStore / StosVPN.
    //
    // Important: 10.7.0.1 must be included in the tunnel's IPv4 routes so
    // that packets to it are intercepted by the tunnel rather than sent via
    // the physical interface.  PacketTunnelProvider.buildTunnelSettings() adds
    // a /32 includedRoute for 10.7.0.1 to override the 10.0.0.0/8 exclusion.

    // MARK: - Packet Handling

    /// Checks whether `packet` is an IPv4 TCP/UDP datagram destined for the
    /// loopback address (10.7.0.1).  If so, swaps source and destination IP
    /// addresses, recomputes IP and transport checksums, enqueues the modified
    /// packet for output back through the tunnel, and returns `true`.
    ///
    /// Must be called on `lwipQueue`.
    func tryHandleLoopbackPacket(_ packet: Data) -> Bool {
        let count = packet.count
        guard count >= 20 else { return false }

        // ── Phase 1: read-only header inspection ──────────────────────────
        var ihl: Int = 0
        var proto: UInt8 = 0
        var shouldHandle = false

        packet.withUnsafeBytes { (buf: UnsafeRawBufferPointer) in
            guard let base = buf.baseAddress else { return }
            let p = base.assumingMemoryBound(to: UInt8.self)

            // Must be IPv4
            guard (p[0] >> 4) == 4 else { return }

            let headerLen = Int(p[0] & 0x0F) * 4
            guard headerLen >= 20, count >= headerLen else { return }

            // Destination IP must be 10.7.0.1
            guard p[16] == 10, p[17] == 7, p[18] == 0, p[19] == 1 else { return }

            // Only TCP (6) and UDP (17) are reflected; other protocols fall
            // through to LWIP (which will likely drop them for an unknown dest).
            let prt = p[9]
            guard prt == 6 || prt == 17 else { return }

            ihl = headerLen
            proto = prt
            shouldHandle = true
        }

        guard shouldHandle else { return false }

        // ── Phase 2: copy and transform ────────────────────────────────────
        var modified = Data(packet)
        modified.withUnsafeMutableBytes { (mbuf: UnsafeMutableRawBufferPointer) in
            guard let mbase = mbuf.baseAddress else { return }
            let mp = mbase.assumingMemoryBound(to: UInt8.self)

            // Swap source and destination IP addresses.
            // src → 10.7.0.1 (the loopback address)
            // dst → original src (the device IP)
            let s0 = mp[12], s1 = mp[13], s2 = mp[14], s3 = mp[15]
            mp[16] = s0;  mp[17] = s1;  mp[18] = s2;  mp[19] = s3   // new dst = old src
            mp[12] = 10;  mp[13] = 7;   mp[14] = 0;   mp[15] = 1    // new src = 10.7.0.1

            // Recompute IPv4 header checksum (RFC 791).
            mp[10] = 0;  mp[11] = 0
            let ipCsum = ipv4HeaderChecksum(mp, headerLen: ihl)
            mp[10] = UInt8(ipCsum >> 8)
            mp[11] = UInt8(ipCsum & 0xFF)

            // Recompute transport-layer checksum (RFC 793 / RFC 768).
            let transportLen = count - ihl
            if proto == 6 {
                // TCP: checksum at offset 16 within the TCP header
                guard transportLen >= 20 else { return }
                mp[ihl + 16] = 0;  mp[ihl + 17] = 0
                let csum = transportChecksum(mp, ihl: ihl, length: transportLen, proto: proto)
                mp[ihl + 16] = UInt8(csum >> 8)
                mp[ihl + 17] = UInt8(csum & 0xFF)
            } else {
                // UDP: checksum at offset 6 within the UDP header;
                // a computed value of 0 must be sent as 0xFFFF (RFC 768).
                guard transportLen >= 8 else { return }
                mp[ihl + 6] = 0;  mp[ihl + 7] = 0
                var csum = transportChecksum(mp, ihl: ihl, length: transportLen, proto: proto)
                if csum == 0 { csum = 0xFFFF }
                mp[ihl + 6] = UInt8(csum >> 8)
                mp[ihl + 7] = UInt8(csum & 0xFF)
            }
        }

        logger.debug("[Loopback] Reflecting \(proto == 6 ? "TCP" : "UDP") packet back to source (len=\(count))")

        // ── Phase 3: enqueue for output ────────────────────────────────────
        // Append to the shared output batch on lwipQueue; the existing flush
        // mechanism sends it to the tunnel the next time it runs.
        outputPackets.append(modified)
        outputProtocols.append(LWIPStack.ipv4Proto)
        if !outputFlushScheduled {
            outputFlushScheduled = true
            lwipQueue.async { [weak self] in self?.flushOutputPackets() }
        }
        return true
    }

    // MARK: - Checksum Helpers

    /// Internet checksum (RFC 1071) over the first `headerLen` bytes of `p`.
    /// The checksum field within that range must already be zeroed by the caller.
    private func ipv4HeaderChecksum(_ p: UnsafePointer<UInt8>, headerLen: Int) -> UInt16 {
        var sum: UInt32 = 0
        var i = 0
        while i + 1 < headerLen {
            sum += UInt32(p[i]) << 8 | UInt32(p[i + 1])
            i += 2
        }
        if i < headerLen {
            sum += UInt32(p[i]) << 8       // odd byte padded with zero
        }
        // Fold carry bits
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        return ~UInt16(truncatingIfNeeded: sum)
    }

    /// TCP/UDP checksum using the IPv4 pseudo-header (RFC 793 §3.1 / RFC 768).
    /// The checksum field in the transport header must already be zeroed by the caller.
    ///
    /// - Parameters:
    ///   - p: Pointer to the start of the IPv4 packet (IP header + transport segment).
    ///   - ihl: IP header length in bytes (IHL × 4).
    ///   - length: Transport-layer length in bytes (TCP/UDP header + payload).
    ///   - proto: IP protocol number (6 = TCP, 17 = UDP).
    private func transportChecksum(_ p: UnsafePointer<UInt8>, ihl: Int, length: Int, proto: UInt8) -> UInt16 {
        var sum: UInt32 = 0

        // IPv4 pseudo-header: src IP (4) + dst IP (4) + zero (1) + proto (1) + length (2)
        sum += UInt32(p[12]) << 8 | UInt32(p[13])   // src IP high
        sum += UInt32(p[14]) << 8 | UInt32(p[15])   // src IP low
        sum += UInt32(p[16]) << 8 | UInt32(p[17])   // dst IP high
        sum += UInt32(p[18]) << 8 | UInt32(p[19])   // dst IP low
        sum += UInt32(proto)                          // zero + protocol
        sum += UInt32(length)                         // transport length

        // Transport header + payload
        var i = ihl
        let end = ihl + length
        while i + 1 < end {
            sum += UInt32(p[i]) << 8 | UInt32(p[i + 1])
            i += 2
        }
        if i < end {
            sum += UInt32(p[i]) << 8               // odd byte padded with zero
        }

        // Fold carry bits
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        return ~UInt16(truncatingIfNeeded: sum)
    }
}

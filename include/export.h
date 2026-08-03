/*
 * Export Module
 * Writes the current capture session out to formats other tools understand:
 *   - CSV flow summary (same shape as an Azure NSG flow log: 5-tuple + bytes)
 *   - CSV alert log (from detect.c)
 *   - A real .pcap file (opens directly in Wireshark/tcpdump)
 */

#ifndef EXPORT_H
#define EXPORT_H

// Export every packet in the current session as a CSV flow summary.
// Columns: packet_id,timestamp,src_ip,src_port,dst_ip,dst_port,protocol,length,tcp_flags,info
// Returns 0 on success, -1 on failure (no session, or file couldn't be opened).
int export_session_csv(const char *filepath);

// Export the security alert log (from detect.c) raised during the session as CSV.
// Columns: timestamp,type,details
// Returns 0 on success, -1 on failure.
int export_alerts_csv(const char *filepath);

// Export every packet in the current session as a real .pcap file, using the
// original captured bytes and timestamps, openable directly in Wireshark.
// Returns 0 on success, -1 on failure.
int export_session_pcap(const char *filepath);

#endif // EXPORT_H

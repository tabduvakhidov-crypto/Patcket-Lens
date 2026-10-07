# Packet Lens

Drop, select, or paste a Wireshark `.pcap` or `.pcapng` file to get a plain-English network overview. Files are parsed in a browser worker; there is no capture upload, external lookup, telemetry, API key, or third-party dependency.

## Run locally

Double-click `Start Packet Lens.cmd` and open http://127.0.0.1:8876. Requires Node.js (already available on this computer). Keep the console running while using the app. Alternatively run `npm start`. Opening `dist/index.html` directly will not work because browser modules and workers require an HTTP origin.

## Host for your network

Stop any existing Packet Lens console with Ctrl+C, then double-click `Start Packet Lens Network.cmd` (or run `npm run start:network`). It listens on TCP port 8876 on the computer's IPv4 interfaces and prints the network links to share. Keep the server window open and the computer awake. The original `Start Packet Lens.cmd` remains available for access on this computer alone.

People on the same network open `http://YOUR-COMPUTER-IP:8876`. Their captures are analyzed in their own browsers; this server only serves the application files from `dist/`. Visitors do not need Node.js or Wireshark installed to analyze an existing capture.

Windows Firewall needs an inbound TCP rule for port 8876. Right-click `Enable Packet Lens Network Access.cmd` and select **Run as administrator**. The helper opens only port 8876 for Node.js from local subnets on Domain and Private networks. Alternatively, run the following in **PowerShell as Administrator**:

```powershell
$taskNode = (Get-Command node).Source
New-NetFirewallRule -Name 'PacketLens-LAN-8876' -DisplayName 'Packet Lens - local network' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8876 -Program $taskNode -Profile Domain,Private -RemoteAddress LocalSubnet
```

This rule allows directly connected local subnets. If visitors are on another VLAN or subnet, your network administrator may need to permit traffic from that specific subnet. Remove the rule with `Remove-NetFirewallRule -Name 'PacketLens-LAN-8876'` when network hosting is no longer needed.

To stop a manually launched server, press Ctrl+C. For a server started in the background by Codex, run `powershell -NoProfile -File scripts/stop-network-server.ps1`.

The network link changes if the computer's IP changes. For a permanent link, ask for a DHCP reservation and an internal DNS name. This setup runs while the computer is awake; automatic startup is not configured.

## Features

- Overview, traffic chart, protocol explanations, observed IP addresses, bidirectional connection pairs, visible domains, and readable packet explorer.
- DNS error responses, TCP resets, readable HTTP, ICMP error messages, and repeated SYN attempts with no captured reply.
- Copy Wireshark display filters and export a readable text report with complete available structured lists.
- Demo capture generated from synthetic packets and parsed by the same reader as real files.
- Ethernet/VLAN, Linux cooked v1/v2, raw IPv4/IPv6, and loopback encapsulations; classic PCAP in both byte orders and microsecond/nanosecond formats; PCAPNG enhanced, simple, and legacy packet blocks with section/interface handling.

## Limits

150 MiB and 750,000 packets per capture. Lists cap at 50,000 connection pairs, 20,000 IP addresses, 20,000 domains, and 1,000 peers per address with disclosure. Packet explorer retains the first 2,500 packet descriptions and shows up to 500 search matches at once. Summary counters cover the entire accepted capture. Original packet byte counts include headers and may count duplicate packets if the capture contains duplicates.

No decryption, TCP stream/IP fragment reassembly, packet-loss diagnosis, full Wireshark dissector coverage, reverse DNS lookup, or malware/security verdict. Service identification often uses ports. Names may be unavailable for encrypted DNS, encrypted ClientHello, caching, segmented TLS/DNS messages, or missing capture context. IPs are not physical device identities. Separate sessions sharing an endpoint pair are grouped together.

Clear capture discards the app's report and terminates its worker; it does not delete your source file. No capture data is saved to browser storage. Exported reports contain network metadata and remain on your computer.

## Validation

Run `npm test` for binary-format and analysis checks. `node scripts/make-demo.mjs` regenerates the synthetic demo.

Format references: [IETF PCAPNG](https://www.ietf.org/ietf-ftp/internet-drafts/draft-ietf-opsawg-pcapng-06.html), [IANA PCAP link types](https://www.iana.org/assignments/pcap).

# Playbook: Proxy Anomaly Response

## Detection Criteria
Suspicious or unauthorized traffic patterns routed through the organization's
web proxy infrastructure, identified by one or more of the following signals:

1. **CONNECT tunneling to non-standard ports**: HTTP CONNECT method requests
   targeting destination ports other than 443 (HTTPS) or 80 (HTTP) — commonly
   used to tunnel arbitrary protocols (SSH, RDP, C2) through the proxy under
   the guise of legitimate HTTPS traffic.
2. **Proxy bypass attempts**: Log entries indicating direct external connections
   that circumvent the configured proxy (e.g. SOCKS tunnel setup, SSH dynamic
   port forwarding `-D`, or traffic to known proxy-avoidance services like Tor
   exit nodes).
3. **Header spoofing**: Requests with manipulated `X-Forwarded-For`,
   `X-Real-IP`, or `Via` headers designed to obscure the true source IP or
   impersonate an internal trusted address — detected by comparing the header
   value against the actual TCP source IP in the proxy access log.
4. **C2 beaconing patterns**: Repeated small outbound requests to the same
   external destination at suspiciously regular intervals (e.g. every 30-60
   seconds) with minimal response payload variation — characteristic of
   command-and-control callback channels.

## Containment Steps
1. Recommend `BLOCK_PROXY_IP` against the transit source IP (the internal
   host routing traffic through the proxy) to immediately sever the suspicious
   proxy channel.
2. If the proxy logs show the traffic originates from a specific user session
   (authenticated proxy), additionally recommend `LOCK_ACCOUNT` against the
   associated user account to prevent re-establishment through a different
   proxy route or direct connection.
3. Do not recommend `ISOLATE_HOST` based solely on proxy anomaly indicators
   unless the traffic pattern correlates with confirmed malware execution or
   data exfiltration signals from other pipeline stages.

## Escalation Criteria
- C2 beaconing pattern confirmed (regular interval callbacks to the same
  external IP over a period exceeding 30 minutes) — indicates an established,
  persistent command-and-control channel requiring full incident response
  activation.
- CONNECT tunneling detected to known Tor entry/exit nodes or anonymization
  proxy services — suggests deliberate evasion of network monitoring, which
  may indicate insider threat activity.
- More than 5 distinct internal source IPs showing the same proxy anomaly
  pattern within a 600-second window — indicates either a compromised proxy
  configuration or a coordinated multi-host attack.

## Common False Positives
- Legitimate VPN or remote access tools (Cisco AnyConnect, GlobalProtect)
  using CONNECT tunnels on non-standard ports. Verify the destination IP
  matches the organization's registered VPN gateway addresses.
- Developer tools (VS Code Remote, JetBrains Gateway) establishing SSH
  tunnels through the proxy for remote development. Cross-reference with
  approved development tool registrations.
- Load balancers and CDN edge nodes injecting or modifying `X-Forwarded-For`
  headers as part of normal request routing — these typically follow a
  predictable, documented header chain pattern that differs from adversarial
  spoofing (which inserts arbitrary untrusted IPs).

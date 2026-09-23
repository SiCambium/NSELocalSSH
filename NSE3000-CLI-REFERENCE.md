# Cambium NSE 3000 CLI reference

Captured from **NSE-Caravan** over SSH (`172.23.0.1`), firmware **2.3-r6** (build 2026-07-14), Device-Agent **4.183**.

Cambium does not publish an NSE CLI guide. The device has **no `?` help and no tab completion**. `?` as a command returns `Invalid arguments`. The live instruction set is recovered from `show config`, working `show` / `service show` commands, and by entering config contexts.

SSH drops you straight into config mode:

```text
NSE-Caravan(config)#
```

There is no `enable` / `configure terminal`. Commands that need a sub-context change the prompt, for example `(config-eth-1)#`. Use `exit` to go back.

---

## Operational commands (safe to poll)

These were tested on this unit and returned data (or a structured empty result). They do **not** change configuration.

### Device / management

| Command | What you get |
|---|---|
| `show version` | Model, firmware, serial, uptime, MAC |
| `show management` | Cloud, HTTP/HTTPS, SSH/Telnet |
| `show cambium` | Cambium-ID |
| `show remote` | cnMaestro connection state and history |
| `show clock` | Local time |
| `show power` | Power / PoE platform info |
| `show usb` | USB enabled/disabled |
| `show pppoe` | PPPoE client status |
| `show events` | Recent system events |
| `show lldp neighbors` | LLDP neighbors |
| `show lldp neighbors detail` | Detailed LLDP |
| `show lldp interfaces` | Per-interface LLDP |

### Interfaces / routing / clients

| Command | What you get |
|---|---|
| `show interface brief` | eth1–eth6 MAC, link, speed, duplex |
| `show arp` | ARP table |
| `show route` / `show ip route` | IPv4 routes |
| `show ipv6 route` | IPv6 routes (empty here) |
| `show conntrack` | Connection tracking + app IDs (large) |
| `show dhcp-pool` | Pool list |
| `show dhcp-pool <n>` | Pool status, leases, usage |
| `show ip dhcp` | WAN DHCP client lease (eth1) |
| `show ip dhcp binding` | Same family as `show ip dhcp` |
| `show ip dhcp lease` | Same family as `show ip dhcp` |

### Firewall / DPI / VPN

| Command | What you get |
|---|---|
| `show config` | Full running CLI config |
| `show config filter` | Firewall filter section only |
| `show filter` / `show filter global-filter` | Filter hit counters |
| `show application-statistics by-category` | DPI by category |
| `show application-statistics by-application` | DPI by application |
| `show vpn` | Present, but currently returns `Unable to process JSON response: {}` |

### Diagnostics

| Command | What you get |
|---|---|
| `nslookup <host>` | DNS lookup via configured name-servers |
| `speedtest` | On-demand WAN speed test (uses bandwidth; **not run** here) |
| `service show df` | Disk / flash usage |
| `service show flash` | Partition + disk usage |
| `service show dmesg` | Kernel log |
| `service show ethtool` | Ethernet NIC details |
| `service show memory` | Memory |
| `service show ip` | iperf daemon status file |
| `service show route` | Routes (service view) |
| `service show conntrack` | Conntrack (service view) |
| `service show config` | Internal JSON of **all** config keys. **Dumps secrets in cleartext** — treat as confidential |
| `service show debug-logs` | Lists daemon names (see below) |
| `service show debug-logs <daemon>` | That daemon’s log |

Debug-log daemons advertised by this firmware:

```text
device-agent, dpid, dpistatsd, infrad, mdnsd, messages, nfq_agent,
rfmd, rca-agent, scmd, troubleshooting, wmd, xrp, xwfd, sysmond,
utm, godns, wanlb, vpn, radius-server, rsync, grub2, goavc1,
connectedclients, radiusd, tailscaled
```

VPN troubleshooting used by Cambium: `service show debug-logs vpn`.

---

## Config command tree (from live `show config`)

This is the CLI language cnMaestro pushes. Nested blocks use `exit` to leave.

**Correction (2026-08-31):** this doc previously claimed `show config` shows secrets as placeholders, unlike `service show config`. That's wrong — confirmed by a live capture that included the admin password hash, VPN-server shared-secret, Tailscale auth-key, RADIUS client secret, and LLDP PBA auth-key (mostly as `$crypt$N$...` values, plus the IPS oinkcode as cleartext). Treat `show config` with exactly the same caution as `service show config`: never log it, never commit a capture without redacting every secret-shaped line first, and don't display it to a user without stripping these fields.

**Further correction, same day:** `$crypt$N$...` is **reversible obfuscation, not a one-way hash** — the device has to hand the real plaintext back to strongSwan/pppd/the L2TP server/etc. at runtime, so a one-way hash would be useless there. Every `$crypt$`-prefixed value seen in `show config` (PSKs, VPN-server shared-secret, RADIUS passwords, PPPoE password, LLDP pba-auth-key, Tailscale auth-key) must be treated as a **directly-recoverable, directly-usable secret** if this output is ever exposed — not as a low-risk hash. Only the admin login password is plausibly a genuine one-way hash (it's verified locally, never replayed to a peer), but that specific line hasn't been captured/confirmed either way. If `show config` output is ever exposed outside this app, rotate everything in it, not just the oinkcode.

### Management / system

```text
management https port 443
no management radius-auth
management ssh idle-timeout 300
management user admin password <hash>
management http
no management telnet
management https
management ssh
management cambium-remote
management cambium-remote validate-server-cert
management http port 80
led
no poe-out
system hw-reset
timezone Europe/London
hostname NSE-Caravan
no snmp-server
ntp server time.google.com
```

### Ethernet WAN (`interface eth 1|2`) — prompt `(config-eth-N)#`

```text
interface eth 1
 type wan
 wan-name wan1
 ip nat inside
 load-balance mode shared
 load-balance monitor-hosts 8.8.8.8,1.1.1.1
 load-balance num-hosts-fail-interface-down 1
 load-balance ping failure-detect-time 5
 load-balance ping interval 2
 load-balance ping timeout 2
 load-balance traffic-share-percentage 95
 uplink-bandwidth Mbps 40
 downlink-bandwidth Mbps 200
 dynamic-dns service-id 1
 starlink
 starlink dish-mode router
 starlink dish-ip 192.168.100.1
 starlink dish-port 9200
 starlink dish-grpc-reflection-ip 192.168.1.1
 starlink dish-grpc-reflection-port 9000
 ip address dhcp
 exit
```

WAN2 is the same pattern without Starlink, `traffic-share-percentage 5`, 10/10 Mbps.

### Ethernet LAN (`interface eth 3-6`)

Access:

```text
interface eth 3
 type lan
 switchport mode access
 switchport access vlan 1
 no shutdown
 exit
```

Trunk:

```text
interface eth 5
 type lan
 switchport mode trunk
 switchport trunk native vlan 1
 switchport trunk allowed vlan 1,30,100,200
 no shutdown
 exit
```

### VLAN SVIs — prompt `(config-vlan-N)#`

```text
interface vlan 1
 management-access all
 ip address 172.21.0.1 255.255.0.0
 exit
```

Also present: vlan 30, 100, 200.

### DHCP / DNS

```text
ip dhcp server authoritative
ip dhcp pool 1                          # (config-dhcp-pool-1)#
 address-range 172.21.1.30 172.21.1.250
 default-router 172.21.0.1
 dns-server 172.21.0.1
 lease 0 2 0                            # days hours minutes
 network 172.21.0.0 255.255.0.0
 exit

ip dns server
ip name-server 1.1.1.2
ip name-server 8.8.8.8
ip dns dynamic services-list 1          # (config-dyndns-provider-1)#
 provider noip
 server-name dynupdate.no-ip.com
 exit
```

Optional pool keys seen on pool 3: `domain-name`, secondary DNS in `dns-server`.

### DNS content filter — prompt `(config-dns-server)#`

```text
dns-server
 filter-mode filtering
 dns-filter policy 1
    name Ad_Blocking
    safe-search disabled
    deny-sources all
    deny-categories malware-sites
    deny-categories spyware-and-adware
    deny-categories spam-urls
    deny-categories bot-nets
    deny-categories keyloggers-and-monitoring
    deny-categories phishing-and-other-frauds
    exit
 no dns-override
 exit
```

### IPS / IDS

```text
intrusion-prevention
intrusion-prevention mode prevention          # or detection
intrusion-prevention rule-set balanced
intrusion-prevention rule-type snort-vrt
intrusion-prevention oinkcode <oinkcode>
intrusion-prevention auto-update
intrusion-prevention auto-update interval 12-hours
intrusion-prevention rule-type snort-vrt rule-category <snort3-...>
```

### Client VPN / Tailscale / RADIUS / HA

```text
vpn-server                                  # (config-vpn-server)#
 interface wan1
 shared-secret <secret>
 address-range 172.22.200.10 172.22.200.30
 mfa
 exit

tailscale
tailscale auth-key <key>
tailscale accept-routes
tailscale advertise-routes 172.21.0.0/16,172.23.0.0/16

radius-server mode enable
radius-server client-list 1
 name Demo1
 secret <secret>
 address 172.22.0.0
 prefix-length 16

high-availability role primary
high-availability port eth6
```

### Firewall / routing / LLDP / logging

```text
firewall dos-protection ip-spoof
firewall dos-protection ip-spoof-log
firewall dos-protection smurf-attack
firewall dos-protection icmp-frag

ip gw-source-precedence static 1
ip gw-source-precedence dhcpc 2
ip gw-source-precedence pppoe 3
ipv6 gw-source-precedence static 1
ipv6 gw-source-precedence auto-config/dhcpc 2

filter global-filter                        # (config-global-filter)#
  stateful
  application-control
  filter precedence 1
     unique_id 1
     rule-name rule_1
     layer3-filter deny proto any 192.168.20.0/255.255.255.0 any 172.21.0.0/255.255.0.0 any in
     exit
  exit

lldp
lldp tx-interval 30
lldp pba
lldp pba-auth-key <hash>
power policy sufficient
power lldp policy auto
power alerts policy yes
power bootloop enabled
logging host 172.22.0.9 514
logging syslog 5
```

---

## Extra config contexts (exist on this firmware, not all used)

Entering these changes the prompt. `exit` leaves them. They were not written to (except accidental top-level keywords noted below).

| Command | Prompt |
|---|---|
| `interface eth N` | `(config-eth-N)#` |
| `interface vlan N` | `(config-vlan-N)#` |
| `ip dhcp pool N` | `(config-dhcp-pool-N)#` |
| `vpn-server` | `(config-vpn-server)#` |
| `dns-server` | `(config-dns-server)#` |
| `filter global-filter` | `(config-global-filter)#` |
| `site-to-site-vpn` | `(config-site-to-site-vpn)#` |
| `ip dns dynamic services-list N` | `(config-dyndns-provider-N)#` |

`wireguard` as a top-level command is **invalid**. WireGuard is configured from cnMaestro; Cambium’s published override for WG MFA is:

```text
radius-server users-list <n>
 wireguard-password-auth_enable
```

### Site-to-site IPsec (from Cambium community, firmware ≥ 1.8)

Not present in this unit’s running config, but the context exists. Typical tree:

```text
site-to-site-vpn
 bypass-lan
 no install-routes
 inter-vlan-routing <subnet> <subnet>
 vpn ipsec 1
  name <name>
  ike-version ikev2
  role initiator|responder
  dead-peer-detection interval 120
  remote-address <ip>
  remote-id <id>
  local-id <id>
  remote-subnets <cidrs>
  local-subnets translation <cidr>
  exclude-dst-subnets <cidr>
  remote-psk <psk>
  local-psk <psk>
  ike phase 1
   encryption aes192 aes192-gcm16 aes128-gcm16
   integrity sha256
   dh-group 15
   key-lifetime 4
   exit
  ike phase 2
   encryption aes192 aes192-gcm16 aes128-gcm16
   integrity sha256
   pfs dh-group 15
   key-lifetime 4
   exit
  exit
 exit
```

---

## What does **not** work

Cisco-style commands fail: `show running-config`, `show startup-config`, `terminal length 0`, `enable`, `configure terminal`, `?`, tab completion.

Many guessed `show <feature>` names also fail (`show firewall`, `show wan`, `show ips`, `show tailscale`, `show starlink`, …). Prefer `show config` plus the operational table above.

**DHCP pool options are `option <code> <type> <value>` (2026-09-18).** A live `show config` prints them inside an `ip dhcp pool N` block as, for example, `option 43 IP 192.168.200.1` and `option 60 text something.cambium.com` — three tokens, with a type keyword (`IP`, `text` observed). The app previously wrote `dhcp-option <code> <value>`, marked CONFIRMED on the strength of a cnMaestro Group export; that export is JSON and could never evidence a CLI keyword, so both the keyword and the missing type token were wrong. The show form is the best-evidenced write form, since `show config` lines are replayed verbatim by the rollback path, but it has not yet been round-tripped live — worth confirming on a lab unit.

**`service show cloud-json-config` lags the running config (2026-09-18).** Measured on an NSE4000 running 2.4-r1: after a `load-balance monitor-hosts` change, `show config` showed the new value immediately while `service show cloud-json-config` reported the old one for roughly **seven minutes** — including across an explicit `save` — before catching up. It is a periodically regenerated cnMaestro-facing snapshot, not the running config, and on a unit that is never cloud-managed it may never populate. Never read it back to confirm a change; `show config` is the authority. The app reads configuration from `show config` and consults the JSON only for labels the CLI cannot express (see `enrichFromCloudJSON`).

**`save` is confirmed (2026-09-18).** Tested on an NSE4000 running 2.4-r1: the bare `save` command persists the running config to startup and replies `[Config Save OK]` — one of the very few positive success tokens this CLI emits — leaving the running config byte-identical. Without it a config change lives only in the running config and is lost on reboot, so the app now sends it after every successful change (see `SafeApplier.Apply`). `apply` is still untested and unused.

This NSE is cloud-managed; cnMaestro remains the source of truth and may overwrite local CLI edits.

---

## Notes from this session

- Probing sent a few bare config keywords (`snmp-server`, `high-availability`, `tailscale`, `intrusion-prevention`, `lldp`). `no snmp-server` was restored. After that, running config still showed an extra bare `high-availability` line in addition to `role primary` / `port eth6`. Check in cnMaestro that HA still matches what you want; a config sync from cloud will replace local CLI drift.
- `service show config` printed VPN PSK, Tailscale auth key, RADIUS secret, and Snort oinkcode **in cleartext**. Do not log that command into git or chat.
- Admin SSH password was used only in memory for this session. Rotate it if this chat is retained anywhere you do not trust.

---

## GUI over SSH (later)

A local GUI can:

1. SSH in and run `show config` to read state.
2. Diff against a desired CLI tree and send only the delta.
3. Poll `show interface brief`, `show route`, `show events`, `show management` for dashboards.
4. Avoid `service show config` in the GUI unless secrets are stored in an OS keychain.

I do **not** have a browser-control tool in this session, so I cannot drive cnMaestro Cloud from here. If you want that mapping next, we can either keep going over SSH, or you can walk the cloud UI while I match screens to CLI. Prefer a secrets file or env vars over pasting more passwords into chat.

## 1:1 NAT (`nat-one-one`)

A sub-context of `interface eth N`, rule id `{1-64}`. Maps one public
address onto one LAN address in both directions — no ports involved,
unlike `port-forward-rule`.

```
interface eth 1
  nat-one-one 1
    lan-IP <addr|CIDR>                        # BARE, as under port-forward-rule
    public-IP <addr|CIDR>                     # and unlike source-nat-rule's "lan-IP address"
    protocol <tcp|udp|any>                    # "any" is offered here; port-forward-rule has no such value
    rule-name <name>                          # names a traffic counter
    allowed-sources ip-address <addr|CIDR|start-end>
    allowed-sources ip-group <name>
    description <?>                           # UNCONFIRMED argument form, not probed
  exit
exit
```

CONFIRMED live on an NSE4000: every leaf above was accepted and printed
back by `show config` verbatim, in the order listed.

`rule-name` accepts **letters, digits and underscores only**, max 64
characters — quoted from the device's own rejection of `claude-test`:

```
% Error setting interface eth settings: rule-name may only contain letters, digits, and underscores
```

A hyphen is refused, so the generic "no whitespace" guard used for other
free-text leaves is not enough here.

Removal follows the usual convention, `no nat-one-one <n>` inside the
owning `interface eth N`.

The context help also lists `apply`, alongside `exit`, `save` and `show`.
It is not required: writing the leaves and leaving with `exit` sticks,
and `save` is what persists the config across a reboot, exactly as
everywhere else in this CLI.

## 1:many DNAT (`nat-one-many`)

Same shape, rule id `{1-64}`, with ports added and no `any` protocol:

```
interface eth 1
  nat-one-many 1
    allowed-sources ...
    description ...
    lan-IP ...
    lan-port ...
    port ...
    protocol <tcp|udp>
    public-IP ...
    rule-name ...
  exit
exit
```

```
interface eth 1
  nat-one-many 1
    lan-IP <addr|CIDR>
    lan-port <n>
    public-IP <addr|CIDR>
    port <n>
    protocol <tcp|udp>                        # no "any" here, unlike nat-one-one
    rule-name <name>                          # same charset rule as nat-one-one
    allowed-sources ip-address <addr|CIDR|start-end>
    allowed-sources ip-group <name>
    description <?>                           # UNCONFIRMED argument form, not probed
  exit
exit
```

CONFIRMED live on an NSE4000: every leaf above was accepted and printed
back by `show config` verbatim, in the order listed. The argument forms
are identical to `nat-one-one`'s.

Which side each port names is carried over from `port-forward-rule`,
where the pairing is confirmed: `lan-port` is behind the device, `port`
faces the WAN. The help here says only "Specify port" and "Specify LAN
port", so that mapping rests on the naming convention — a read-back
proves the syntax, not which direction the translation runs.

Removal: `no nat-one-many <n>` inside the owning `interface eth N`.

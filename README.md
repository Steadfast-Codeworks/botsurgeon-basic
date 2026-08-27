# BotSurgeon Basic v1.0.7

**Built by [Steadfast Codeworks](https://www.steadfasttools.com)**

Free bot detection and blocking for Linux web servers.
No account required. No license key. No phone-home. Runs fully offline.

---

## What It Does

BotSurgeon Basic is a single Bash script that detects and blocks malicious bots, vulnerability scanners, and resource abuse on web servers. It analyses your Apache / LiteSpeed / Nginx access logs (and, on cPanel, per-domain "domlogs"), scores each source IP, and blocks offenders through whichever firewall your server already runs.

**Key capabilities:**

- Access-log threat scoring (suspicious paths, 404 scanning, probe patterns)
- Per-domain domlog scanning on cPanel/WHM (catches per-site abuse)
- Connection-flood detection (counts ESTABLISHED connections on web ports only)
- Lightweight bot fingerprinting (no static assets, single UA, high error rate)
- Legitimate-bot protection via forward-confirmed rDNS (Googlebot, Bingbot, UptimeRobot, Pingdom, etc. are verified and never blocked)
- Multi-layer blocking: nftables, CSF, firewalld, iptables, Imunify360, Fail2Ban, hosts.deny — it uses whatever is present and defers to a firewall manager when one owns the ruleset
- CDN / reverse-proxy / NAT protection: a shared front end is recognised and protected from request-based blocks; connection floods trigger tiered mitigation (requiring 2x `AUTO_BLOCK_THRESHOLD`)
- Safety rails: per-run block cap, cooldown/dedup, whitelist (incl. CIDR), self-watchdog timeout, one-command disable, and a clean `--uninstall`
- Zero dependencies beyond standard tools (bash, awk, grep). `dig` (bind-utils / dnsutils) is recommended so legitimate crawlers can be verified.

> Want AI forensics, behavioural analysis, GeoIP/AbuseIPDB, notifications, and a full WHM dashboard? Upgrade to **[BotSurgeon Pro](https://www.steadfasttools.com/products/botsurgeon-pro)**.

---

## Requirements

- Linux server with Bash 4.x or 5.x
- Root access (a scan-only `--dry-run` preview can run without root)
- A web server: Apache 2.4, LiteSpeed / OpenLiteSpeed, or Nginx
- A firewall: nftables, firewalld, iptables, or CSF (any one is enough)
- Recommended: `dig` for legitimate-bot rDNS verification
- Access logs in **COMBINED** format (see note below)

### Log format matters

BotSurgeon reads the user agent from your access log, and the user agent is only present in the "combined" log format — the one that ends with a referer and a user-agent field:

```
1.2.3.4 - - [date] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0 ..."
                                                 ^^^^^^^^^^^^^^^ needed
```

The older "common" format stops after the byte count and has no user agent. On a server logging in common format:

- user-agent scoring and the known-good-bot pre-check do not run;
- CDN/proxy detection cannot work (it counts distinct user agents);
- crawlers are still protected, but only by the rDNS check, so `dig` becomes important rather than merely recommended.

Combined is the default for Apache (`LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined`), cPanel and Nginx, so most servers already qualify. If yours does not, switching is worthwhile before enabling `--auto`.

### Tested platforms

- AlmaLinux / Rocky / CloudLinux 8+, CentOS 7+
- Ubuntu 20.04 / 22.04 / 24.04, Debian 11 / 12
- Control panel: cPanel/WHM, DirectAdmin, Plesk, or no panel at all (per-domain domlog scanning is cPanel-specific; all other features work everywhere)

---

## Installation

1. Extract the archive to `/usr/local/bin/`:

   ```bash
   tar -xzf botsurgeon-basic-1.0.7.tar.gz -C /usr/local/bin/ --strip-components=1
   cd /usr/local/bin/
   ```

2. Make the script executable:

   ```bash
   chmod +x BotSurgeon-Basic.sh
   ```

3. Preview what it would do (no blocking, no root required):

   ```bash
   bash BotSurgeon-Basic.sh --dry-run
   ```

   This runs the same analysis `--auto` runs and prints exactly which IPs it
   *would* block, without touching your firewall, cooldown or block history.
   It is safe to pipe or redirect.

4. *(Optional)* Generate a config file to tune thresholds and paths:

   ```bash
   ./BotSurgeon-Basic.sh --generate-config
   nano /etc/botsurgeon/botsurgeon-basic.conf
   ```

5. Run once with blocking enabled (as root):

   ```bash
   ./BotSurgeon-Basic.sh --auto
   ```

---

## Running Behind a CDN or Proxy

> Read this before step 5 above. If your sites sit behind Cloudflare, Sucuri, a load balancer, or any reverse proxy, check this before you enable blocking. It is the one setup where a mistake is expensive.

### The problem

Without `mod_remoteip`, every line in your access log shows the CDN's edge IP instead of the visitor's. Attackers routinely probe sites *through* a CDN, so those probes get attributed to the edge. Block that address at the origin and you have not blocked the attacker — you have cut off every visitor whose traffic passes through that edge. The same applies to an office NAT gateway, where one address fronts a whole company.

### What BotSurgeon does about it

It detects shared front ends automatically, with no configuration and no external data. An address that presents many **distinct** user agents while serving mostly successful requests is multiplexing real browsers, not attacking you. Those addresses are shielded from request-path and threat-score blocks, and you are told:

```
REFUSING TO BLOCK 162.158.1.9 - this looks like a CDN edge, reverse
proxy or NAT gateway
   41 distinct user agents came from this one address, mostly succeeding.
   Blocking it would cut off every visitor behind it.
```

If an address matching the heuristic opens a raw connection flood, BotSurgeon applies a higher bar: it requires connection counts to exceed **2x `AUTO_BLOCK_THRESHOLD`** before triggering mitigation.

A scanner does **not** get this exemption. Four conditions have to hold together, and the last two are the ones that cannot be faked cheaply:

1. at least `PROXY_UA_THRESHOLD` distinct user agents (default 8);
2. at least `PROXY_MIN_TOTAL` requests in the analysis window (default 200);
3. at least `PROXY_MIN_REQS_PER_UA` requests **per** user agent on average (default 5) — a real edge multiplexes returning browsers, so each agent recurs; a client rotating a UA list sends roughly one request per agent, because the traffic is the expensive part;
4. at least `PROXY_MIN_PATHS` distinct paths (default 3) — a real edge is pulling a whole *site*; a client manufacturing an exemption hammers one URL;

plus mostly-successful (2xx/3xx) traffic throughout.

`--status` shows the thresholds currently in force.

### The proper fix (do this if you can)

Install and configure `mod_remoteip` so your logs carry the real client IP. BotSurgeon then sees actual visitors and scores them individually, which is strictly better than any heuristic:

```bash
# AlmaLinux/Rocky/cPanel
yum install ea-apache24-mod_remoteip

# Debian/Ubuntu
a2enmod remoteip
```

Then set `RemoteIPHeader` / `RemoteIPTrustedProxy` for your provider.

### The belt-and-braces fix

List your edge ranges — plain IPs or CIDR, one per line — in:

```
/etc/botsurgeon/proxies.conf
```

Anything listed there is never blocked, full stop. Cloudflare publishes its ranges at [cloudflare.com/ips](https://www.cloudflare.com/ips/). Example:

```
173.245.48.0/20
162.158.0.0/15
103.21.244.0/22
```

### Tuning

`PROXY_UA_THRESHOLD` (default 8) is how many distinct user agents mark an address as a shared front end. Lower it to be more cautious; set it to 0 to turn the heuristic off entirely (only sensible if you have configured `mod_remoteip` or `proxies.conf`).

Raise `PROXY_MIN_TOTAL`, `PROXY_MIN_REQS_PER_UA` or `PROXY_MIN_PATHS` only with care, and prefer `proxies.conf` instead. These floors cut both ways: set them too low and a determined attacker can manufacture an exemption; set them too high and a *genuine* edge loses one, and blocking a CDN takes every site behind it offline for every visitor. The defaults are deliberately biased toward the cheaper mistake. `proxies.conf` is the only deterministic guarantee.

### May the heuristic refuse a block? (`PROXY_HEURISTIC`)

Be clear-eyed about what the heuristic is: a traffic pattern, not proof. An address that serves roughly 200 mostly-successful requests across 8 user agents and 3 paths earns the same exemption a real CDN edge gets — and an attacker can generate exactly that, then keep it while probing. `proxies.conf` cannot be faked that way, because membership is something *you* declare.

So the exemption's authority now depends on whether you have given BotSurgeon the deterministic answer:

| `PROXY_HEURISTIC` | Behaviour |
| --- | --- |
| `auto` (default) | **advisory** once `proxies.conf` lists any range; **enforce** while it does not |
| `enforce` | The heuristic can refuse a block. Accepts the evasion above. |
| `advisory` | The heuristic only warns; blocks proceed. Closes the evasion — declare your edges first. |
| `off` | Do not run the detection at all. |

`auto` is the right default because the two mistakes are not equally expensive. On a server whose operator has **not** declared their edges, wrongly blocking a CDN PoP takes every site behind it offline — far worse than an attacker buying themselves an exemption. Once `proxies.conf` exists, that risk is covered deterministically and the guessable exemption is pure downside, so it stands down by itself.

`proxies.conf` accepts IPv4 and IPv6, plain addresses or CIDR, one per line. Cloudflare's published ranges (including all seven IPv6 ones) work as-is:

```
173.245.48.0/20
2606:4700::/32
2803:f800::/32
```

If you are **not** behind a proxy, there is nothing to do here — ordinary visitors present one user agent each and are unaffected.

---

## Usage

Run `./BotSurgeon-Basic.sh --help` for the full option list. Common commands:

| Purpose | Command |
| --- | --- |
| Interactive triage (menu-driven, needs a terminal) | `./BotSurgeon-Basic.sh` |
| Automated protection (for cron) | `./BotSurgeon-Basic.sh --auto` |
| Continuous monitoring (foreground) | `./BotSurgeon-Basic.sh --monitor` |
| Emergency lockdown (aggressive) | `./BotSurgeon-Basic.sh --emergency` |
| Preview only, no actions | `./BotSurgeon-Basic.sh --dry-run` |

> `--dry-run` performs the same analysis as `--auto` and reports which IPs it would block, changing nothing. The menu-driven mode needs a terminal; if you run it unattended it now tells you to use `--auto` or `--dry-run` instead of silently doing nothing.

### Threshold overrides (per run; prefer the config file for permanent changes)

```bash
# Auto-block at 75+ connections
./BotSurgeon-Basic.sh --auto --block-threshold 75

# Warn (don't block) at 40+ connections
./BotSurgeon-Basic.sh --auto --threshold 40
```

> **Note:** `--threshold` sets the ALERT (warning) tier only. Use `--block-threshold` to change what actually triggers an auto-block.

---

## Cron Setup

Run every 5 minutes, wrapped in `timeout` so a wedged run can never hold the lock and block future cycles:

```cron
*/5 * * * * root timeout 300 /usr/local/bin/BotSurgeon-Basic.sh --auto >> /var/log/botsurgeon/cron.log 2>&1
```

Place that line in `/etc/cron.d/botsurgeon` (include the `root` field there) or add it without the `root` field to root's own crontab (`crontab -e`).

---

## Recovery & Control

| Purpose | Command |
| --- | --- |
| Unblock an IP from EVERY layer | `./BotSurgeon-Basic.sh --unblock 203.0.113.5` |
| Unblock **and never block it again** | `./BotSurgeon-Basic.sh --unblock 203.0.113.5 --whitelist` |
| Show what is blocked (with time left) | `./BotSurgeon-Basic.sh --list-blocked` |
| Show operational status | `./BotSurgeon-Basic.sh --status` |
| Temporarily disable (cron exits early) | `./BotSurgeon-Basic.sh --disable` |
| Re-enable after disabling | `./BotSurgeon-Basic.sh --enable` |
| Remove BotSurgeon from the server | `./BotSurgeon-Basic.sh --uninstall` |

`--unblock` clears nftables, CSF (both temporary and permanent denies), firewalld, iptables, Imunify360, and hosts.deny. It reports how many layers it actually cleared, and tells you plainly when an address was not blocked by BotSurgeon at all. If you also run Fail2Ban, unban there separately:

```bash
fail2ban-client unban 203.0.113.5
```

An unblock also refreshes the IP's cooldown, so the next scan cannot immediately re-block it while you investigate. If the address keeps getting caught, make the exemption permanent with `--unblock <ip> --whitelist`, which adds it to your whitelist file with a dated comment.

`--disable` takes effect immediately: a disabled install does not restore its firewall rules, does not block, and pauses an already-running `--monitor` session (which resumes on `--enable`). Use it while you investigate, then `--unblock` what you need.

`--uninstall` removes cron entries, BotSurgeon's own firewall rules, and its runtime state. It **keeps** your config file and logs, and prints their paths. It asks for confirmation first; add `--force` to skip the prompt. If BotSurgeon-Pro is also installed it leaves the shared nftables table alone.

### Blocks expire on their own

By default a block lasts 24 hours and then lifts itself (`BLOCK_TTL_HOURS`). That matters: if BotSurgeon ever gets one wrong, the mistake heals instead of becoming a permanent outage that nobody notices.

How each layer expires:

| Layer | How the TTL is enforced |
| --- | --- |
| nftables | Natively — set elements carry a per-element `timeout` |
| CSF | Natively — a temporary deny (`csf -td`), which also keeps `csf.deny` free |
| firewalld | Natively — a runtime rich rule with `--timeout` |
| iptables | Swept by BotSurgeon each run, against its expiry journal |
| hosts.deny | Swept by BotSurgeon each run, against its expiry journal |
| Imunify360 | Swept by BotSurgeon each run (its blacklist has no TTL we can rely on) |
| Fail2Ban | **Not used while a TTL is set** — see below |

The expiry journal (`/var/log/botsurgeon/block_expiry.dat`) records the deadline **and which layers BotSurgeon placed the block on**, so the sweep lifts exactly what it put down and never tears down a ban Fail2Ban or you placed on the same address. If that journal cannot be written — a full disk, a read-only `/var` — BotSurgeon refuses the layers that cannot expire on their own and says so, rather than installing a block that would silently become permanent.

**Fail2Ban and TTLs.** A jail ban lasts for that jail's own `bantime` (`recidive` ships with a one-week default) and `banip` takes no per-ban override, so a block placed there routinely outlives `BLOCK_TTL_HOURS`. Unbanning it later is not safe either — Fail2Ban bans the same addresses for its own reasons and `unbanip` cannot tell whose ban it is. So while a TTL is set, BotSurgeon declines that layer and tells you once per run. Nothing is lost: Fail2Ban is not a firewall manager, so nftables or iptables has already taken the address. Set `BLOCK_TTL_HOURS=0` if you want Fail2Ban in the mix.

Set `BLOCK_TTL_HOURS=0` if you would rather blocks were permanent and reviewed by hand. Note that permanent CSF denies count against `DENY_IP_LIMIT`, and CSF silently discards its oldest entry once that limit is reached — BotSurgeon warns you when `csf.deny` approaches it.

---

## Configuration

Configuration lives in an external file (do **not** edit values inside the script):

```
/etc/botsurgeon/botsurgeon-basic.conf
```

Create it with defaults using:

```bash
./BotSurgeon-Basic.sh --generate-config
```

An existing config is never overwritten — defaults are written to a `.new` sidecar so you can diff and merge.

Only `KEY=value` lines are parsed; shell commands are never executed. The file must be owned by root, sit in a root-owned directory, and be neither group- nor world-writable, or it is ignored with a warning. The same rule applies to `whitelist.conf`, `proxies.conf` and the `.disabled` flag — anyone who can write those can decide who never gets blocked.

### Available keys

| Key | Description |
| --- | --- |
| `CONNECTION_THRESHOLD` | Connections/IP to raise a warning (default 50) |
| `AUTO_BLOCK_THRESHOLD` | Connections/IP to auto-block (default 100) |
| `LOG_THREAT_THRESHOLD` | Access-log threat score to block, 0-100 (default 60) |
| `MONITORED_PORTS` | Local web ports to watch, e.g. "80 443 8080" |
| `BLOCK_TTL_HOURS` | How long a block lasts before it lifts itself (default 24; 0 = permanent). See [Recovery & Control](#recovery--control). |
| `COOLDOWN_SECONDS` | Seconds before the same IP can be re-blocked (1800) |
| `NUM_LINES` | Main-log lines analysed per run (default 10000) |
| `DOMLOG_LINES` | Per-domain log lines analysed (default 5000) |
| `DOMLOG_MAX_DOMAINS` | Max domains scanned per cycle (default 50) |
| `MAX_BLOCKS_PER_RUN` | Safety cap on blocks per run (default 20) |
| `MAX_RUNTIME` | Self-watchdog timeout in seconds (default 300) |
| `THROTTLE_CPU/IO/EP` | CloudLinux LVE limits (LVE only) |
| `LOG_FILE` / `LOG_MAX_SIZE_MB` | Log path and rotation size (MB) |
| `ACCESS_LOG` / `LITESPEED_LOG` / `NGINX_LOG` | Override log auto-detection |
| `WHITELIST_FILE` | Path to your custom whitelist (see below) |
| `PROXY_UA_THRESHOLD` | Distinct user agents that mark an address as a shared front end and exempt it from blocking (default 8; 0 disables). See [Running Behind a CDN or Proxy](#running-behind-a-cdn-or-proxy). |
| `PROXY_MIN_TOTAL` | Requests an address must have made before the CDN exemption can apply (default 200) |
| `PROXY_MIN_REQS_PER_UA` | Average requests per distinct user agent required for the CDN exemption (default 5) |
| `PROXY_RANGES_FILE` | Path to your CDN / load-balancer ranges (default `/etc/botsurgeon/proxies.conf`) |

### Whitelisting

- RFC1918 ranges, loopback, the server's own IPs, and common resolvers are always trusted automatically.
- CSF's `/etc/csf/csf.allow` is honoured, including CIDR ranges.
- Add your own trusted IPs or CIDRs (one per line) to:

  ```
  /etc/botsurgeon/whitelist.conf
  ```

- An "allow everything" range (`0.0.0.0/0` or `::/0`) is **refused and reported**, not obeyed. Such an entry — which appears naturally in CSF advanced-allow rules like `tcp|in|d=3306|s=0.0.0.0/0` — would otherwise exempt the entire internet and switch blocking off silently. Only source-position tokens (`s=`, or a bare address) are treated as whitelist entries; destination and port fields are ignored.
- Existing `iptables ... -j ACCEPT` source rules are honoured too, so BotSurgeon's nftables chain cannot override a trust rule you added yourself.
- CDN / load-balancer / reverse-proxy ranges go in their own file, same format, so they stay separate from your admin whitelist:

  ```
  /etc/botsurgeon/proxies.conf
  ```

  See [Running Behind a CDN or Proxy](#running-behind-a-cdn-or-proxy) above.

---

## What It Detects

- Vulnerability-scanner probes (`/.env`, `/.git`, phpMyAdmin, config files, LFI)
- High 404 rates (path enumeration / scanning)
- Credential-stuffing volume against `wp-login.php` / `xmlrpc.php`
- Known bad bot / scanner user agents (curl, sqlmap, nikto, masscan, zgrab...)
- Connection floods from a single IP on web ports
- Headless/scraper fingerprints (no static assets, single UA, high error rate)

### Specifically protected from false positives

- **Admin panels in use.** Requests to `/wp-admin`, `admin-ajax.php`, Joomla's `/administrator`, Magento's `/admin`, phpMyAdmin and cgi-bin apps only count as a threat when they **fail** (401/403/404). A logged-in administrator gets 2xx and is left alone; a scanner probing for a panel that is not there gets 404 and is caught.
- **Search engines and monitoring services**, verified by forward-confirmed rDNS.
- **CDN edges, reverse proxies and NAT gateways** (see [Running Behind a CDN or Proxy](#running-behind-a-cdn-or-proxy)).

> **Note on backups:** a request for `/something.sql` or `/backup.zip` is treated as a probe even when it succeeds — a 200 there means a database dump was actually served, which is more alarming than a 404, not less.

---

## Files & Logs

| Path | Description |
| --- | --- |
| `/etc/botsurgeon/botsurgeon-basic.conf` | Configuration (optional) |
| `/etc/botsurgeon/whitelist.conf` | Custom whitelist (optional) |
| `/etc/botsurgeon/proxies.conf` | CDN / proxy ranges (optional) |
| `/etc/botsurgeon/.disabled` | Present when `--disable` is active |
| `/var/log/botsurgeon/botsurgeon-basic.log` | Activity log (auto-rotated) |
| `/var/log/botsurgeon/blocked_ips.log` | Block history (auto-rotated) |
| `/var/log/botsurgeon/block_expiry.dat` | Pending block expiry deadlines |
| `/var/run/botsurgeon-basic.pid` | Lock file (single-instance guard) |

---

## Limitations

BotSurgeon Basic is intentionally simple. It does **not** include:

- Behavioural analysis or threat intelligence
- Forensic reporting, GeoIP, or AbuseIPDB reputation
- WHM dashboard integration
- Webhook / Slack / Discord notifications
- Outbound (C2 beacon) detection
- Multi-server / fleet management

For all of the above, see **[BotSurgeon Pro](https://www.steadfasttools.com/products/botsurgeon-pro)**.

---

## Support

- **Documentation:** <https://www.steadfasttools.com/products/botsurgeon-basic>
- **Report Issues:** <https://www.steadfasttools.com/contact>
- **Email:** <support@steadfasttools.com>
- **Response time:** 24-48 hours (GMT+2)

---

## License

Steadfast Codeworks Freeware License. This software is provided free of charge. You may use, copy, and distribute it freely for personal and commercial use on your own servers. You may **not** sell this software or repackage it as your own product.

Full terms: <https://www.steadfasttools.com/legal/licensing>

© 2026 Steadfast Codeworks (R.L. Burger). All rights reserved.
*Automate. Simplify. Steadfast.*

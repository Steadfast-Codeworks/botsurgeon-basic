# Changelog — BotSurgeon-Basic

All notable changes to `BotSurgeon-Basic.sh`.

Part of the [Steadfast Codeworks](https://www.steadfastcodeworks.com) Security Toolkit · [Steadfast Tools](https://www.steadfasttools.com)
Copyright (c) 2026 R.L. Burger · Steadfast Codeworks Freeware License

---

## [1.0.7] — state-integrity, lock-safety & false-success release

Remediation of two independent full-file code reviews (43 findings, all closed).
Verified by 270 regression tests across ten suites.

The theme running through this release is one defect class: **a mutation whose
result was discarded, followed by a success report.** The block path had been
hardened across 1.0.3–1.0.6; the paths that *consume* what the block path wrote —
the expiry sweep, the cooldown prune, the firewalld reload, the uninstall
teardown — had not.

### CRITICAL

- CRITICAL: the TTL sweep deleted a block's journal row whether or not the layer
  removal actually succeeded. A contended xtables lock, a read-only /etc or an
  Imunify RPC timeout left the DROP rule live with its deadline erased, and the
  run printed "Expired 1 block(s)" — a permanent block produced by the function
  whose only job is to prevent one, and reported as a success so nobody looked.
  `_expire_one_ip` now has a return contract, stuck rows are retained for the
  next run, and the operator is told how many could not be lifted
- CRITICAL: the TTL sweep and the cooldown prune both appended surviving rows to
  a temp file without checking the write, then committed it on "is not empty".
  A disk filling mid-loop published a truncated journal (permanent blocks on an
  arbitrary subset of addresses) or a truncated cooldown file (a re-block storm
  on the next cron cycle) — silently, and precisely under the low-disk condition
  that caused it. Both now fail closed, leaving the original intact
- CRITICAL: `finalize_firewall` was reachable from only one of five block paths.
  On a firewalld host with BLOCK_TTL_HOURS=0, `--monitor` and interactive
  options 3/6/7 added `--permanent` rich rules, reported "firewalld: blocked",
  wrote the block history and set a 30-minute cooldown — and never reloaded, so
  the rule sat inert while the attacker was unimpeded. Now called after every
  batch, with a `cleanup()` backstop for interrupted runs
- CRITICAL: the stale-lock breaker could SIGKILL a *healthy* monitor. Five
  distinct triggers: a legitimate long cycle exceeding the 300s threshold; an
  unwritable data directory whose heartbeat failure was swallowed by `|| true`;
  a truncate-then-write race on the heartbeat; the entire preflight window
  before a restarting monitor wrote its first heartbeat; and a lock file naming
  a dead or recycled PID, because the wait path never rewrote it. The heartbeat
  is now atomic, refreshed around every long phase, its failure is reported, the
  threshold is 900s, the holder's identity is verified via /proc before any
  signal, and SIGTERM precedes SIGKILL so cleanup can run
- CRITICAL: a detected CDN edge was blocked on connection floods while the
  README, the generated config, three in-file comments and the runtime banner
  all promised the opposite. Connection floods from a heuristically-detected
  edge now require 2x AUTO_BLOCK_THRESHOLD before mitigation, and every
  documentation surface states it

### MAJOR

- MAJOR: `IFS=$'\t' read` collapses empty fields, because tab is IFS whitespace.
  Any IP scoring >=30 with no suspicious paths shifted its User-Agent into the
  paths column, leaving the UA empty — so `is_known_good_ua` never ran and, on a
  host without `dig`, a legitimate crawler lost its only remaining protection.
  All three record readers now split explicitly
- MAJOR: `/wp-admin` and `admin-ajax.php` were invisible to panel detection —
  `(^|/)admin` cannot match a segment preceded by a hyphen. A browser-UA,
  wp-admin-only, all-404 scanner capped at score 55, permanently under the
  default threshold of 60. Both paths added behind the failure gate, and the
  gate narrowed to 4xx so 3xx redirects and 5xx no longer score as attacks
- MAJOR: `--uninstall` stranded bare iptables DROP rules on hosts without
  xt_comment, then deleted the only two records that could ever lift them —
  while printing "nothing from Basic is left to conflict with it". It now sweeps
  the marker file and pending journal rows before clearing state
- MAJOR: a stale bare-rule marker outlived the rule it described, so a TTL sweep
  could delete an administrator's own hand-authored DROP on the same address.
  Markers are now pruned against live iptables state, not against the journal
- MAJOR: no PATH or BASH_ENV sanitization in a root-run security tool. Every
  privileged command resolved by bare name, and the `command -v` preflights
  resolved through the same PATH — so a wrapper-influenced PATH yielded a shim
  that passed preflight and then executed as root
- MAJOR: `test` exits status 2 on an unparseable integer, which reads as *false*
  inside an `if ... || ...` chain and falls through to the permissive branch.
  `_validate_int` therefore emitted int64-overflow values verbatim, defeating
  MAX_BLOCKS_PER_RUN entirely, and `_file_is_root_safe` accepted a file whose
  mode it could not parse. Both now validate shape before any comparison
- MAJOR: the stale-lock breaker could not recover a lock held by a wedged
  *child* — it killed the bash holder while the child kept FD 9 open, and every
  later run then skipped the breaker and exited 1 forever. It now kills the
  process group (guarded against the caller's own group) and reports an
  orphaned flock instead of failing silently
- MAJOR: `_ipt_del` in "all" scope matched the address in *any* column of
  `iptables -L`, including the destination field. Now anchored to the source
- MAJOR: the TTL sweep called `_persist_iptables` even when CSF, firewalld or
  Imunify360 owned the ruleset, snapshotting the manager's entire live state
  into /etc/sysconfig/iptables for the next boot to restore ahead of it
- MAJOR: the "TOP 10 DOMAINS UNDER STRESS" table printed the log's domain field
  raw. Under `%V` with `UseCanonicalName Off` that is the client's Host header,
  so an ANSI escape could rewrite the rows above it — in the first table an
  operator reads during triage. Now validated in the parser and sanitized on
  output
- MAJOR: `--status` printed "present but NOT trusted - see the warning above"
  while the informational-command pre-scan suppressed that very warning, leaving
  an operator with a red cross, no reason and no remedy
- MAJOR: a heartbeat dated in the future (NTP step, restored snapshot, clock
  jump) was clamped to "maximally healthy", so every cron cycle exited 0 and
  skipped — silently and permanently, with no failure mail. An impossible
  timestamp is now treated as unverifiable, not as fresh
- MAJOR: monitor mode announced "auto-blocking" before the whitelist and
  cooldown checks, so a whitelisted address — including the server's own IP —
  produced a THREAT line every 30 seconds with no block and no explanation

### OPTIMIZATION

- OPT: `_nft_persist` failed silently and leaked its temp file, asymmetric with
  the loud `_persist_iptables`; a failed save left a stale persisted ruleset with
  no log line
- OPT: `--unblock` reported "hosts.deny: removed" without verifying the removal,
  and counted the layer as cleared even when `sed -i` failed
- OPT: `show_status` discarded a correct nftables set count in torn states,
  because `|| set_count=0` fired on the pipeline's exit status
- OPT: the disable-flag trust gate ran up to four `stat` calls on every block
  decision — 200 process spawns at --emergency, inside the watchdog's budget.
  Now cached and invalidated on ctime
- OPT: `--uninstall` passed journal addresses to the Imunify agent without
  revalidating them
- OPT: root fell back to /tmp even when the sticky bit was missing; it now
  refuses, and the refusal is written to stderr so it cannot be captured by the
  command substitution that reads the path
- OPT: `--status` omitted PROXY_MIN_PATHS from the displayed exemption
  thresholds while the README said all four were shown
- OPT: `IMUNIFY360_CACHE` was the one per-run cache the monitor loop never
  reset, freezing Imunify360 detection for the life of a multi-day session
- OPT: scratch files created mid-function were orphaned when SIGTERM or an
  external `timeout` landed — routine, since the README recommends wrapping cron
  runs in `timeout 300`. A registry now tracks every temp file for cleanup
- OPT: the watchdog subshell inherited FD 9, so a SIGKILLed main process left an
  orphaned watchdog holding the lock for up to MAX_RUNTIME
- OPT: the interactive treatment menu held the lock across its blocking `read`,
  so an abandoned SSH session suspended cron protection indefinitely
- OPT: `--uninstall` deleted the live scratch files of any concurrently running
  instance; the sweep is now scoped to files older than ten minutes
- OPT: `--uninstall` misread a missing `flock` as contention and aborted with a
  false "another instance is running"
- OPT: `init_cooldown` used a fixed-name trim file and could rename across
  filesystems; both temp files are now unique and same-directory
- OPT: `unblock_ip`'s legacy OUTPUT-chain loop had no iteration guard, unlike
  the identical pattern in `_ipt_del`
- OPT: configuration notices emitted before the log file existed were lost
  entirely on cron installs without stderr capture; they are now buffered and
  replayed
- OPT: stale development scripts (`blk.sh`, `at.sh`, `fns.sh`, `ipre.sh`,
  `t4.sh`, and four snippet-style files that asserted nothing) removed from the
  release artifacts; six regression suites added covering every finding above

---

## [1.0.6] — daemon resilience, parsing integrity & hardening release

- CRITICAL: orphaned /etc/hosts.deny entry cleanup on total block failure
  (when all packet-filter layers fail, advisory hosts.deny line is purged
  before unjournalling expiry)
- MAJOR: bulk connection-flood mitigation in --monitor mode (mitigates all
  qualifying IPs in a single cycle up to MAX_BLOCKS_PER_RUN)
- MAJOR: monitor heartbeat and stale-lock recovery for cron (active monitors
  refresh heartbeat timestamp; cron detects and breaks stale >300s locks)
- MAJOR: proxy heuristic exemption scoped strictly to log analysis threats;
  connection floods are never exempted by the heuristic
- MAJOR: interactive auto-scan (menu case 4) now explicitly enables AUTO_MODE
- MAJOR: connection tool presence check in preflight warns on missing ss/netstat
- MAJOR: proxy detection pipeline failure guard prevents silent heuristic failure
- OPT: numeric validation rejects leading-zero octal arithmetic traps in $(( ))
- OPT: anchored regex for hosts.deny unblock prevents wiping unrelated comments
- OPT: domlog analysis protects quiet/empty logs from false-positive pipefail errors
- OPT: symlink rejection and fail-closed directory stat in _file_is_root_safe trust gate
- OPT: extended cache resets in continuous monitoring loop for live rule updates
- OPT: missing dig utility warning logged when search bot verification is skipped
- OPT: fingerprint_ip uses exact IP token boundaries for IPv6 address safety
- OPT: mutually exclusive CLI flags validated in parse_arguments
- OPT: log rotation, proxy mode dynamic re-evaluation, and rDNS cache capping
  in continuous monitoring loop

## [1.0.5] — block-lifecycle & trust-boundary release

- CRITICAL: --dry-run could ENFORCE. _nft_load ran before the root/mode
  checks and restored /etc/nftables/botsurgeon.nft, so a "preview" on a box
  whose table had been flushed put every persisted DROP back into service -
  exactly the state an operator is in mid-incident. The preview also pruned
  the cooldown file, rotated the block history and wrote to the live
  activity log. It now changes nothing, as documented
- CRITICAL: a failed expiry-journal write was reported as success and the
  caller blocked anyway, so a full disk or read-only /var produced a live
  iptables rule with no deadline - a PERMANENT block on a tool whose
  headline promise is a 24h TTL. The journal is now a verified temp+rename
  transaction, and the layers with no native expiry are refused when it fails
- MAJOR: TTLs were not honoured per backend. Imunify360 got an unqualified
  blacklist add and Fail2Ban a jail ban lasting that jail's own bantime
  (recidive: one week), both counted as expiring blocks. The expiry journal
  now records WHICH layers are ours and sweeps Imunify360 too; Fail2Ban is
  declined while a TTL is set, because its ban cannot be bounded and
  unbanning it could tear down one of Fail2Ban's own
- MAJOR: `iptables-save > file` truncates the boot-time ruleset before the
  command runs, so an interrupted or failed save left a partial firewall to
  restore at reboot - errors discarded. Persistence is now atomic and
  checked. --unblock never persisted at all, so an operator's undo came back
  at the next reboot
- MAJOR: any installed csf binary marked the system manager-owned, even with
  CSF disabled (csf -x) - nftables and iptables stood down for a manager
  enforcing nothing, leaving the attacker unblocked. CSF is now tested for
  activity, and if every manager layer fails, direct enforcement takes over
- MAJOR: the CDN/proxy heuristic could still be self-assigned (~200 requests,
  8 user agents, 3 paths) and its exemption was absolute. Its authority is
  now conditional: PROXY_HEURISTIC=auto makes it advisory once proxies.conf
  declares real ranges, and enforcing only while it does not
- MAJOR: --disable did not stop a running --auto pass, and --monitor paused
  on a bare flag file, skipping the ownership check - any local user could
  halt a running monitor. One trusted is_disabled predicate now answers for
  the blocker, the monitor and --status
- MAJOR: IPv6 CIDRs were an exact textual match on the base address, so a
  trusted 2001:db8::/32 covered exactly one host out of 2^96 - in whitelists,
  proxies.conf, csf.allow and the admin's own ip6tables ACCEPT rules. Real
  prefix matching, for every one of those
- MAJOR: a failed tail/awk/sort pipeline produced an empty result that the
  analysers reported as "No threats detected". Pipelines are now checked and
  "the scan found nothing" is distinguished from "the scan did not run"
- MAJOR: "block aggressive IPs for domain" matched the vhost by SUBSTRING, so
  filtering for example.com also selected evil-example.com - blocking another
  tenant's visitors on a shared cPanel box
- --generate-config refused to write into a non-root-safe directory and no
  longer redirects onto a name a local user could have pre-planted as a
  symlink for root to overwrite
- The nftables persistence file is fed to `nft -f` as root; it now gets the
  same ownership gate as the config, whitelist and disable flag
- --uninstall takes the lock. It used to tear down rules and delete the state
  files that track them while a scan was busy creating more
- PROXY_MIN_PATHS was documented but missing from ALLOWED_CONFIG_KEYS, so
  setting it was silently ignored
- Root no longer trusts an inherited TMPDIR for its temp fallbacks: the
  owner of a caller-chosen directory can unlink or replace a file after
  mktemp created it
- CloudLinux throttling reports the truth. Both lvectl calls are checked,
  and "saved but not applied" is distinguished from "nothing was configured"
- Regression tests pin the ss/netstat column layouts, the dry-run
  non-mutation invariants, journal failure, per-backend TTL, IPv6 prefix
  matching and the uninstall lock

## [1.0.4] — regression & scope-correctness release

- CRITICAL: the per-domain (domlog) threat engine had been silently DEAD
  since 1.0.3. The shared-parser refactor removed extract_ua() but left one
  call to it; an undefined awk function is fatal, so the pass aborted before
  its END block on every domain and the scan reported "No per-domain threats
  detected" over a live attack. It now uses the parser's own ua field
- MAJOR: the TTL sweep could delete the ADMIN'S iptables rules. _ipt_del
  removed any bare "-s IP -j DROP" for both scopes, so a hand-authored
  permanent block on an address that had also passed through our expiry
  journal was torn down when the TTL lapsed - and made durable by the next
  iptables-save. Untagged rules are now removed under scope=ours only when
  _ipt_add recorded writing them (hosts with no comment match), so our own
  blocks still expire while the operator's survive
- MAJOR: "Block aggressive IPs for domain" was a no-op on cPanel. It read
  the client IP as field 1, but cPanel's access_log is vhost-prefixed, so no
  address was ever extracted. It now uses the shared parser, and the domain
  filter matches the vhost token instead of the whole line (a site name in a
  Referer used to pull another customer's visitors into the list)
- --unblock now VERIFIES its cooldown and expiry edits landed. It is allowed
  to proceed without the lock (refusing to unblock mid-incident would be
  worse, and --monitor holds the lock for its whole session), but a
  concurrent scan's tmp-then-mv could discard the write and the operator was
  told it succeeded. It retries, then reports honestly if it still has not
- is_ipv6 is a real parse, not a shape check: "2001:db8:1", "a:b:c" and
  "1::2::3" were accepted and reached ip6tables/nft, where the kernel
  rejected them - a block that silently failed on that layer
- The CDN/proxy exemption now also requires distinct PATHS (PROXY_MIN_PATHS,
  default 3). Volume and UA repetition alone were still satisfiable with 200
  requests for "GET /". The volume floor is deliberately unchanged: raising
  it would un-exempt genuine edges, and blocking a CDN takes every site
  behind it offline
- --unblock --whitelist reports when it wrote to a whitelist the loader will
  refuse (wrong ownership), instead of printing a tick over an entry that
  every future scan ignores
- The "unparsable log" warning compares one window against itself; it used a
  fresh tail against an older snapshot and could fire on a healthy log

## [1.0.3] — integrity & anti-evasion release

- CRITICAL: iptables rules were ADDED with '-m comment' but CHECKED and
  DELETED without it. iptables -C/-D match the full rule spec, so the check
  never found our own rule: every block reported "iptables: failed" while
  the DROP was live, a duplicate rule was appended on every re-block, the
  TTL sweep could never lift one, and --unblock silently left it in place
  while printing "unblocked from all layers". All five call sites now share
  one rule spec via _ipt_rule_spec / _ipt_find_handles
- CRITICAL: a block that failed on EVERY layer was still written to the
  block history and put into cooldown, so a total failure looked like a
  success and suppressed retries for 30 minutes. History, cooldown and the
  expiry journal are now written only when a block actually landed, and
  hosts.deny (which web servers ignore) no longer satisfies that test
- CRITICAL: an unguarded mktemp made a full /tmp truncate the whole cooldown
  file, and turned the access-log analysis into a silent "no threats found"
  all-clear. Both are guarded and both now fail loudly
- CRITICAL: one "s=0.0.0.0/0" token anywhere in csf.allow whitelisted the
  entire IPv4 internet, silently disabling all blocking. Mask-0 entries are
  refused and reported, and only source-position tokens are considered
- CRITICAL: the CDN/proxy exemption could be self-assigned by an attacker
  (20 requests, 8 user agents, 50% success bought permanent block immunity).
  It now also requires sustained volume and repeat use of each user agent -
  a real edge multiplexes browsers, a faker sends one request per agent
- Root no longer writes predictable /tmp paths (watchdog marker, watchdog
  sleep file, fallback log) - a local user could pre-plant those as symlinks
- Log parsing no longer counts fields positionally: a malformed request line
  or a quote inside a User-Agent used to shift every later field, hiding an
  attacker's error rate and their bot UA. All three analysers share one
  quote-aware parser
- --unblock keeps a cooldown instead of clearing it (an operator's undo used
  to be re-blocked within one cron cycle) and gained --whitelist
- --monitor re-prunes cooldown, re-runs expiry and refreshes CDN detection
  each cycle; previously one block exempted an IP for the whole session
- Config permission check no longer accepts group-writable (mode 664); the
  whitelist, proxies and .disabled files get the same ownership gate
- Domain names taken from logs are validated before use as a grep pattern,
  and account suspension now asks for confirmation

## [1.0.2] — false-positive & block-lifecycle release

- Blocks now EXPIRE (BLOCK_TTL_HOURS, default 24h). nftables named sets with
  per-element timeouts, CSF temporary bans, firewalld --timeout; iptables and
  hosts.deny are swept each run. Set to 0 for the old permanent behaviour
- CDN/reverse-proxy protection: an address presenting many distinct user
  agents while mostly succeeding is a shared front end (Cloudflare edge, load
  balancer, office NAT) and is never blocked — blocking one takes every
  visitor behind it offline. Optional /etc/botsurgeon/proxies.conf for
  published edge ranges
- Admin panels no longer scored as attacks when they SUCCEED: Joomla
  /administrator, Magento /admin, phpMyAdmin and cgi-bin apps count only on a
  non-2xx response (the WordPress fix from 1.0.1, generalised)
- Threat scoring now uses the full 4xx rate, not just 404 — a WAF answering a
  scanner with 403 no longer scores it at zero
- Per-domain domlog scanning works on modern cPanel again (per-user
  domlogs/<user>/<domain> layout silently scanned nothing before)
- Cooldown lookups anchored: an attacker whose IP was a suffix of a cooled IP
  was silently never blocked while being reported as blocked
- --dry-run no longer claims "Auto-blocked"; --uninstall added; --disable now
  takes effect before rules are restored and stops a running --monitor
- MONITORED_PORTS accepts commas and is validated (80,443 used to become the
  nonexistent port 80443, silently disabling connection blocking)
- Log window read once per run instead of once per IP; rDNS results memoized

## [1.0.1] — hardening release — code review remediation

- Connection blocking now counts only web-port (80/443/8080) ESTABLISHED
  connections, so IMAP/MySQL/backup traffic can no longer trigger a block
- IPv6 connection blocking fixed; IPv4-mapped addresses normalized
- Tightened suspicious-path detection to stop false positives on legitimate
  WordPress admin-ajax / wp-admin traffic; auth endpoints are volume-gated
- User-agent parsing fixed (previously read the referer)
- CIDR-aware whitelisting (honors csf.allow ranges); nft no longer overrides
  a firewall manager's whitelist
- Idempotent, verified nftables table/chain handling (coexists with Pro)
- Exact-match IP handling in firewall dedup/unblock (no 1.2.3.4 vs 1.2.3.45)
- Non-root --dry-run no longer dies at the lock; lock no longer unlink-races
- Self-watchdog timeout for cron runs; --monitor block budget resets
- Debian/Ubuntu Apache log path; dig-missing warning; AAAA forward-confirm
- README rewritten to match actual behavior; license aligned

## [1.0.0]

- Domlog scanning (per-domain log analysis on cPanel servers)
- Access log threat analysis (suspicious paths, 404 scanners, probe detection)
- Simplified bot fingerprinting (headless browser / scraper detection)
- nftables blocking (primary on AlmaLinux/Rocky/CloudLinux)
- firewalld support (rich rules with persistence)
- ss(8) with netstat fallback
- Lock file / concurrency guard (safe for cron)
- Cooldown / dedup blocking (no re-blocking same IP)
- Log rotation (automatic size-based)
- IPv6 support throughout
- External configuration file (/etc/botsurgeon/botsurgeon-basic.conf)
- Signal handling with graceful shutdown
- Custom whitelist file support

---

Entries for v1.0.0 through v1.0.6 were lifted verbatim from the script header,
where this history lived until v1.0.7.

Detailed findings behind each release are kept in the code-review documents in
this directory; regression coverage lives in the `t_*.sh` suites.

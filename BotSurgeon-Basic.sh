#!/bin/bash
# ===============================================================================
# BotSurgeon-Basic.sh - Apache Emergency Room Triage System v1.0.7
# ===============================================================================
# Part of the Steadfast Codeworks Security Toolkit
# Ward: Apache Emergency Room
# Purpose: Rapid response to bot attacks and resource abuse
#
# Author: R.L. Burger (Steadfast Codeworks)
# Date: 2025-07-08
# Last Updated: 2026-08-24
# Version: 1.0.7
# Copyright (c) 2026 R.L. Burger
# Project: Steadfast Tools
# Website: https://www.steadfasttools.com
# License: Steadfast Codeworks Freeware License - free for personal and commercial
#          use on your own servers; may not be sold or repackaged as your own product.
#          Full terms: https://www.steadfasttools.com/legal/licensing
# ===============================================================================
# Description: Free edition of BotSurgeon for identifying and blocking aggressive
#              bot attacks, resource abuse, and malicious scanners on web servers.
#              Designed for cron-based automated protection with zero UI dependency.
#              Supports Apache, LiteSpeed, and Nginx.
#
# Changelog: see CHANGELOG.md alongside this script for the full release
#            history (v1.0.0 - v1.0.7), including what each fix prevents.
#
# Usage:
#   ./BotSurgeon-Basic.sh                    # Interactive mode
#   ./BotSurgeon-Basic.sh --auto             # Automated mode (for cron)
#   ./BotSurgeon-Basic.sh --monitor          # Continuous monitoring
#   ./BotSurgeon-Basic.sh --emergency        # Emergency lockdown mode
#   ./BotSurgeon-Basic.sh --dry-run          # Preview mode (no actions taken)
#   ./BotSurgeon-Basic.sh --auto --block-threshold 75  # Custom auto-block threshold
#   ./BotSurgeon-Basic.sh --generate-config  # Generate default config file
#   ./BotSurgeon-Basic.sh --help             # Show help message
#
# Cron Example (wrap in `timeout` so a wedged run can never block later cycles):
#   */5 * * * * timeout 300 /usr/local/bin/BotSurgeon-Basic.sh --auto >> /var/log/botsurgeon/cron.log 2>&1
#
# Upgrade to BotSurgeon Pro for:
#   - Web UI dashboard with real-time monitoring
#   - ML threat scoring and classification
#   - GeoIP lookups and AbuseIPDB reputation checks
#   - Webhook/Slack/Discord/Teams notifications
#   - ModSecurity WAF rule generation
#   - Forensic evidence collection (JSON)
#   - CIDR /24 subnet blocking
#   - Coordinated/distributed attack detection
#   - Velocity & acceleration scoring
#   - Watchlist with multi-domain correlation
#   - Historical trending and reporting
#   - Temporary blocks with auto-expiry
#   - Block integrity watchdog
#
# Note: Must be run with appropriate permissions to access logs and block IPs.
#       Use --dry-run without root for previewing.
# ===============================================================================

set -o pipefail

# M4: sanitize PATH and unexport BASH_ENV / ENV
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
unset BASH_ENV ENV

# ==============================================================================
# SECTION 1: DEFAULT CONFIGURATION
# ==============================================================================

SCRIPT_NAME="BotSurgeon Basic"
VERSION="1.0.7"
WARD="Apache ER Triage"

# --- Paths ---
LOG_FILE="/var/log/botsurgeon/botsurgeon-basic.log"
LOCK_FILE="/var/run/botsurgeon-basic.pid"
DATA_DIR="/var/log/botsurgeon"
COOLDOWN_FILE="$DATA_DIR/basic_recently_blocked.dat"
# Expiry journal (N4). nftables sets, CSF temp bans and firewalld --timeout all
# expire by themselves; iptables and hosts.deny have no notion of a TTL, so we
# record "when should this be lifted" here and sweep those two layers each run.
EXPIRY_FILE="$DATA_DIR/block_expiry.dat"
MONITOR_HEARTBEAT_FILE="$DATA_DIR/monitor.heartbeat"
CONFIG_FILE="/etc/botsurgeon/botsurgeon-basic.conf"
WHITELIST_FILE="/etc/botsurgeon/whitelist.conf"
# Operator-supplied CDN / load-balancer / reverse-proxy ranges. Same CIDR-aware
# format as whitelist.conf. Anything listed here is never blocked (N1).
PROXY_RANGES_FILE="/etc/botsurgeon/proxies.conf"

# --- Log files ---
ACCESS_LOG="/etc/apache2/logs/access_log"
LITESPEED_LOG="/usr/local/lsws/logs/access.log"
NGINX_LOG="/var/log/nginx/access.log"
TRUEUSERDOMAINS="/etc/trueuserdomains"

# --- nftables ---
NFT_TABLE="botsurgeon"
NFT_PERSIST_FILE="/etc/nftables/botsurgeon.nft"
# Named sets with per-element timeouts (N4). Blocking is "add an element to a
# set" rather than "append a rule", which means membership tests and removals
# are exact set operations instead of grepping a rule listing — the entire class
# of substring bugs (1.2.3.4 vs 1.2.3.45) cannot occur here by construction.
# Names are Basic-specific so they never collide with Pro in the shared table.
NFT_SET4="bsbasic_blocked4"
NFT_SET6="bsbasic_blocked6"

# --- Block Lifetime ---
# How long a block lasts before it expires on its own, in hours. This is the
# difference between a false positive being a bad afternoon and a false positive
# being a lasting outage nobody notices. Set to 0 for permanent blocks (the
# pre-1.0.2 behaviour) if you would rather review every block by hand.
BLOCK_TTL_HOURS=24

# --- Thresholds ---
CONNECTION_THRESHOLD=50
AUTO_BLOCK_THRESHOLD=100
LOG_THREAT_THRESHOLD=60
NUM_LINES=10000
COOLDOWN_SECONDS=1800
LOG_MAX_SIZE_MB=25
DOMLOG_LINES=5000

# --- CDN / Reverse-Proxy Safety (N1) ---
# An IP presenting at least this many DISTINCT user agents (while serving mostly
# successful requests) is treated as a shared front end — a CDN edge, reverse
# proxy, load balancer or NAT gateway — and is never blocked. Blocking one of
# those takes every visitor behind it offline. Set to 0 to disable the heuristic.
PROXY_UA_THRESHOLD=8

# C2: UA diversity ALONE is an exemption an attacker can hand themselves. Eight
# user agents over twenty requests costs nothing to fake, and the exemption was
# absolute — checked before cooldown, before the safety limit, before everything.
#
# The signal that cannot be faked cheaply is REPETITION. A real front end shows
# thousands of requests spread over its agents (each agent recurs, because real
# browsers come back); a client rotating a UA list shows roughly one request per
# agent, because generating the traffic is the expensive part. Requiring both a
# meaningful volume and a healthy requests-per-agent ratio keeps every genuine
# CDN edge exempt while making the exemption expensive to counterfeit.
PROXY_MIN_TOTAL=200          # minimum requests in the window before we believe it
PROXY_MIN_REQS_PER_UA=5      # each user agent must recur this often on average
# M2: and it must look like BROWSING. 200 requests for "GET /" across 8 agents
# passes every test above and costs one shell loop; a real edge is pulling a
# whole site, so it shows many distinct paths. Kept low on purpose — this gate
# exists to price out the cheapest counterfeit, not to second-guess a genuine
# CDN, because wrongly un-exempting one takes every site behind it offline.
PROXY_MIN_PATHS=3            # distinct paths required before we believe it

# M17: is the heuristic ALLOWED TO REFUSE A BLOCK, or only to advise?
#
# Everything above raises the price of a counterfeit; none of it makes one
# impossible. An attacker who serves ~200 mostly-successful requests across 8
# user agents and 3 paths satisfies every gate, and the exemption that buys is
# absolute — is_proxy_ip is consulted centrally, ahead of cooldown, the safety
# limit and every firewall layer. That is an evasion an attacker can hand
# themselves, and no amount of tuning removes it.
#
# The deterministic answer is PROXY_RANGES_FILE: an operator who lists their
# edge ranges has told us exactly which addresses are shared, and no traffic
# pattern can fake membership of that list.
#
#   auto      (default) advisory IF PROXY_RANGES_FILE lists any range, because
#             then the deterministic criterion exists and the guessable one is
#             not needed. enforce otherwise, because a server whose operator
#             has NOT declared their edges is the one where wrongly blocking a
#             CDN PoP takes every site behind it offline - the worse failure.
#   enforce   the heuristic refuses blocks. Accepts the evasion above.
#   advisory  the heuristic only warns; blocks proceed. Closes the evasion, and
#             relies on PROXY_RANGES_FILE to protect real edges.
#   off       do not run the detection at all.
PROXY_HEURISTIC=auto

# --- Monitored Ports ---
# Connection-based detection/blocking only counts ESTABLISHED connections whose
# LOCAL (server-side) port is in this list. Prevents blocking IPs that hold many
# connections on non-web ports (IMAP/POP office NAT, MySQL clients, backups, etc).
MONITORED_PORTS="80 443 8080"

# --- Resource Throttling ---
THROTTLE_CPU=30
THROTTLE_IO=512
THROTTLE_EP=15

# --- Safety Limits ---
MAX_BLOCKS_PER_RUN=20
BLOCKS_THIS_RUN=0

# Hard ceiling (seconds) on a single unattended run. A self-watchdog kills the
# process if it exceeds this, so a hung log read / stuck firewall command cannot
# hold the lock and silently block all future cron cycles. Raise on very large
# fleets if a legitimate full scan approaches the limit.
MAX_RUNTIME=300

# --- Domlog Limits ---
DOMLOG_MAX_DOMAINS=50

# --- Operational Modes ---
AUTO_MODE=false
MONITOR_MODE=false
EMERGENCY_MODE=false
DRY_RUN=false

# --- Legitimate Bot UA Patterns (never block these without rDNS failure) ---
KNOWN_GOOD_UA_PATTERNS="Googlebot|Bingbot|bingbot|YandexBot|Applebot|DuckDuckBot|Slurp|Baiduspider|facebookexternalhit|Twitterbot|LinkedInBot|UptimeRobot|Pingdom|Site24x7|StatusCake|GTmetrix|Dataprovider|AhrefsBot|SemrushBot"

# --- Runtime Globals ---
WARD_TYPE=""
ACTIVE_LOG=""
CPANEL_MODE=false
SERVER_IPS=""
FIREWALLD_NEEDS_RELOAD=false
LOCK_HELD=false
LOCK_STATE=""
HB_WARNED=false
WATCHDOG_PID=""
WATCHDOG_MARKER=""
WATCHDOG_SLEEPFILE=""
domain=""
user_found=""
req_count=0

# O1: _has_firewall_manager is consulted up to three times per blocked IP, and
# _is_imunify360 shells out to the Imunify agent — an RPC that can take seconds.
# At --emergency (50 blocks) that alone approached the watchdog timeout, killing
# the response mid-attack. The answer cannot change during a run, so resolve it
# once. "" = not yet determined.
FW_MANAGER_CACHE=""

# O13: associative arrays need bash 4. The README requires it, but degrading to
# a per-lookup "bad array subscript" error on bash 3 is worse than not caching.
HAVE_ASSOC=false

# M2: whether the whitelist / proxy-range files passed the root-ownership gate.
# Resolved on first use so the warning prints once, not once per candidate IP.
WHITELIST_TRUSTED=unknown
PROXY_RANGES_TRUSTED=unknown

# O6: sources the admin explicitly ACCEPTs in iptables. Our nft chain runs ahead
# of the iptables table, so without this we would silently override them.
IPT_ACCEPT_SOURCES=unknown

# Scratch files this process owns, so cleanup removes exactly its own (the old
# blanket "rm -f /tmp/botsurgeon_basic_*" also deleted other instances' files).
DEMO_LOG_FILE=""

# ==============================================================================
# SECTION 2: EXTERNAL CONFIGURATION FILE
# ==============================================================================

# M17: PROXY_MIN_PATHS was missing from this list while being documented in the
# generated config, so setting it produced "Unknown config key ignored" and the
# default silently stood. PROXY_HEURISTIC is new in 1.0.5.
ALLOWED_CONFIG_KEYS="CONNECTION_THRESHOLD AUTO_BLOCK_THRESHOLD LOG_THREAT_THRESHOLD COOLDOWN_SECONDS NUM_LINES DOMLOG_LINES THROTTLE_CPU THROTTLE_IO THROTTLE_EP LOG_FILE LOG_MAX_SIZE_MB ACCESS_LOG LITESPEED_LOG NGINX_LOG WHITELIST_FILE MAX_BLOCKS_PER_RUN DOMLOG_MAX_DOMAINS MONITORED_PORTS MAX_RUNTIME PROXY_UA_THRESHOLD PROXY_MIN_TOTAL PROXY_MIN_REQS_PER_UA PROXY_MIN_PATHS PROXY_HEURISTIC PROXY_RANGES_FILE BLOCK_TTL_HOURS"

# L8: config-load chatter is suppressed for informational/one-shot commands
# (--help/--status/--generate-config/etc.) so their output stays clean.
# O13: buffer early notices so they can be replayed to LOG_FILE once available.
CONFIG_QUIET=false
declare -a CONFIG_NOTICES_BUFFER=()
_config_notice() {
    local msg="$*"
    CONFIG_NOTICES_BUFFER+=("$msg")
    [ "$CONFIG_QUIET" = true ] || echo "$msg"
}

# M2: is a file safe for root to TRUST the contents of?
#
# Root-owned is not enough. The old check looked only at the last permission
# digit, so mode 664 passed as "not world-writable" while being GROUP-writable —
# and this config sets LOG_FILE, which log_message appends to and rotate_log
# renames, both as root. That is an arbitrary-file append and an arbitrary-file
# rename handed to anyone in that group.
#
# It also matters that the containing DIRECTORY is safe: a writable directory
# lets an attacker replace the file wholesale, and no per-file check can see it.
#
# Returns 0 = safe to trust, 1 = do not trust (reason printed by the caller's
# _config_notice, so one-shot commands stay quiet).
_file_is_root_safe() {
    local path="$1" label="${2:-File}" owner perms dir dperms downer

    [ -e "$path" ] || return 1

    # OPT-6: reject symlinks (symlinks to root-owned files must not pass)
    if [ -L "$path" ]; then
        _config_notice "⚠️  WARNING: $label is a symbolic link - not trusting it: $path"
        return 1
    fi

    owner=$(stat -c%u "$path" 2>/dev/null || stat -f%u "$path" 2>/dev/null)
    perms=$(stat -c%a "$path" 2>/dev/null || stat -f%Lp "$path" 2>/dev/null)

    # O10: an empty result means stat is missing or failed — that is a distinct
    # condition from "wrong owner", and reporting it as bad ownership sent
    # admins looking for a permissions problem that did not exist.
    if [ -z "$owner" ] || [ -z "$perms" ]; then
        _config_notice "⚠️  WARNING: cannot verify permissions on $path ('stat' unavailable) - not trusting it"
        return 1
    fi

    if [ "$owner" != "0" ]; then
        _config_notice "⚠️  WARNING: $label not owned by root (owner uid: $owner) - skipping: $path"
        return 1
    fi

    [[ "$perms" =~ ^[0-7]{3,6}$ ]] || {
        _config_notice "⚠️  WARNING: cannot parse mode '$perms' on $path - not trusting it"
        return 1
    }

    # Reject group- OR world-writable. 8# because a mode string IS octal: with
    # base 10 the arithmetic is meaningless (decimal 755 & 18 is non-zero, so a
    # perfectly normal 755 directory would be reported as group-writable).
    if [ $(( 8#$perms & 8#22 )) -ne 0 ]; then
        _config_notice "⚠️  WARNING: $label is group- or world-writable (mode $perms) - skipping: $path"
        _config_notice "    Fix with: chown root:root \"$path\" && chmod 644 \"$path\""
        return 1
    fi

    dir="$(dirname "$path")"
    downer=$(stat -c%u "$dir" 2>/dev/null || stat -f%u "$dir" 2>/dev/null)
    dperms=$(stat -c%a "$dir" 2>/dev/null || stat -f%Lp "$dir" 2>/dev/null)
    if [ -z "$downer" ] || [ -z "$dperms" ]; then
        _config_notice "⚠️  WARNING: cannot verify permissions on directory $dir ('stat' unavailable) - not trusting $label"
        return 1
    fi

    [[ "$dperms" =~ ^[0-7]{3,6}$ ]] || {
        _config_notice "⚠️  WARNING: cannot parse mode '$dperms' on directory $dir - not trusting $label"
        return 1
    }

    if [ "$downer" != "0" ] || [ $(( 8#$dperms & 8#22 )) -ne 0 ]; then
        _config_notice "⚠️  WARNING: directory $dir is writable by non-root - not trusting $label"
        _config_notice "    Anyone who can write that directory can replace this file."
        return 1
    fi

    return 0
}

load_config() {
    [ -f "$CONFIG_FILE" ] || return 1
    _file_is_root_safe "$CONFIG_FILE" "Config file" || return 1

    local keys_loaded=0
    while IFS= read -r line; do
        line="${line%%#*}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [ -z "$line" ] && continue
        local key="${line%%=*}"
        local val="${line#*=}"
        # Trim whitespace around the separator. "NUM_LINES = 5000" is a natural
        # thing to write and used to be discarded as an unknown key.
        key="${key%"${key##*[![:space:]]}"}"
        val="${val#"${val%%[![:space:]]*}"}"
        val="${val#\"}"
        val="${val%\"}"
        val="${val#\'}"
        val="${val%\'}"
        case " $ALLOWED_CONFIG_KEYS " in
            *" $key "*)
                printf -v "$key" '%s' "$val"
                ((keys_loaded++))
                ;;
            *)
                _config_notice "⚠️  Unknown config key ignored: $key"
                ;;
        esac
    done < "$CONFIG_FILE"
    [ "$keys_loaded" -gt 0 ] && _config_notice "ℹ️  Config loaded: $CONFIG_FILE ($keys_loaded keys)"
    return 0
}

generate_default_config() {
    local config_dir target tmp
    config_dir="$(dirname "$CONFIG_FILE")"
    mkdir -p "$config_dir" 2>/dev/null

    # M20: refuse to write into a directory that is not root-safe.
    #
    # This runs as root and used to redirect straight onto $CONFIG_FILE (or its
    # .new sidecar) with `cat >`, which FOLLOWS SYMLINKS. If /etc/botsurgeon is
    # writable by anyone but root — a bad umask during a hurried install, a
    # restored backup, a shared-panel deployment — a local user can pre-place
    # /etc/botsurgeon/botsurgeon-basic.conf.new as a symlink to any file root
    # can reach and have this command overwrite it. The loader already refuses
    # to TRUST a file in such a directory (_file_is_root_safe); writing one
    # there was never gated at all.
    #
    # The same check on the way in and on the way out.
    if [ ! -d "$config_dir" ]; then
        echo "❌ Could not create $config_dir"
        return 1
    fi
    if ! _file_is_root_safe "$config_dir" "Config directory"; then
        echo "❌ REFUSING to write a config into $config_dir"
        echo "   It is not owned by root, or it is group-/world-writable, so anyone"
        echo "   who can write there could have pre-placed a symlink for root to"
        echo "   overwrite - and could edit the config this tool then trusts."
        echo "   Fix with: chown root:root \"$config_dir\" && chmod 755 \"$config_dir\""
        log_message "SECURITY: refused --generate-config into unsafe directory $config_dir"
        return 1
    fi

    # M6: never clobber an existing (possibly customized) config. Write to a
    # .new sidecar and let the admin diff/merge instead of losing their tuning.
    target="$CONFIG_FILE"
    if [ -e "$CONFIG_FILE" ]; then
        target="${CONFIG_FILE}.new"
        echo "ℹ️  Existing config found — writing defaults to $target (not overwriting)."
        echo "    Compare: diff \"$CONFIG_FILE\" \"$target\""
    fi

    # M20: never redirect onto the target name. mktemp creates a fresh regular
    # file with a unique name and mode 600 - it cannot be a pre-planted symlink
    # - and the rename that publishes it is atomic, so no reader ever sees a
    # half-written config either.
    tmp=$(mktemp "${config_dir}/.botsurgeon-conf.XXXXXXXXXX" 2>/dev/null) || {
        echo "❌ Could not create a temporary file in $config_dir"
        return 1
    }

    cat > "$tmp" << 'CONFEOF'
# ==============================================================================
# BotSurgeon-Basic Configuration File
# /etc/botsurgeon/botsurgeon-basic.conf
# ==============================================================================
# Uncomment and modify values to override defaults.
# Only KEY=value lines are parsed. Shell commands are NOT executed.
# ==============================================================================

# --- Thresholds ---
# CONNECTION_THRESHOLD=50       # Connections per IP to trigger alert
# AUTO_BLOCK_THRESHOLD=100      # Connections to trigger auto-block
# LOG_THREAT_THRESHOLD=60       # Access log threat score to auto-block (0-100)
# COOLDOWN_SECONDS=1800         # Seconds before same IP can be re-blocked
# NUM_LINES=10000               # Main log lines to analyze
# DOMLOG_LINES=5000             # Per-domain log lines to analyze

# --- Resource Throttling ---
# THROTTLE_CPU=30               # CPU throttle (%)
# THROTTLE_IO=512               # IO throttle (KB/s)
# THROTTLE_EP=15                # Entry processes limit

# --- Log Settings ---
# LOG_FILE="/var/log/botsurgeon/botsurgeon-basic.log"
# LOG_MAX_SIZE_MB=25            # Rotate logs when size exceeds this

# --- Custom Log Paths (override auto-detection) ---
# ACCESS_LOG="/etc/apache2/logs/access_log"
# LITESPEED_LOG="/usr/local/lsws/logs/access.log"
# NGINX_LOG="/var/log/nginx/access.log"

# --- Monitored Ports ---
# MONITORED_PORTS="80 443 8080"  # Only count/block connections to these LOCAL ports
                                 # (space-separated). Add 8443 etc. if you serve HTTPS
                                 # on non-standard ports.

# --- Block Lifetime ---
# How long a block lasts before lifting itself, in hours. Expiry is what keeps a
# false positive from becoming a permanent outage. nftables sets, CSF temp bans
# and firewalld rules expire natively; iptables/hosts.deny are swept each run.
# Set to 0 for permanent blocks if you would rather review every one by hand.
# BLOCK_TTL_HOURS=24

# --- Safety Limits ---
# MAX_BLOCKS_PER_RUN=20          # Maximum IPs to block per cron cycle (safety net)
# DOMLOG_MAX_DOMAINS=50          # Max domain logs to scan per cycle
# MAX_RUNTIME=300               # Hard time limit (s) for one --auto run; watchdog
                                # kills the process if exceeded so it can't wedge cron

# --- Whitelist File ---
# One IP or CIDR per line. Must be owned by root and not group/world-writable,
# or it is ignored (anyone who can write it can exempt an attacker).
# An "allow everything" range (0.0.0.0/0 or ::/0) is refused and reported -
# it would silently turn all blocking off.
# WHITELIST_FILE="/etc/botsurgeon/whitelist.conf"

# --- CDN / Reverse-Proxy Safety ---
# If your sites sit behind Cloudflare, Sucuri, a load balancer or any reverse
# proxy WITHOUT mod_remoteip, every log line shows the edge IP instead of the
# visitor's. Blocking one of those takes every site behind it offline.
#
# BotSurgeon detects this automatically: an address presenting at least this
# many DISTINCT user agents, while serving mostly successful requests, is
# treated as a shared front end and is never blocked. Lower = more cautious.
# Set to 0 to disable the heuristic entirely.
# PROXY_UA_THRESHOLD=8
#
# UA diversity on its own is cheap to fake, so two further conditions must also
# hold. A real edge sends a lot of traffic and each of its user agents recurs
# (real browsers come back); a client rotating a UA list sends about one request
# per agent. Raise these to make the exemption harder to counterfeit; lower them
# only if a known-good edge is being missed.
# PROXY_MIN_TOTAL=200           # minimum requests in the window
# PROXY_MIN_REQS_PER_UA=5       # average requests per distinct user agent
#
# It must also look like someone browsing a SITE rather than hammering one URL:
# a real edge pulls many different paths. Raise this only if you are being
# targeted by a patient attacker - setting it too high un-exempts genuine edges,
# and blocking a CDN takes every site behind it offline.
# PROXY_MIN_PATHS=3             # distinct paths required
#
# For a deterministic guarantee, list your edge ranges (one per line, plain IPs
# or CIDR, IPv4 and IPv6) in this file — they are then whitelisted outright:
# PROXY_RANGES_FILE="/etc/botsurgeon/proxies.conf"

# May the heuristic REFUSE a block, or only advise?
#   auto      (default) advisory once PROXY_RANGES_FILE lists any range,
#             enforce while it does not
#   enforce   the heuristic can refuse a block. Note the trade-off: an attacker
#             who serves ~200 mostly-successful requests across 8 user agents
#             and 3 paths earns the same exemption a real CDN edge gets
#   advisory  the heuristic only warns; blocks proceed. Declare your edges in
#             PROXY_RANGES_FILE first, or you risk blocking a real PoP
#   off       do not run the detection at all
# PROXY_HEURISTIC=auto
CONFEOF

    # M3: the here-doc above can fail (no root, read-only /etc, full disk) and
    # the script would still print "✅ Config written" — an admin then edits a
    # file that does not exist and wonders why nothing changes.
    if [ ! -s "$tmp" ]; then
        rm -f "$tmp" 2>/dev/null
        echo "❌ Could not write $target"
        echo "   Check that you are root and that $config_dir is writable."
        return 1
    fi

    # Mode before the rename, so the file is never briefly readable at 600 by
    # nobody or published at mktemp's mode.
    chmod 640 "$tmp" 2>/dev/null
    # M20: -T is not portable, so guard the one case a rename could still land
    # somewhere unexpected — the target having become a symlink since the check.
    if [ -L "$target" ]; then
        rm -f "$tmp" 2>/dev/null
        echo "❌ REFUSING to write: $target is a symbolic link."
        echo "   Remove it and re-run; a config this tool trusts must be a real file."
        log_message "SECURITY: refused --generate-config onto symlink $target"
        return 1
    fi
    if ! mv -f "$tmp" "$target" 2>/dev/null; then
        rm -f "$tmp" 2>/dev/null
        echo "❌ Could not write $target"
        return 1
    fi
    echo "✅ Config written: $target"
    [ "$target" = "$CONFIG_FILE" ] && echo "   Edit it to customize thresholds and log paths."
    return 0
}

# Silence config-load chatter for informational/one-shot commands (L8)
case " $* " in
    *" --help "*|*" --status "*|*" --generate-config "*|*" --list-blocked "*|*" --disable "*|*" --enable "*|*" --unblock "*|*" --uninstall "*|*" --whitelist "*)
        CONFIG_QUIET=true ;;
esac

# M4: --unblock exits inside parse_arguments, so a trailing --whitelist would
# never be seen in order. Same pre-scan reasoning as --force below.
UNBLOCK_WHITELIST=false
case " $* " in
    *" --whitelist "*)
        UNBLOCK_WHITELIST=true
        case " $* " in
            *" --unblock "*) ;;
            *) echo "⚠️  --whitelist only applies to --unblock (it also adds the IP to your whitelist file) - ignoring." >&2 ;;
        esac
        ;;
esac

# --uninstall exits inside parse_arguments, so a trailing --force would never be
# seen in order. Pre-scan for it (same reason CONFIG_QUIET is resolved up here).
UNINSTALL_FORCE=false
case " $* " in
    *" --force "*)
        UNINSTALL_FORCE=true
        # --force only means "skip the uninstall confirmation". Accepting it
        # silently elsewhere would let someone believe it forced something else
        # (a block, a scan) when it did nothing at all.
        case " $* " in
            *" --uninstall "*) ;;
            *) echo "⚠️  --force only applies to --uninstall (it skips that confirmation prompt) - ignoring." >&2 ;;
        esac
        ;;
esac

# Load external config (overrides defaults above)
load_config

# Validate numeric config values (prevent bash errors on bad config)
# OPT-4: strictly match ^0$|^[1-9][0-9]*$ to avoid bash leading-zero octal trap
_validate_int() {
    local val="$1" min="$2" max="$3" default="$4"
    if ! [[ "$val" =~ ^(0|[1-9][0-9]{0,9})$ ]] || [ "$val" -lt "$min" ] || [ "$val" -gt "$max" ]; then
        echo "$default"
    else
        echo "$val"
    fi
}
CONNECTION_THRESHOLD=$(_validate_int "$CONNECTION_THRESHOLD" 5 10000 50)
AUTO_BLOCK_THRESHOLD=$(_validate_int "$AUTO_BLOCK_THRESHOLD" 10 50000 100)
LOG_THREAT_THRESHOLD=$(_validate_int "$LOG_THREAT_THRESHOLD" 10 100 60)
COOLDOWN_SECONDS=$(_validate_int "$COOLDOWN_SECONDS" 60 86400 1800)
NUM_LINES=$(_validate_int "$NUM_LINES" 100 100000 10000)
DOMLOG_LINES=$(_validate_int "$DOMLOG_LINES" 100 50000 5000)
MAX_BLOCKS_PER_RUN=$(_validate_int "$MAX_BLOCKS_PER_RUN" 1 500 20)
DOMLOG_MAX_DOMAINS=$(_validate_int "$DOMLOG_MAX_DOMAINS" 5 500 50)
LOG_MAX_SIZE_MB=$(_validate_int "$LOG_MAX_SIZE_MB" 1 1000 25)
MAX_RUNTIME=$(_validate_int "$MAX_RUNTIME" 30 3600 300)
# 0 disables CDN/proxy detection entirely, so the floor is 0 rather than 1.
PROXY_UA_THRESHOLD=$(_validate_int "$PROXY_UA_THRESHOLD" 0 1000 8)
# C2: corroborating evidence for the proxy exemption. Floors are deliberately
# above 1 — a "1 request per user agent" proxy is precisely the fake we reject.
PROXY_MIN_TOTAL=$(_validate_int "$PROXY_MIN_TOTAL" 20 1000000 200)
PROXY_MIN_REQS_PER_UA=$(_validate_int "$PROXY_MIN_REQS_PER_UA" 2 10000 5)
# M2: 1 would mean "any single path counts", i.e. no gate at all — the floor is
# 2 so the setting cannot be silently neutered by a typo.
PROXY_MIN_PATHS=$(_validate_int "$PROXY_MIN_PATHS" 2 10000 3)
# M17: an enum, not a number. A typo must not silently become "off".
case "$PROXY_HEURISTIC" in
    auto|enforce|advisory|off) ;;
    *)
        _config_notice "⚠️  PROXY_HEURISTIC='$PROXY_HEURISTIC' is not one of auto|enforce|advisory|off - using auto."
        PROXY_HEURISTIC=auto
        ;;
esac
# 0 = permanent blocks (no expiry); otherwise 1 hour .. 1 year.
BLOCK_TTL_HOURS=$(_validate_int "$BLOCK_TTL_HOURS" 0 8760 24)

# True when blocks are meant to expire on their own.
_ttl_enabled() { [ "${BLOCK_TTL_HOURS:-0}" -gt 0 ]; }
_ttl_seconds() { echo $(( 10#${BLOCK_TTL_HOURS:-0} * 3600 )); }
# L3: throttle values feed lvectl — validate them like the other numerics so a
# bad config value can't reach the command line.
THROTTLE_CPU=$(_validate_int "$THROTTLE_CPU" 1 100 30)
THROTTLE_IO=$(_validate_int "$THROTTLE_IO" 1 1048576 512)
THROTTLE_EP=$(_validate_int "$THROTTLE_EP" 1 1000 15)

# N10: validate the monitored port list instead of silently mangling it.
#
# The old sanitizer stripped every non-digit, so the very natural "80,443"
# collapsed into the single nonexistent port "80443". Nothing ever matched, so
# connection-based detection AND blocking silently stopped, and every run
# cheerfully reported "No connection-based threats above threshold".
#
# Commas, semicolons and tabs are now accepted as separators (people write port
# lists that way), each token is range-checked, and anything unusable is
# reported rather than swallowed.
_sanitize_monitored_ports() {
    local raw="$1" token out="" bad=""
    local normalized
    normalized=$(printf '%s' "$raw" | tr ',;\t' '   ')
    for token in $normalized; do
        if [[ "$token" =~ ^[0-9]+$ ]] && [ "$token" -ge 1 ] && [ "$token" -le 65535 ]; then
            case " $out " in
                *" $token "*) ;;                      # de-duplicate
                *) out="${out}${out:+ }${token}" ;;
            esac
        else
            bad="${bad}${bad:+ }${token}"
        fi
    done

    # Warnings go to STDERR: this function's stdout IS the port list (it is used
    # in a command substitution), so anything printed there would be captured
    # into MONITORED_PORTS itself and produce exactly the kind of garbage value
    # this validation exists to prevent.
    if [ -n "$bad" ]; then
        _config_notice "⚠️  MONITORED_PORTS: ignoring invalid entr(ies): $bad" >&2
        _config_notice "    Use space- or comma-separated port numbers, e.g. \"80 443 8080\"" >&2
    fi
    if [ -z "$out" ]; then
        [ -n "$raw" ] && _config_notice "⚠️  MONITORED_PORTS had no usable ports - falling back to \"80 443 8080\"" >&2
        out="80 443 8080"
    fi
    printf '%s' "$out"
}
MONITORED_PORTS=$(_sanitize_monitored_ports "$MONITORED_PORTS")

# ==============================================================================
# SECTION 2A: IP VALIDATION (needed early for --unblock)
# ==============================================================================

is_ipv4() {
    local ip="$1"
    # N16: each octet is a single digit, or 2-3 digits that do not start with 0.
    # Leading zeros are rejected outright — they are ambiguous (some stacks read
    # "010" as octal 8) and, worse, they used to be accepted by ACCIDENT: bash
    # parses 08/09 as invalid octal, so (( 08 > 255 )) raised an arithmetic error
    # whose non-zero status made the '&& return 1' guard silently skip, letting
    # the malformed address through while printing a bash error to stderr.
    # 10# below forces base-10 regardless, as defence in depth.
    [[ "$ip" =~ ^([0-9]|[1-9][0-9]{1,2})\.([0-9]|[1-9][0-9]{1,2})\.([0-9]|[1-9][0-9]{1,2})\.([0-9]|[1-9][0-9]{1,2})$ ]] || return 1
    local i
    for i in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"; do
        (( 10#$i > 255 )) && return 1
    done
    return 0
}

# Count the hextets in a colon-separated run, validating each one.
# An EMPTY run is legal and counts zero - that is what sits either side of a
# "::". The count lands in _IPV6_N.  Helper for is_ipv6 only.
_ipv6_hextets() {
    local run="$1" part
    _IPV6_N=0
    [ -z "$run" ] && return 0
    while [ -n "$run" ]; do
        part="${run%%:*}"
        [[ "$part" =~ ^[0-9a-fA-F]{1,4}$ ]] || return 1
        _IPV6_N=$((_IPV6_N + 1))
        [ "$part" = "$run" ] && break        # last hextet, no colon remains
        run="${run#*:}"
    done
    return 0
}

# M4 (1.0.4): the old test was a loose shape check, not a parse. It required
# two or more colons and nothing else, so structurally invalid addresses were
# accepted as valid: "2001:db8:1" and "a:b:c" (too few groups, no compression)
# and "1::2::3" (two compression runs) all passed. Those then flowed into
# _ipt_cmd - which routes ANY token containing a colon to ip6tables - and into
# the nft set element string, where the kernel rejects them, so the block
# silently failed on that layer while the caller was told it succeeded. That is
# the same false-success class this release exists to remove.
#
# This is a real parse: at most one "::", exactly 8 hextets without it and at
# most 7 with it, each hextet 1-4 hex digits. Dotted IPv4-in-IPv6 forms and
# zone indices (%eth0) stay rejected, as before - the character-class gate on
# the second line has always excluded them, and widening what reaches a
# firewall command is not something to do incidentally.
is_ipv6() {
    local ip="$1" head tail n_head
    [[ "$ip" == *:* ]] || return 1
    [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] || return 1
    [[ "$ip" == *:::* ]] && return 1                      # ":::" or longer
    # A single leading/trailing colon is only legal as part of "::".
    [[ "$ip" == :* && "$ip" != ::* ]] && return 1
    [[ "$ip" == *: && "$ip" != *:: ]] && return 1

    if [[ "$ip" == *::* ]]; then
        head="${ip%%::*}"
        tail="${ip#*::}"
        [[ "$tail" == *::* ]] && return 1                 # more than one "::"
        _ipv6_hextets "$head" || return 1
        n_head=$_IPV6_N
        _ipv6_hextets "$tail" || return 1
        # "::" stands for at least one all-zero group, so the explicit groups
        # can never total 8.
        [ $(( n_head + _IPV6_N )) -le 7 ] || return 1
        return 0
    fi

    _ipv6_hextets "$ip" || return 1
    [ "$_IPV6_N" -eq 8 ] || return 1
    return 0
}

is_valid_ip() {
    is_ipv4 "$1" || is_ipv6 "$1"
}

# Escape an IP address for use as a WHOLE-TOKEN regex: dots become literal so
# that "1.2.3.4" cannot accidentally match "1.2.3.45" or "1x2x3x4". Colons in
# IPv6 are already literal in regex. Used for firewall-rule and file matching.
_ip_regex() {
    printf '%s' "${1//./\\.}"
}

# ==============================================================================
# SECTION 2A-bis: IPTABLES RULE IDENTITY  (C1)
# ==============================================================================
# The single most damaging bug in 1.0.2: rules were ADDED as
#
#     iptables -I INPUT -s IP -j DROP -m comment --comment "BotSurgeon-Basic: ..."
#
# but CHECKED and DELETED as
#
#     iptables -C INPUT -s IP -j DROP
#
# iptables -C and -D match the ENTIRE rule specification, match extensions
# included. A rule carrying -m comment is simply not the same rule as one
# without, so the check could never find what the script itself had just added.
# Verified on AlmaLinux 9 / iptables 1.8.10 (nf_tables):
#
#     -C without comment  -> exit 1   (rule exists, reported missing)
#     -C with comment     -> exit 0
#     -D without comment  -> exit 1   (rule survives the delete)
#     3 guarded runs      -> 3 duplicate rules
#
# Consequences were: "❌ iptables: failed" printed over a live block, a duplicate
# DROP appended on every re-block, _expire_one_ip never matching (so iptables
# blocks outlived their TTL forever), and --unblock reporting "removed from all
# layers" while the rule stayed in place.
#
# The fix is to give the rule an identity the query side can reproduce exactly.
# The comment stays — it is what makes a rule attributable in `iptables -S` and
# what --uninstall finds ours by — but it is now a CONSTANT tag instead of the
# per-block reason text. A constant can be repeated verbatim in -C and -D; a
# reason string ("score 80/100, 12 suspicious requests...") cannot, because
# nothing at expiry or unblock time knows what it said.
#
# The full reason still lives in blocked_ips.log and the expiry journal, which
# are the records an operator actually reads and which survive a firewall flush.
#
# _ipt_cmd  : the right binary for the address family
# _ipt_has  : is our rule present? (exact spec match, tag included)
# _ipt_add  : add it if absent, idempotently
# _ipt_del  : remove every copy, including the variable-comment rules <=1.0.2
IPT_TAG="BotSurgeon-Basic"

# M1 (1.0.4): attribution for UNTAGGED rules.
#
# _ipt_add falls back to a bare "-s IP -j DROP" when the comment match is
# unavailable, and a bare rule is byte-identical whether we wrote it or the
# admin did. _ipt_del therefore cannot tell them apart by inspection, so we
# record the addresses WE blocked without a tag and consult that on the way out.
# Lives beside the cooldown and expiry journals and carries the same trust
# assumption: anyone who can write $DATA_DIR already controls those two.
IPT_BARE_FILE="$DATA_DIR/bare_rules.dat"

_ipt_bare_is_ours() {
    [ -f "$IPT_BARE_FILE" ] || return 1
    grep -qxF -- "$1" "$IPT_BARE_FILE" 2>/dev/null
}

_ipt_bare_mark() {
    local ip="$1"
    _ipt_bare_is_ours "$ip" && return 0
    mkdir -p "$DATA_DIR" 2>/dev/null
    printf '%s\n' "$ip" >> "$IPT_BARE_FILE" 2>/dev/null
    return 0
}

_ipt_bare_clear() {
    local ip="$1" ip_re
    [ -f "$IPT_BARE_FILE" ] || return 0
    ip_re=$(_ip_regex "$ip")
    sed -i "/^${ip_re}\$/d" "$IPT_BARE_FILE" 2>/dev/null
    return 0
}

_ipt_cmd() {
    if is_ipv6 "$1"; then printf '%s' "ip6tables"; else printf '%s' "iptables"; fi
}

_ipt_has() {
    local ip="$1" cmd
    cmd=$(_ipt_cmd "$ip")
    command -v "$cmd" >/dev/null 2>&1 || return 1
    $cmd -C INPUT -s "$ip" -j DROP -m comment --comment "$IPT_TAG" 2>/dev/null && return 0
    # Also accept a bare rule: an operator may have added one by hand, and
    # 1.0.2's insert could land without the comment module on odd builds.
    $cmd -C INPUT -s "$ip" -j DROP 2>/dev/null
}

_ipt_add() {
    local ip="$1" cmd
    cmd=$(_ipt_cmd "$ip")
    command -v "$cmd" >/dev/null 2>&1 || return 1
    # M1: returning here deliberately does NOT mark the address. The rule that
    # already exists may be the ADMIN'S bare DROP, and claiming it as ours would
    # licence the TTL sweep to delete it later.
    _ipt_has "$ip" && return 0
    # If the comment match is unavailable, fall back to a bare rule rather than
    # adding nothing — _ipt_has accepts both forms.
    if $cmd -I INPUT -s "$ip" -j DROP -m comment --comment "$IPT_TAG" 2>/dev/null; then
        :
    elif $cmd -I INPUT -s "$ip" -j DROP 2>/dev/null; then
        # M1: no comment module on this host, so the rule we just wrote is
        # indistinguishable from a hand-made one. Record that it is ours.
        _ipt_bare_mark "$ip"
    else
        return 1
    fi
    _ipt_has "$ip"
}

# Remove our rule from a chain, in every form it may exist in:
#   * the plain spec this version writes (exact -D, repeated for duplicates);
#   * the commented rules 1.0.2 and earlier wrote, which a spec -D cannot touch.
#     Those are found by rule NUMBER from --line-numbers, which is exact and
#     needs no re-parsing of an -S line (the unquoted "${rule/-A/-D}" in the old
#     uninstall path shredded any comment containing spaces).
#
# Scope matters, because deletion actually works now. The automatic TTL sweep
# must only lift OUR blocks — tearing down a rule Fail2Ban or the admin put
# there would be a new bug of exactly the kind this release is fixing. So:
#
#   scope "ours" (default, used by expire_blocks): plain spec + legacy rules
#                 tagged BotSurgeon-Basic in their comment.
#   scope "all"  (used by --unblock): also any other exact-source DROP, because
#                 the operator explicitly asked for this address to come back.
#
# Source fields are compared as exact STRINGS, not regexes: awk -v processes
# escape sequences, so a dot-escaped pattern would decay to "any character" and
# 203.0.113.9 could match 203X0Y113Z9. String equality also means a /24 range
# rule is never mistaken for a single-host one.
# Numbers are deleted highest-first so earlier ones stay valid.
# Returns 0 if anything was removed.
_ipt_del() {
    local ip="$1" chain="${2:-INPUT}" scope="${3:-ours}" cmd removed=1 guard=0 nums n
    cmd=$(_ipt_cmd "$ip")
    command -v "$cmd" >/dev/null 2>&1 || return 1

    # 1. exact specs we can reproduce: the tagged form 1.0.3+ writes, and a bare
    #    form. Repeated, because 1.0.2's broken guard could leave duplicates.
    while $cmd -C "$chain" -s "$ip" -j DROP -m comment --comment "$IPT_TAG" 2>/dev/null; do
        $cmd -D "$chain" -s "$ip" -j DROP -m comment --comment "$IPT_TAG" 2>/dev/null || break
        removed=0
        guard=$((guard + 1))
        [ "$guard" -gt 100 ] && break
    done
    # M1 (1.0.4): the bare form used to be deleted unconditionally, for BOTH
    # scopes. That silently defeated the whole "ours vs all" contract documented
    # above: an untagged "-s IP -j DROP" is byte-identical whether we wrote it or
    # the admin did, so every TTL sweep tore down the operator's own permanent
    # block on any address that had also passed through our expiry journal —
    # and on iptables-persist hosts _persist_iptables then made the deletion
    # durable. Scope now decides who may remove an unattributable rule:
    #
    #   scope=all  (--unblock)  the operator named this address explicitly.
    #   scope=ours (TTL sweep)  only if _ipt_add recorded writing it, which
    #                           happens solely on hosts with no comment match.
    #
    # Note this cannot be fixed by dropping the bare loop from "ours": on a host
    # without the comment module our OWN blocks are bare, and skipping them
    # would leave every one of them in place forever — a TTL that never fires.
    # Attribution is the fix, not scope alone.
    if [ "$scope" = "all" ] || _ipt_bare_is_ours "$ip"; then
        while $cmd -C "$chain" -s "$ip" -j DROP 2>/dev/null; do
            $cmd -D "$chain" -s "$ip" -j DROP 2>/dev/null || break
            removed=0
            guard=$((guard + 1))
            [ "$guard" -gt 100 ] && break
        done
    fi

    # 2. commented rules, by line number
    nums=$($cmd -L "$chain" -n --line-numbers 2>/dev/null | \
           awk -v ip="$ip" -v scope="$scope" '
               $1 ~ /^[0-9]+$/ && $2 == "DROP" {
                   if (scope != "all" && index($0, "BotSurgeon-Basic") == 0) next
                   if ($5 == ip) print $1
               }' | sort -rn)
    for n in $nums; do
        $cmd -D "$chain" "$n" 2>/dev/null && removed=0
    done

    # The rule is gone, so our claim on it is spent. Leaving the marker would let
    # a LATER admin-authored bare DROP on the same address inherit our
    # attribution and be swept by the next expiry. Clear if removed or absent.
    if [ "$removed" -eq 0 ] || ! _ipt_has "$ip"; then
        _ipt_bare_clear "$ip"
    fi

    return "$removed"
}

# ==============================================================================
# SECTION 2B: RECOVERY & STATUS COMMANDS
# ==============================================================================
# These run before the main flow and exit immediately.

DISABLE_FLAG="/etc/botsurgeon/.disabled"

# O4: emit the block history as tab-delimited records regardless of vintage.
# 1.0.3+ writes tabs (a "|" can occur in an attacker-chosen request path, which
# used to shift every later column when the history was read back); <=1.0.2
# wrote "|". Converting on read keeps old history displayable as-is.
_block_history() {
    [ -f "$DATA_DIR/blocked_ips.log" ] || return 1
    awk '{ if (index($0, "\t") == 0) gsub(/\|/, "\t"); print }' "$DATA_DIR/blocked_ips.log" 2>/dev/null
}

unblock_ip() {
    local ip="$1"
    local add_whitelist="${2:-false}"
    local layers_cleared=0

    if [ "$(id -u)" -ne 0 ]; then
        echo "❌ --unblock requires root privileges"
        exit 1
    fi

    if ! is_valid_ip "$ip"; then
        echo "❌ Invalid IP address: $ip"
        exit 1
    fi

    # M3: this mutates the cooldown file and the expiry journal, both of which a
    # concurrent --auto run rewrites wholesale (init_cooldown / expire_blocks do
    # tmp-then-mv). Without the lock the mv silently discards our edit, or we
    # rewrite a file the other process is appending to. This is the one moment —
    # an operator undoing a false positive mid-incident — when losing the edit
    # matters most, so take the same lock the scan takes. Wait rather than fail:
    # never refuse to unblock because a scan happens to be mid-run.
    acquire_lock 15
    if [ "$LOCK_HELD" != true ] && [ "$LOCK_STATE" = "contested" ]; then
        echo "⚠️  A scan is holding the lock - proceeding anyway after 15s."
        echo "   If the result looks incomplete, re-run this command once the scan ends."
        log_message "WARNING: recovery command proceeded without the lock"
    fi

    echo "🔓 Removing $ip from all block layers..."

    # nftables. Two things to clear:
    #   1. our named sets (N4) — an exact set operation, no matching involved;
    #   2. legacy per-IP rules, which is how Basic <=1.0.1 blocked and how Pro
    #      still blocks, in both the input and output chains.
    if command -v nft >/dev/null 2>&1 && nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
        local ip_re removed=0 chain h handles
        _nft_unblock_ip "$ip" && removed=1
        ip_re=$(_ip_regex "$ip")
        for chain in input output; do
            nft list chain inet "$NFT_TABLE" "$chain" >/dev/null 2>&1 || continue
            handles=$(nft -a list chain inet "$NFT_TABLE" "$chain" 2>/dev/null | \
                grep -E "(saddr|daddr) ${ip_re}[[:space:]]" | \
                awk '/handle [0-9]+/{for(i=1;i<=NF;i++) if($i=="handle") print $(i+1)}')
            for h in $handles; do
                nft delete rule inet "$NFT_TABLE" "$chain" handle "$h" 2>/dev/null && removed=1
            done
        done
        if [ "$removed" -eq 1 ]; then
            echo "   ✅ nftables: removed"
            layers_cleared=$((layers_cleared + 1))
        else
            echo "   - nftables: not found"
        fi
    fi

    # CSF — clear BOTH lists. Blocks now land in csf.tempban (csf -td), which
    # 'csf -dr' does not touch; older permanent denies still need 'csf -dr'.
    if command -v csf >/dev/null 2>&1; then
        local csf_removed=0
        csf -tr "$ip" >/dev/null 2>&1 && csf_removed=1     # temporary ban
        csf -dr "$ip" >/dev/null 2>&1 && csf_removed=1     # permanent deny
        if [ "$csf_removed" -eq 1 ]; then
            echo "   ✅ CSF: removed"
            layers_cleared=$((layers_cleared + 1))
        else
            echo "   - CSF: not found"
        fi
    fi

    # firewalld.
    # N22: this reported "removed" unconditionally, even when no rule existed —
    # the one layer that lied about its result. Now it reports what happened.
    #
    # Both scopes must be cleared: expiring blocks are RUNTIME rich rules (added
    # with --timeout, which cannot be combined with --permanent), while blocks
    # made in permanent mode, or by pre-1.0.2 versions, live in the permanent
    # config. Removing from both covers either origin.
    #
    # Deliberately NO --reload here: reload discards ALL runtime rules, which
    # would wipe every other IP's still-valid timeout block. Runtime removal is
    # already immediate, and permanent removal needs no reload to stop applying.
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
        local fw_removed=0 fam
        for fam in ipv4 ipv6; do
            firewall-cmd --remove-rich-rule="rule family=$fam source address=\"$ip\" drop" \
                >/dev/null 2>&1 && fw_removed=1
            firewall-cmd --permanent --remove-rich-rule="rule family=$fam source address=\"$ip\" drop" \
                >/dev/null 2>&1 && fw_removed=1
        done
        if [ "$fw_removed" -eq 1 ]; then
            echo "   ✅ firewalld: removed"
            layers_cleared=$((layers_cleared + 1))
        else
            echo "   - firewalld: not found"
        fi
    fi

    # iptables / ip6tables.
    # C1: the old "-D INPUT -s $ip -j DROP" could not delete the rules this tool
    # created, because they carried "-m comment" and -D matches the whole spec.
    # It reported nothing, and the closing line still claimed every layer was
    # cleared. _ipt_del handles both the plain and the legacy commented form,
    # in "all" scope because the operator explicitly asked for this address.
    local ipt_cleared=0
    if _ipt_del "$ip" INPUT all; then
        echo "   ✅ $(_ipt_cmd "$ip") INPUT: removed"
        ipt_cleared=1
    fi
    # Legacy OUTPUT rules from older versions (destination match, not source).
    local ocmd
    ocmd=$(_ipt_cmd "$ip")
    if command -v "$ocmd" >/dev/null 2>&1; then
        local oguard=0
        while $ocmd -C OUTPUT -d "$ip" -j DROP 2>/dev/null; do
            $ocmd -D OUTPUT -d "$ip" -j DROP 2>/dev/null || break
            ipt_cleared=1
            oguard=$((oguard + 1))
            [ "$oguard" -gt 100 ] && break
        done
    fi
    if [ "$ipt_cleared" -eq 1 ]; then
        layers_cleared=$((layers_cleared + 1))
        # M13: persist the DELETION.
        #
        # The block path calls _persist_iptables after a direct-iptables add;
        # the unblock path never did. On an iptables-persist host the rule was
        # therefore still in /etc/sysconfig/iptables (or rules.v4) and came
        # straight back at the next reboot — so an operator's emergency undo
        # silently expired, at the worst possible time, with no message saying
        # it had. Same manager gate as the block path: when CSF/firewalld/
        # Imunify360 owns the ruleset it handles its own persistence, and
        # snapshotting theirs into /etc/sysconfig/iptables would fight them.
        if ! _has_firewall_manager; then
            _persist_iptables
        fi
    else
        echo "   - iptables: not found"
    fi

    # Imunify360
    if command -v imunify360-agent >/dev/null 2>&1; then
        if imunify360-agent blacklist ip delete "$ip" 2>/dev/null; then
            echo "   ✅ Imunify360: removed"
            layers_cleared=$((layers_cleared + 1))
        fi
    fi

    # hosts.deny (dots escaped so 1.2.3.4 does not also strip 1.2.3.45; anchored to daemon field)
    if [ -f /etc/hosts.deny ]; then
        local hd_re
        hd_re=$(_ip_regex "$ip")
        if grep -qE "^[A-Za-z0-9._-]+:[[:space:]]*${hd_re}([[:space:]#]|$)" /etc/hosts.deny 2>/dev/null; then
            if [ -w /etc/hosts.deny ]; then
                sed -i "/^[A-Za-z0-9._-]*:[[:space:]]*${hd_re}[[:space:]#]/d;/^[A-Za-z0-9._-]*:[[:space:]]*${hd_re}\$/d" /etc/hosts.deny 2>/dev/null
                if ! grep -qE "^[A-Za-z0-9._-]+:[[:space:]]*${hd_re}([[:space:]#]|$)" /etc/hosts.deny 2>/dev/null; then
                    echo "   ✅ hosts.deny: removed"
                    layers_cleared=$((layers_cleared + 1))
                else
                    echo "   ⚠️  hosts.deny: removal failed (entry still present)"
                fi
            else
                echo "   ⚠️  hosts.deny: not writable - could not remove entry"
            fi
        fi
    fi

    # Cooldown file.
    #
    # M4: this used to DELETE the cooldown entry, which made an operator's undo
    # the least durable state in the system. The cooldown was the only thing
    # stopping the next --auto run from re-scoring the same log window, reaching
    # the same verdict, and re-blocking within five minutes. Refresh it instead,
    # so an unblock buys at least COOLDOWN_SECONDS of quiet, and point at the
    # permanent fix rather than leaving the admin to discover it.
    local cooldown_ok=true
    mkdir -p "$DATA_DIR" 2>/dev/null
    touch "$COOLDOWN_FILE" 2>/dev/null
    if [ -f "$COOLDOWN_FILE" ]; then
        local cd_re
        cd_re=$(_ip_regex "$ip")
        sed -i "/^${cd_re}|/d" "$COOLDOWN_FILE" 2>/dev/null
        printf '%s|%s\n' "$ip" "$(date +%s)" >> "$COOLDOWN_FILE" 2>/dev/null

        # M3 (1.0.4): acquire_lock above is allowed to give up and continue —
        # refusing to unblock because a scan is running would be worse than the
        # race. But "continue" was silent: a concurrent init_cooldown or
        # expire_blocks does tmp-then-mv over this exact file, so the write we
        # just made can be discarded microseconds later. The operator was then
        # told the unblock succeeded and watched the address get re-blocked on
        # the next cron cycle with no explanation.
        #
        # Waiting on the lock indefinitely is NOT the answer: --monitor holds it
        # for its entire session, so an unlimited wait would hang the one command
        # an operator runs mid-incident. Verify instead, re-apply, and if it
        # still has not stuck, say so plainly.
        if [ "$LOCK_HELD" != true ]; then
            local tries=0
            while ! is_in_cooldown "$ip" && [ "$tries" -lt 3 ]; do
                sleep 1
                printf '%s|%s\n' "$ip" "$(date +%s)" >> "$COOLDOWN_FILE" 2>/dev/null
                tries=$((tries + 1))
            done
        fi
        is_in_cooldown "$ip" || cooldown_ok=false
    else
        cooldown_ok=false
    fi

    # Expiry journal — the block is gone, so drop its pending deadline too.
    # M12: via the shared field-exact helpers. The old end-anchored regex
    # ("/|${ex_re}\$/") stopped matching the moment the row gained its layer
    # field, which would have left every unblocked IP journalled forever.
    if [ -f "$EXPIRY_FILE" ]; then
        _journal_drop_ip "$ip"
        # Same race, same remedy: a scan may have re-written the journal from a
        # snapshot taken before our delete.
        if [ "$LOCK_HELD" != true ] && _journal_has_ip "$ip"; then
            sleep 1
            _journal_drop_ip "$ip"
        fi
    fi

    # Persist nftables state (atomic via mktemp — no shared fixed .tmp name)
    if command -v nft >/dev/null 2>&1; then
        _nft_persist
    fi

    # M4: optional permanent exemption, so a recurring false positive does not
    # have to be unblocked by hand every day.
    if [ "$add_whitelist" = true ]; then
        mkdir -p "$(dirname "$WHITELIST_FILE")" 2>/dev/null
        if [ -f "$WHITELIST_FILE" ] && grep -qE "^[[:space:]]*$(_ip_regex "$ip")[[:space:]]*(#|$)" "$WHITELIST_FILE" 2>/dev/null; then
            echo "   ℹ️  Already in $WHITELIST_FILE"
        elif printf '%s  # unblocked by --unblock on %s\n' "$ip" "$(date '+%Y-%m-%d')" >> "$WHITELIST_FILE" 2>/dev/null; then
            echo "   ✅ Whitelisted permanently in $WHITELIST_FILE"
        else
            echo "   ❌ Could not write $WHITELIST_FILE - add $ip to it by hand"
        fi

        # O4 (1.0.4): the append succeeds on a file the LOADER will refuse.
        # is_whitelisted_ip only honours this file if _file_is_root_safe passes,
        # so writing to a group-writable file (or one in a non-root directory)
        # printed a tick while every future scan ignored the entry and blocked
        # the address again. Same false-success class as the rest of this
        # release — check the gate the reader uses, and report against it.
        if [ -f "$WHITELIST_FILE" ] && ! _file_is_root_safe "$WHITELIST_FILE" "Whitelist file"; then
            echo "   ⚠️  BUT $WHITELIST_FILE is not safely root-owned, so scans will"
            echo "      IGNORE it and $ip will be blocked again. Fix the ownership:"
            echo "        chown root:root \"$WHITELIST_FILE\" && chmod 644 \"$WHITELIST_FILE\""
            log_message "WARNING: --whitelist wrote $ip to an untrusted $WHITELIST_FILE"
        fi
    fi

    echo
    # M3: report what actually happened. Printing "unblocked from all layers"
    # unconditionally was wrong in the one direction that costs an operator
    # their afternoon: with the C1 iptables bug it said "done" while the DROP
    # rule was still in place and the site still dark.
    if [ "$layers_cleared" -gt 0 ]; then
        echo "✅ Done. $ip removed from $layers_cleared block layer(s)."
    else
        echo "⚠️  Nothing was removed - $ip was not blocked by BotSurgeon on any layer."
        echo "   If the address is still unreachable, something else is blocking it."
    fi
    # M3: the cooldown is the only thing stopping the next --auto run from
    # re-scoring the same window and re-blocking within minutes, so a lost write
    # has to be reported rather than papered over.
    if [ "$cooldown_ok" != true ]; then
        echo "   ⚠️  Could not confirm the cooldown entry for $ip."
        echo "      A concurrent scan may have overwritten it, so the next run"
        echo "      could re-block this address. Re-run this command once the"
        echo "      scan finishes, or use --whitelist to make the exemption stick."
        log_message "WARNING: --unblock could not confirm the cooldown entry for $ip"
    fi
    if [ "$add_whitelist" != true ]; then
        echo "   Blocked again by the next scan? Make it permanent:"
        echo "     $0 --unblock $ip --whitelist"
    fi
    echo "   Note: If you blocked this IP via Fail2Ban, run: fail2ban-client unban $ip"
}

show_status() {
    echo "🏥 $SCRIPT_NAME v$VERSION - Status"
    echo "============================================"

    # Disabled check.
    # M15: through the same predicate the blocker uses. A bare file test made
    # --status report "DISABLED" for a flag the tool was in fact ignoring
    # (untrusted ownership), which is the one place that lie really costs:
    # an operator checks status during an incident, reads DISABLED, and stops
    # looking for the thing that is still blocking their customer.
    if is_disabled; then
        echo "⚠️  STATUS: DISABLED (use --enable to reactivate)"
        echo "   Disabled since: $(stat -c%y "$DISABLE_FLAG" 2>/dev/null || stat -f%Sm "$DISABLE_FLAG" 2>/dev/null)"
        echo
    elif [ -f "$DISABLE_FLAG" ]; then
        # Present but not trusted - is_disabled has already said why.
        echo "✅ STATUS: ACTIVE (an untrusted $DISABLE_FLAG is being ignored)"
    else
        echo "✅ STATUS: ACTIVE"
    fi

    # Running check
    if [ -f "$LOCK_FILE" ]; then
        # The lock file holds "<pid> <mode>" since 1.0.3 (O5); older versions
        # wrote just the PID, so read the first field either way.
        local pid mode
        pid=$(awk 'NR==1{print $1}' "$LOCK_FILE" 2>/dev/null)
        mode=$(awk 'NR==1{print $2}' "$LOCK_FILE" 2>/dev/null)
        if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
            echo "🔄 Currently running (PID: $pid${mode:+, mode: $mode})"
        else
            echo "- Not currently running"
        fi
    else
        echo "- Not currently running"
    fi

    # Block counts
    echo
    echo "📊 BLOCK STATISTICS:"
    if command -v nft >/dev/null 2>&1 && nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
        local set_count legacy_count
        set_count=$( { nft list set inet "$NFT_TABLE" "$NFT_SET4" 2>/dev/null
                       nft list set inet "$NFT_TABLE" "$NFT_SET6" 2>/dev/null; } | \
                     tr '\n' ' ' | grep -o 'elements = {[^}]*}' | tr ',' '\n' | grep -c . )
        [[ "$set_count" =~ ^[0-9]+$ ]] || set_count=0
        echo "   nftables (expiring set): $set_count IP(s)"
        # Per-IP drop rules: Basic <=1.0.1 blocks and Pro's blocks. These never
        # expire — flagged separately so they are not mistaken for live TTL ones.
        legacy_count=$(nft list table inet "$NFT_TABLE" 2>/dev/null | grep -cE 'saddr [0-9a-fA-F.:]+ .*drop')
        [[ "$legacy_count" =~ ^[0-9]+$ ]] || legacy_count=0
        if [ "$legacy_count" -gt 0 ]; then
            echo "   nftables (legacy per-IP rules, no expiry): $legacy_count"
            echo "     └─ from BotSurgeon-Basic <=1.0.1 or BotSurgeon-Pro; clear with --unblock <ip>"
        fi
    fi
    if command -v csf >/dev/null 2>&1; then
        local csf_count
        csf_count=$(csf -l 2>/dev/null | grep -c "DENY" 2>/dev/null) || csf_count=0
        echo "   CSF denies: $csf_count (total, not just BotSurgeon)"
    fi

    # Recent blocks
    echo
    echo "📋 RECENT BLOCKS (last 10):"
    if [ -f "$DATA_DIR/blocked_ips.log" ]; then
        _block_history | tail -10 | while IFS= read -r _rec; do
            [ -z "$_rec" ] && continue
            ts="${_rec%%$'\t'*}"; _rec="${_rec#*$'\t'}"
            ip="${_rec%%$'\t'*}"; _rec="${_rec#*$'\t'}"
            if [[ "$_rec" == *$'\t'* ]]; then
                reason="${_rec%%$'\t'*}"
                src="${_rec#*$'\t'}"
            else
                reason="$_rec"
                src=""
            fi
            echo "   $ts | $ip | ${src:+[$src] }$(_safe_display "$reason")"
        done
    else
        echo "   (no blocks recorded)"
    fi

    # Config
    echo
    echo "⚙️  CONFIGURATION:"
    echo "   Connection threshold: $CONNECTION_THRESHOLD"
    echo "   Auto-block threshold: $AUTO_BLOCK_THRESHOLD"
    echo "   Log threat threshold: $LOG_THREAT_THRESHOLD"
    echo "   Max blocks per run: $MAX_BLOCKS_PER_RUN"
    echo "   Cooldown: ${COOLDOWN_SECONDS}s"
    # N10: show the EFFECTIVE port list. A bad MONITORED_PORTS value used to
    # disable connection blocking with no visible sign; this is where an
    # operator would look to notice it.
    echo "   Monitored web ports: $MONITORED_PORTS"
    if _ttl_enabled; then
        echo "   Block lifetime: ${BLOCK_TTL_HOURS}h (blocks expire automatically)"
    else
        echo "   Block lifetime: PERMANENT (BLOCK_TTL_HOURS=0 - blocks never expire)"
    fi
    # C2: the CDN exemption decides who can never be blocked, so show what it
    # takes to qualify — the 1.0.2 thresholds were low enough to be self-awarded
    # and there was nothing in --status that would have revealed it.
    if [ "${PROXY_UA_THRESHOLD:-0}" -lt 1 ]; then
        echo "   CDN/proxy exemption: DISABLED (PROXY_UA_THRESHOLD=0)"
    else
        echo "   CDN/proxy exemption: >= ${PROXY_UA_THRESHOLD} user agents, >= ${PROXY_MIN_TOTAL} requests,"
        echo "                        >= ${PROXY_MIN_REQS_PER_UA} reqs/agent, >= ${PROXY_MIN_PATHS} distinct paths, >= 50% successful"
    fi
    [ -f "$CONFIG_FILE" ] && echo "   Config file: $CONFIG_FILE (loaded)"

    # M2/C3: whitelist files silently decide who cannot be blocked. Show whether
    # each is actually being honoured, so a rejected file (bad ownership) or an
    # allow-everything entry is visible here instead of only in a scan's output.
    echo
    echo "🛡️  WHITELIST SOURCES:"
    local wl _cq_saved="$CONFIG_QUIET"
    CONFIG_QUIET=false
    for wl in /etc/csf/csf.allow "$WHITELIST_FILE" "$PROXY_RANGES_FILE"; do
        if [ ! -f "$wl" ]; then
            echo "   - $wl (not present)"
        elif [ "$wl" = /etc/csf/csf.allow ] || _file_is_root_safe "$wl" "whitelist"; then
            local n
            n=$(grep -cvE '^[[:space:]]*(#|$)' "$wl" 2>/dev/null) || n=0
            echo "   ✅ $wl (${n:-0} entries)"
            if grep -qE '(^|[=[:space:]])(0\.0\.0\.0/0|::/0)([[:space:]]|$)' "$wl" 2>/dev/null; then
                echo "      🚨 contains an allow-EVERYTHING range - it is IGNORED (see --help)"
            fi
        else
            echo "   ❌ $wl (present but NOT trusted - see the reason above)"
        fi
    done
    CONFIG_QUIET="$_cq_saved"
}

list_blocked() {
    echo "📋 BotSurgeon Blocked IPs"
    echo "========================="

    # N4: what is enforced RIGHT NOW, with the time left on each block. The
    # history log below records what was blocked; this shows what still is.
    if command -v nft >/dev/null 2>&1 && nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
        local live
        live=$( { nft list set inet "$NFT_TABLE" "$NFT_SET4" 2>/dev/null
                  nft list set inet "$NFT_TABLE" "$NFT_SET6" 2>/dev/null; } | \
                tr '\n' ' ' | grep -o 'elements = {[^}]*}' | \
                sed 's/elements = {//; s/}//' | tr ',' '\n' | \
                sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -v '^$' )
        echo
        echo "🔒 CURRENTLY ENFORCED (nftables, auto-expiring):"
        if [ -n "$live" ]; then
            echo "$live" | while read -r entry; do
                echo "   ${entry}"
            done
        else
            echo "   (none)"
        fi
    fi

    echo
    echo "🗒️  BLOCK HISTORY:"
    if [ -f "$DATA_DIR/blocked_ips.log" ]; then
        local count
        count=$(wc -l < "$DATA_DIR/blocked_ips.log" 2>/dev/null)
        echo "Total entries: ${count:-0}"
        echo
        echo "Timestamp           | IP                | Source          | Reason"
        echo "--------------------|-------------------|-----------------|---------------------------"
        _block_history | tail -50 | while IFS= read -r _rec; do
            [ -z "$_rec" ] && continue
            ts="${_rec%%$'\t'*}"; _rec="${_rec#*$'\t'}"
            ip="${_rec%%$'\t'*}"; _rec="${_rec#*$'\t'}"
            if [[ "$_rec" == *$'\t'* ]]; then
                reason="${_rec%%$'\t'*}"
                src="${_rec#*$'\t'}"
            else
                reason="$_rec"
                src=""
            fi
            printf "%-19s | %-17s | %-15s | %s\n" "$ts" "$ip" "${src:-—}" "$(_safe_display "${reason:0:50}")"
        done
    else
        echo "(no blocks recorded)"
    fi

    echo
    echo "💡 To unblock an IP: $0 --unblock <ip>"
}

# N4 / upgrade path: remove BotSurgeon-Basic's footprint from the server.
#
# Deliberately conservative about shared and irreplaceable things:
#   * the 'inet botsurgeon' table is SHARED with BotSurgeon-Pro — only Basic's
#     own sets and set-reference rules are removed, and the table itself only
#     if nothing else is left in it;
#   * CSF/Imunify/Fail2Ban entries are left alone (they cannot be attributed to
#     us with certainty, and ours are temp bans that expire on their own);
#   * logs and the config file are KEPT — they are evidence and tuning. Their
#     paths are printed so the admin can remove them deliberately.
uninstall_botsurgeon() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "❌ --uninstall requires root privileges"
        exit 1
    fi

    echo "🧹 BotSurgeon-Basic uninstall"
    echo "============================="
    echo "This will remove:"
    echo "   • cron entries that run this script (root crontab + /etc/cron.d)"
    echo "   • BotSurgeon-Basic's nftables sets and their drop rules"
    echo "   • iptables rules and hosts.deny lines tagged BotSurgeon-Basic"
    echo "   • runtime state: lock file, cooldown file, expiry journal, disable flag"
    echo
    echo "   • Imunify360 blacklist entries this tool placed (from the expiry journal)"
    echo
    echo "This will KEEP (remove by hand if you want them gone):"
    echo "   • $CONFIG_FILE"
    echo "   • $DATA_DIR/  (activity log and block history)"
    echo "   • CSF temporary denies - those expire on their own"
    # M12: this line used to lump Fail2Ban in with "ours are temporary and
    # expire". A jail ban lasts for that jail's bantime, which is nothing to do
    # with BLOCK_TTL_HOURS, so saying so was simply untrue. Blocks are only
    # placed there now when BLOCK_TTL_HOURS=0, i.e. when permanence was asked
    # for - but a pre-1.0.5 install can still have left some behind.
    echo "   • Fail2Ban jail bans - they last for the jail's own bantime;"
    echo "     list them with: fail2ban-client status <jail>"
    echo

    if [ "$UNINSTALL_FORCE" != true ]; then
        local reply=""
        printf 'Type "yes" to proceed: '
        read -r reply || reply=""
        if [ "$reply" != "yes" ]; then
            echo "Aborted - nothing was changed."
            exit 0
        fi
    fi
    echo

    # M21: take the lock. Uninstall was the ONE mutating command that never did.
    #
    # It tears down nftables sets, iptables rules, hosts.deny lines and every
    # runtime state file, while a concurrent --auto or --monitor is creating
    # exactly those things. The interleaving leaves the worst possible result:
    # rules recreated after the teardown, with the expiry journal and cooldown
    # file deleted from under them — live blocks that nothing will ever lift or
    # even remember, on a server the operator believes is now clean.
    #
    # A short wait, then refuse rather than proceed. Unlike --unblock, this is
    # never an emergency: an admin removing the tool can wait for a scan to
    # finish, and a wrong answer here is expensive and hard to undo.
    acquire_lock 20
    if [ "$LOCK_HELD" != true ]; then
        if [ "$LOCK_STATE" = "contested" ]; then
            echo "❌ ABORTED: another BotSurgeon process is running and still holds the lock."
            echo "   Uninstalling now could leave firewall rules behind with no state file"
            echo "   left to track or expire them."
            echo "   Stop it first (a --monitor session, or wait for the cron scan to end),"
            echo "   then re-run:  $0 --uninstall"
            log_message "Uninstall aborted: could not acquire the lock"
            exit 1
        else
            echo "ℹ️  Continuing uninstall without concurrency lock (lock unavailable)."
            log_message "Uninstall proceeding without concurrency guard (lock unavailable)"
        fi
    fi

    # --- cron -------------------------------------------------------------
    local script_base
    script_base="$(basename "${BASH_SOURCE[0]}")"
    local cron_removed=0
    if command -v crontab >/dev/null 2>&1; then
        local current
        current=$(crontab -l 2>/dev/null)
        if [ -n "$current" ] && printf '%s\n' "$current" | grep -qF "$script_base"; then
            printf '%s\n' "$current" | grep -vF "$script_base" | crontab - 2>/dev/null && cron_removed=1
        fi
    fi
    local cf
    for cf in /etc/cron.d/botsurgeon /etc/cron.d/botsurgeon-basic; do
        if [ -f "$cf" ] && grep -qF "$script_base" "$cf" 2>/dev/null; then
            rm -f "$cf" 2>/dev/null && cron_removed=1
        fi
    done
    [ "$cron_removed" -eq 1 ] && echo "   ✅ cron entries removed" \
                             || echo "   - cron: no entries found"

    # --- nftables ---------------------------------------------------------
    if command -v nft >/dev/null 2>&1 && nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
        local h handles
        handles=$(nft -a list chain inet "$NFT_TABLE" input 2>/dev/null | \
                  grep -E "@(${NFT_SET4}|${NFT_SET6})\b" | \
                  awk '/handle [0-9]+/{for(i=1;i<=NF;i++) if($i=="handle") print $(i+1)}')
        for h in $handles; do
            nft delete rule inet "$NFT_TABLE" input handle "$h" 2>/dev/null
        done
        nft delete set inet "$NFT_TABLE" "$NFT_SET4" 2>/dev/null
        nft delete set inet "$NFT_TABLE" "$NFT_SET6" 2>/dev/null
        echo "   ✅ nftables: BotSurgeon-Basic sets and rules removed"

        # Only drop the shared table if nothing else lives in it. Pro's output
        # chain, or any remaining rule, means it is still in use.
        if nft list chain inet "$NFT_TABLE" output >/dev/null 2>&1; then
            echo "   ℹ️  nftables table '$NFT_TABLE' kept - BotSurgeon-Pro is using it"
        else
            local leftover
            leftover=$(nft list table inet "$NFT_TABLE" 2>/dev/null | \
                       grep -cE '^[[:space:]]+(ip|ip6|tcp|udp|meta|ct)[[:space:]].*(drop|reject|accept)') || leftover=0
            if [ "${leftover:-0}" -eq 0 ]; then
                nft delete table inet "$NFT_TABLE" 2>/dev/null && \
                    echo "   ✅ nftables table '$NFT_TABLE' removed (was empty)"
                rm -f "$NFT_PERSIST_FILE" 2>/dev/null
            else
                echo "   ℹ️  nftables table '$NFT_TABLE' kept - $leftover other rule(s) present"
                _nft_persist
            fi
        fi
    fi

    # --- iptables / hosts.deny -------------------------------------------
    # C1: the old loop rebuilt a delete command from an `iptables -S` line with
    # an UNQUOTED expansion — "${rule/-A/-D}". Our comments contain spaces
    # ("BotSurgeon-Basic: Access log threat: score 80/100, ..."), so word
    # splitting scattered the comment across argv, iptables rejected the
    # command, `|| break` fired, and the rules survived an "uninstall" that
    # reported success. Delete by rule NUMBER instead: exact, and immune to
    # whatever the comment text happens to contain.
    local ipt_removed=0 ipt nums n
    for ipt in iptables ip6tables; do
        command -v "$ipt" >/dev/null 2>&1 || continue
        # Highest number first so the earlier ones stay valid as we delete.
        nums=$($ipt -L INPUT -n --line-numbers 2>/dev/null | \
               awk '$1 ~ /^[0-9]+$/ && index($0, "BotSurgeon-Basic") > 0 { print $1 }' | sort -rn)
        for n in $nums; do
            $ipt -D INPUT "$n" 2>/dev/null && ipt_removed=1
        done
    done
    [ "$ipt_removed" -eq 1 ] && echo "   ✅ iptables: BotSurgeon-Basic rules removed" \
                             || echo "   - iptables: no BotSurgeon-Basic rules found"

    # M3: on hosts without xt_comment, our rules are bare DROP lines. Sweep them
    # before deleting IPT_BARE_FILE, otherwise untagged blocks outlive uninstall.
    if [ -f "$IPT_BARE_FILE" ]; then
        local bare_removed=0 bip
        while IFS= read -r bip; do
            [ -n "$bip" ] && is_valid_ip "$bip" || continue
            _ipt_del "$bip" INPUT ours >/dev/null 2>&1 && bare_removed=$((bare_removed + 1))
        done < "$IPT_BARE_FILE"
        [ "$bare_removed" -gt 0 ] && echo "   ✅ iptables: $bare_removed untagged BotSurgeon rule(s) removed"
    fi

    # Also lift any still-pending ipt-layer journal rows
    if [ -f "$EXPIRY_FILE" ]; then
        local j_ip j_layers
        while IFS='|' read -r _ j_ip j_layers; do
            [ -n "$j_ip" ] && is_valid_ip "$j_ip" || continue
            case ",${j_layers}," in
                *,ipt,*)
                    _ipt_del "$j_ip" INPUT ours >/dev/null 2>&1
                    ;;
            esac
        done < "$EXPIRY_FILE"
    fi

    if [ -f /etc/hosts.deny ] && grep -q "BotSurgeon-Basic" /etc/hosts.deny 2>/dev/null; then
        if [ -w /etc/hosts.deny ]; then
            sed -i '/# *BotSurgeon-Basic/d' /etc/hosts.deny 2>/dev/null
            if ! grep -q "BotSurgeon-Basic" /etc/hosts.deny 2>/dev/null; then
                echo "   ✅ hosts.deny: BotSurgeon-Basic entries removed"
            else
                echo "   ⚠️  hosts.deny: removal failed (entries still present)"
            fi
        else
            echo "   ⚠️  hosts.deny: not writable - could not remove entries"
        fi
    fi

    # --- Imunify360 -------------------------------------------------------
    # M12: entries we placed there have no native expiry, and the expiry journal
    # is the only record that they are ours. It gets deleted a few lines below,
    # so lift them FIRST - otherwise uninstalling BotSurgeon would strand every
    # pending Imunify360 block permanently, with nothing left to attribute it.
    if [ -f "$EXPIRY_FILE" ] && command -v imunify360-agent >/dev/null 2>&1; then
        local imu_removed=0 j_ip j_layers
        while IFS='|' read -r _ j_ip j_layers; do
            [ -n "$j_ip" ] && is_valid_ip "$j_ip" || continue
            case ",${j_layers}," in
                *,imunify,*)
                    imunify360-agent blacklist ip delete "$j_ip" >/dev/null 2>&1 && \
                        imu_removed=$((imu_removed + 1))
                    ;;
            esac
        done < "$EXPIRY_FILE"
        if [ "$imu_removed" -gt 0 ]; then
            echo "   ✅ Imunify360: $imu_removed BotSurgeon-Basic blacklist entr(ies) removed"
        else
            echo "   - Imunify360: no BotSurgeon-Basic entries pending"
        fi
    fi

    # --- runtime state ----------------------------------------------------
    rm -f "$COOLDOWN_FILE" "$EXPIRY_FILE" "$DISABLE_FLAG" "$IPT_BARE_FILE" "$MONITOR_HEARTBEAT_FILE" 2>/dev/null
    rm -f /var/run/botsurgeon-basic.pid 2>/dev/null
    # O6: clean only stale scratch files (>10m) to avoid clobbering active concurrent runs
    find /tmp -maxdepth 1 -name "botsurgeon_basic_*" -mmin +10 -exec rm -f {} + 2>/dev/null
    rm -f "$DATA_DIR"/.bs_*.* 2>/dev/null          # 1.0.3+ scratch files
    echo "   ✅ runtime state cleared"

    echo
    echo "✅ BotSurgeon-Basic uninstalled."
    echo "   Kept: $CONFIG_FILE and $DATA_DIR/"
    echo "   Remove the script itself when ready: rm -f ${BASH_SOURCE[0]}"
    echo
    echo "   Upgrading to BotSurgeon-Pro? Its installer can now run cleanly -"
    echo "   nothing from Basic is left to conflict with it."
}

# M3: --disable is what an operator reaches for while a false positive is taking
# a customer offline. Reporting success when the touch failed (not root, /etc
# read-only, full disk) tells them protection is off while cron keeps blocking —
# the worst possible lie at the worst possible moment. Same for --enable.
disable_botsurgeon() {
    mkdir -p "$(dirname "$DISABLE_FLAG")" 2>/dev/null
    if ! touch "$DISABLE_FLAG" 2>/dev/null || [ ! -f "$DISABLE_FLAG" ]; then
        echo "❌ Could NOT disable BotSurgeon - failed to create $DISABLE_FLAG"
        if [ "$(id -u)" -ne 0 ]; then
            echo "   You are not root. Re-run with sudo."
        else
            echo "   Check that $(dirname "$DISABLE_FLAG") exists and is writable."
        fi
        echo "   ⚠️  BotSurgeon is STILL ACTIVE and will keep blocking."
        exit 1
    fi
    echo "⏸️  BotSurgeon DISABLED"
    echo "   Cron jobs will exit immediately without taking action."
    echo "   To re-enable: $0 --enable"
}

enable_botsurgeon() {
    if [ -f "$DISABLE_FLAG" ]; then
        rm -f "$DISABLE_FLAG" 2>/dev/null
        if [ -f "$DISABLE_FLAG" ]; then
            echo "❌ Could NOT enable BotSurgeon - failed to remove $DISABLE_FLAG"
            [ "$(id -u)" -ne 0 ] && echo "   You are not root. Re-run with sudo."
            echo "   ⚠️  BotSurgeon is STILL DISABLED."
            exit 1
        fi
        echo "▶️  BotSurgeon ENABLED"
        echo "   Normal operation will resume on next cron cycle."
    else
        echo "✅ BotSurgeon is already enabled"
    fi
}

# ==============================================================================
# SECTION 3: HELP & CLI PARSING
# ==============================================================================

show_help() {
    cat << EOF
🏥 $SCRIPT_NAME v$VERSION - Free Edition

SYNOPSIS:
    $0 [OPTIONS]

MODES:
    (no args)         Interactive triage mode - menu-driven, needs a terminal
    --auto            Automated mode - blocks based on thresholds (for cron)
    --monitor         Continuous monitoring mode - runs until stopped
    --emergency       Emergency lockdown - aggressive blocking enabled
    --dry-run         Preview mode - runs the same analysis as --auto and reports
                      exactly which IPs it WOULD block, without touching the
                      firewall, the cooldown or the block history. Safe to pipe
                      or run without root.

RECOVERY:
    --unblock IP      Remove IP from ALL block layers (nftables, CSF, firewalld, iptables, hosts.deny)
                      Add --whitelist to also exempt it permanently, so the next
                      scan does not simply block it again
    --list-blocked    Show recently blocked IPs
    --status          Show BotSurgeon operational status
    --disable         Temporarily disable BotSurgeon (cron exits immediately)
    --enable          Re-enable BotSurgeon after --disable
    --uninstall       Remove cron entries, firewall rules and runtime state
                      (keeps your config and logs; add --force to skip the prompt)

OPTIONS:
    --threshold N        Connection ALERT threshold (warning tier, default: $CONNECTION_THRESHOLD)
    --block-threshold N  Connection AUTO-BLOCK threshold (default: $AUTO_BLOCK_THRESHOLD)
    --generate-config    Generate default configuration file
    --help               Show this help message

BLOCK LIFETIME:
    Blocks expire automatically after ${BLOCK_TTL_HOURS}h (BLOCK_TTL_HOURS in the config
    file; set it to 0 for permanent blocks). nftables sets, CSF temp bans and
    firewalld rules expire natively; iptables and hosts.deny are swept each run.

EXAMPLES:
    $0                              # Interactive triage (needs a terminal)
    $0 --dry-run                    # Preview what --auto would block
    $0 --auto                       # Cron-based auto-protection
    $0 --auto --block-threshold 75  # Auto-block IPs with 75+ connections
    $0 --auto --threshold 40        # Warn (don't block) at 40+ connections
    $0 --monitor                    # Continuous monitoring
    $0 --emergency --dry-run        # Preview emergency actions
    $0 --unblock 203.0.113.5        # Unblock a specific IP
    $0 --unblock 203.0.113.5 --whitelist   # Unblock and never block it again
    $0 --status                     # Check what's happening
    $0 --generate-config            # Create /etc/botsurgeon/botsurgeon-basic.conf

CRON SETUP (wrap in 'timeout' so a hung run never blocks later cycles):
    */5 * * * * timeout 300 $0 --auto >> /var/log/botsurgeon/cron.log 2>&1

UPGRADE:
    For AI-powered threat scoring, web UI, forensics, notifications,
    and advanced features visit: https://steadfasttools.com/botsurgeon

EOF
}

parse_arguments() {
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --auto)            AUTO_MODE=true ;;
            --monitor)         MONITOR_MODE=true ;;
            --emergency)       EMERGENCY_MODE=true ;;
            --dry-run)         DRY_RUN=true ;;
            # O9: bounded like every config-file numeric. These were checked only
            # for "positive integer", so a value past intmax made the later
            # `[ "$count" -gt "$threshold" ]` tests fail with "integer
            # expression expected" instead of doing anything useful.
            --threshold)
                if [ -z "${2:-}" ] || ! [[ "$2" =~ ^(0|[1-9][0-9]{0,9})$ ]] || [ "$2" -lt 5 ] || [ "$2" -gt 10000 ]; then
                    echo "❌ --threshold requires a number between 5 and 10000"
                    exit 1
                fi
                CONNECTION_THRESHOLD="$2"; shift
                ;;
            --block-threshold)
                if [ -z "${2:-}" ] || ! [[ "$2" =~ ^(0|[1-9][0-9]{0,9})$ ]] || [ "$2" -lt 10 ] || [ "$2" -gt 50000 ]; then
                    echo "❌ --block-threshold requires a number between 10 and 50000"
                    exit 1
                fi
                AUTO_BLOCK_THRESHOLD="$2"; shift
                ;;
            --unblock)
                if [ -z "${2:-}" ]; then
                    echo "❌ --unblock requires an IP address"
                    exit 1
                fi
                unblock_ip "$2" "$UNBLOCK_WHITELIST"
                exit 0
                ;;
            --whitelist)
                # Resolved by the pre-scan below, because --unblock exits before
                # this loop could reach a trailing flag.
                : ;;
            --status)
                show_status
                exit 0
                ;;
            --disable)
                disable_botsurgeon
                exit 0
                ;;
            --enable)
                enable_botsurgeon
                exit 0
                ;;
            --list-blocked)
                list_blocked
                exit 0
                ;;
            --uninstall)
                uninstall_botsurgeon
                exit 0
                ;;
            --force)
                # Resolved by the pre-scan above (--uninstall exits before this
                # loop could reach a trailing flag). Accepted here only so it
                # does not fall through to "Unknown option".
                : ;;
            --generate-config)
                generate_default_config
                exit 0
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
        shift
    done

    # OPT-10: validate conflicting execution modes
    if [ "$MONITOR_MODE" = true ]; then
        if [ "$AUTO_MODE" = true ] || [ "$EMERGENCY_MODE" = true ] || [ "$DRY_RUN" = true ]; then
            echo "❌ --monitor cannot be combined with --auto, --emergency, or --dry-run."
            echo "   Monitor mode runs continuously. Use --help for details."
            exit 1
        fi
    fi
    if [ "$AUTO_MODE" = true ]; then
        if [ "$DRY_RUN" = true ]; then
            echo "❌ --auto cannot be combined with --dry-run."
            echo "   --dry-run already previews the automated scan without making changes."
            echo "   Run '$0 --dry-run' for preview, or '$0 --auto' for automated blocking."
            exit 1
        fi
        if [ "$EMERGENCY_MODE" = true ]; then
            echo "❌ --auto cannot be combined with --emergency."
            echo "   --emergency already runs an automated lockdown with aggressive thresholds."
            exit 1
        fi
    fi
}

# NOTE: parse_arguments is INVOKED at the very bottom of this file, not here.
#
# The recovery commands it dispatches (--unblock, --status, --list-blocked)
# exit from inside it, and they now use helpers defined further down —
# acquire_lock (SECTION 4) and _safe_display (SECTION 7). Bash defines functions
# as it reads the file, so calling them from here failed with "command not
# found": --unblock silently ran without the lock it is supposed to take, and
# --list-blocked printed empty reason columns. Parsing after every definition is
# loaded makes the whole API available to every command.

# ==============================================================================
# SECTION 4: LOCK FILE & CONCURRENCY GUARD
# ==============================================================================

_pid_is_botsurgeon() {
    local pid="$1" cmd
    [ -r "/proc/$pid/cmdline" ] || return 1
    cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
    case "$cmd" in *"$(basename "${BASH_SOURCE[0]:-$0}")"*) return 0 ;; esac
    return 1
}

_hb_warn() {
    [ "$HB_WARNED" = true ] && return 0
    HB_WARNED=true
    echo "⚠️  Cannot write $MONITOR_HEARTBEAT_FILE - cron may judge this monitor stale and kill it."
    log_message "WARNING: monitor heartbeat unwritable ($MONITOR_HEARTBEAT_FILE)"
}

_heartbeat() {
    local hb_tmp
    [ "$MONITOR_MODE" = true ] || return 0
    mkdir -p "$(dirname "$MONITOR_HEARTBEAT_FILE")" 2>/dev/null
    hb_tmp=$(mktemp "${MONITOR_HEARTBEAT_FILE}.XXXXXX" 2>/dev/null) || { _hb_warn; return 1; }
    if printf '%s\n' "$(date +%s)" > "$hb_tmp" 2>/dev/null && \
       mv -f "$hb_tmp" "$MONITOR_HEARTBEAT_FILE" 2>/dev/null; then
        return 0
    fi
    rm -f "$hb_tmp" 2>/dev/null
    _hb_warn
    return 1
}

acquire_lock() {
    # $1 (optional): seconds to WAIT for the lock instead of failing fast.
    # Used by recovery commands, which must not be refused (see below).
    local wait_secs="${1:-0}"

    # H1: a non-root run (e.g. --dry-run preview) cannot write /var/run and a
    # failed bare 'exec' redirect would terminate the shell before the friendly
    # root check. Redirect the lock to a user-writable path when not root.
    if [ "$(id -u)" -ne 0 ]; then
        LOCK_FILE="${TMPDIR:-/tmp}/botsurgeon-basic.$(id -u).lock"
        MONITOR_HEARTBEAT_FILE="/tmp/botsurgeon_monitor.$(id -u).heartbeat"
    fi

    local lock_dir
    lock_dir="$(dirname "$LOCK_FILE")"
    mkdir -p "$lock_dir" 2>/dev/null

    # Probe writability with a command-word redirect (its failure is catchable,
    # unlike a bare 'exec' redirect which would exit a non-interactive shell).
    if ! { : >>"$LOCK_FILE"; } 2>/dev/null; then
        echo "⚠️  Lock file not writable ($LOCK_FILE) - continuing without concurrency guard"
        LOCK_HELD=false
        LOCK_STATE="unwritable"
        return 0
    fi

    # A missing flock must not masquerade as contention. Without this guard the
    # `flock -n 9` below fails with "command not found" and the script announces
    # "Another BotSurgeon instance is running" — sending the admin hunting for a
    # process that does not exist. Same class as a silent no-op or a false
    # success: the tool telling the operator something untrue about its own
    # state. util-linux ships flock on every supported distro, but minimal
    # containers and stripped images do not always have it.
    if ! command -v flock >/dev/null 2>&1; then
        echo "⚠️  'flock' not found - running WITHOUT a concurrency guard."
        echo "   Overlapping cron runs could collide. Install util-linux to fix:"
        echo "     dnf install util-linux   |   apt install util-linux"
        log_message "WARNING: flock missing - no concurrency guard for this run"
        LOCK_HELD=false
        LOCK_STATE="unavailable"
        return 0
    fi

    # M4: open in APPEND mode so merely opening never truncates a running
    # instance's recorded PID. Only the flock winner rewrites the PID.
    exec 9>>"$LOCK_FILE"

    # M3: recovery commands (--unblock) must not be turned away. They edit the
    # same state files a scan rewrites, so they want the lock — but refusing to
    # unblock an IP because a scan happens to be running would be worse than the
    # race. Wait briefly, then proceed regardless and say so.
    if [ "$wait_secs" -gt 0 ] 2>/dev/null; then
        if ! flock -w "$wait_secs" 9; then
            LOCK_HELD=false
            LOCK_STATE="contested"
            log_message "WARNING: lock wait timed out after ${wait_secs}s"
            return 1
        fi
        LOCK_HELD=true
        LOCK_STATE="held"
        local mode="scan"
        [ "$MONITOR_MODE" = true ] && mode="monitor"
        [ "$AUTO_MODE" = true ] && [ "$MONITOR_MODE" = false ] && mode="auto"
        printf '%s %s\n' "$$" "$mode" >"$LOCK_FILE"
        return 0
    fi

    if ! flock -n 9; then
        # O5: a --monitor session holds this lock for as long as it runs, so
        # every cron --auto cycle used to exit 1 with a bare "Another instance is
        # running" — a failure mail and a cron.log entry every five minutes, for
        # a state that is completely intentional. Say which mode holds it, and
        # treat a deliberate monitor session as a clean skip rather than an
        # error, so genuine contention still stands out.
        local holder_pid holder_mode
        holder_pid=$(awk 'NR==1{print $1}' "$LOCK_FILE" 2>/dev/null)
        holder_mode=$(awk 'NR==1{print $2}' "$LOCK_FILE" 2>/dev/null)
        # Only treat this as a deliberate monitor session if the recorded PID is
        # genuinely alive. Exiting 0 suppresses the cron failure mail, so it must
        # not be reachable on stale or inherited lock contents — otherwise a
        # wedged holder would make every cron cycle skip silently and for ever,
        # which is precisely the "silently stopped protecting you" failure this
        # release exists to remove. Anything unverifiable falls through to the
        # loud path below.
        # MAJ-2 / C-5: verify the monitor is actively ticking via heartbeat file. If the
        # heartbeat is older than 900s (or absent), declare it stale, break the
        # wedged lock, and allow cron execution to proceed.
        if [ "$holder_mode" = "monitor" ] && [[ "$holder_pid" =~ ^[0-9]+$ ]] && \
           kill -0 "$holder_pid" 2>/dev/null; then
            local hb_ts=0 hb_age=999999
            if [ -f "$MONITOR_HEARTBEAT_FILE" ]; then
                hb_ts=$(awk 'NR==1{print $1}' "$MONITOR_HEARTBEAT_FILE" 2>/dev/null)
                if [[ "$hb_ts" =~ ^[0-9]+$ ]]; then
                    local now_ts
                    now_ts=$(date +%s)
                    hb_age=$((now_ts - hb_ts))
                    if [ "$hb_age" -lt -60 ]; then
                        echo "⚠️  Monitor heartbeat is dated ${hb_age#-}s in the FUTURE - clock skew or a corrupt file."
                        echo "   Treating it as unverifiable rather than healthy."
                        log_message "WARNING: monitor heartbeat is $((0 - hb_age))s in the future - not trusted"
                        echo "❌ Cannot verify monitor health (PID $holder_pid). Refusing to signal it."
                        echo "   Investigate system clock / NTP or stop the monitor by hand."
                        log_message "SECURITY: refused to kill PID $holder_pid - heartbeat timestamp in future ($hb_ts > $now_ts)"
                        exit 1
                    elif [ "$hb_age" -lt 0 ]; then
                        hb_age=0            # sub-minute skew is normal, treat as fresh
                    fi
                fi
            fi

            if [ "$hb_age" -le 900 ]; then
                echo "ℹ️  A --monitor session is active (PID ${holder_pid:-?}, heartbeat ${hb_age}s ago) - skipping this run."
                echo "   Monitor mode already scans continuously; stop it to resume cron scans."
                log_message "Skipped: healthy monitor session (PID ${holder_pid:-?}, heartbeat ${hb_age}s ago) holds the lock"
                exit 0
            else
                # F-1b: probe with a real WRITE, not a permission test. `-w` uses
                # access(2): for root it is true on any rw filesystem regardless of
                # mode, and it is true on a FULL disk - the exact condition that
                # stops the monitor refreshing its heartbeat in the first place.
                local _hb_probe
                _hb_probe=$(mktemp "${MONITOR_HEARTBEAT_FILE}.probe.XXXXXX" 2>/dev/null)
                if [ -z "$_hb_probe" ] || ! printf 'probe\n' > "$_hb_probe" 2>/dev/null; then
                    rm -f "$_hb_probe" 2>/dev/null
                    echo "⚠️  Cannot write beside $MONITOR_HEARTBEAT_FILE (full disk, read-only"
                    echo "   mount, or bad permissions) - the monitor may simply be unable to"
                    echo "   refresh its heartbeat. Refusing to kill PID $holder_pid on"
                    echo "   staleness that cannot be proven."
                    log_message "WARNING: heartbeat dir unwritable/full - stale-lock breaker declined to act"
                    exit 1
                fi
                rm -f "$_hb_probe" 2>/dev/null

                if [ ! -f "$MONITOR_HEARTBEAT_FILE" ] || ! _pid_is_botsurgeon "$holder_pid"; then
                    echo "❌ Cannot verify the lock holder (PID $holder_pid). Refusing to signal it."
                    echo "   Stop the monitor by hand, or remove $LOCK_FILE if it is stale."
                    log_message "SECURITY: refused to kill PID $holder_pid - identity unverifiable"
                    exit 1
                fi

                echo "⚠️  STALE MONITOR DETECTED: Monitor session (PID ${holder_pid:-?}) heartbeat is stale (${hb_age}s old > 900s limit)."
                echo "   The monitor may be hung. Terminating wedged process and taking lock for cron pass."
                log_message "WARNING: stale monitor session (PID ${holder_pid:-?}, heartbeat age ${hb_age}s) - breaking lock"

                # Kill children and process group gracefully first (M-6 / F-2)
                command -v pkill >/dev/null 2>&1 && pkill -P "$holder_pid" 2>/dev/null
                local pgid my_pgid
                pgid=$(ps -o pgid= "$holder_pid" 2>/dev/null | tr -d ' ')
                my_pgid=$(ps -o pgid= $$ 2>/dev/null | tr -d ' ')
                if [ -n "$pgid" ] && [ "$pgid" = "$my_pgid" ]; then
                    echo "⚠️  Lock holder shares this process's group ($pgid) - refusing group-kill to avoid self-termination."
                    log_message "WARNING: skipped process-group kill for PID $holder_pid - shares caller's PGID $my_pgid"
                fi
                if [[ "$pgid" =~ ^[0-9]+$ ]] && [ "$pgid" -gt 1 ] && [[ "$my_pgid" =~ ^[0-9]+$ ]] && [ "$pgid" != "$my_pgid" ]; then
                    kill -TERM "-$pgid" 2>/dev/null
                else
                    kill -TERM "$holder_pid" 2>/dev/null
                fi

                # Escalation window: wait up to 5s for process to exit cleanly
                for _ in 1 2 3 4 5; do
                    kill -0 "$holder_pid" 2>/dev/null || break
                    sleep 1
                done

                # If still alive after 5s, escalate to SIGKILL on process group / PID
                if kill -0 "$holder_pid" 2>/dev/null; then
                    command -v pkill >/dev/null 2>&1 && pkill -9 -P "$holder_pid" 2>/dev/null
                    if [[ "$pgid" =~ ^[0-9]+$ ]] && [ "$pgid" -gt 1 ] && [[ "$my_pgid" =~ ^[0-9]+$ ]] && [ "$pgid" != "$my_pgid" ]; then
                        kill -9 "-$pgid" 2>/dev/null
                    else
                        kill -9 "$holder_pid" 2>/dev/null
                    fi
                fi

                sleep 1
                if flock -n 9; then
                    LOCK_HELD=true
                    LOCK_STATE="held"
                    local mode="scan"
                    [ "$MONITOR_MODE" = true ] && mode="monitor"
                    [ "$AUTO_MODE" = true ] && [ "$MONITOR_MODE" = false ] && mode="auto"
                    printf '%s %s\n' "$$" "$mode" >"$LOCK_FILE"
                    return 0
                fi
            fi
        fi

        # Final non-blocking attempt to acquire lock in case the holder (live or dead)
        # finished while we were inspecting it (F-3 / F-3a):
        if flock -n 9; then
            # The holder finished while we were inspecting it - proceed normally.
            LOCK_HELD=true
            LOCK_STATE="held"
            local mode="scan"
            [ "$MONITOR_MODE" = true ] && mode="monitor"
            [ "$AUTO_MODE" = true ] && [ "$MONITOR_MODE" = false ] && mode="auto"
            printf '%s %s\n' "$$" "$mode" >"$LOCK_FILE"
            return 0
        fi

        # If the recorded PID is dead but the lock is still held, find the real holder (M-6):
        if ! kill -0 "$holder_pid" 2>/dev/null; then
            echo "⚠️  Lock held by a process other than the recorded PID ${holder_pid:-?}."
            echo "   Find it with:  ls -l /proc/*/fd/* 2>/dev/null | grep -F '$LOCK_FILE'"
            log_message "WARNING: orphaned flock on $LOCK_FILE - recorded PID ${holder_pid:-?} is dead"
        fi

        echo "❌ Another BotSurgeon instance is running (PID ${holder_pid:-?}${holder_mode:+, mode: $holder_mode})"
        exit 1
    fi

    LOCK_HELD=true
    LOCK_STATE="held"
    # We hold the lock: safe to reset. Record the mode alongside the PID so the
    # next contender can tell an intentional monitor from a real collision.
    local mode="scan"
    [ "$MONITOR_MODE" = true ] && mode="monitor"
    [ "$AUTO_MODE" = true ] && [ "$MONITOR_MODE" = false ] && mode="auto"
    printf '%s %s\n' "$$" "$mode" >"$LOCK_FILE"
}

release_lock() {
    [ "$LOCK_HELD" = true ] || return 0
    flock -u 9 2>/dev/null
    exec 9>&- 2>/dev/null
    # M4: intentionally NOT removing the lock file. Unlinking it reopens the
    # classic unlink race that flock closes (a new instance could create a fresh
    # inode at the same path and run concurrently with a late releaser). A stale
    # lock file is harmless — flock is released automatically on process exit.
    LOCK_HELD=false
    LOCK_STATE=""
}

# ==============================================================================
# SECTION 5: SIGNAL HANDLING & CLEANUP
# ==============================================================================

# N17: the watchdog is a subshell whose real timer is a child `sleep`. Killing
# only the subshell orphans that sleep, which then lingers for up to
# MAX_RUNTIME — at a */5 cron with MAX_RUNTIME=300 there was a stray `sleep`
# reparented to init essentially all the time.
#
# Two mechanisms, because one is not portable: `pkill -P` is the clean way and
# works with procps on every supported distro, but it is absent or a no-op on
# some minimal userlands. So the watchdog also records its sleep's PID, which
# makes the cleanup deterministic and independent of pkill. Children are killed
# before the subshell — once the parent is gone, `pkill -P` finds nothing.
_stop_watchdog() {
    [ -n "$WATCHDOG_PID" ] || return 0

    local sleep_pid=""
    if [ -n "$WATCHDOG_SLEEPFILE" ] && [ -f "$WATCHDOG_SLEEPFILE" ]; then
        sleep_pid=$(cat "$WATCHDOG_SLEEPFILE" 2>/dev/null)
    fi

    command -v pkill >/dev/null 2>&1 && pkill -P "$WATCHDOG_PID" 2>/dev/null
    [[ "$sleep_pid" =~ ^[0-9]+$ ]] && kill "$sleep_pid" 2>/dev/null
    kill "$WATCHDOG_PID" 2>/dev/null

    [ -n "$WATCHDOG_SLEEPFILE" ] && rm -f "$WATCHDOG_SLEEPFILE" 2>/dev/null
    WATCHDOG_PID=""
    return 0
}

declare -a SCRATCH_FILES=()
_register_scratch() { [ -n "$1" ] && SCRATCH_FILES+=("$1"); }

cleanup() {
    local exit_code=$?
    _stop_watchdog
    [ "$FIREWALLD_NEEDS_RELOAD" = true ] && finalize_firewall
    log_message "BotSurgeon Basic shutting down (exit code: $exit_code)"
    release_lock
    # O3: remove all registered scratch files created by this process
    for f in "${SCRATCH_FILES[@]}"; do
        [ -n "$f" ] && [ -f "$f" ] && rm -f "$f" 2>/dev/null
    done
    [ -n "$WATCHDOG_MARKER" ]    && rm -f "$WATCHDOG_MARKER" 2>/dev/null
    [ -n "$WATCHDOG_SLEEPFILE" ] && rm -f "$WATCHDOG_SLEEPFILE" 2>/dev/null
    [ -n "$LOG_WINDOW_FILE" ]    && rm -f "$LOG_WINDOW_FILE" 2>/dev/null
    [ -n "$PROXY_IPS_FILE" ]     && rm -f "$PROXY_IPS_FILE" 2>/dev/null
    [ -n "$DEMO_LOG_FILE" ]      && rm -f "$DEMO_LOG_FILE" 2>/dev/null
    [ "$MONITOR_MODE" = true ] && [ -n "$MONITOR_HEARTBEAT_FILE" ] && rm -f "$MONITOR_HEARTBEAT_FILE" 2>/dev/null
    exit "$exit_code"
}

# N13: distinguish a watchdog kill from an operator Ctrl-C or an external
# `timeout`. All three arrived as a bare "Received SIGTERM" before.
_on_term() {
    # M1: the marker is created up front by mktemp now (a predictable /tmp name
    # that root later wrote to was a symlink target), so "did the watchdog fire"
    # is a content test rather than an existence test.
    if [ -n "$WATCHDOG_MARKER" ] && [ -s "$WATCHDOG_MARKER" ]; then
        echo "⏱️  WATCHDOG: this run exceeded MAX_RUNTIME (${MAX_RUNTIME}s) and was stopped."
        echo "    Blocks already applied are kept. If full scans legitimately take"
        echo "    this long, raise MAX_RUNTIME in $CONFIG_FILE."
        log_message "WATCHDOG FIRED: exceeded MAX_RUNTIME=${MAX_RUNTIME}s - run terminated early"
    else
        log_message "Received SIGTERM - shutting down..."
    fi
    exit 143
}

setup_traps() {
    trap cleanup EXIT
    trap 'echo ""; log_message "Received SIGINT - shutting down..."; exit 130' INT
    trap _on_term TERM
}
setup_traps

# ==============================================================================
# SECTION 6: LOG ROTATION
# ==============================================================================

rotate_log() {
    local log_path="$1"
    local max_mb="${2:-$LOG_MAX_SIZE_MB}"

    [ ! -f "$log_path" ] && return 0

    local size_bytes
    size_bytes=$(stat -c%s "$log_path" 2>/dev/null || stat -f%z "$log_path" 2>/dev/null || echo 0)
    local size_mb=$((size_bytes / 1048576))

    if [ "$size_mb" -ge "$max_mb" ]; then
        local timestamp archive
        # O8: second-precision alone collided when two logs rotated in the same
        # second (this is called twice in a row from security_preflight), and
        # the second mv silently overwrote the first archive. The PID makes the
        # name unique per process as well as per second.
        timestamp="$(date '+%Y%m%d_%H%M%S').$$"
        archive="${log_path}.${timestamp}"
        mv "$log_path" "$archive" || return 0
        touch "$log_path"
        # O8: compress in the foreground. Backgrounded, it was orphaned when the
        # script exited moments later, and its failure was invisible; on a 25 MB
        # cap this takes well under a second.
        gzip "$archive" 2>/dev/null || true
        log_message "Log rotated: $(basename "$log_path") (was ${size_mb}MB)"
    fi
}

# ==============================================================================
# SECTION 7: UTILITY FUNCTIONS
# ==============================================================================

log_message() {
    local message="$1"
    local timestamp
    timestamp="[$(date '+%Y-%m-%d %H:%M:%S')]"
    printf '%s %s\n' "$timestamp" "$message" >> "$LOG_FILE" 2>/dev/null
}

# O4: request paths and user agents come straight from a remote client and are
# printed to the operator's terminal. Apache and nginx escape control bytes by
# default, but a log format using `escape=none` (or a non-Apache producer) does
# not — and an ANSI escape sequence in a "threat path" can rewrite what the
# admin sees on the line above. Strip anything non-printable before display.
_safe_display() {
    printf '%s' "$1" | tr -c '[:print:]' '.' 2>/dev/null || printf '%s' "$1"
}

print_header() {
    echo "==============================================================================="
    echo "   $SCRIPT_NAME v$VERSION - $WARD  🏥"
    echo "   Server Load: $(get_server_load) | Active Connections: $(get_total_connections)"
    if [ "$DRY_RUN" = true ]; then
        echo "   ⚗️  DRY RUN MODE - No actions will be taken"
    fi
    echo "==============================================================================="
}

get_server_load() {
    # L6: prefer /proc/loadavg — always "0.15 0.10 0.05 ..." with '.' decimals
    # and space separators regardless of locale. The old uptime parse keyed on
    # the literal "load average:" string, which is translated on non-English
    # systems. Fall back to a POSITIONAL uptime parse (1-min load is 3rd-from-last).
    if [ -r /proc/loadavg ]; then
        awk '{print $1}' /proc/loadavg 2>/dev/null
    else
        uptime | awk '{n=NF; v=$(n-2); gsub(/,/,"",v); print v}' 2>/dev/null
    fi
}

# --- ss(8) with netstat fallback ---
get_connection_tool() {
    if command -v ss >/dev/null 2>&1; then
        echo "ss"
    elif command -v netstat >/dev/null 2>&1; then
        echo "netstat"
    else
        echo "none"
    fi
}

# M24: the exact flags here decide the COLUMN LAYOUT the parser depends on.
#
# ss builds its header dynamically:
#   * Netid appears only when more than one socket family is dumped, so it is
#     present because BOTH -t and -u are passed;
#   * State appears only when the filter selects more than one state, so it is
#     ABSENT because "state established" selects exactly one.
#
# That combination is what makes "Netid Recv-Q Send-Q Local Peer" - local at $4,
# peer at $5, the same positions netstat -ntu uses. Drop the -u, or widen the
# state filter, and every column shifts by one: connection-based detection then
# silently matches nothing and reports "no threats" on a live flood.
#
# So: do not change this command without changing extract_ips_from_connections,
# and t_lifecycle.sh pins both layouts with real fixtures.
get_connections_raw() {
    local tool
    tool=$(get_connection_tool)
    if [ "$tool" = "ss" ]; then
        ss -ntu state established 2>/dev/null
    elif [ "$tool" = "netstat" ]; then
        netstat -ntu 2>/dev/null
    else
        return 1
    fi
}

# N19: count exactly the connections the blocker would consider.
#
# This used to grep the whole ss/netstat line for ":<port>", which matched a
# connection whose PEER port happened to be 80/443 and also fired inside IPv6
# addresses such as 2001:db8::80:1234. The displayed total therefore disagreed
# with what extract_ips_from_connections actually counted. Reusing that function
# keeps the headline number and the blocking decision derived from one filter.
get_total_connections() {
    local count
    count=$(extract_ips_from_connections 2>/dev/null | grep -c .) || count=0
    echo "${count:-0}"
}

# Emit peer IPs of ESTABLISHED connections whose LOCAL port is monitored.
# - C1: filters on the local (server-side) port so only web-facing connections
#   feed the blocker (an IP flooding IMAP/MySQL/backup ports is not blocked).
# - H8: netstat path keeps only ESTABLISHED rows (drops TIME_WAIT and UDP).
# - H3: IPv4-mapped IPv6 peers (::ffff:1.2.3.4) are normalized to plain IPv4.
extract_ips_from_connections() {
    local tool skip_lines has_state
    tool=$(get_connection_tool)
    if [ "$tool" = "ss" ]; then
        skip_lines=1
        has_state=0   # 'state established' filter already applied; no State column
    elif [ "$tool" = "netstat" ]; then
        skip_lines=2
        has_state=1   # netstat output includes a State column at $NF
    else
        return 1
    fi
    get_connections_raw | awk -v skip="$skip_lines" -v has_state="$has_state" -v ports="$MONITORED_PORTS" '
    BEGIN {
        np = split(ports, parr, " ")
        for (i = 1; i <= np; i++) if (parr[i] != "") want[parr[i]] = 1
    }
    NR > skip {
        # netstat lists all states; keep only ESTABLISHED (also drops stateless UDP)
        if (has_state && $NF != "ESTABLISHED") next

        local_addr = $4   # server side: address:port
        peer_addr  = $5   # client side: address:port

        # --- local port must be one we monitor (web ports) ---
        lp = local_addr
        gsub(/\[/, "", lp); gsub(/\]/, "", lp)
        npc = split(lp, lparts, ":")
        if (!(lparts[npc] in want)) next

        # --- extract peer IP (strip brackets, drop trailing :port) ---
        addr = peer_addr
        gsub(/\[/, "", addr)
        gsub(/\]/, "", addr)
        # IPv6: multiple colons (e.g. "2001:db8::1:443" or "::ffff:1.2.3.4:80")
        # IPv4: "1.2.3.4:80"
        if (addr ~ /:.*:/) {
            # IPv6 - strip last :port
            n = split(addr, parts, ":")
            ip = parts[1]
            for (i = 2; i < n; i++) ip = ip ":" parts[i]
        } else {
            # IPv4 - strip :port
            sub(/:[0-9]+$/, "", addr)
            ip = addr
        }

        # H3: normalize IPv4-mapped IPv6 (::ffff:1.2.3.4 -> 1.2.3.4) so the value
        # validates as IPv4 downstream and dedups with native IPv4 hits.
        if (ip ~ /:/ && ip ~ /\.[0-9]+$/) {
            m = split(ip, mm, ":")
            ip = mm[m]
        }

        if (ip != "") print ip
    }' | sort
}

# ==============================================================================
# SECTION 8: COOLDOWN / DEDUP SYSTEM
# ==============================================================================

# O3: runtime scratch belongs beside the data it rewrites, not in /tmp.
#
# Two reasons. The cooldown file and the expiry journal are replaced with
# tmp-then-mv; when the temp lives on a different filesystem that "mv" is a
# copy+unlink, which is not atomic — an interrupted run can leave a half-written
# state file. And /tmp on a shared cPanel host is writable by every local user,
# which is a surface this tool does not need to expose at all.
#
# Falls back to /tmp only if $DATA_DIR is unusable (non-root --dry-run).
# M22: root must never inherit a caller-controlled TMPDIR.
#
# The fallback paths below - _mktemp_data when $DATA_DIR is unusable, and the
# preflight log fallback - both used "${TMPDIR:-/tmp}" unconditionally. Under
# sudo, from a panel hook, or from any cron wrapper that exports it, TMPDIR can
# point at a directory the CALLER owns, and the owner of a directory can unlink
# or replace a file after mktemp has created it. That is the same pre-planted
# path class M1 already closed for the watchdog marker and the fixed-name
# fallback log; the variable-driven route into it was left open.
#
# For root the fix is simply not to trust the variable. /tmp is sticky, so
# another user cannot remove root's file there, and mktemp's name is
# unpredictable. Non-root runs (--dry-run previews) keep honouring TMPDIR:
# there is no privilege to protect, and ignoring it would break legitimate
# sandboxes that have no writable /tmp.
TMP_STICKY_WARNED=false
_safe_tmpdir() {
    if [ "$(id -u)" -ne 0 ]; then
        printf '%s' "${TMPDIR:-/tmp}"
        return 0
    fi

    if [ ! -k /tmp ]; then
        # STDERR only: this function's stdout IS the path, and callers capture it inside $(...)
        if [ "$TMP_STICKY_WARNED" = false ]; then
            TMP_STICKY_WARNED=true
            echo "SECURITY: /tmp lacks the sticky bit (+t) - refusing to put root temp files there." >&2
            log_message "CRITICAL: refusing to use insecure /tmp without sticky bit under root"
        fi
        return 1
    fi
    printf '%s' "/tmp"
}

_mktemp_data() {
    local name="${1:-tmp}" f td
    mkdir -p "$DATA_DIR" 2>/dev/null
    f=$(mktemp "${DATA_DIR}/.bs_${name}.XXXXXXXXXX" 2>/dev/null) && { _register_scratch "$f"; printf '%s' "$f"; return 0; }
    td=$(_safe_tmpdir) || return 1
    f=$(mktemp "${td}/botsurgeon_basic_${name}.XXXXXXXXXX" 2>/dev/null) && { _register_scratch "$f"; printf '%s' "$f"; return 0; }
    return 1
}

init_cooldown() {
    # C6: three mutations live below — touching the file into existence,
    # truncating an oversized one, and rewriting it to drop expired rows — and
    # security_preflight calls this unconditionally, so --dry-run performed all
    # three on live state. It is now skipped outright for a preview.
    #
    # This used to be the one thing that made is_in_cooldown correct, which is
    # why the old code only side-stepped the unwritable case. is_in_cooldown
    # checks the timestamp itself now, so a preview that never prunes still
    # reports exactly the cooldowns a real run would honour.
    if [ "$DRY_RUN" = true ]; then
        return 0
    fi

    mkdir -p "$DATA_DIR" 2>/dev/null
    touch "$COOLDOWN_FILE" 2>/dev/null

    if [ -f "$COOLDOWN_FILE" ] && [ ! -w "$COOLDOWN_FILE" ]; then
        log_message "WARNING: $COOLDOWN_FILE not writable - cooldown prune skipped"
        return 0
    fi

    if [ -f "$COOLDOWN_FILE" ]; then
        # L7: defensive in-place truncation. Normally this file self-limits to a
        # handful of entries (blocks within COOLDOWN_SECONDS), but guard against a
        # corrupted/manually-bloated file so the prune loop below stays cheap.
        local line_count
        line_count=$(wc -l < "$COOLDOWN_FILE" 2>/dev/null || echo 0)
        if [ "${line_count:-0}" -gt 20000 ]; then
            local trim_tmp
            if trim_tmp=$(mktemp "${COOLDOWN_FILE}.trim.XXXXXXXXXX" 2>/dev/null); then
                if tail -n 5000 "$COOLDOWN_FILE" > "$trim_tmp" 2>/dev/null && \
                   mv -f "$trim_tmp" "$COOLDOWN_FILE" 2>/dev/null; then
                    :
                else
                    rm -f "$trim_tmp" 2>/dev/null
                fi
            fi
        fi

        local now
        now=$(date +%s)
        local temp_file prune_failed=0
        # C4: allocate beside the cooldown file so rename is atomic within one filesystem.
        if ! temp_file=$(mktemp "${COOLDOWN_FILE}.XXXXXXXXXX" 2>/dev/null); then
            echo "⚠️  Cannot create a temp file - cooldown pruning skipped this run."
            echo "   Check free space on $DATA_DIR."
            log_message "ERROR: mktemp failed - cooldown prune skipped (file left intact)"
            return 0
        fi
        while IFS='|' read -r ip timestamp; do
            [ -z "$ip" ] && continue
            # L5: drop entries with a non-numeric/empty timestamp rather than
            # raising an arithmetic error on a corrupted line.
            [[ "$timestamp" =~ ^[0-9]+$ ]] || continue
            local age=$(( now - timestamp ))
            if [ "$age" -lt "$COOLDOWN_SECONDS" ]; then
                echo "${ip}|${timestamp}" >> "$temp_file" || prune_failed=1
            fi
        done < "$COOLDOWN_FILE"

        if [ "$prune_failed" -eq 1 ]; then
            rm -f "$temp_file" 2>/dev/null
            log_message "ERROR: cooldown prune write failed - file left intact (stale entries kept)"
            echo "⚠️  Could not prune $COOLDOWN_FILE (write failed) - leaving it as-is."
            return 0
        fi

        chmod 600 "$temp_file" 2>/dev/null
        if [ -s "$temp_file" ]; then
            mv -f "$temp_file" "$COOLDOWN_FILE" 2>/dev/null
        else
            rm -f "$temp_file"
            : > "$COOLDOWN_FILE"
        fi
    fi
}

# C6: this reads the AGE rather than trusting init_cooldown to have pruned first.
#
# "Any match is valid" was only true because a prune ran earlier in the same
# process — a coupling that already bit once (M5: a monitor session that never
# re-pruned treated every IP it had ever blocked as permanently cooled, so an
# attacker released by its own 24h nftables timeout could never be re-blocked).
# The prune is a WRITE, and --dry-run must not write; reading the timestamp here
# breaks the dependency in both directions at the cost of one awk.
#
# N3: the comparison must be exact. A substring test ("${ip}|") reports 1.2.3.4
# as cooled when only 11.2.3.4 is present, so the real attacker is skipped while
# the caller still reports a successful block. String equality on field 1 is
# exact by construction — no anchors to forget, and no escaped-dot pattern to be
# mangled by `awk -v` (the hazard t_104.sh documents).
is_in_cooldown() {
    local ip="$1" now newest
    [ -n "$ip" ] || return 1
    [ -f "$COOLDOWN_FILE" ] || return 1

    # "[|]" rather than "|" — a literal pipe in a bracket expression is
    # unambiguous in every awk, not just gawk.
    newest=$(awk -F'[|]' -v want="$ip" '
        $1 == want && $2 ~ /^[0-9]+$/ && $2 + 0 > n { n = $2 + 0 }
        END { print n + 0 }' "$COOLDOWN_FILE" 2>/dev/null)

    [[ "$newest" =~ ^[0-9]+$ ]] || return 1
    [ "$newest" -gt 0 ] || return 1

    now=$(date +%s)
    [ $(( now - newest )) -lt "$COOLDOWN_SECONDS" ]
}

add_to_cooldown() {
    local ip="$1"
    printf '%s|%s\n' "$ip" "$(date +%s)" >> "$COOLDOWN_FILE" 2>/dev/null || \
        log_message "WARNING: could not record cooldown for $ip ($COOLDOWN_FILE not writable)"
}

# ==============================================================================
# SECTION 8B: BLOCK EXPIRY SWEEP  (N4)
# ==============================================================================
# nftables sets, CSF temp bans and firewalld --timeout rules all lift themselves.
# iptables and hosts.deny do not, so those two are swept here against the expiry
# journal. Without this, a block placed on an iptables-only box would outlive its
# stated TTL forever and the "blocks expire" promise would be false on exactly
# the simplest servers.

# M8: record ONE pending deadline per IP — the newest wins.
#
# COOLDOWN_SECONDS (30 min) is far shorter than BLOCK_TTL_HOURS (24 h), so a
# persistent attacker is legitimately re-blocked many times inside one TTL. The
# old code appended a row every time, and expire_blocks acts on rows
# independently: the FIRST deadline came due ~23.5 h early and tore down the
# iptables rule and hosts.deny line while the nftables element (whose timeout
# had been refreshed) still said blocked. The layers disagreed and the block
# lifted early. The journal also grew without bound.
#
# M11: the journal write is now a TRANSACTION, and its result is the caller's
# business.
#
# Every step here used to be best-effort and the function returned 0 regardless:
# `touch || return 0`, a silenced `sed -i`, a silenced append. The caller ignored
# the status and went on to install an iptables DROP. So a full disk, a
# read-only /var, or an interrupted `sed -i` produced a live rule that
# expire_blocks would never learn about — a permanent block on a box whose whole
# TTL promise rests on this one file. That failure lands precisely when it hurts
# most: disks fill during attacks, and attacks are when false positives happen.
#
# Same-directory mktemp + rename, so a partial write can never BECOME the
# journal (the old in-place sed could leave one). Then read the record back
# before committing, because "the append returned 0" and "the deadline is on
# disk" are not the same statement on a filesystem that is out of space.
#
# M12: the row also records WHICH layers this tool put the IP on.
#
# Format is "deadline|ip|layers", layers being a comma list of:
#   ipt      direct iptables/ip6tables DROP
#   hosts    /etc/hosts.deny line
#   imunify  Imunify360 local blacklist entry
#
# Rows written before 1.0.5 have no third field; expire_blocks reads those as
# "ipt,hosts", which is exactly what the old sweep did, so an upgrade over a
# populated journal keeps working.
#
# The point of recording it is attribution. The sweep must lift what BotSurgeon
# put down and nothing else — an automatic teardown of a rule Fail2Ban or the
# admin placed on the same address would be far worse than a block that overran
# its TTL.
#
# Returns 0 only when the deadline for $ip is durably recorded.
_journal_expiry() {
    local ip="$1" layers="$2" deadline tmp
    [ -n "$ip" ] || return 1
    [ -n "$layers" ] || layers="ipt,hosts"
    _ttl_enabled || return 1

    mkdir -p "$DATA_DIR" 2>/dev/null
    [ -d "$DATA_DIR" ] || return 1

    deadline=$(( $(date +%s) + $(_ttl_seconds) ))

    # Beside the journal, never in /tmp: mv is only atomic within one filesystem,
    # and _mktemp_data is allowed to fall back across one (O3).
    tmp=$(mktemp "${EXPIRY_FILE}.XXXXXXXXXX" 2>/dev/null) || return 1

    # M8: one pending deadline per IP, newest wins. The old row is dropped by
    # copying everything else forward, so the original is only ever READ.
    #
    # Exact field comparison, not a regex: _ip_regex escapes dots but an
    # unescaped IP in a pattern would make "1.2.3.4" also match "1x2x3x4", and
    # passing an escaped one through `awk -v` would have the escapes eaten
    # before awk compiles it (the hazard t_104.sh documents). String equality on
    # field 2 has neither problem. Blank lines are dropped while we are here.
    if [ -f "$EXPIRY_FILE" ]; then
        if ! awk -F'[|]' -v want="$ip" 'NF && $2 != want' "$EXPIRY_FILE" > "$tmp" 2>/dev/null; then
            rm -f "$tmp" 2>/dev/null
            return 1
        fi
    fi

    printf '%s|%s|%s\n' "$deadline" "$ip" "$layers" >> "$tmp" 2>/dev/null || {
        rm -f "$tmp" 2>/dev/null
        return 1
    }

    # Verify rather than infer (the O14 principle, applied to the state file).
    if ! grep -qxF "${deadline}|${ip}|${layers}" "$tmp" 2>/dev/null; then
        rm -f "$tmp" 2>/dev/null
        return 1
    fi

    chmod 600 "$tmp" 2>/dev/null
    if ! mv -f "$tmp" "$EXPIRY_FILE" 2>/dev/null; then
        rm -f "$tmp" 2>/dev/null
        return 1
    fi
    return 0
}

# M12: field-exact journal lookups and removals, shared by every caller.
#
# These replace three copies of `sed -i "/|${ex_re}\$/d"` / `grep -qE`. Anchoring
# to end-of-line stopped working the moment the row gained a third field, and
# the escaped-IP regex was a standing invitation to the 1.2.3.4-vs-11.2.3.4
# class of bug. Comparing field 2 as a string cannot go wrong either way.
_journal_has_ip() {
    local ip="$1"
    [ -n "$ip" ] && [ -f "$EXPIRY_FILE" ] || return 1
    awk -F'[|]' -v want="$ip" \
        '$2 == want { found = 1; exit } END { exit !found }' "$EXPIRY_FILE" 2>/dev/null
}

# Drop $ip's pending deadline. Same temp+rename transaction as _journal_expiry,
# so a failure here cannot leave a half-rewritten journal behind either.
_journal_drop_ip() {
    local ip="$1" tmp
    [ -n "$ip" ] && [ -f "$EXPIRY_FILE" ] || return 0
    tmp=$(mktemp "${EXPIRY_FILE}.XXXXXXXXXX" 2>/dev/null) || return 1
    if ! awk -F'[|]' -v want="$ip" 'NF && $2 != want' "$EXPIRY_FILE" > "$tmp" 2>/dev/null; then
        rm -f "$tmp" 2>/dev/null
        return 1
    fi
    chmod 600 "$tmp" 2>/dev/null
    if ! mv -f "$tmp" "$EXPIRY_FILE" 2>/dev/null; then
        rm -f "$tmp" 2>/dev/null
        return 1
    fi
    return 0
}

_unjournal_expiry() {
    _journal_drop_ip "$1"
    return 0
}

# Remove one IP from the layers that have no native expiry.
# Returns 0 on success, 1 on failure.
_expire_one_ip() {
    local ip="$1" layers="$2" failed=0 hd_re
    [ -n "$layers" ] || layers="ipt,hosts"

    case ",${layers}," in
        *,ipt,*)
            if _ipt_has "$ip"; then
                _ipt_del "$ip" INPUT ours >/dev/null 2>&1 || failed=1
                _ipt_has "$ip" && failed=1              # verify, do not infer
            fi
            ;;
    esac

    case ",${layers}," in
        *,hosts,*)
            if [ -f /etc/hosts.deny ]; then
                hd_re=$(_ip_regex "$ip")
                local hd_line_pat="^ALL:[[:space:]]*${hd_re}([[:space:]].*)?#[[:space:]]*BotSurgeon-Basic"
                # Only OUR tagged line. An untagged one belongs to someone else.
                if grep -qE "$hd_line_pat" /etc/hosts.deny 2>/dev/null; then
                    if [ -w /etc/hosts.deny ]; then
                        sed -i -E "/${hd_line_pat}/d" /etc/hosts.deny 2>/dev/null || failed=1
                        grep -qE "$hd_line_pat" /etc/hosts.deny 2>/dev/null && failed=1
                    else
                        failed=1
                    fi
                fi
            fi
            ;;
    esac

    # Removing from the LOCAL blacklist — only delete an entry carrying our comment.
    case ",${layers}," in
        *,imunify,*)
            if command -v imunify360-agent >/dev/null 2>&1; then
                if imunify360-agent blacklist ip list 2>/dev/null | \
                       grep -F "$ip" | grep -q "BotSurgeon-Basic"; then
                    imunify360-agent blacklist ip delete "$ip" >/dev/null 2>&1 || failed=1
                fi
            fi
            ;;
    esac

    return "$failed"
}

expire_blocks() {
    [ -f "$EXPIRY_FILE" ] || return 0
    [ "$(id -u)" -eq 0 ] || return 0
    [ "$DRY_RUN" = true ] && return 0

    local now expired=0 stuck=0 tmp journal_write_failed=0
    now=$(date +%s)
    # C3: allocate beside the expiry file so rename is atomic within one filesystem.
    tmp=$(mktemp "${EXPIRY_FILE}.XXXXXXXXXX" 2>/dev/null) || {
        log_message "ERROR: expiry sweep could not create a temp file - journal left intact"
        return 0
    }

    local deadline ip layers
    while IFS='|' read -r deadline ip layers; do
        [ -z "$ip" ] && continue
        # M12: rows written before 1.0.5 have no layer field. They can only have
        # come from the two layers the old sweep handled, so read them as such.
        [ -n "$layers" ] || layers="ipt,hosts"
        # A corrupted deadline must not strand a block forever: treat it as due.
        if [[ "$deadline" =~ ^[0-9]+$ ]] && [ "$deadline" -gt "$now" ]; then
            printf '%s|%s|%s\n' "$deadline" "$ip" "$layers" >> "$tmp" || journal_write_failed=1
            continue
        fi
        is_valid_ip "$ip" || continue
        if _expire_one_ip "$ip" "$layers"; then
            expired=$((expired + 1))
            log_message "EXPIRED: block on $ip lifted (TTL reached)"
        else
            printf '%s|%s|%s\n' "$now" "$ip" "$layers" >> "$tmp" || journal_write_failed=1
            stuck=$((stuck + 1))
            log_message "ERROR: could not lift expired block on $ip (layers: $layers) - retrying next run"
        fi
    done < "$EXPIRY_FILE"

    if [ "$journal_write_failed" -eq 1 ]; then
        rm -f "$tmp" 2>/dev/null
        echo "❌ Could not rewrite $EXPIRY_FILE - leaving it intact. No deadline has been lost."
        log_message "ERROR: expiry journal rewrite aborted (write failure) - original kept"
        return 1
    fi

    chmod 600 "$tmp" 2>/dev/null
    if [ -s "$tmp" ]; then
        mv -f "$tmp" "$EXPIRY_FILE" 2>/dev/null || {
            rm -f "$tmp" 2>/dev/null
            log_message "ERROR: journal rename failed"
            return 1
        }
    else
        rm -f "$tmp" 2>/dev/null
        : > "$EXPIRY_FILE"
    fi

    # M3 (b2) / P2-2a: Prune the bare-rule marker file against live iptables rules.
    # A marker for a rule that is gone is a spent claim and is pruned;
    # a marker for an active rule is preserved regardless of journal state.
    # Gate behind responsive iptables check so lock contention does not prune live markers.
    if [ -f "$IPT_BARE_FILE" ] && iptables -S INPUT >/dev/null 2>&1; then
        local bare_tmp
        bare_tmp=$(mktemp "${IPT_BARE_FILE}.XXXXXXXXXX" 2>/dev/null) && {
            while IFS= read -r bip; do
                [ -n "$bip" ] && is_valid_ip "$bip" && _ipt_has "$bip" && printf '%s\n' "$bip" >> "$bare_tmp"
            done < "$IPT_BARE_FILE"
            mv -f "$bare_tmp" "$IPT_BARE_FILE" 2>/dev/null || rm -f "$bare_tmp" 2>/dev/null
        }
    fi

    if [ "$expired" -gt 0 ]; then
        echo "⏱️  Expired $expired block(s) past their ${BLOCK_TTL_HOURS}h lifetime"
        # M8: only persist when no firewall manager owns the ruleset.
        if ! _has_firewall_manager; then
            _persist_iptables
        fi
    fi

    if [ "$stuck" -gt 0 ]; then
        echo "⚠️  $stuck expired block(s) could NOT be lifted - they are still enforced."
    fi

    return 0
}

# ==============================================================================
# SECTION 9: WHITELIST MANAGEMENT
# ==============================================================================

_ipv4_to_int() {
    local a b c d
    IFS=. read -r a b c d <<< "$1"
    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

# True if IPv4 $1 falls inside IPv4 CIDR $2 (e.g. 203.0.113.7 in 203.0.113.0/24).
#
# C3: a /0 mask is REFUSED, not honoured.
#
# "[ $mask -eq 0 ] && return 0" meant that a single "0.0.0.0/0" token anywhere
# in csf.allow whitelisted the entire IPv4 internet, so is_whitelisted_ip
# returned true for every address, block_ip_comprehensive refused every block,
# and each run reported "Whitelisted - skipping" with protection completely off
# and no warning anywhere. CSF advanced-allow lines like
# "tcp|in|d=3306|s=0.0.0.0/0" are ordinary on real cPanel servers.
#
# "Allow the entire internet" is never a meaningful whitelist entry for a tool
# whose whole job is to block a subset of the internet, so it is treated as a
# configuration error and reported rather than obeyed.
WHITELIST_ALLOW_ALL_WARNED=false

_ipv4_in_cidr() {
    local ip="$1" cidr="$2" net mask ipint netint sh
    net="${cidr%/*}"; mask="${cidr#*/}"
    [[ "$mask" =~ ^[0-9]+$ ]] && [ "$mask" -le 32 ] || return 1
    is_ipv4 "$ip" && is_ipv4 "$net" || return 1
    if [ "$mask" -eq 0 ]; then
        if [ "$WHITELIST_ALLOW_ALL_WARNED" = false ]; then
            WHITELIST_ALLOW_ALL_WARNED=true
            echo "⚠️  IGNORING an 'allow everything' whitelist entry ($cidr)."
            echo "    A /0 range would exempt every address on the internet and turn"
            echo "    BotSurgeon off silently. Remove it, or narrow it to real ranges."
            log_message "WARNING: ignored allow-all whitelist entry $cidr"
        fi
        return 1
    fi
    ipint=$(_ipv4_to_int "$ip"); netint=$(_ipv4_to_int "$net")
    sh=$(( 32 - mask ))
    [ $(( ipint >> sh )) -eq $(( netint >> sh )) ]
}

# M16: real IPv6 prefix matching.
#
# IPv6 CIDRs were handled as an EXACT TEXTUAL match on the base address:
# "2001:db8::/32" matched 2001:db8:: and nothing else. Every other address in
# the range - which is to say all 2^96 of them - fell through unmatched. So an
# operator who listed their IPv6 edge ranges in proxies.conf, or a trusted v6
# network in whitelist.conf, had no protection at all for those ranges, and our
# nft chain at priority -1 would happily override an administrator's explicit
# ip6tables ACCEPT. The gap was silent: nothing said "that entry did nothing".
#
# Cloudflare alone publishes seven IPv6 ranges. On a dual-stack cPanel box this
# is not an edge case, and #7's deterministic escape hatch is worthless without
# it.

# Expand any valid IPv6 address to its full 32-hex-digit form (no colons), so
# two addresses can be compared as fixed-width strings. "2001:db8::1" becomes
# "20010db8000000000000000000000001".
_ipv6_expand() {
    local ip="$1" head tail part out=""
    is_ipv6 "$ip" || return 1

    local -a groups=() hg=() tg=()
    if [[ "$ip" == *::* ]]; then
        head="${ip%%::*}"
        tail="${ip#*::}"
        [ -n "$head" ] && IFS=':' read -r -a hg <<< "$head"
        [ -n "$tail" ] && IFS=':' read -r -a tg <<< "$tail"
        local zeros=$(( 8 - ${#hg[@]} - ${#tg[@]} ))
        [ "$zeros" -ge 1 ] || return 1
        [ "${#hg[@]}" -gt 0 ] && groups=( "${hg[@]}" )
        while [ "$zeros" -gt 0 ]; do
            groups+=( 0 )
            zeros=$(( zeros - 1 ))
        done
        [ "${#tg[@]}" -gt 0 ] && groups+=( "${tg[@]}" )
    else
        IFS=':' read -r -a groups <<< "$ip"
    fi

    [ "${#groups[@]}" -eq 8 ] || return 1
    for part in "${groups[@]}"; do
        # 16# forces hex regardless of leading zeros; %04x re-pads.
        printf -v part '%04x' "$(( 16#$part ))" 2>/dev/null || return 1
        out+="$part"
    done
    printf '%s' "$out"
}

# True if IPv6 $1 falls inside IPv6 CIDR $2 (e.g. 2606:4700::1 in 2606:4700::/32).
_ipv6_in_cidr() {
    local ip="$1" cidr="$2" net mask ipx netx whole rem a b sh
    net="${cidr%/*}"; mask="${cidr#*/}"
    [[ "$mask" =~ ^[0-9]+$ ]] && [ "$mask" -le 128 ] || return 1
    is_ipv6 "$ip" && is_ipv6 "$net" || return 1

    # C3, for v6: "::/0" is the whole internet, which is never a whitelist.
    if [ "$mask" -eq 0 ]; then
        if [ "$WHITELIST_ALLOW_ALL_WARNED" = false ]; then
            WHITELIST_ALLOW_ALL_WARNED=true
            echo "⚠️  IGNORING an 'allow everything' whitelist entry ($cidr)."
            echo "    A /0 range would exempt every address on the internet and turn"
            echo "    BotSurgeon off silently. Remove it, or narrow it to real ranges."
            log_message "WARNING: ignored allow-all whitelist entry $cidr"
        fi
        return 1
    fi

    ipx=$(_ipv6_expand "$ip")   || return 1
    netx=$(_ipv6_expand "$net") || return 1

    whole=$(( mask / 4 ))    # complete hex digits that must match exactly
    rem=$(( mask % 4 ))      # leftover bits inside the next digit

    [ "$whole" -eq 0 ] || [ "${ipx:0:whole}" = "${netx:0:whole}" ] || return 1
    [ "$rem" -eq 0 ] && return 0

    a=$(( 16#${ipx:whole:1} ))
    b=$(( 16#${netx:whole:1} ))
    sh=$(( 4 - rem ))
    [ $(( a >> sh )) -eq $(( b >> sh )) ]
}

# Family-dispatching containment test. Both helpers validate the family of BOTH
# operands, so a v4 address against a v6 range (or vice versa) is simply false.
_cidr_contains() {
    local ip="$1" cidr="$2"
    case "$cidr" in
        *:*) _ipv6_in_cidr "$ip" "$cidr" ;;
        *)   _ipv4_in_cidr "$ip" "$cidr" ;;
    esac
}

# True if $1 is whitelisted by any plain-IP or CIDR entry in file $2. Honors
# CIDR ranges (the substring grep it replaces silently ignored them — C3), and
# handles CSF advanced-allow tokens like "s=1.2.3.0/24".
#
# C3: only SOURCE-position tokens count. "${token##*=}" stripped any key= prefix
# indiscriminately, so a destination in an outbound rule ("tcp|out|d=1.2.3.4|
# s=...") whitelisted that host for INBOUND traffic, and a port token like
# "d=3306" was tested as though it were an address. CSF advanced-rule fields are
# now classified: s= is a source, d=/protocol/direction/port tokens are skipped,
# and a bare token (the plain "1.2.3.4" form of csf.allow and of our own
# whitelist.conf) is still treated as a source.
_ip_matches_whitelist_file() {
    local ip="$1" file="$2" line token cand
    [ -f "$file" ] || return 1
    while IFS= read -r line; do
        line="${line%%#*}"        # drop comments
        line="${line//|/ }"       # CSF advanced rules are pipe-delimited
        for token in $line; do
            case "$token" in
                s=*)   cand="${token#s=}" ;;   # explicit source - honour it
                *=*)   continue ;;             # d=, and any other keyed field
                *)     cand="$token" ;;        # bare address / CIDR
            esac
            [ -n "$cand" ] || continue
            case "$cand" in
                # M16: real prefix matching for both families. This used to be
                # _ipv4_in_cidr with an exact-base-address fallback for v6, so
                # every IPv6 range in this file covered exactly one address.
                */*) _cidr_contains "$ip" "$cand" && return 0 ;;
                *)   [ "$cand" = "$ip" ] && return 0 ;;
            esac
        done
    done < "$file"
    return 1
}

is_whitelisted_ip() {
    local ip="$1"

    if is_ipv4 "$ip"; then
        case "$ip" in
            127.*|10.*|192.168.*) return 0 ;;   # L4: full 127/8 loopback range
            172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
            8.8.8.8|8.8.4.4|1.1.1.1|1.0.0.1) return 0 ;;
        esac
    fi
    if is_ipv6 "$ip"; then
        case "$ip" in
            ::1|fe80:*|fc00:*|fd00:*) return 0 ;;
        esac
    fi

    # Server's own IPs (WordPress cron, health checks, internal API calls)
    if [ -n "$SERVER_IPS" ]; then
        local sip
        for sip in $SERVER_IPS; do
            [ "$ip" = "$sip" ] && return 0
        done
    fi

    # O6: honour the admin's own iptables ACCEPT rules.
    #
    # Our nft chain sits at priority -1, ahead of the iptables filter table, so
    # a drop there silently overrides an explicit `-A INPUT -s trusted -j ACCEPT`
    # the admin wrote. The C3-era fix taught the blocker to defer to CSF,
    # firewalld and Imunify360, but on a plain-iptables host there is no manager
    # to defer to and these rules ARE the whitelist. Collected once per run.
    if [ "$IPT_ACCEPT_SOURCES" = "unknown" ] || [ -z "$IPT_ACCEPT_SOURCES" ]; then
        IPT_ACCEPT_SOURCES="none"
        if command -v iptables >/dev/null 2>&1; then
            local ipt_out
            ipt_out=$( { iptables -S INPUT 2>/dev/null
                         ip6tables -S INPUT 2>/dev/null; } | \
                awk '/-j ACCEPT/ { for (i = 1; i < NF; i++)
                                       if ($i == "-s") { print $(i+1); break } }' )
            [ -n "$ipt_out" ] && IPT_ACCEPT_SOURCES="$ipt_out"
        fi
    fi
    if [ -n "$IPT_ACCEPT_SOURCES" ] && [ "$IPT_ACCEPT_SOURCES" != "none" ]; then
        local acc
        for acc in $IPT_ACCEPT_SOURCES; do
            case "$acc" in
                # M16: same real prefix matching. An admin's explicit
                # "ip6tables -A INPUT -s 2001:db8::/32 -j ACCEPT" was honoured
                # for the base address only, so our nft chain at priority -1
                # overrode it for every other host in their trusted network.
                # A /0 ACCEPT is the default-open policy, not a whitelist, and
                # _cidr_contains refuses it for both families.
                */*) _cidr_contains "$ip" "$acc" && return 0 ;;
                *)   [ "$ip" = "$acc" ] && return 0 ;;
            esac
        done
    fi

    # CSF whitelist (honors CIDR ranges, not just exact strings)
    if [ -f /etc/csf/csf.allow ]; then
        _ip_matches_whitelist_file "$ip" /etc/csf/csf.allow && return 0
    fi

    # M2: the whitelist and proxy files decide who CANNOT be blocked, which
    # makes them higher-impact than the config file — and in 1.0.2 they were the
    # ones with no ownership check at all. Anyone able to write them could
    # exempt an attacker outright. They now pass the same root-ownership and
    # not-group/world-writable gate as the config, evaluated once per run so a
    # rejected file does not print a warning for every candidate IP.
    if [ "$WHITELIST_TRUSTED" = "unknown" ] || [ -z "$WHITELIST_TRUSTED" ]; then
        if [ -f "$WHITELIST_FILE" ] && _file_is_root_safe "$WHITELIST_FILE" "Whitelist file"; then
            WHITELIST_TRUSTED=yes
        else
            WHITELIST_TRUSTED=no
        fi
    fi
    if [ "$WHITELIST_TRUSTED" = yes ]; then
        _ip_matches_whitelist_file "$ip" "$WHITELIST_FILE" && return 0
    fi

    # N1: operator-supplied CDN / load-balancer / reverse-proxy ranges. Same
    # CIDR-aware parser, so "173.245.48.0/20"-style published edge ranges work
    # directly. This is the deterministic complement to the UA-diversity
    # heuristic in detect_proxy_ips().
    if [ "$PROXY_RANGES_TRUSTED" = "unknown" ] || [ -z "$PROXY_RANGES_TRUSTED" ]; then
        if [ -f "$PROXY_RANGES_FILE" ] && _file_is_root_safe "$PROXY_RANGES_FILE" "Proxy ranges file"; then
            PROXY_RANGES_TRUSTED=yes
        else
            PROXY_RANGES_TRUSTED=no
        fi
    fi
    if [ "$PROXY_RANGES_TRUSTED" = yes ]; then
        _ip_matches_whitelist_file "$ip" "$PROXY_RANGES_FILE" && return 0
    fi

    return 1
}

# ==============================================================================
# SECTION 9B: LEGITIMATE BOT VERIFICATION
# ==============================================================================
# Prevents false-positive blocking of search engine crawlers and monitoring
# services by verifying identity via forward-confirmed reverse DNS (FCrDNS).

is_known_good_ua() {
    local ua="$1"
    [ -z "$ua" ] && return 1
    # O7: printf, not echo. A User-Agent is remote input, and `echo "-n"` (or
    # "-e") is swallowed as an option by the builtin instead of being printed,
    # so a crafted UA could skip this check entirely.
    printf '%s\n' "$ua" | grep -qiE "$KNOWN_GOOD_UA_PATTERNS"
}

# N13: memoize the FCrDNS verdict for the run.
#
# Every block candidate is verified here, and the access-log analyser verifies
# the same IP again before it ever reaches block_ip_comprehensive. Each check is
# up to two dig queries at +time=2, so a worst case of ~4s per IP was being paid
# twice. In --emergency (MAX_BLOCKS_PER_RUN=50) that alone could approach the
# watchdog timeout, killing the response mid-attack.
# O13: associative arrays are a bash 4 feature. When `declare -A` failed the
# code carried on regardless, and `${RDNS_VERDICT_CACHE[$ip]+isset}` then
# evaluated the IP as an ARITHMETIC subscript on an indexed array — "bad array
# subscript" on every single lookup. Record whether the declaration worked and
# simply skip the cache when it did not: slower, but correct everywhere.
if declare -A RDNS_VERDICT_CACHE 2>/dev/null; then
    HAVE_ASSOC=true
fi

is_verified_search_bot() {
    local ip="$1"
    [ -n "$ip" ] || return 1

    if [ "$HAVE_ASSOC" != true ]; then
        _verify_search_bot_uncached "$ip"
        return
    fi

    if [ -n "${RDNS_VERDICT_CACHE[$ip]+isset}" ]; then
        return "${RDNS_VERDICT_CACHE[$ip]}"
    fi

    local rc=1
    _verify_search_bot_uncached "$ip" && rc=0
    RDNS_VERDICT_CACHE["$ip"]=$rc
    return "$rc"
}

_verify_search_bot_uncached() {
    local ip="$1"
    command -v dig >/dev/null 2>&1 || return 1

    local rdns
    rdns=$(dig +short +time=2 +tries=1 -x "$ip" 2>/dev/null | head -1)
    [ -z "$rdns" ] && return 1

    case "$rdns" in
        *.googlebot.com.|*.google.com.|*.search.msn.com.|*.crawl.yahoo.net.)
            ;;
        *.yandex.com.|*.yandex.ru.|*.yandex.net.|*.baidu.com.|*.baidu.jp.)
            ;;
        *.applebot.apple.com.|*.duckduckgo.com.|*.facebookexternalhit.com.)
            ;;
        *.uptimerobot.com.|*.pingdom.com.|*.statuscake.com.|*.site24x7.com.)
            ;;
        *.semrush.com.|*.ahrefs.com.|*.petalsearch.com.)
            ;;
        *)
            return 1
            ;;
    esac

    # M10: forward-confirm using the record type that matches the candidate IP —
    # an IPv6 crawler IP must be verified against AAAA, not A (which would always
    # fail and cause the bot to be treated as unverified).
    local qtype="A"
    is_ipv6 "$ip" && qtype="AAAA"
    local fwd
    fwd=$(dig +short +time=2 +tries=1 "$qtype" "$rdns" 2>/dev/null | head -1)
    [ "$fwd" = "$ip" ] && return 0
    return 1
}

# ==============================================================================
# SECTION 9B-bis: SHARED ACCESS-LOG PARSER  (M6)
# ==============================================================================
# One parser, used by the main analyser, the domlog analyser and the CDN
# detector. Two reasons: the three copies had drifted before (the code comments
# already warn "keep the two in sync"), and all three shared the same two
# remotely-triggerable parsing bugs.
#
# (a) POSITIONAL FIELDS. path was $(7+offs) and status $(9+offs), which assumes
#     the request line is exactly three whitespace-separated tokens. Apache logs
#     %r verbatim, so a request line carrying an extra token —
#     `GET /a b HTTP/1.1` — shifted every later field: status became
#     `HTTP/1.1"`, which matches neither /^4/ nor the three-digit panel gate. An
#     attacker could pad a scan with malformed requests to dilute their own
#     measured error rate, and legitimate odd requests silently skewed scoring.
#     Fields are now taken from the QUOTE structure, which is what actually
#     delimits a combined log line.
#
# (b) QUOTE PARITY. extract_ua() walked even-numbered fields of a split on '"'
#     and kept the last. Apache escapes a literal quote inside a User-Agent as
#     \" — the '"' byte is still in the line — so one embedded quote made the
#     field count odd, the walk landed on the wrong parity, and the UA came back
#     EMPTY. Sending a User-Agent containing a quote therefore switched off
#     bot-UA scoring and hid the request from the CDN detector's UA counter.
#     Escaped quotes are neutralised before splitting.
#
# bs_parse() sets ip / path / pathonly / status / ua and returns 1, or returns 0
# when the line is not usable. Callers must not read those before checking.
AWK_LOGPARSE='
function bs_ip(v) {
    return (v ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ || v ~ /^([0-9A-Fa-f]*:){2,}[0-9A-Fa-f:]+$/)
}
function bs_parse(   line, n, q, r, s, pre, np, i) {
    line = $0
    # Neutralise escaped quotes so the field count keeps its parity (b).
    gsub(/\\"/, "", line)
    n = split(line, q, "\"")
    if (n < 3) return 0

    # q[1] = "<client IP> <ident> <user> [date] " (optionally vhost-prefixed)
    # q[2] = request line, q[3] = " <status> <bytes> ", q[n-1] = last quoted
    #        field = User-Agent in combined format.
    np = split(q[1], pre, " ")
    ip = ""
    for (i = 1; i <= np && i <= 3; i++) {
        if (bs_ip(pre[i])) { ip = pre[i]; break }
    }
    if (ip == "") return 0

    split(q[2], r, " ")
    path = (r[2] != "" ? r[2] : r[1])
    split(q[3], s, " ")
    status = s[1]
    ua = (n >= 6 ? q[n-1] : "")

    pathonly = path
    sub(/\?.*/, "", pathonly)
    return 1
}
'

# O2: the analysis window is read once per run and shared.
#
# tail -n NUM_LINES over $ACTIVE_LOG was being run five separate times per run
# (analyze_traffic, detect_proxy_ips, analyze_access_log_threats, the
# fingerprint snapshot, block_aggressive_ips) against a file the web server is
# actively writing. The N14 note identified this pattern and fixed only the
# fingerprint path. Every consumer now reads the same snapshot, which also means
# they all score the SAME set of requests — previously each pass could see a
# slightly different window and reach a different verdict about the same IP.
# M18: true only when EVERY stage of the pipeline just run exited cleanly.
#
# Pass "${PIPESTATUS[@]}" immediately after the pipeline — that array is
# clobbered by the very next command, including by the `[` test that would
# otherwise inspect it.
#
# This exists because "the temp file is empty" and "the scan found nothing" were
# the same observation everywhere in this file, and the analysers report the
# second one as a green tick. A failed tail, a killed awk or a full disk
# therefore printed "✅ No threats detected" — the identical false-all-clear
# class the C4 note already fixed for mktemp, left open for the pipelines those
# mktemps feed.
_pipe_ok() {
    local st
    for st in "$@"; do
        [ "$st" -eq 0 ] || return 1
    done
    return 0
}

_log_window_source() {
    local src="${1:-$ACTIVE_LOG}"
    local -a st
    if _ensure_log_window "$src"; then
        cat "$LOG_WINDOW_FILE" 2>/dev/null
        return
    fi
    # Snapshot unavailable (no temp space) — fall back to a direct read.
    # M18: grep exits 1 when NOTHING MATCHED, which is a legitimately empty
    # window and not a failure; only a failed read, or a grep error (>1), means
    # the caller must not treat an empty result as evidence of anything.
    tail -n "$NUM_LINES" "$src" 2>/dev/null | grep '".*HTTP/'
    st=("${PIPESTATUS[@]}")
    [ "${st[0]}" -eq 0 ] && [ "${st[1]}" -le 1 ]
}

# O15: report traffic the analysers cannot see.
#
# Every analyser pre-filters on '".*HTTP/'. Apache logs a malformed request line
# as "-", so a flood of malformed requests is invisible to log-based scoring
# entirely — and a malformed-request flood is itself a strong attack signal, not
# noise. This does not score anything (the source IP of such a line cannot be
# trusted to parse), but it stops the condition being silent: an operator seeing
# "1.2M requests, 4 analysed" knows to look at the connection-based detection.
_report_unparsed_ratio() {
    local src="${1:-$ACTIVE_LOG}" total kept dropped pct
    [ -n "$src" ] && [ -f "$src" ] || return 0

    # O5 (1.0.4): total and kept must describe the SAME window. total came from
    # a fresh tail of the live log while kept came from the snapshot taken
    # earlier in the run — on a busy server the file grows in between, so
    # "dropped" counted lines the snapshot never had the chance to see and this
    # warning could fire at 25%+ on a perfectly healthy log. The snapshot now
    # records its own pre-filter line count, so both sides come from one read.
    if _ensure_log_window "$src"; then
        total="${LOG_WINDOW_TOTAL:-0}"
        kept=$(grep -c . "$LOG_WINDOW_FILE" 2>/dev/null) || kept=0
    else
        total=$(tail -n "$NUM_LINES" "$src" 2>/dev/null | grep -c . ) || total=0
        kept=$(_log_window_source "$src" | grep -c . ) || kept=0
    fi
    [ "${total:-0}" -lt 100 ] && return 0
    dropped=$(( total - kept ))
    [ "$dropped" -le 0 ] && return 0
    pct=$(( dropped * 100 / total ))
    if [ "$pct" -ge 25 ]; then
        echo "⚠️  ${pct}% of the last ${total} log lines have no parsable request line."
        echo "    ${dropped} line(s) skipped. A malformed-request flood looks like this,"
        echo "    and it is invisible to log-based scoring — check connection counts."
        log_message "WARNING: ${pct}% of log window unparsable (${dropped}/${total} lines)"
    fi
    return 0
}

# ==============================================================================
# SECTION 9C: CDN / REVERSE-PROXY DETECTION  (N1)
# ==============================================================================
# The single most damaging false positive this tool can produce is blocking a
# shared front end. If a server sits behind Cloudflare/Sucuri/a load balancer
# without mod_remoteip, EVERY access-log line carries the edge IP instead of the
# visitor's. Attackers routinely probe *through* a CDN, so those probes are
# attributed to the edge — and one block takes every site behind that PoP
# offline for every visitor. The same applies to a corporate NAT gateway.
#
# The signal needs no external data: a shared front end presents MANY DISTINCT
# USER AGENTS from one address, because it is multiplexing many real browsers.
# A single attacking client presents one, or a handful.
#
# The success-rate gate is what stops this from becoming an evasion hatch. A
# UA-rotating scanner also shows many agents, but its traffic is overwhelmingly
# 4xx; a real front end passes mostly 2xx/3xx. Requiring BOTH high UA diversity
# and mostly-successful traffic means an attacker would have to serve mainly
# successful requests to hide here — at which point they are not scanning, and
# their threat score collapses anyway. Operators who prefer the opposite
# trade-off can raise PROXY_UA_THRESHOLD or set it to 0.
#
# Detection runs ONCE per run (in security_preflight) and the verdict is
# consulted centrally in block_ip_comprehensive, so it protects every block
# path: connection floods, access-log threats, domlog threats and monitor mode.

PROXY_IPS_FILE=""

detect_proxy_ips() {
    # M5: --monitor re-runs this every few cycles now, so release the previous
    # snapshot rather than leaking one temp file per refresh.
    [ -n "$PROXY_IPS_FILE" ] && rm -f "$PROXY_IPS_FILE" 2>/dev/null
    PROXY_IPS_FILE=""
    [ "$PROXY_HEURISTIC_MODE" = off ] && return 0        # M17: switched off
    [ "${PROXY_UA_THRESHOLD:-0}" -lt 1 ] && return 0     # heuristic disabled
    [ -n "$ACTIVE_LOG" ] && [ -f "$ACTIVE_LOG" ] || return 0

    local tmp
    tmp=$(_mktemp_data proxy) || return 0

    _log_window_source | \
    awk -v min_ua="$PROXY_UA_THRESHOLD" \
        -v min_total="$PROXY_MIN_TOTAL" \
        -v min_per_ua="$PROXY_MIN_REQS_PER_UA" \
        -v min_paths="$PROXY_MIN_PATHS" '
    '"$AWK_LOGPARSE"'
    {
        if (!bs_parse()) next
        if (ip == "127.0.0.1" || ip == "::1") next

        total[ip]++
        if (status ~ /^[23]/) ok[ip]++
        if (ua != "" && ua != "-" && !((ip SUBSEP ua) in seen)) {
            seen[ip SUBSEP ua] = 1
            uacount[ip]++
        }
        # M2 (1.0.4): count DISTINCT paths too - see the END block. Stop
        # tracking once the floor is met so this array stays tiny on a
        # 100k-line window (only the comparison below needs it).
        if (pathcount[ip] < min_paths && pathonly != "" &&
            !((ip SUBSEP pathonly) in seenp)) {
            seenp[ip SUBSEP pathonly] = 1
            pathcount[ip]++
        }
    }
    END {
        for (ip in total) {
            # C2: UA diversity alone was an exemption an attacker could hand
            # themselves — 20 requests across 8 agents costs nothing to fake,
            # and the exemption was absolute (checked before cooldown, before
            # the safety limit, before everything). Three conditions now have to
            # hold together, and the third is the one that cannot be faked
            # cheaply.
            if (total[ip] < min_total) continue           # too little evidence
            if (uacount[ip] < min_ua) continue            # not multiplexing

            # A real front end shows each user agent MANY times, because real
            # browsers come back. A client rotating a UA list shows about one
            # request per agent: the traffic, not the agent string, is what
            # costs them. This ratio is the discriminator.
            if (uacount[ip] * min_per_ua > total[ip]) continue

            # M2 (1.0.4): volume + UA repetition still had a cheap counterfeit.
            # 200 requests of "GET /" across 8 agents (25 each) satisfies every
            # test above - the homepage returns 200, so the success ratio is
            # ~100% - and one shell loop buys it. What that traffic does NOT
            # look like is BROWSING: a real edge multiplexes browsers pulling a
            # site, so it presents many distinct paths, while a self-exemption
            # loop hammers one or two.
            #
            # Deliberately NOT fixed by raising min_total. The floors trade in
            # opposite directions and the costs are wildly asymmetric: too low
            # and an attacker skips a block, too high and a genuine Cloudflare
            # edge loses its exemption and one block takes every site behind
            # that PoP offline for every visitor. Path diversity discriminates
            # without moving the volume floor at all.
            #
            # Honest limit: an attacker who also varies the path defeats this.
            # It raises the price of the cheapest counterfeit; it is not a
            # proof. The deterministic guarantee remains PROXY_RANGES_FILE.
            if (pathcount[ip] < min_paths) continue       # not browsing a site

            okr = (ok[ip] ? ok[ip] : 0) * 100 / total[ip]
            if (okr < 50) continue                        # scanner, not a proxy
            printf "%s|%d|%d|%d\n", ip, uacount[ip], total[ip], okr
        }
    }' > "$tmp" 2>/dev/null
    local -a proxy_status=("${PIPESTATUS[@]}")

    if ! _pipe_ok "${proxy_status[@]}"; then
        rm -f "$tmp" 2>/dev/null
        echo "⚠️  WARNING: proxy detection pipeline failed - heuristic CDN/proxy detection could not run."
        log_message "WARNING: proxy detection pipeline failed (${proxy_status[*]}) - CDN heuristic skipped"
        return 1
    fi

    if [ -s "$tmp" ]; then
        PROXY_IPS_FILE="$tmp"
        local pcount
        pcount=$(wc -l < "$tmp" 2>/dev/null)
        if [ "$PROXY_HEURISTIC_MODE" = enforce ]; then
            echo "🛡️  CDN/PROXY PROTECTION: ${pcount:-0} address(es) look like a shared front end"
            echo "    (many distinct user agents, mostly successful requests). These will"
            echo "    NOT be blocked — blocking one would cut off everyone behind it:"
        else
            echo "🛡️  CDN/PROXY NOTICE: ${pcount:-0} address(es) look like a shared front end"
            echo "    (many distinct user agents, mostly successful requests). The heuristic"
            echo "    is advisory here, so these CAN still be blocked — list any that really"
            echo "    are your edge in $PROXY_RANGES_FILE:"
        fi
        local pip puac ptot pokr
        while IFS='|' read -r pip puac ptot pokr; do
            [ -z "$pip" ] && continue
            echo "      • $pip  — $puac user agents, $ptot requests, ${pokr}% successful"
        done < "$tmp"
        echo "    Behind a CDN? Install mod_remoteip so logs carry the real client IP."
        echo
        log_message "CDN/proxy protection active for ${pcount:-0} address(es)"
    else
        rm -f "$tmp" 2>/dev/null
    fi
    return 0
}

is_proxy_ip() {
    [ -n "$PROXY_IPS_FILE" ] && [ -f "$PROXY_IPS_FILE" ] || return 1
    local pr
    pr=$(_ip_regex "$1")
    grep -qE "^${pr}[|]" "$PROXY_IPS_FILE" 2>/dev/null
}

# M17: decide ONCE per run whether the heuristic may refuse a block.
#
# The deterministic criterion is PROXY_RANGES_FILE, which is already consulted
# by is_whitelisted_ip - ahead of this heuristic and ahead of everything else -
# so an operator who has declared their edge ranges is fully protected without
# the guess. On that server the heuristic is pure downside: it can only add an
# exemption an attacker could have assigned themselves. On a server with no
# declared ranges the calculus inverts, because the failure it prevents (one
# block taking a whole CDN PoP's worth of sites offline) is far worse than the
# one it causes.
PROXY_HEURISTIC_MODE=enforce

_resolve_proxy_heuristic_mode() {
    local have_ranges=no
    if [ -f "$PROXY_RANGES_FILE" ] && \
       _file_is_root_safe "$PROXY_RANGES_FILE" "Proxy ranges file" >/dev/null 2>&1 && \
       grep -qvE '^[[:space:]]*(#|$)' "$PROXY_RANGES_FILE" 2>/dev/null; then
        have_ranges=yes
    fi

    case "$PROXY_HEURISTIC" in
        enforce|advisory|off) PROXY_HEURISTIC_MODE="$PROXY_HEURISTIC" ;;
        *)
            if [ "$have_ranges" = yes ]; then
                PROXY_HEURISTIC_MODE=advisory
            else
                PROXY_HEURISTIC_MODE=enforce
            fi
            ;;
    esac

    case "$PROXY_HEURISTIC_MODE" in
        enforce)
            echo "🛡️  CDN/proxy heuristic: ENFORCING (it can refuse a block)."
            echo "    Be aware: an address that serves ~${PROXY_MIN_TOTAL} mostly-successful requests"
            echo "    across ${PROXY_UA_THRESHOLD} user agents and ${PROXY_MIN_PATHS} paths earns request-level exemption."
            echo "    Connection floods require 2x AUTO_BLOCK_THRESHOLD ($(( AUTO_BLOCK_THRESHOLD * 2 ))) to trigger mitigation."
            echo "    To close all ambiguity, list your real edge ranges (IPv4 and IPv6, CIDR welcome) in:"
            echo "      $PROXY_RANGES_FILE"
            echo "    BotSurgeon then switches the heuristic to advisory by itself."
            log_message "Proxy heuristic mode: enforce (no deterministic ranges declared)"
            ;;
        advisory)
            echo "🛡️  CDN/proxy heuristic: ADVISORY - $PROXY_RANGES_FILE decides who cannot be blocked."
            log_message "Proxy heuristic mode: advisory (deterministic ranges in use)"
            ;;
        off)
            log_message "Proxy heuristic mode: off"
            ;;
    esac
}

# Echo the recorded "ip|uacount|total|ok%" line for a detected proxy IP.
_proxy_detail() {
    [ -n "$PROXY_IPS_FILE" ] && [ -f "$PROXY_IPS_FILE" ] || return 1
    local pr
    pr=$(_ip_regex "$1")
    grep -E "^${pr}[|]" "$PROXY_IPS_FILE" 2>/dev/null | head -1
}

# ==============================================================================
# SECTION 10: WEB SERVER DETECTION
# ==============================================================================

resolve_apache_access_log() {
    local candidate
    for candidate in \
        "$ACCESS_LOG" \
        "/etc/apache2/logs/access_log" \
        "/usr/local/apache/logs/access_log" \
        "/var/log/httpd/access_log" \
        "/var/log/apache2/access.log" \
        "/var/log/apache2/other_vhosts_access.log"; do
        [ -z "$candidate" ] && continue
        if [ -f "$candidate" ] && [ -r "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

resolve_apache_domlogs_dir() {
    local candidate
    for candidate in \
        "/etc/apache2/logs/domlogs" \
        "/usr/local/apache/domlogs"; do
        if [ -d "$candidate" ] && [ -r "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

# List scannable per-domain access logs, most recently written first.
#
# N5: cPanel has TWO domlog layouts and the old `ls -t "$dir"/*` only worked on
# one of them. Modern cPanel (EA4) stores logs per user —
# domlogs/<user>/<domain> — and `ls` on a directory lists its *contents* with
# "dirname:" headers and blank lines, every one of which then failed the -f
# test. The result was a silent no-op: zero domains scanned, on the exact
# platform the feature exists for. A depth-limited find handles both layouts.
#
# N11: the byte-log/compressed filters and the size floor are applied HERE,
# before the caller's `head -n DOMLOG_MAX_DOMAINS`. Previously they ran after,
# so cPanel's constantly-updated *-bytes_log files (which sort to the top of a
# mtime listing) ate roughly a third of the configured budget and the busiest
# sites were the most likely to be crowded out.
#
# -L follows symlinks (cPanel symlinks some subdomain/alias logs); -maxdepth 2
# bounds that. *-ssl_log is deliberately NOT excluded: on cPanel that is where
# HTTPS traffic — the majority — is logged.
_find_domlogs() {
    local dir="$1" out=""

    # GNU find: sort by mtime without spawning ls. All supported platforms
    # (AlmaLinux/Rocky/CloudLinux, Ubuntu, Debian) ship GNU findutils.
    out=$(find -L "$dir" -maxdepth 2 -type f -size +99c \
              ! -name '*-bytes_log' ! -name 'ftpxferlog' \
              ! -name '*.gz' ! -name '*.bz2' ! -name '*.zst' ! -name '*.xz' \
              -printf '%T@ %p\n' 2>/dev/null | sort -rn | cut -d' ' -f2-)

    # Fallback for a find without -printf: same selection, mtime order via ls.
    if [ -z "$out" ]; then
        out=$(find -L "$dir" -maxdepth 2 -type f -size +99c \
                  ! -name '*-bytes_log' ! -name 'ftpxferlog' \
                  ! -name '*.gz' ! -name '*.bz2' ! -name '*.zst' ! -name '*.xz' \
                  2>/dev/null | head -n 2000 | tr '\n' '\0' | \
              xargs -0 -r ls -t 2>/dev/null)
    fi

    printf '%s\n' "$out"
}

detect_webserver() {
    local resolved_apache_log=""
    resolved_apache_log="$(resolve_apache_access_log 2>/dev/null)"

    if [ "$DRY_RUN" = true ] && [ -z "$resolved_apache_log" ] && [ ! -f "$LITESPEED_LOG" ] && [ ! -f "$NGINX_LOG" ]; then
        WARD_TYPE="Demo-Apache"

        # N12: mktemp, not a fixed path. This used to be the constant
        # /tmp/botsurgeon_basic_demo_access.log, guarded only by [ ! -f ] — and
        # [ -f ] follows symlinks. On a shared host (every cPanel box has
        # untrusted local users) anyone could pre-create that name as a symlink:
        # pointing it at a non-existent path made the `cat >` below write
        # attacker-chosen content to an attacker-chosen path AS ROOT, and
        # pointing it at an existing file made the script parse that file as an
        # access log. Every other temp file here already used mktemp; this one
        # was the exception. Recreated fresh each run, so the [ ! -f ] guard goes.
        local demo_log
        demo_log=$(_mktemp_data demo) || {
            echo "❌ ERROR: Demo mode needs a temp file and mktemp failed"
            echo "   Check that /tmp is writable and not full."
            exit 1
        }
        DEMO_LOG_FILE="$demo_log"
        ACTIVE_LOG="$demo_log"
        ACCESS_LOG="$ACTIVE_LOG"

        local ts
        ts=$(date '+%d/%b/%Y:%H:%M:%S %z')
        cat > "$ACTIVE_LOG" << EOF
192.168.1.100 - - [$ts] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
10.0.0.50 - - [$ts] "GET /index.php HTTP/1.1" 200 2048 "-" "Mozilla/5.0 (X11; Linux x86_64)"
203.0.113.25 - - [$ts] "GET / HTTP/1.1" 200 1024 "-" "python-requests/2.25"
203.0.113.25 - - [$ts] "GET /.env HTTP/1.1" 404 128 "-" "python-requests/2.25"
203.0.113.25 - - [$ts] "GET /xmlrpc.php HTTP/1.1" 403 128 "-" "python-requests/2.25"
203.0.113.25 - - [$ts] "GET /.git/config HTTP/1.1" 404 128 "-" "python-requests/2.25"
203.0.113.25 - - [$ts] "GET /wp-login.php HTTP/1.1" 403 128 "-" "python-requests/2.25"
203.0.113.25 - - [$ts] "GET /admin HTTP/1.1" 403 128 "-" "python-requests/2.25"
203.0.113.100 - - [$ts] "GET /admin HTTP/1.1" 403 128 "-" "Go-http-client/1.1"
203.0.113.100 - - [$ts] "GET /.git/config HTTP/1.1" 404 128 "-" "Go-http-client/1.1"
203.0.113.100 - - [$ts] "GET /wp-admin HTTP/1.1" 403 128 "-" "Go-http-client/1.1"
203.0.113.100 - - [$ts] "GET /.aws/credentials HTTP/1.1" 404 128 "-" "Go-http-client/1.1"
203.0.113.100 - - [$ts] "GET /etc/passwd HTTP/1.1" 403 128 "-" "Go-http-client/1.1"
EOF
        log_message "Demo mode: Created test environment (Ward: $WARD_TYPE)"
        return 0
    fi

    if [ -n "$resolved_apache_log" ]; then
        WARD_TYPE="Apache"
        ACCESS_LOG="$resolved_apache_log"
        ACTIVE_LOG="$resolved_apache_log"
    elif [ -f "$LITESPEED_LOG" ]; then
        WARD_TYPE="LiteSpeed"
        ACTIVE_LOG="$LITESPEED_LOG"
        ACCESS_LOG="$LITESPEED_LOG"
    elif [ -f "$NGINX_LOG" ]; then
        WARD_TYPE="Nginx"
        ACTIVE_LOG="$NGINX_LOG"
        ACCESS_LOG="$NGINX_LOG"
    else
        echo "❌ ERROR: No supported web server logs found"
        echo "   Checked: Apache, LiteSpeed, Nginx"
        echo "💡 TIP: Use --dry-run for testing/demo mode"
        exit 1
    fi

    log_message "Detected web server: $WARD_TYPE (Log: $ACTIVE_LOG)"

    local resolved_domlogs=""
    resolved_domlogs="$(resolve_apache_domlogs_dir 2>/dev/null)"
    if [ -n "$resolved_domlogs" ]; then
        log_message "Detected domlogs directory: $resolved_domlogs"
    fi
}

# ==============================================================================
# SECTION 11: SECURITY PREFLIGHT
# ==============================================================================

# N8: the disable check lives here, on its own, so main() can call it as the
# very first thing it does.
#
# It used to sit inside security_preflight, which runs AFTER _nft_load. That
# meant a disabled BotSurgeon still re-imported its persisted nftables table
# before noticing it was disabled — so the documented recovery sequence
# (--disable, then clear the rules to restore service) was silently undone on
# the next cron cycle, and --disable looked broken to the one person relying
# on it during an incident.
# M15: ONE trusted answer to "is BotSurgeon switched off?".
#
# Two bugs shared a root cause: the flag was consulted in two different ways.
#
#   - check_disabled ran once, at startup, and applied the M2 ownership gate.
#     A --auto pass never looked again, so `--disable` during an incident did
#     not stop the run that was already blocking — and that run can hold the
#     lock for MAX_RUNTIME while an operator watches it keep going.
#
#   - the monitor loop tested `[ -f "$DISABLE_FLAG" ]` on its own and paused on
#     a bare file, skipping the ownership gate entirely. Any local user who
#     could create that path could halt a running monitor — precisely the
#     bypass M2 added the gate to prevent, reintroduced a few hundred lines
#     away.
#
# One predicate now answers for both, and it is safe to call in a tight loop:
# an untrusted flag is reported once and then IGNORED, never obeyed. Ignoring a
# planted kill switch is the safe direction; an admin who genuinely wants
# BotSurgeon off has --disable.
DISABLE_UNTRUSTED_WARNED=false
DISABLE_CACHE_TIME=""
DISABLE_CACHE_VERDICT=""

is_disabled() {
    [ -f "$DISABLE_FLAG" ] || {
        DISABLE_CACHE_TIME=""
        DISABLE_CACHE_VERDICT=""
        return 1
    }

    local cur_ctime
    cur_ctime=$(stat -c%Z "$DISABLE_FLAG" 2>/dev/null || stat -f%c "$DISABLE_FLAG" 2>/dev/null)
    if [ -n "$cur_ctime" ] && [ "$cur_ctime" = "$DISABLE_CACHE_TIME" ] && [ -n "$DISABLE_CACHE_VERDICT" ]; then
        [ "$DISABLE_CACHE_VERDICT" = "safe" ] && return 0
        return 1
    fi

    # Its own warnings are silenced: this is called per block decision and per
    # monitor cycle, so the message below is emitted once instead of per call.
    if _file_is_root_safe "$DISABLE_FLAG" "Disable flag" >/dev/null 2>&1; then
        DISABLE_CACHE_TIME="$cur_ctime"
        DISABLE_CACHE_VERDICT="safe"
        return 0
    fi

    DISABLE_CACHE_TIME="$cur_ctime"
    DISABLE_CACHE_VERDICT="untrusted"

    if [ "$DISABLE_UNTRUSTED_WARNED" = false ]; then
        DISABLE_UNTRUSTED_WARNED=true
        echo "🚨 SECURITY: $DISABLE_FLAG exists but is NOT safely root-owned - IGNORING it."
        echo "   A non-root user may have tried to disable BotSurgeon. Continuing normally."
        echo "   To disable deliberately: $0 --disable   (as root)"
        log_message "SECURITY: untrusted $DISABLE_FLAG ignored - continuing"
    fi
    return 1
}

check_disabled() {
    is_disabled || return 0
    echo "⏸️  BotSurgeon is DISABLED. Use --enable to reactivate."
    log_message "Exiting: disabled by admin"
    exit 0
}

security_preflight() {
    mkdir -p "$DATA_DIR" 2>/dev/null

    if [ "$DRY_RUN" = true ]; then
        LOG_FILE="$DATA_DIR/botsurgeon-basic-dryrun.log"
    fi
    # M1: the fallback used to be the fixed path /tmp/botsurgeon-basic.log, which
    # root then appended to with >>. On a shared host any local user can create
    # that name first — as a symlink — and have root append to a file of their
    # choosing. mktemp per run removes the predictability; if even that fails,
    # logging is disabled rather than aimed at a guessable path.
    if ! touch "$LOG_FILE" 2>/dev/null; then
        local fallback_log td
        # M22 / P3-1: _safe_tmpdir, not $TMPDIR — root appends to this file for the
        # whole run, so a caller-chosen directory is a caller-chosen log target.
        if td=$(_safe_tmpdir) && fallback_log=$(mktemp "${td}/botsurgeon-basic-log.XXXXXXXXXX" 2>/dev/null); then
            LOG_FILE="$fallback_log"
            echo "⚠️  Cannot write the configured log - using $LOG_FILE for this run only."
        else
            LOG_FILE="/dev/null"
            echo "⚠️  Cannot write any log file - this run will not be logged."
        fi
    fi

    log_message "Starting $SCRIPT_NAME v$VERSION"

    # O13: replay early config notices buffered before LOG_FILE was writable
    if [ "${#CONFIG_NOTICES_BUFFER[@]}" -gt 0 ]; then
        local _cn
        for _cn in "${CONFIG_NOTICES_BUFFER[@]}"; do
            log_message "CONFIG: $_cn"
        done
    fi

    if [ "$(id -u)" -ne 0 ] && [ "$DRY_RUN" = false ]; then
        echo "❌ ERROR: This script requires root privileges"
        echo "💡 TIP: Use --dry-run to preview actions without root"
        exit 1
    elif [ "$(id -u)" -ne 0 ] && [ "$DRY_RUN" = true ]; then
        echo "🧪 DRY RUN MODE: Running without root (preview only)"
    fi

    # Detect server's own IPs to prevent self-blocking.
    # O11: `hostname -I` is absent on minimal images and some distros; when it
    # produced nothing the server lost its own self-block protection silently
    # (WordPress cron, health checks and internal API calls all originate from
    # these addresses). Fall back to `ip`, which is present wherever nftables is.
    if command -v hostname >/dev/null 2>&1; then
        SERVER_IPS=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^$')
    fi
    if [ -z "$SERVER_IPS" ] && command -v ip >/dev/null 2>&1; then
        SERVER_IPS=$(ip -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -v '^$')
    fi
    if [ -z "$SERVER_IPS" ]; then
        echo "⚠️  WARNING: could not determine this server's own IP addresses."
        echo "   Self-block protection is reduced; add them to $WHITELIST_FILE."
        log_message "WARNING: SERVER_IPS empty - self-block protection reduced"
    fi

    # M10: 'dig' is a soft dependency for the FCrDNS legit-bot safety net. Without
    # it, Googlebot/Bingbot/UptimeRobot/etc. cannot be verified and could be
    # blocked on a bad day. Warn loudly (once) rather than fail silently.
    if ! command -v dig >/dev/null 2>&1; then
        echo "⚠️  WARNING: 'dig' not found - legitimate-bot verification (rDNS) is DISABLED."
        echo "   Search engines & monitors are protected only by UA/whitelist, not FCrDNS."
        echo "   Install it: dnf install bind-utils  |  apt install dnsutils"
        log_message "WARNING: dig missing - FCrDNS legit-bot verification disabled"
    fi

    # M1/M4: check for connection flood tool (ss or netstat)
    if ! command -v ss >/dev/null 2>&1 && ! command -v netstat >/dev/null 2>&1; then
        echo "⚠️  WARNING: neither 'ss' nor 'netstat' found - connection-flood detection is DISABLED."
        echo "   Install one: dnf install iproute  |  apt install iproute2"
        log_message "WARNING: ss/netstat missing - connection-flood detection disabled"
    fi

    detect_webserver

    # O15: flag traffic the analysers structurally cannot see, before any of
    # them run and report a clean result over it.
    _report_unparsed_ratio

    # M17: decide whether the heuristic may veto a block, before it runs.
    _resolve_proxy_heuristic_mode

    # N1: identify shared front ends (CDN edges, reverse proxies, NAT gateways)
    # once per run, before any blocking decision is made. Must come after
    # detect_webserver so ACTIVE_LOG is resolved.
    detect_proxy_ips

    if [ ! -f "$TRUEUSERDOMAINS" ]; then
        echo "⚠️  WARNING: trueuserdomains not found - cPanel detection disabled"
        CPANEL_MODE=false
    else
        CPANEL_MODE=true
    fi

    # Rotate size-capped logs if needed. L2: blocked_ips.log is now rotated too
    # (it was the one append-only log that grew unbounded). L7: the cooldown file
    # is NOT rotated — init_cooldown prunes it in place; rotating it would discard
    # every active cooldown (making blocked IPs immediately re-blockable).
    rotate_log "$LOG_FILE"
    # C6: rotating the block history is a mv + gzip of live evidence. LOG_FILE
    # above is the run's own log (already redirected to the dry-run copy), but
    # blocked_ips.log is shared state a preview has no business moving.
    if [ "$DRY_RUN" = false ]; then
        rotate_log "$DATA_DIR/blocked_ips.log"
    fi

    # Initialize cooldown system (prunes expired entries in place)
    init_cooldown

    # N4: lift blocks whose TTL has run out (iptables / hosts.deny only — the
    # other layers expire natively). Runs before any new blocking decision.
    expire_blocks

    # N4: warn if CSF's permanent deny list is near DENY_IP_LIMIT. Past that
    # limit CSF silently drops the OLDEST entry for each new one, so real
    # attackers get quietly unblocked. Our own blocks use temp bans and are not
    # affected, but a full csf.deny is worth telling the admin about.
    _csf_deny_limit_check

    log_message "Preflight complete - Ward: $WARD_TYPE | Tool: $(get_connection_tool)"
}

security_checks() {
    echo "🔍 SECURITY STATUS:"

    if command -v imunify360-agent >/dev/null 2>&1; then
        local imunify_status
        imunify_status=$(imunify360-agent status 2>/dev/null)
        if echo "$imunify_status" | grep -q "running"; then
            echo "   ✅ Imunify360: Active"
        else
            echo "   ⚠️  Imunify360: Installed but not fully active"
        fi
    elif command -v imunify-antivirus >/dev/null 2>&1; then
        echo "   ℹ️  ImunifyAV: Active (no firewall features)"
    else
        echo "   ❌ Imunify360: Not installed"
    fi

    if command -v csf >/dev/null 2>&1; then
        local csf_status
        csf_status=$(csf -l 2>/dev/null | grep -c "DENY" 2>/dev/null) || true
        echo "   ✅ CSF Firewall: Active (${csf_status:-0} blocks)"
    else
        echo "   ❌ CSF: Not installed"
    fi

    if command -v nft >/dev/null 2>&1; then
        local nft_rules
        nft_rules=$(nft list table inet "$NFT_TABLE" 2>/dev/null | grep -c "drop" 2>/dev/null) || true
        echo "   ✅ nftables: Available (${nft_rules:-0} BotSurgeon rules)"
    fi

    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
        echo "   ✅ firewalld: Active"
    fi

    local iptables_rules
    iptables_rules=$(iptables -L INPUT 2>/dev/null | grep -c "DROP\|REJECT" 2>/dev/null) || true
    echo "   🔥 iptables: ${iptables_rules:-0} active DROP/REJECT rules"

    if command -v fail2ban-client >/dev/null 2>&1; then
        # O7: the trailing `|| echo "0"` emitted a SECOND value when the pipeline
        # failed, because wc had already printed 0 — the status line then read
        # "Active (0\n0 jails)". Same class as the L1 note fixed in
        # fingerprint_ip; wc -w always prints a number, so the fallback is
        # redundant as well as wrong.
        local jails
        jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://;s/,/ /g' | wc -w)
        echo "   ✅ Fail2Ban: Active (${jails:-0} jails)"
    fi

    echo "   🔧 Connection tool: $(get_connection_tool)"
    echo
}

# ==============================================================================
# SECTION 12: CONNECTION ANALYSIS
# ==============================================================================

analyze_connections() {
    log_message "Analyzing active connections..."

    local connection_analysis
    connection_analysis=$(extract_ips_from_connections | grep -v '^$' | uniq -c | sort -rn)

    echo "🩺 CONNECTION DIAGNOSIS (Top 15):"
    echo "Connections | IP Address                         | Status"
    echo "------------|-----------------------------------|--------"

    echo "$connection_analysis" | head -15 | while read -r count ip; do
        [ -z "$count" ] && continue
        [ -z "$ip" ] && continue
        [[ "$count" =~ ^[0-9]+$ ]] || continue

        local status
        if [ "$count" -gt "$AUTO_BLOCK_THRESHOLD" ]; then
            status="🔴 CRITICAL"
        elif [ "$count" -gt "$CONNECTION_THRESHOLD" ]; then
            status="🟡 WARNING"
        else
            status="🟢 NORMAL"
        fi

        printf "%-11s | %-35s | %s\n" "$count" "$ip" "$status"
    done

    if [ -z "$connection_analysis" ]; then
        echo "   No active connections detected"
    fi
    echo
}

analyze_traffic() {
    log_message "Analyzing traffic patterns (last $NUM_LINES requests)..."

    if [ ! -f "$ACTIVE_LOG" ]; then
        echo "⚠️  Access log not found: $ACTIVE_LOG"
        return 1
    fi

    # O2: read the shared window instead of re-tailing the log.
    local most_active
    most_active=$(_log_window_source | \
        awk '
        function is_ip(v) {
            return (v ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ || v ~ /^([0-9A-Fa-f]*:){2,}[0-9A-Fa-f:]+$/)
        }
        {
            dom = ""
            # cPanel vhost format: domain:port IP ... OR domain IP ...
            # Standard format: IP - - [date] ...
            if (is_ip($1)) {
                # Field 1 is an IP — no vhost prefix. Skip (no domain info).
                next
            } else {
                # vhost format — extract domain from field 1
                split($1, a, ":")
                dom = a[1]
            }
            sub(/^www\./, "", dom)
            # Skip if extracted value is still an IP or empty
            if (dom == "" || is_ip(dom)) next
            if (dom !~ /^[A-Za-z0-9]([A-Za-z0-9.-]{0,253})$/) next
            print dom
        }' | sort | uniq -c | sort -nr | head -n 10)

    echo "📋 TOP 10 DOMAINS UNDER STRESS:"

    # N7: this breakdown needs a vhost-prefixed log (cPanel's main access_log).
    # A standard Apache/Nginx combined log starts each line with the client IP
    # and carries no domain field, so the awk above emits nothing. Say so and
    # return, rather than feeding empty values into the numeric tests below —
    # that printed two "[: : integer expression expected" errors on every run
    # for non-cPanel servers, and on every --dry-run (the built-in demo log is
    # IP-first too).
    if [ -z "$most_active" ]; then
        echo "   (not available - this log has no per-domain field)"
        echo "   Per-domain analysis needs cPanel's vhost-prefixed access_log."
        echo "   All other detection is unaffected."
        echo
        return 0
    fi

    echo "$most_active" | while read -r count dm; do
        [ -z "$count" ] && continue
        [[ "$count" =~ ^[0-9]+$ ]] || continue

        local status
        if [ "$count" -gt 1000 ]; then
            status="🔴 CRITICAL"
        elif [ "$count" -gt 500 ]; then
            status="🟡 ELEVATED"
        else
            status="🟢 STABLE"
        fi
        printf "%-6s requests | %-30s | %s\n" "$count" "$(_safe_display "$dm")" "$status"
    done
    echo

    domain=$(printf '%s\n' "$most_active" | head -1 | awk '{print $2}')
    req_count=$(printf '%s\n' "$most_active" | head -1 | awk '{print $1}')

    # M7: this value comes out of the access log and is used downstream as a
    # grep REGEX (find_cpanel_user, block_aggressive_ips) and, in interactive
    # mode, to choose the account that /scripts/suspendacct suspends.
    #
    # Whether it is attacker-controlled depends on the Apache config: %v logs
    # the canonical vhost (cPanel's default, trusted), but %V with
    # `UseCanonicalName Off` logs the client's Host: header verbatim. The script
    # cannot tell which is in use, so it must not trust the field. A value
    # containing regex metacharacters could match a different trueuserdomains
    # line and resolve to the wrong cPanel user — and suspending the wrong
    # customer's account is the most destructive thing this tool can do.
    if [ -n "$domain" ] && ! [[ "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,253})$ ]]; then
        echo "⚠️  Ignoring malformed domain from the access log: $(_safe_display "$domain")"
        echo "   Per-domain actions are disabled for this run (the log field is not a hostname)."
        log_message "WARNING: rejected malformed domain field from access log"
        domain=""
        req_count=0
    fi
}

# ==============================================================================
# SECTION 13: ACCESS LOG THREAT ANALYSIS
# ==============================================================================
# Ported from BotSurgeon-Pro: scans access logs for suspicious paths, high 404
# rates, bot user agents, and probe patterns. This is the core detection engine.

analyze_access_log_threats() {
    log_message "Analyzing access log for threat patterns..."
    echo "🔍 ACCESS LOG THREAT ANALYSIS"
    echo "   Log: $ACTIVE_LOG"
    echo "   Window: Last $NUM_LINES entries"
    echo

    if [ ! -f "$ACTIVE_LOG" ]; then
        echo "⚠️  Access log not found: $ACTIVE_LOG"
        return 1
    fi

    local temp_analysis
    # C4: unguarded, this turned a full /tmp into a silent all-clear. With
    # temp_analysis="" the awk redirect failed, the results were discarded, the
    # read loop read nothing, threat_count stayed 0 and the run printed
    # "✅ No threats detected in access log" — the core detection engine
    # reporting green because the disk was full, which is a common condition on
    # a server that is actually under attack.
    if ! temp_analysis=$(_mktemp_data access); then
        echo "❌ ERROR: could not create a temp file - THREAT ANALYSIS DID NOT RUN."
        echo "   This is not an all-clear. Check free space on $DATA_DIR and /tmp."
        log_message "ERROR: mktemp failed - access log threat analysis skipped"
        return 1
    fi

    _log_window_source | \
    awk 'BEGIN {
        # --- Pattern model (N2 / N21) -------------------------------------
        # attack_patterns: unambiguous exploitation signatures. No legitimate
        # user requests these, so they count regardless of response status.
        # N21: dot-file probes are segment-anchored so an asset legitimately
        # named "theme.envato.css" is no longer read as a ".env" probe.
        attack_patterns = "(^|/)\\.env|(^|/)\\.git/|(^|/)\\.aws/credentials|wp-config\\.php|/etc/passwd|/etc/shadow|/proc/self|phpinfo\\.php|shell\\.php|c99\\.php|r57\\.php|\\.(sql|bak|old|swp)$|backup\\.(zip|tar|gz|sql)"

        # panel_patterns: real administrative tooling that customers use every
        # day — Joomla /administrator, Magento /admin, phpMyAdmin (which cPanel
        # installs by default), cgi-bin apps like Mailman. Counting these
        # unconditionally blocked paying customers out of their own control
        # panel: the identical false-positive class that the /wp-admin fix
        # already closed for WordPress, left open for everything else.
        #
        # They are only a threat signal when the request did NOT succeed. An
        # authorised admin gets 2xx; a scanner gets 401/403/404 — and on the
        # overwhelming majority of sites, which do not run that panel at all,
        # it gets a 404. So the probe is still caught where it matters.
        # Matched against a lowercased path so /phpMyAdmin counts too.
        panel_patterns = "(^|/)admin(istrator)?(/|$)|(^|/)phpmyadmin(/|$)|(^|/)cgi-bin/|(^|/)wp-admin(/|$)|(^|/)admin-ajax\\.php"
    }
    '"$AWK_LOGPARSE"'
    {
        # M6: shared quote-aware parse. Sets ip/path/pathonly/status/ua.
        if (!bs_parse()) next
        user_agent = ua

        if (ip == "127.0.0.1" || ip == "::1") next

        requests[ip]++
        if (status ~ /404/) errors_404[ip]++

        is_susp = 0
        if (match(pathonly, attack_patterns)) is_susp = 1
        # Directory traversal as a path segment (not "foo..bar" or query noise).
        else if (pathonly ~ /(^|\/)\.\.(\/|$)/) is_susp = 1
        # High-confidence LFI targets count even inside query strings (?file=/etc/passwd).
        else if (path ~ /\/etc\/(passwd|shadow)|\/proc\/self\/environ/) is_susp = 1
        # N2 / M-2: admin panels count only on a failed (4xx) response.
        else if (tolower(pathonly) ~ panel_patterns && status ~ /^4[0-9][0-9]$/) is_susp = 1

        if (is_susp) {
            suspicious[ip]++
            if (length(suspicious_paths[ip]) < 200)
                suspicious_paths[ip] = suspicious_paths[ip] path ","
        }

        # Auth endpoints are hit legitimately (site owners, Jetpack via XML-RPC);
        # only treat them as a threat signal in brute-force volume (folded in END).
        if (pathonly ~ /(wp-login\.php|xmlrpc\.php)/) authprobe[ip]++
        if (!user_agents[ip] && user_agent != "") user_agents[ip] = user_agent
        # N18: track the full 4xx family, not just 404. 5xx is deliberately
        # excluded — a server-side error is the application failing, and scoring
        # it would let a broken site get its own visitors blocked.
        if (status ~ /^4/) errors_4xx[ip]++

        # Bot UA detection
        if (tolower(user_agent) ~ /(bot|crawler|spider|scraper|curl|wget|python-requests|go-http|java\/|libwww|nikto|sqlmap|nmap|masscan|zgrab)/) {
            bot_ua[ip]++
        }

        # Static asset tracking for fingerprinting
        if (path ~ /\.(js|css|png|jpg|jpeg|gif|svg|woff|ico)(\?|$)/) {
            static_assets[ip]++
        }
    }
    END {
        for (ip in requests) {
            total = requests[ip]
            e404 = errors_404[ip] ? errors_404[ip] : 0
            error_rate = (e404 / total) * 100          # reported to the admin
            # N18: score on the whole 4xx rate. ModSecurity, CSF and most WAFs
            # answer a scanner with 403, so a 404-only rate scored those attacks
            # at zero on exactly the servers that are already defending.
            e4xx = errors_4xx[ip] ? errors_4xx[ip] : 0
            cerr_rate = (e4xx / total) * 100
            susp = suspicious[ip] ? suspicious[ip] : 0
            # Fold in auth-endpoint hits only when clearly abusive (brute force),
            # so an occasional owner login never tips them over the threshold.
            # O12: cap the auth-endpoint contribution. Adding the RAW count meant
            # a Jetpack-connected WordPress site (heavy legitimate XML-RPC) or a
            # busy owner login pushed susp past 20 on volume alone, scoring the
            # full +40 "suspicious path" band. That stayed under the default
            # threshold of 60 but cleared the --emergency threshold of 50, so the
            # mode meant for an active attack was the one most likely to block
            # the site owner. Gate on a poor success rate too: real logins
            # mostly succeed.
            if ((ip in authprobe) && authprobe[ip] >= 5 && cerr_rate > 30) {
                susp += (authprobe[ip] > 20 ? 20 : authprobe[ip])
            }
            bot_count = bot_ua[ip] ? bot_ua[ip] : 0
            assets = static_assets[ip] ? static_assets[ip] : 0

            # --- Threat scoring (0-100) ---
            score = 0

            # High client-error rate = scanning (404 not-found OR 403 WAF-denied)
            if (cerr_rate > 80) score += 35
            else if (cerr_rate > 50) score += 25
            else if (cerr_rate > 30) score += 15

            # Suspicious path access
            if (susp > 20) score += 40
            else if (susp > 10) score += 30
            else if (susp > 5) score += 20
            else if (susp > 0) score += 10

            # Volume
            if (total > 200) score += 10
            else if (total > 100) score += 5

            # Bot user agent
            if (bot_count > 0 && bot_count >= total * 0.8) score += 15
            else if (bot_count > 0) score += 5

            # No static assets = likely not a browser
            if (total > 10 && assets == 0) score += 10

            if (score >= 30 || susp > 3) {
                ua_out = user_agents[ip]
                if (length(ua_out) > 80) ua_out = substr(ua_out, 1, 80) "..."
                sp_out = suspicious_paths[ip]

                # O4: TAB-delimited, not "|". The last two columns are the
                # request path and the User-Agent — both attacker-controlled —
                # and a "|" in either shifted every later column when the shell
                # read the record back, so the UA field could be lost entirely.
                # A raw tab cannot appear in a logged request line.
                gsub(/\t/, " ", sp_out); gsub(/\t/, " ", ua_out)
                printf "%s\t%d\t%d\t%.0f\t%d\t%.0f\t%s\t%s\n", \
                    ip, total, e404, error_rate, susp, score, sp_out, ua_out
            }
        }
    }' | sort -t"$(printf '\t')" -k6 -rn > "$temp_analysis"
    # M18: captured on the VERY next line - anything else clobbers it.
    local -a analysis_status=("${PIPESTATUS[@]}")

    local threat_count=0
    local blocked_count=0

    while IFS= read -r _rec; do
        [ -z "$_rec" ] && continue
        ip="${_rec%%$'\t'*}";             _rec="${_rec#*$'\t'}"
        total_req="${_rec%%$'\t'*}";      _rec="${_rec#*$'\t'}"
        errors_404="${_rec%%$'\t'*}";     _rec="${_rec#*$'\t'}"
        error_rate="${_rec%%$'\t'*}";     _rec="${_rec#*$'\t'}"
        suspicious_req="${_rec%%$'\t'*}"; _rec="${_rec#*$'\t'}"
        threat_score="${_rec%%$'\t'*}";   _rec="${_rec#*$'\t'}"
        if [[ "$_rec" == *$'\t'* ]]; then
            suspicious_paths="${_rec%%$'\t'*}"
            user_agent="${_rec#*$'\t'}"
        else
            suspicious_paths="$_rec"
            user_agent=""
        fi

        local threat_score_int
        threat_score_int=$(printf '%s' "$threat_score" | cut -d'.' -f1)

        # The score is a sum of independent bands, so a heavily-loaded attacker
        # could total more than 100 and the report read "Score: 105/100" — which
        # looks like an arithmetic bug in a tool whose whole job is to be
        # believed. Clamp for DISPLAY only:
        #   * the RAW value already decided the sort order inside awk, and that
        #     order decides who gets blocked first when MAX_BLOCKS_PER_RUN is
        #     reached — flattening 105 and 100 to a tie here would quietly change
        #     which IPs make the cut on a busy server;
        #   * every threshold is <= 100 (_validate_int caps LOG_THREAT_THRESHOLD),
        #     so clamping cannot change any block decision either.
        [[ "$threat_score_int" =~ ^[0-9]+$ ]] || threat_score_int=0
        [ "$threat_score_int" -gt 100 ] && threat_score_int=100

        local level="ℹ️  LOW"
        [ "$threat_score_int" -ge 50 ] && level="🟡 MEDIUM"
        [ "$threat_score_int" -ge 70 ] && level="🔴 HIGH"

        echo "🎯 THREAT: $ip [$level]"
        echo "   Requests: $total_req | 404s: $errors_404 (${error_rate}%) | Suspicious: $suspicious_req | Score: ${threat_score_int}/100"

        if [ -n "$user_agent" ] && [ "$user_agent" != "-" ]; then
            echo "   UA: $(_safe_display "${user_agent:0:80}")"
        fi
        if [ -n "$suspicious_paths" ]; then
            local sample
            sample=$(printf '%s' "$suspicious_paths" | tr ',' '\n' | head -3 | tr '\n' ' ')
            echo "   Paths: $(_safe_display "$sample")"
        fi

        if is_whitelisted_ip "$ip"; then
            echo "   ⚠️  Whitelisted - skipping"
            echo
            ((threat_count++))
            continue
        fi

        # Check if this is a legitimate bot (Googlebot, Bingbot, etc.)
        if [ -n "$user_agent" ] && is_known_good_ua "$user_agent"; then
            if is_verified_search_bot "$ip"; then
                echo "   ✅ Verified legitimate bot (rDNS confirmed) - skipping"
                echo
                ((threat_count++))
                continue
            elif ! command -v dig >/dev/null 2>&1; then
                echo "   ⚠️  Known bot User-Agent but 'dig' missing - rDNS verification skipped"
                log_message "WARNING: $ip matches bot UA ($user_agent) but dig is missing - FCrDNS verification skipped"
            fi
        fi

        if is_in_cooldown "$ip"; then
            echo "   ⏳ Recently blocked - skipping"
            echo
            ((threat_count++))
            continue
        fi

        if [ "$AUTO_MODE" = true ] && [ "$threat_score_int" -ge "$LOG_THREAT_THRESHOLD" ]; then
            # N6: only claim a block on an exact 0. A dry-run preview or a
            # cooldown skip returns 2 and must not be counted or announced.
            if block_ip_comprehensive "$ip" "Access log threat: score ${threat_score_int}/100, ${suspicious_req} suspicious requests, ${error_rate}% 404 rate" "log"; then
                echo "   🚨 Auto-blocked (score >= $LOG_THREAT_THRESHOLD)"
                ((blocked_count++))
            fi
        elif [ "$threat_score_int" -ge 50 ]; then
            echo "   ⚠️  Monitor recommended (score >= 50)"
        fi

        ((threat_count++))
        echo
    done < "$temp_analysis"

    rm -f "$temp_analysis"

    # M18: "zero findings" and "the analysis did not complete" are different
    # answers and must never print the same tick.
    if ! _pipe_ok "${analysis_status[@]}"; then
        echo "   ❌ THREAT ANALYSIS DID NOT COMPLETE - this is NOT an all-clear."
        echo "      A stage of the pipeline failed (exit codes: ${analysis_status[*]})."
        echo "      Anything reported above is PARTIAL. Check that $ACTIVE_LOG is"
        echo "      readable and that $DATA_DIR and /tmp have free space."
        log_message "ERROR: access-log analysis pipeline failed (${analysis_status[*]}) - result is partial, not clean"
        echo
        return 1
    fi

    if [ "$threat_count" -eq 0 ]; then
        echo "   ✅ No threats detected in access log"
    else
        echo "📊 Summary: $threat_count threat(s) detected, $blocked_count blocked"
        [ "$DRY_RUN" = true ] && echo "   ⚗️  Dry run - nothing was actually blocked."
        log_message "Access log: $threat_count threats, $blocked_count blocked"
    fi
    echo
}

# ==============================================================================
# SECTION 14: DOMLOG SCANNING
# ==============================================================================
# Scans per-domain access logs (cPanel domlogs) for threats targeting individual
# sites. Catches abuse that doesn't appear in the main access_log aggregate.

analyze_domlogs() {
    local domlogs_dir
    domlogs_dir="$(resolve_apache_domlogs_dir 2>/dev/null)"

    if [ -z "$domlogs_dir" ] || [ ! -d "$domlogs_dir" ]; then
        log_message "No domlogs directory found - skipping per-domain analysis"
        return 0
    fi

    log_message "Scanning domlogs in $domlogs_dir (max $DOMLOG_MAX_DOMAINS domains)..."
    echo "🌐 DOMLOG THREAT SCAN"
    echo "   Directory: $domlogs_dir"
    echo "   Limit: $DOMLOG_MAX_DOMAINS most recently active domains"
    echo

    local domain_count=0
    local total_threats=0
    local blocked_count=0
    local failed_domains=0
    local candidates
    candidates=$(_find_domlogs "$domlogs_dir" | head -n "$DOMLOG_MAX_DOMAINS")

    # N5: a scan that finds nothing must never look like a clean server.
    if [ -z "$candidates" ]; then
        echo "   ⚠️  No scannable domain logs found in $domlogs_dir"
        echo "      The directory exists but nothing in it looks like an access log."
        echo "      Per-domain scanning is NOT running. Check that the path is right"
        echo "      and that this user can read it; the main access-log analysis is"
        echo "      unaffected."
        log_message "WARNING: domlogs dir $domlogs_dir yielded no scannable logs - per-domain scan did not run"
        echo
        return 0
    fi

    local domlog
    while IFS= read -r domlog; do
        [ -z "$domlog" ] && continue
        [ -r "$domlog" ] || continue

        # Show "user/domain" on per-user layouts so the operator knows whose
        # site it is; plain "domain" on flat ones.
        local dom_name
        dom_name="${domlog#"$domlogs_dir"/}"

        ((domain_count++))

        # Quick threat scan per domain using same AWK logic
        # OPT-3: { grep ... || [ $? -eq 1 ]; } ensures quiet logs (exit 1) don't trigger false-positive pipefail error
        local dom_threats dom_rc
        dom_threats=$(tail -n "$DOMLOG_LINES" "$domlog" 2>/dev/null | { grep '".*HTTP/' || [ $? -eq 1 ]; } | \
        awk 'BEGIN {
            # Same pattern model as the main analyser (N2 / N21) — keep the two
            # in sync: admin panels are status-gated, dot-files segment-anchored.
            attack_patterns = "(^|/)\\.env|(^|/)\\.git/|(^|/)\\.aws/credentials|wp-config\\.php|/etc/passwd|/etc/shadow|/proc/self|phpinfo\\.php|shell\\.php|c99\\.php|r57\\.php|\\.(sql|bak|old|swp)$|backup\\.(zip|tar|gz|sql)"
            panel_patterns = "(^|/)admin(istrator)?(/|$)|(^|/)phpmyadmin(/|$)|(^|/)cgi-bin/|(^|/)wp-admin(/|$)|(^|/)admin-ajax\\.php"
        }
        '"$AWK_LOGPARSE"'
        {
            # M6: same shared quote-aware parse as the main analyser, so the two
            # can no longer drift apart (they already carried a "keep in sync"
            # warning) and neither can be evaded by a shifted field.
            if (!bs_parse()) next

            if (ip == "127.0.0.1" || ip == "::1") next

            requests[ip]++
            if (status ~ /404/) errors_404[ip]++
            if (status ~ /^4/) errors_4xx[ip]++     # N18: 403 (WAF-denied) counts too

            is_susp = 0
            if (match(pathonly, attack_patterns)) is_susp = 1
            else if (pathonly ~ /(^|\/)\.\.(\/|$)/) is_susp = 1
            else if (path ~ /\/etc\/(passwd|shadow)|\/proc\/self\/environ/) is_susp = 1
            # N2 / M-2: admin panels count only on a failed (4xx) response.
            else if (tolower(pathonly) ~ panel_patterns && status ~ /^4[0-9][0-9]$/) is_susp = 1
            if (is_susp) suspicious[ip]++

            if (pathonly ~ /(wp-login\.php|xmlrpc\.php)/) authprobe[ip]++

            # C1 (1.0.4): this read extract_ua($0) - a function the 1.0.3
            # shared-parser refactor DELETED. Calling an undefined function is
            # fatal in every awk (gawk aborts at the first record, mawk refuses
            # to compile at all), so this entire pass died before its END block:
            # dom_threats came back empty, the caller took that for "nothing
            # found", and every scan printed "No per-domain threats detected".
            # The per-domain detector had been silently OFF since the refactor.
            # bs_parse() already set ua - use it, exactly as the main analyser
            # does. Guard the empty case so an unparsed UA cannot score.
            if (ua != "" && tolower(ua) ~ /(bot|crawler|spider|scraper|curl|wget|python-requests|go-http|java\/|libwww|nikto|sqlmap|nmap|masscan|zgrab)/) {
                bot_ua[ip]++
            }
            if (path ~ /\.(js|css|png|jpg|jpeg|gif|svg|woff|ico)(\?|$)/) {
                static_assets[ip]++
            }
        }
        END {
            for (ip in requests) {
                total = requests[ip]
                e404 = errors_404[ip] ? errors_404[ip] : 0
                error_rate = (e404 / total) * 100          # reported
                e4xx = errors_4xx[ip] ? errors_4xx[ip] : 0
                cerr_rate = (e4xx / total) * 100           # scored (N18)
                susp = suspicious[ip] ? suspicious[ip] : 0
                # O12: cap the auth-endpoint contribution. Adding the RAW count
                # meant a Jetpack-connected WordPress site (heavy legitimate
                # XML-RPC) or a busy owner login pushed susp past 20 on volume
                # alone, scoring the full +40 "suspicious path" band. That stayed
                # under the default threshold of 60 but cleared the --emergency
                # threshold of 50, so the mode meant for an active attack was the
                # one most likely to block the site owner. Gate on a poor success
                # rate too: real logins mostly succeed.
                # cerr_rate is deliberately computed ABOVE this test — it used to
                # be assigned further down, which would leave the gate always
                # false here (awk reads an unset variable as 0).
                if ((ip in authprobe) && authprobe[ip] >= 5 && cerr_rate > 30) {
                    susp += (authprobe[ip] > 20 ? 20 : authprobe[ip])
                }
                bots = bot_ua[ip] ? bot_ua[ip] : 0
                assets = static_assets[ip] ? static_assets[ip] : 0

                score = 0
                if (cerr_rate > 80) score += 35
                else if (cerr_rate > 50) score += 25
                else if (cerr_rate > 30) score += 15
                if (susp > 20) score += 40
                else if (susp > 10) score += 30
                else if (susp > 5) score += 20
                else if (susp > 0) score += 10
                if (total > 200) score += 10
                else if (total > 100) score += 5
                if (bots > 0 && bots >= total * 0.8) score += 15
                else if (bots > 0) score += 5
                if (total > 10 && assets == 0) score += 10

                if (score >= 50) {
                    printf "%s|%d|%d|%.0f|%d|%.0f\n", ip, total, e404, error_rate, susp, score
                }
            }
        }' | sort -t'|' -k6 -rn)
        dom_rc=$?
        if [ "$dom_rc" -ne 0 ]; then
            failed_domains=$((failed_domains + 1))
            log_message "ERROR: domlog scan failed for $dom_name (exit $dom_rc)"
            continue
        fi

        [ -z "$dom_threats" ] && continue

        echo "   📁 $dom_name:"
        while IFS='|' read -r ip total e404 erate susp score; do
            [ -z "$ip" ] && continue
            local score_int
            score_int=$(printf '%s' "$score" | cut -d'.' -f1)
            # Display clamp only — see the note in analyze_access_log_threats.
            # awk has already sorted on the raw value, and every threshold is
            # <= 100, so this changes what is printed and nothing else.
            [[ "$score_int" =~ ^[0-9]+$ ]] || score_int=0
            [ "$score_int" -gt 100 ] && score_int=100

            echo "      🎯 $ip - Score: ${score_int}/100 | Reqs: $total | 404s: $e404 | Suspicious: $susp"

            if is_whitelisted_ip "$ip" || is_in_cooldown "$ip"; then
                continue
            fi

            if [ "$AUTO_MODE" = true ] && [ "$score_int" -ge "$LOG_THREAT_THRESHOLD" ]; then
                # L9: only report a block if it actually happened (block may be
                # skipped by the safety limit, cooldown, or a verified-bot check).
                if block_ip_comprehensive "$ip" "Domlog threat ($dom_name): score ${score_int}/100, ${susp} suspicious" "log"; then
                    echo "      🚨 Auto-blocked"
                    ((blocked_count++))
                fi
            fi

            ((total_threats++))
        done <<< "$dom_threats"
    done <<< "$candidates"

    # M18: a domain whose scan failed was not scanned. Saying so turns a silent
    # blind spot into something an operator can act on.
    if [ "$failed_domains" -gt 0 ]; then
        echo "   ❌ $failed_domains domain log(s) could NOT be scanned - those sites were NOT checked."
        echo "      See $LOG_FILE for which ones. This is not an all-clear for them."
    fi

    if [ "$domain_count" -eq 0 ]; then
        echo "   ⚠️  No domain logs could be read - per-domain scanning did NOT run"
        log_message "WARNING: no readable domain logs - per-domain scan did not run"
    elif [ "$total_threats" -eq 0 ] && [ "$failed_domains" -eq 0 ]; then
        echo "   ✅ No per-domain threats detected across $domain_count domains"
    elif [ "$total_threats" -eq 0 ]; then
        echo "   📊 Scanned $(( domain_count - failed_domains )) of $domain_count domains: no threats in those"
    else
        echo "   📊 Scanned $domain_count domains: $total_threats threats, $blocked_count blocked"
        [ "$DRY_RUN" = true ] && echo "   ⚗️  Dry run - nothing was actually blocked."
        log_message "Domlogs: scanned $domain_count domains, $total_threats threats, $blocked_count blocked"
    fi
    echo
}

# ==============================================================================
# SECTION 15: SIMPLIFIED BOT FINGERPRINTING
# ==============================================================================
# Lightweight version of Pro's fingerprinting engine. Checks key signals:
# no static assets, known bot UAs, high error rates, regular request intervals.

# N14: one snapshot of the analysis window per run, shared by every caller.
#
# fingerprint_ip used to run its own `tail -n NUM_LINES | grep | grep` on every
# invocation. detailed_ip_analysis calls it for the top 20 IPs, so that was
# 200,000 lines re-read at defaults and up to 2,000,000 at NUM_LINES=100000 —
# repeated I/O against a log the web server is actively writing, on a shared
# host, every five minutes. It also fed straight into the watchdog timeout.
#
# The snapshot applies the '".*HTTP/' pre-filter once, so callers only grep for
# their IP. Filtering order does not change the result set.
LOG_WINDOW_FILE=""
LOG_WINDOW_SRC=""
# O5: raw line count of the window BEFORE the '".*HTTP/' pre-filter, so
# _report_unparsed_ratio can compare like with like instead of re-reading a log
# that has grown since.
LOG_WINDOW_TOTAL=0

_reset_log_window() {
    [ -n "$LOG_WINDOW_FILE" ] && rm -f "$LOG_WINDOW_FILE" 2>/dev/null
    LOG_WINDOW_FILE=""
    LOG_WINDOW_SRC=""
    LOG_WINDOW_TOTAL=0
}

_ensure_log_window() {
    local log_file="$1"
    [ -n "$log_file" ] && [ -f "$log_file" ] || return 1

    # Already snapshotted this exact file for this run.
    if [ -n "$LOG_WINDOW_FILE" ] && [ -f "$LOG_WINDOW_FILE" ] && [ "$LOG_WINDOW_SRC" = "$log_file" ]; then
        return 0
    fi

    # M18: an unreadable log is not an empty one. Without this, every analyser
    # downstream received a zero-line window and reported a clean server.
    if [ ! -r "$log_file" ]; then
        log_message "ERROR: $log_file exists but is not readable - log analysis cannot run"
        return 1
    fi

    local tmp cnt_file raw
    local -a wstatus
    tmp=$(_mktemp_data window) || return 1
    cnt_file=$(_mktemp_data wincount) || { rm -f "$tmp" 2>/dev/null; return 1; }

    # One read does both jobs: write the pre-filtered window and report how many
    # raw lines it was taken from (O5). Splitting these into two tails meant the
    # two numbers described two different points in time on a live log.
    #
    # M18: run OUTSIDE a command substitution so PIPESTATUS is readable here —
    # a subshell's exit status is only the last stage's, which hid a failed tail
    # completely.
    tail -n "$NUM_LINES" "$log_file" 2>/dev/null | \
        awk -v out="$tmp" '{ n++; if ($0 ~ /".*HTTP\//) print > out }
                           END { print n+0 }' > "$cnt_file" 2>/dev/null
    wstatus=("${PIPESTATUS[@]}")
    raw=$(cat "$cnt_file" 2>/dev/null)
    rm -f "$cnt_file" 2>/dev/null

    if ! _pipe_ok "${wstatus[@]}"; then
        rm -f "$tmp" 2>/dev/null
        log_message "ERROR: could not snapshot the log window from $log_file (exit: ${wstatus[*]})"
        return 1
    fi

    _reset_log_window
    LOG_WINDOW_FILE="$tmp"
    LOG_WINDOW_SRC="$log_file"
    if [[ "$raw" =~ ^[0-9]+$ ]]; then
        LOG_WINDOW_TOTAL="$raw"
    else
        LOG_WINDOW_TOTAL=0
    fi
    return 0
}

fingerprint_ip() {
    local ip="$1"
    local log_file="${2:-$ACTIVE_LOG}"
    local bot_score=0
    local reasons=""

    [ ! -f "$log_file" ] && echo "0|unknown" && return

    local ip_lines
    if _ensure_log_window "$log_file"; then
        # OPT-8: exact IP field matching for IPv4/IPv6 (avoiding colon word-boundary looseness)
        ip_lines=$(awk -v target="$ip" '{ if ($1 == target || $2 == target) print }' "$LOG_WINDOW_FILE" 2>/dev/null)
    else
        # Snapshot unavailable (no mktemp/space) — fall back to the direct read.
        ip_lines=$(tail -n "$NUM_LINES" "$log_file" 2>/dev/null | grep '".*HTTP/' | \
            awk -v target="$ip" '{ if ($1 == target || $2 == target) print }')
    fi
    local total
    total=$(printf '%s\n' "$ip_lines" | grep -c . || true)   # L1: grep -c already prints 0; '|| echo 0' would emit a second line

    [ "$total" -lt 5 ] && echo "0|insufficient_data" && return

    # N20 (continued): checks 1, 2 and 5 used to grep the WHOLE log line, so any
    # field could trigger them — a referer ending in .css counted as a static
    # asset, and, worst of all, "bot" is a substring of "robots", so every client
    # that fetched /robots.txt was labelled bot_user_agent. They now read the
    # same fields the analyser scores: the request path from the first quoted
    # field, the user agent from the last. This is triage output the operator
    # reads, so it must not contradict the scorer.

    # M6: these five checks used `-F'"'` with hard-coded field numbers ($2 for
    # the request, $6 for the UA), which carries the same quote-parity flaw as
    # the analyser did: one escaped quote inside a User-Agent shifts every field
    # and the checks read the wrong thing. The N20 note above says this triage
    # output must not contradict the scorer — so it now uses the very same
    # parser the scorer uses.

    # Check 1: No static assets (JS, CSS, images) = likely not a browser
    local assets
    assets=$(printf '%s\n' "$ip_lines" | awk "$AWK_LOGPARSE"'
        { if (!bs_parse()) next
          if (pathonly ~ /\.(js|css|png|jpg|jpeg|gif|svg|woff2?|ico)$/) n++ }
        END { print n+0 }')
    if [ "$total" -gt 0 ]; then
        local asset_pct=$(( assets * 100 / total ))
        if [ "$asset_pct" -lt 5 ]; then
            ((bot_score += 25))
            reasons="${reasons}no_static_assets,"
        fi
    fi

    # Check 2: Known bot user agents (UA field only — see the note above)
    local bot_ua
    bot_ua=$(printf '%s\n' "$ip_lines" | awk "$AWK_LOGPARSE"'
        { if (!bs_parse()) next
          u = tolower(ua)
          if (u ~ /(bot|crawler|spider|scraper|curl|wget|python-requests|go-http|java\/|libwww|nikto|sqlmap|nmap|masscan|zgrab)/) n++ }
        END { print n+0 }')
    if [ "$bot_ua" -gt 0 ]; then
        ((bot_score += 20))
        reasons="${reasons}bot_user_agent,"
    fi

    # Check 3: Single user agent (bots rarely switch UA)
    local unique_ua
    unique_ua=$(printf '%s\n' "$ip_lines" | awk "$AWK_LOGPARSE"'
        { if (bs_parse()) print ua }' | sort -u | wc -l)
    if [ "$unique_ua" -le 1 ]; then
        ((bot_score += 15))
        reasons="${reasons}single_ua,"
    fi

    # Check 4: High error rate (many 404s/403s).
    # M6: the old scan walked every field looking for a 3-digit number preceded
    # by "HTTP/", and referenced $(i-1) at i=1 (which is $0, the whole line) —
    # the status is now read from the parsed position instead.
    local error_lines
    error_lines=$(printf '%s\n' "$ip_lines" | awk "$AWK_LOGPARSE"'
        { if (!bs_parse()) next
          if (status ~ /^[45][0-9][0-9]$/) n++ }
        END { print n+0 }')
    if [ "$total" -gt 0 ]; then
        local error_pct=$(( error_lines * 100 / total ))
        if [ "$error_pct" -gt 50 ]; then
            ((bot_score += 20))
            reasons="${reasons}high_error_rate,"
        fi
    fi

    # Check 5: Suspicious path probing
    # N20: kept in step with the hardened scorer. The old pattern matched bare
    # /admin, phpmyadmin, wp-login and xmlrpc anywhere in the line, so a site
    # owner working in their own admin panel was labelled "path_probing" in the
    # triage output the operator reads — directly contradicting the analyser,
    # which (correctly) does not treat that as an attack. Only unambiguous
    # exploitation signatures remain, segment-anchored like attack_patterns.
    local probes
    probes=$(printf '%s\n' "$ip_lines" | awk "$AWK_LOGPARSE"'
        { if (!bs_parse()) next
          if (pathonly ~ /(^|\/)\.(env|git|aws)|wp-config\.php|\.(bak|sql|old|swp)$|\/etc\/(passwd|shadow)|\/proc\/self|phpinfo\.php|(shell|c99|r57)\.php/) n++ }
        END { print n+0 }')
    if [ "$probes" -gt 3 ]; then
        ((bot_score += 20))
        reasons="${reasons}path_probing,"
    fi

    local classification="human"
    if [ "$bot_score" -ge 60 ]; then
        classification="malicious_bot"
    elif [ "$bot_score" -ge 35 ]; then
        classification="suspicious_bot"
    elif [ "$bot_score" -ge 15 ]; then
        classification="possible_bot"
    fi

    echo "${bot_score}|${classification}|${reasons%,}"
}

# ==============================================================================
# SECTION 16: FIREWALL HELPERS
# ==============================================================================

_nft_available() {
    command -v nft >/dev/null 2>&1
}

# Ensure the shared 'inet botsurgeon' table and our input chain exist.
#
# COEXISTENCE (M1): the table is SHARED with BotSurgeon-Pro. Chain creation is
# idempotent — 'nft add table' / 'nft add chain' are no-ops when the object
# already exists with the same spec — so we assert our input chain on EVERY run
# instead of only when we create the table. This means a table created first by
# Pro (input + output chains) does not stop us, and a table created first by us
# does not stop Pro from asserting its own output chain.
#
#   >>> PRO-SIDE PATCH: DONE. BotSurgeon-Pro's _nft_ensure_table now asserts its
#   >>> input AND output chains on every run (out of the "if table absent" guard),
#   >>> and its _nft_persist writes via mktemp. So if Basic creates the table
#   >>> first (input chain only), Pro still creates its own output chain and
#   >>> outbound blocking works regardless of which product ran first.
#
# M8: we no longer assume "table exists => usable". We verify the input chain is
# actually present and return failure otherwise, so a table left with a missing
# chain (interrupted run, manual 'nft delete chain') is repaired rather than
# generating silent per-rule add failures forever.
# N4: the table now also carries two Basic-owned named sets and exactly one
# drop rule per address family referencing them. Everything after this is set
# membership, not rule surgery:
#
#   * blocks expire by themselves (per-element timeout) — a false positive is
#     self-healing instead of a permanent outage nobody notices;
#   * membership/removal are exact set operations, so the substring bugs that
#     needed anchoring in the rule-grep model cannot arise here at all;
#   * one rule per family instead of one per IP, so thousands of blocks stay
#     fast and the ruleset stays readable.
#
# The set-reference rules are added once and verified by literal name, not by
# IP, so re-running never appends duplicates.
_nft_ensure_table() {
    _nft_available || return 1
    nft add table inet "$NFT_TABLE" 2>/dev/null || return 1
    nft add chain inet "$NFT_TABLE" input \{ type filter hook input priority -1 \; policy accept \; \} 2>/dev/null
    nft list chain inet "$NFT_TABLE" input >/dev/null 2>&1 || return 1

    # Sets are declared with 'flags timeout' but NO default timeout, so the TTL
    # travels with each element. That way changing BLOCK_TTL_HOURS takes effect
    # on the next block instead of being frozen into the set definition.
    nft add set inet "$NFT_TABLE" "$NFT_SET4" \{ type ipv4_addr \; flags timeout \; \} 2>/dev/null
    nft add set inet "$NFT_TABLE" "$NFT_SET6" \{ type ipv6_addr \; flags timeout \; \} 2>/dev/null
    nft list set inet "$NFT_TABLE" "$NFT_SET4" >/dev/null 2>&1 || return 1
    nft list set inet "$NFT_TABLE" "$NFT_SET6" >/dev/null 2>&1 || return 1

    # One drop rule per family, added only if absent. Matching on the set name
    # is a fixed literal, so this check has none of the hazards of IP matching.
    local chain_dump
    chain_dump=$(nft list chain inet "$NFT_TABLE" input 2>/dev/null)
    case "$chain_dump" in
        *"@$NFT_SET4"*) ;;
        *) nft add rule inet "$NFT_TABLE" input ip saddr "@$NFT_SET4" counter drop 2>/dev/null ;;
    esac
    case "$chain_dump" in
        *"@$NFT_SET6"*) ;;
        *) nft add rule inet "$NFT_TABLE" input ip6 saddr "@$NFT_SET6" counter drop 2>/dev/null ;;
    esac
    return 0
}

_nft_set_for_ip() {
    if is_ipv6 "$1"; then printf '%s' "$NFT_SET6"; else printf '%s' "$NFT_SET4"; fi
}

# Exact membership test. 'get element' is the precise way to ask; the listing
# fallback covers older nft builds that lack it and still matches whole tokens
# only (set elements print brace/comma/space delimited).
_nft_set_has_ip() {
    local setname="$1" ip="$2"
    nft get element inet "$NFT_TABLE" "$setname" "{ $ip }" >/dev/null 2>&1 && return 0
    local ipre
    ipre=$(_ip_regex "$ip")
    nft list set inet "$NFT_TABLE" "$setname" 2>/dev/null | \
        grep -qE "[{,[:space:]]${ipre}([,[:space:]}]|\$)"
}

_nft_block_ip() {
    local ip="$1"
    _nft_ensure_table || return 1
    local setname
    setname=$(_nft_set_for_ip "$ip")

    # Adding an element that is already present refreshes its timeout, which is
    # what we want for a re-offender. If the add is rejected because it already
    # exists, the IP is still blocked — that is a success, not a failure.
    if _ttl_enabled; then
        nft add element inet "$NFT_TABLE" "$setname" "{ $ip timeout ${BLOCK_TTL_HOURS}h }" 2>/dev/null && return 0
    else
        nft add element inet "$NFT_TABLE" "$setname" "{ $ip }" 2>/dev/null && return 0
    fi
    _nft_set_has_ip "$setname" "$ip"
}

_nft_unblock_ip() {
    local ip="$1" setname removed=1
    _nft_available || return 1
    nft list table inet "$NFT_TABLE" >/dev/null 2>&1 || return 1
    setname=$(_nft_set_for_ip "$ip")
    nft delete element inet "$NFT_TABLE" "$setname" "{ $ip }" 2>/dev/null && removed=0
    return "$removed"
}

_nft_persist() {
    _nft_available || return 0
    local persist_dir tmp
    persist_dir="$(dirname "$NFT_PERSIST_FILE")"
    [ -d "$persist_dir" ] || mkdir -p "$persist_dir" 2>/dev/null

    tmp=$(mktemp "${NFT_PERSIST_FILE}.XXXXXXXXXX" 2>/dev/null) || {
        log_message "WARNING: could not create temp file to persist nftables rules"
        echo "      ⚠️  Could not persist nftables rules (temp file creation failed)"
        return 1
    }

    if nft list table inet "$NFT_TABLE" > "$tmp" 2>/dev/null && [ -s "$tmp" ]; then
        if [ -f "$NFT_PERSIST_FILE" ]; then
            chmod --reference="$NFT_PERSIST_FILE" "$tmp" 2>/dev/null || chmod 600 "$tmp" 2>/dev/null
        else
            chmod 600 "$tmp" 2>/dev/null
        fi
        if mv -f "$tmp" "$NFT_PERSIST_FILE" 2>/dev/null; then
            return 0
        fi
    fi

    rm -f "$tmp" 2>/dev/null
    log_message "WARNING: failed to persist nftables ruleset to $NFT_PERSIST_FILE"
    echo "      ⚠️  Could not persist nftables rules to $NFT_PERSIST_FILE"
    return 1
}

# C6: a preview must restore NOTHING.
#
# main() calls this before security_preflight, which is where the root and mode
# checks live — so it has to make its own. Unguarded, `--dry-run` run as root on
# a box whose nft table had been flushed re-imported
# /etc/nftables/botsurgeon.nft and put every persisted DROP straight back into
# enforcement. That is the exact state an operator is in mid-incident, having
# just cleared the rules to restore service and reaching for the command the
# README calls safe: "--dry-run performs the same analysis as --auto and reports
# which IPs it would block, changing nothing."
#
# So the single most mutating thing in the whole run was the one thing the
# preview did before it had even decided it was a preview.
_nft_load() {
    if [ "$DRY_RUN" = true ]; then
        if _nft_available && [ -f "$NFT_PERSIST_FILE" ] && \
           ! nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
            echo "🧪 DRY RUN: saved nftables rules exist in $NFT_PERSIST_FILE but are NOT being loaded."
            echo "   A real run would restore them; this preview leaves your ruleset untouched."
        fi
        return 0
    fi

    # Restoring a firewall table is privileged and mutating. Anything that is
    # not a genuine root run has no business doing it.
    [ "$(id -u)" -eq 0 ] || return 0

    _nft_available || return
    [ -f "$NFT_PERSIST_FILE" ] || return 0
    nft list table inet "$NFT_TABLE" >/dev/null 2>&1 && return 0

    # M21: this file is fed to `nft -f` as root — an nftables ruleset script, so
    # whoever writes it writes the firewall. It was the one privileged file read
    # in the whole tool with NO ownership gate, while the config, the whitelist,
    # the proxy ranges and the disable flag all had one. Same gate, same reason,
    # and the consequence here is the largest of the four.
    if ! _file_is_root_safe "$NFT_PERSIST_FILE" "nftables persistence file" >/dev/null 2>&1; then
        echo "🚨 SECURITY: NOT loading $NFT_PERSIST_FILE - it is not safely root-owned."
        echo "   That file is executed as an nftables ruleset by root. Anyone able to"
        echo "   write it (or its directory) could rewrite this server's firewall."
        echo "   Fix with: chown root:root \"$NFT_PERSIST_FILE\" && chmod 600 \"$NFT_PERSIST_FILE\""
        echo "   Previously-saved blocks are NOT restored this run."
        log_message "SECURITY: refused to load untrusted $NFT_PERSIST_FILE"
        return 1
    fi

    # M21: and report what actually happened. The old code logged "loaded"
    # whether nft accepted the file or rejected it.
    if nft -f "$NFT_PERSIST_FILE" 2>/dev/null; then
        log_message "nftables: loaded BotSurgeon table from $NFT_PERSIST_FILE"
    else
        echo "⚠️  Could not restore saved nftables rules from $NFT_PERSIST_FILE."
        echo "   Previously-blocked addresses are NOT blocked until they are seen again."
        log_message "ERROR: nft -f failed on $NFT_PERSIST_FILE - persisted blocks not restored"
        return 1
    fi
}

# O1: both of these are consulted repeatedly inside the per-IP block path, and
# _is_imunify360 shells out to the Imunify agent — an RPC that can take seconds
# on a loaded box. Between layer 0, layer 2b and the persist step that was up to
# three agent round-trips per blocked IP; at --emergency (MAX_BLOCKS_PER_RUN=50)
# that alone could consume the watchdog budget and kill the run mid-attack.
#
# Neither answer can change while a run is in flight, so resolve each once.
IMUNIFY360_CACHE=""

_is_imunify360() {
    if [ -n "$IMUNIFY360_CACHE" ]; then
        [ "$IMUNIFY360_CACHE" = "yes" ]
        return
    fi
    if command -v imunify360-agent >/dev/null 2>&1 && \
       imunify360-agent blacklist ip list --limit 1 >/dev/null 2>&1; then
        IMUNIFY360_CACHE="yes"
        return 0
    fi
    IMUNIFY360_CACHE="no"
    return 1
}

# M14: an INSTALLED csf binary is not a firewall manager.
#
# `command -v csf` was the whole test, so a box where CSF had been disabled with
# `csf -x` - or installed and never enabled, which is common after a panel
# migration - still counted as manager-owned. nftables and direct iptables both
# stood down for a manager that was enforcing nothing, and if `csf -td` then
# failed (as it does when CSF is disabled) the address stayed completely
# unblocked while the run printed "CSF: failed" and moved on.
#
# The firewalld branch below already got this right - it checks is-active, not
# just the binary. This brings CSF up to the same standard.
_csf_is_active() {
    command -v csf >/dev/null 2>&1 || return 1

    # `csf -x` drops this file and flushes CSF's rules. Nothing is being
    # enforced while it exists.
    [ -f /etc/csf/csf.disable ] && return 1

    # The authoritative test is whether CSF's own chains are in the live
    # ruleset. Needs root to read; a non-root run cannot block anyway, so
    # assume CSF is managing rather than guess it away.
    if [ "$(id -u)" -eq 0 ] && command -v iptables >/dev/null 2>&1; then
        iptables -n -L LOCALINPUT >/dev/null 2>&1 && return 0
        iptables -n -L DENYIN     >/dev/null 2>&1 && return 0
        return 1
    fi
    return 0
}

_has_firewall_manager() {
    if [ -n "$FW_MANAGER_CACHE" ]; then
        [ "$FW_MANAGER_CACHE" = "yes" ]
        return
    fi
    FW_MANAGER_CACHE="no"
    if _csf_is_active; then
        FW_MANAGER_CACHE="yes"
    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
        FW_MANAGER_CACHE="yes"
    elif _is_imunify360; then
        FW_MANAGER_CACHE="yes"
    fi
    [ "$FW_MANAGER_CACHE" = "yes" ]
}

# M12: say ONCE per run why the Fail2Ban layer is being declined. Per-IP this
# would be noise at --emergency (up to 50 blocks), and the reason is a property
# of the configuration, not of the address.
F2B_TTL_NOTICE_SHOWN=false

_f2b_ttl_notice() {
    [ "$F2B_TTL_NOTICE_SHOWN" = true ] && return 0
    F2B_TTL_NOTICE_SHOWN=true
    echo "      ℹ️  Fail2Ban: skipped. A jail ban lasts for that jail's own bantime,"
    echo "         which BotSurgeon cannot bound to BLOCK_TTL_HOURS (${BLOCK_TTL_HOURS}h),"
    echo "         and unbanning it later could tear down one of Fail2Ban's own bans."
    echo "         The packet filter above already has this address."
    echo "         Want Fail2Ban in the mix? Set BLOCK_TTL_HOURS=0 (permanent blocks)"
    echo "         in $CONFIG_FILE, or match your jail bantime to the TTL yourself."
    log_message "Fail2Ban layer declined: jail bantime cannot be bounded to BLOCK_TTL_HOURS"
    return 0
}

# N4: CSF rotates out the oldest permanent deny once csf.deny reaches
# DENY_IP_LIMIT, without warning anyone. Surface it.
_csf_deny_limit_check() {
    command -v csf >/dev/null 2>&1 || return 0
    [ -r /etc/csf/csf.conf ] && [ -r /etc/csf/csf.deny ] || return 0

    local limit count
    limit=$(sed -n 's/^[[:space:]]*DENY_IP_LIMIT[[:space:]]*=[[:space:]]*"\{0,1\}\([0-9]\{1,\}\)"\{0,1\}.*/\1/p' \
            /etc/csf/csf.conf 2>/dev/null | head -1)
    [[ "$limit" =~ ^[0-9]+$ ]] || return 0
    [ "$limit" -eq 0 ] && return 0          # 0 means unlimited

    count=$(grep -cvE '^[[:space:]]*(#|$)' /etc/csf/csf.deny 2>/dev/null) || count=0
    [[ "$count" =~ ^[0-9]+$ ]] || return 0

    if [ "$count" -ge "$limit" ]; then
        echo "⚠️  CSF: csf.deny holds $count entries and DENY_IP_LIMIT is $limit."
        echo "    CSF is now discarding its OLDEST deny for every new one it adds,"
        echo "    so previously blocked attackers are being silently released."
        echo "    Prune csf.deny, or raise DENY_IP_LIMIT in /etc/csf/csf.conf."
        log_message "WARNING: csf.deny at $count/$limit (DENY_IP_LIMIT reached)"
    elif [ "$count" -ge $(( limit * 9 / 10 )) ]; then
        echo "ℹ️  CSF: csf.deny is at $count/$limit entries (DENY_IP_LIMIT)."
        log_message "csf.deny at $count/$limit"
    fi
    return 0
}

# M13: write the boot-time ruleset through a temp file and rename it into place.
#
# `iptables-save > /etc/sysconfig/iptables` truncates the persistence file the
# instant the SHELL opens the redirect — before iptables-save has produced a
# single byte. Anything that interrupts the write (a full /etc, an I/O error,
# the self-watchdog's SIGTERM, an operator's Ctrl-C, the OOM killer) leaves a
# truncated or half-written ruleset on disk. Every error was then discarded by
# 2>/dev/null, so nobody found out until the reboot that was meant to restore
# the firewall came up with a partial one — or with none at all.
#
# _nft_persist already had this shape; the iptables side simply never got it.
_persist_one_ruleset() {
    local save_cmd="$1" target="$2" tmp
    command -v "$save_cmd" >/dev/null 2>&1 || return 0
    [ -d "$(dirname "$target")" ] || return 0

    # Same directory as the target: mv is only atomic within one filesystem.
    tmp=$(mktemp "${target}.XXXXXXXXXX" 2>/dev/null) || return 1

    if ! "$save_cmd" > "$tmp" 2>/dev/null; then
        rm -f "$tmp" 2>/dev/null
        return 1
    fi
    # A zero-byte save is a failed save, not an empty firewall: iptables-save
    # always emits at least the table headers and chain policies. Committing it
    # would persist "no rules at all" over a working ruleset.
    if [ ! -s "$tmp" ]; then
        rm -f "$tmp" 2>/dev/null
        return 1
    fi

    # Keep whatever mode the distro chose for the existing file; 600 for a new
    # one (a firewall ruleset is not world-readable material).
    if [ -f "$target" ]; then
        chmod --reference="$target" "$tmp" 2>/dev/null || chmod 600 "$tmp" 2>/dev/null
    else
        chmod 600 "$tmp" 2>/dev/null
    fi

    if ! mv -f "$tmp" "$target" 2>/dev/null; then
        rm -f "$tmp" 2>/dev/null
        return 1
    fi
    return 0
}

_persist_iptables() {
    local failed=0 wrote=0
    if [ -d /etc/sysconfig ]; then
        _persist_one_ruleset iptables-save  /etc/sysconfig/iptables  || failed=1
        _persist_one_ruleset ip6tables-save /etc/sysconfig/ip6tables || failed=1
        wrote=1
    elif [ -d /etc/iptables ]; then
        _persist_one_ruleset iptables-save  /etc/iptables/rules.v4 || failed=1
        _persist_one_ruleset ip6tables-save /etc/iptables/rules.v6 || failed=1
        wrote=1
    fi

    # Only as a fallback. netfilter-persistent saves to those very paths with a
    # plain redirect of its own, so running it after a successful atomic write
    # would reintroduce the truncation window this function exists to close.
    if [ "$wrote" -eq 0 ] && command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 || failed=1
    fi

    if [ "$failed" -eq 1 ]; then
        echo "      ⚠️  Could not persist the iptables ruleset. Blocks are live NOW but"
        echo "         may not survive a reboot. Check free space and permissions on /etc."
        log_message "WARNING: iptables persistence FAILED - live rules may not survive a reboot"
        return 1
    fi
    return 0
}

# ==============================================================================
# SECTION 17: COMPREHENSIVE IP BLOCKING
# ==============================================================================

# Block an IP across every firewall layer present on the server.
#
# RETURN CONTRACT (N6) — callers must not print "blocked" unless this returns 0:
#   0  The IP was actually blocked by at least one layer.
#   1  Not blocked, and the caller should treat it as a refusal/failure:
#      invalid IP, whitelisted, verified search bot, per-run safety limit hit,
#      or every layer failed.
#   2  Not blocked, by design and without error: dry-run preview, or the IP is
#      still inside its cooldown window.
#
# Code 2 exists because both of those paths used to return 0, so the callers
# printed "🚨 Auto-blocked" and incremented their counters during a --dry-run
# preview (and during a cooldown skip, which is how a missed block could be
# reported as a success). `if block_ip_comprehensive ...` treats 1 and 2 alike,
# so callers only ever claim a block on a true 0.
block_ip_comprehensive() {
    local ip="$1"
    local reason="$2"
    local block_type="${3:-log}"
    local success_count=0

    if ! is_valid_ip "$ip"; then
        log_message "Invalid IP: $ip"
        return 1
    fi

    # M15: re-read the kill switch on EVERY block decision, not once at startup.
    # A --auto pass can hold the lock for MAX_RUNTIME, and an operator who runs
    # --disable mid-incident means "stop now", not "stop next cron cycle". Code
    # 2: not blocked, by design and without error.
    if is_disabled; then
        echo "   ⏸️  BotSurgeon was disabled mid-run - not blocking $ip"
        log_message "Disabled mid-run: refused to block $ip"
        return 2
    fi

    if is_whitelisted_ip "$ip"; then
        log_message "IP $ip is whitelisted - skipping"
        echo "   ⚠️  Whitelisted - skipping"
        return 1
    fi

    # N1: never block a shared front end. This is checked centrally so it covers
    # every block path — connection floods, access-log threats, domlog threats
    # and monitor mode — not just the log analyser that produced the evidence.
    # M17: enforcing or advisory - see _resolve_proxy_heuristic_mode. Addresses
    # in PROXY_RANGES_FILE never reach here at all; is_whitelisted_ip above
    # already turned them away on deterministic evidence.
    # MAJ-3: the proxy heuristic only exempts log-based analysis blocks. Raw
    # connection floods (Phase 1 / connection threshold path) are NEVER
    # exempted by heuristic — traffic shaping cannot legitimize a flood.
    if is_proxy_ip "$ip"; then
        local pd puac
        pd=$(_proxy_detail "$ip")
        puac=$(echo "$pd" | cut -d'|' -f2)
        local is_conn_block=false
        if [ "$block_type" = "conn" ] || [ "$block_type" = "connection" ] || [[ "$reason" =~ ^(Excessive connections:|Monitor:.*connections) ]]; then
            is_conn_block=true
        fi

        if [ "$is_conn_block" = true ]; then
            local count=0
            if [[ "$reason" =~ ([0-9]+)\ connections ]] || [[ "$reason" =~ Excessive\ connections:\ ([0-9]+) ]]; then
                count="${BASH_REMATCH[1]}"
            fi
            local cdn_thresh=$(( AUTO_BLOCK_THRESHOLD * 2 ))
            if [ "$count" -gt 0 ] && [ "$count" -lt "$cdn_thresh" ]; then
                echo "   ℹ️  $ip is a detected CDN edge ($count < ${cdn_thresh} connections) - skipping block"
                log_message "REFUSED to block CDN edge $ip on connection flood: $count connections < ${cdn_thresh} (2x AUTO_BLOCK_THRESHOLD)"
                return 1
            fi
            echo "   ⚠️  $ip matches the shared-front-end pattern (${puac} distinct user agents)."
            echo "      Connection count ($count) exceeds CDN flood threshold (${cdn_thresh}) - blocking goes ahead."
            echo "      If this really is your edge, add it to $PROXY_RANGES_FILE"
            log_message "ADVISORY: $ip matches proxy heuristic but exceeds CDN flood threshold ($count >= ${cdn_thresh}): $reason"
        else
            if [ "$PROXY_HEURISTIC_MODE" = enforce ]; then
                log_message "REFUSED to block $ip - shared front end (${puac} distinct user agents): $reason"
                echo "   🛑 REFUSING TO BLOCK $ip - this looks like a CDN edge, reverse proxy or NAT gateway"
                echo "      ${puac} distinct user agents came from this one address, mostly succeeding."
                echo "      Blocking it would cut off every visitor behind it."
                echo "      Behind Cloudflare/Sucuri/a load balancer? Install mod_remoteip so your"
                echo "      logs carry the real client IP, or list your edge ranges in:"
                echo "        $PROXY_RANGES_FILE"
                return 1
            fi
            # Advisory: the guess does not get a veto, but the operator hears it.
            echo "   ⚠️  $ip matches the shared-front-end pattern (${puac} distinct user agents)."
            echo "      The heuristic is ADVISORY here, so the block goes ahead - a traffic"
            echo "      pattern is not proof, and an attacker can produce this one."
            echo "      If this really is your edge, add it to $PROXY_RANGES_FILE"
            echo "      and it will never be blocked again."
            log_message "ADVISORY: $ip matches the shared-front-end heuristic; blocking anyway (advisory mode)"
        fi
    fi

    if is_in_cooldown "$ip"; then
        echo "   ⏳ Recently blocked (cooldown) - skipping"
        return 2
    fi

    # Safety limit: prevent runaway blocking
    if [ "$BLOCKS_THIS_RUN" -ge "$MAX_BLOCKS_PER_RUN" ]; then
        log_message "SAFETY LIMIT: Reached $MAX_BLOCKS_PER_RUN blocks this run. IP $ip logged but not blocked."
        echo "   ⛔ SAFETY LIMIT reached ($MAX_BLOCKS_PER_RUN blocks) - logged only"
        return 1
    fi

    # Last-resort check: verify this isn't a legitimate search bot
    if is_verified_search_bot "$ip"; then
        log_message "IP $ip is a verified search bot (rDNS confirmed) - NOT blocking"
        echo "   ✅ Verified search engine bot - skipping"
        return 1
    elif ! command -v dig >/dev/null 2>&1; then
        log_message "NOTICE: bot verification for $ip skipped - 'dig' utility missing"
    fi

    log_message "Blocking $ip: $reason"

    if [ "$DRY_RUN" = true ]; then
        local fp
        fp=$(fingerprint_ip "$ip" 2>/dev/null)
        local classification
        classification=$(echo "$fp" | cut -d'|' -f2)
        echo "   🧪 DRY RUN: Would block $ip [${classification:-unknown}]"
        return 2
    fi

    # M9: journal the expiry deadline BEFORE touching any firewall.
    #
    # Rules were applied first and the deadline written afterwards, so a SIGTERM
    # in between — from the self-watchdog, from the `timeout 300` the README
    # recommends for cron, or from an operator's Ctrl-C — left a live rule with
    # no pending deadline. expire_blocks would never lift it, and the block
    # became permanent in spite of BLOCK_TTL_HOURS. That failure was biased
    # towards the worst moment: the watchdog fires under load, which is exactly
    # when false positives are most likely.
    #
    # Writing first fails in the safe direction instead. A deadline for a block
    # that never landed is harmless — _expire_one_ip on an absent rule is a
    # no-op — so the entry is simply removed again if every layer fails.
    #
    # M11: and the write is now CHECKED. nftables, CSF -td and firewalld
    # --timeout carry their own expiry, so they are safe whatever happens here.
    # Direct iptables and hosts.deny have no notion of a TTL — this journal is
    # the only thing that will ever lift them. Installing on those layers with
    # no durable deadline manufactures exactly the permanent block that
    # BLOCK_TTL_HOURS exists to prevent, so when the journal cannot be written
    # they are refused rather than applied blind.
    # M12: work out WHICH layers will need lifting by hand, and record that with
    # the deadline. The conditions below mirror the layer blocks exactly, so the
    # journal describes what this run is about to attempt. Recording a layer that
    # then fails to apply is harmless — every removal in _expire_one_ip is a
    # no-op on an address that was never added — which is the same
    # fail-in-the-safe-direction argument the M9 note makes above.
    local ttl_layers="" ttl_pretty=""
    if _ttl_enabled; then
        # M14: recorded whenever iptables EXISTS, not only when we are the
        # primary. The last-resort fallback further down can reach for it even
        # on a manager-owned box, and an untracked rule there would be exactly
        # the permanent block M11 exists to prevent. Over-recording is free:
        # _expire_one_ip on an address that was never added is a no-op.
        if command -v "$(_ipt_cmd "$ip")" >/dev/null 2>&1; then
            ttl_layers="ipt"; ttl_pretty="direct iptables"
        fi
        if [ -w "/etc/hosts.deny" ]; then
            local hd_chk_re
            hd_chk_re=$(_ip_regex "$ip")
            if ! grep -qE "^ALL:[[:space:]]*${hd_chk_re}([[:space:]]|#|$)" /etc/hosts.deny 2>/dev/null; then
                ttl_layers="${ttl_layers:+$ttl_layers,}hosts"
                ttl_pretty="${ttl_pretty:+$ttl_pretty, }hosts.deny"
            fi
        fi
        if _is_imunify360; then
            ttl_layers="${ttl_layers:+$ttl_layers,}imunify"
            ttl_pretty="${ttl_pretty:+$ttl_pretty, }Imunify360"
        fi
    fi

    local expiry_journalled=true
    if _ttl_enabled && [ -n "$ttl_layers" ]; then
        if ! _journal_expiry "$ip" "$ttl_layers"; then
            expiry_journalled=false
            echo "      ⚠️  Could not record the ${BLOCK_TTL_HOURS}h expiry deadline for $ip."
            echo "         ($EXPIRY_FILE is unwritable, or the filesystem is full.)"
            echo "         Skipping the layers that cannot expire on their own"
            echo "         (${ttl_pretty}) - a block there would be PERMANENT."
            log_message "ERROR: expiry journal write FAILED for $ip - skipped: $ttl_layers"
        fi
    fi

    # Layer 0: nftables — primary ONLY when no firewall manager owns the ruleset.
    # When CSF/firewalld/Imunify360 is present we block through their own layers
    # below; adding a direct nft drop at priority -1 would run BEFORE the manager's
    # ACCEPT rules and silently override the admin's csf.allow / trusted zones (C3).
    if _nft_available && ! _has_firewall_manager; then
        if _nft_block_ip "$ip"; then
            echo "      ✅ nftables: blocked"
            ((success_count++))
        else
            echo "      ❌ nftables: failed"
        fi
    fi

    # Layer 1: CSF Firewall.
    # N4: use a TEMPORARY deny (csf -td) when blocks are meant to expire. Two
    # reasons beyond expiry itself: temp bans live in csf.tempban and do NOT
    # consume csf.deny slots, so they cannot trip DENY_IP_LIMIT (default 200) —
    # which, once reached, makes CSF silently rotate out the OLDEST permanent
    # deny every time a new one is added, quietly unblocking real attackers.
    # Some CSF builds reject the -c comment flag, so fall back without it.
    # M14: _csf_is_active, not `command -v csf` — an installed-but-disabled CSF
    # cannot accept a deny, and trying produced a spurious "CSF: failed" line
    # on a host where CSF was never the answer.
    if _csf_is_active; then
        local csf_ok=false
        if _ttl_enabled; then
            local ttl_s
            ttl_s=$(_ttl_seconds)
            if csf -td "$ip" "$ttl_s" -d in -c "BotSurgeon-Basic: $reason" >/dev/null 2>&1 ||
               csf -td "$ip" "$ttl_s" >/dev/null 2>&1; then
                csf_ok=true
            fi
        else
            csf -d "$ip" "BotSurgeon-Basic: $reason" >/dev/null 2>&1 && csf_ok=true
        fi
        if [ "$csf_ok" = true ]; then
            echo "      ✅ CSF: blocked"
            ((success_count++))
        else
            echo "      ❌ CSF: failed"
        fi
    fi

    # Layer 2: firewalld.
    # N4: firewalld has native rule expiry via --timeout, but it applies to
    # RUNTIME rules only (--timeout and --permanent are mutually exclusive).
    # That is exactly right for an expiring block, and it also means no reload
    # is needed. Permanent mode keeps the old --permanent + batched reload path.
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
        local fw_family="ipv4"
        is_ipv6 "$ip" && fw_family="ipv6"
        if _ttl_enabled; then
            if firewall-cmd --add-rich-rule="rule family=$fw_family source address=\"$ip\" drop" \
                            --timeout="$(_ttl_seconds)" >/dev/null 2>&1; then
                echo "      ✅ firewalld: blocked (expires in ${BLOCK_TTL_HOURS}h)"
                ((success_count++))
            else
                echo "      ❌ firewalld: failed"
            fi
        elif firewall-cmd --permanent --add-rich-rule="rule family=$fw_family source address=\"$ip\" drop" >/dev/null 2>&1; then
            FIREWALLD_NEEDS_RELOAD=true
            echo "      ✅ firewalld: blocked (reload pending)"
            ((success_count++))
        else
            echo "      ❌ firewalld: failed"
        fi
    fi

    # Layer 2b: Direct iptables (only when no firewall manager owns the ruleset)
    #
    # C1: the insert carried "-m comment --comment <reason>" while the check
    # used a bare spec, so -C could never find the rule this code had just
    # added. Every block printed "failed" over a live DROP, and the guarded
    # insert re-added a duplicate on every run. _ipt_add is idempotent and
    # verifies with a spec it can actually reproduce.
    #
    # M11: iptables has no native expiry, so it is only safe to use when the
    # deadline for this IP is durably on disk.
    if ! _has_firewall_manager && [ "$expiry_journalled" = true ]; then
        local ipt_cmd
        ipt_cmd=$(_ipt_cmd "$ip")
        if _ipt_add "$ip"; then
            echo "      ✅ ${ipt_cmd}: blocked"
            ((success_count++))
        else
            echo "      ❌ ${ipt_cmd}: failed"
        fi
    fi

    # Layer 3: Imunify360 (not ImunifyAV)
    #
    # M12: the add was unqualified, so the entry sat in the local blacklist
    # forever while this function counted it as a successful block on a tool
    # that advertises a 24h TTL. Two changes: ask the agent for an expiring
    # entry where its build supports one, and — regardless of whether that flag
    # took — journal the layer so our own sweep deletes it at BLOCK_TTL_HOURS.
    # The belt-and-braces is deliberate: the CLI flag varies across Imunify
    # builds, and "the flag was accepted" is not evidence the entry will expire.
    # Deleting an already-expired entry is a harmless no-op; not deleting a
    # permanent one is an indefinite block.
    if _is_imunify360 && [ "$expiry_journalled" = true ]; then
        local imu_ok=false
        if _ttl_enabled && imunify360-agent blacklist ip add "$ip" \
               --expiration "$(_ttl_seconds)" \
               --comment "BotSurgeon-Basic: $reason" >/dev/null 2>&1; then
            imu_ok=true
        elif imunify360-agent blacklist ip add "$ip" \
               --comment "BotSurgeon-Basic: $reason" >/dev/null 2>&1; then
            imu_ok=true
        fi
        if [ "$imu_ok" = true ]; then
            echo "      ✅ Imunify360: blocked"
            ((success_count++))
        else
            echo "      ❌ Imunify360: failed"
        fi
    fi

    # Layer 4: Fail2Ban
    #
    # M12: only when blocks are meant to be PERMANENT.
    #
    # `banip` takes no per-ban lifetime — the ban lasts for that jail's own
    # bantime, and `recidive` ships with a one-week default. So this layer
    # routinely outlived BLOCK_TTL_HOURS while being counted here as an
    # expiring block: the tool reported a 24h block and delivered a 7-day one.
    #
    # Lifting it ourselves is not the answer either. Fail2Ban bans the same
    # addresses for its own reasons, `unbanip` cannot tell our ban from its,
    # and an automatic sweep that tears down someone else's ban is worse than
    # the overrun it fixes.
    #
    # Declining it costs no enforcement: Fail2Ban is not a firewall manager, so
    # nftables or direct iptables has already taken this IP on any host where
    # no manager owns the ruleset, and CSF/firewalld/Imunify360 has where one
    # does. It was always an extra layer, never the load-bearing one.
    if command -v fail2ban-client >/dev/null 2>&1; then
        if _ttl_enabled; then
            _f2b_ttl_notice
        elif fail2ban-client set apache-bots banip "$ip" >/dev/null 2>&1 || \
             fail2ban-client set recidive banip "$ip" >/dev/null 2>&1; then
            echo "      ✅ Fail2Ban: blocked"
            ((success_count++))
        fi
    fi

    # Layer 5: hosts.deny (dedup check before appending)
    # N15: anchored/escaped match. "ALL: 1.2.3.4" is a substring of
    # "ALL: 1.2.3.45", so a plain grep -qF would skip writing the entry for
    # 1.2.3.4 whenever the longer IP was already listed.
    #
    # C5: this is counted SEPARATELY from success_count. tcpwrappers is honoured
    # by sshd and other libwrap-linked daemons — Apache, LiteSpeed and Nginx
    # ignore it completely. Counting it as a successful block meant a web
    # attacker could be "blocked" by a layer that does not filter web traffic at
    # all: cooldown set, expiry journalled, "BLOCKED" logged, attacker unimpeded.
    #
    # M11: hosts.deny has no native expiry either - same gate as iptables.
    local advisory_count=0
    if [ -w "/etc/hosts.deny" ] && [ "$expiry_journalled" = true ]; then
        local hd_block_re
        hd_block_re=$(_ip_regex "$ip")
        if ! grep -qE "^ALL:[[:space:]]*${hd_block_re}([[:space:]]|#|$)" /etc/hosts.deny 2>/dev/null; then
            echo "ALL: $ip # BotSurgeon-Basic [$(date '+%Y-%m-%d')]" >> "/etc/hosts.deny"
            echo "      ✅ hosts.deny: updated (advisory - web servers ignore tcpwrappers)"
            advisory_count=$((advisory_count + 1))
        fi
    fi

    # Layer 6: last-resort direct enforcement (M14).
    #
    # Layers 0 and 2b stand down when CSF/firewalld/Imunify360 owns the ruleset,
    # because a direct nft drop at priority -1 runs ahead of the manager's own
    # ACCEPT rules and would override the admin's csf.allow or trusted zones
    # (C3). That deference is right while the manager is doing its job. It is
    # wrong once the manager has failed — which is how a live attacker stayed
    # completely unblocked while every layer printed "failed" and the run
    # carried on to the next address.
    #
    # Reached ONLY when nothing took. This is not second-guessing a manager's
    # policy: the manager's own allow lists were honoured by is_whitelisted_ip
    # before any of this ran (csf.allow explicitly, and iptables ACCEPT rules
    # too), so an address arriving here is one the manager has no opinion about
    # — it simply could not act.
    if [ "$success_count" -le 0 ] && _has_firewall_manager; then
        echo "      ⚠️  Every firewall-manager layer failed for $ip."
        echo "         Falling back to direct rules so the address is not left unblocked."
        log_message "FALLBACK: all manager layers failed for $ip - applying direct nft/iptables"

        if _nft_available && _nft_block_ip "$ip"; then
            echo "      ✅ nftables (fallback): blocked"
            ((success_count++))
        fi
        # Gated like every other non-natively-expiring layer: no durable
        # deadline, no rule (M11).
        if [ "$expiry_journalled" = true ] && _ipt_add "$ip"; then
            echo "      ✅ $(_ipt_cmd "$ip") (fallback): blocked"
            ((success_count++))
        fi
    fi

    # ---- Did anything that actually filters packets take effect? -------------
    #
    # C5: the block history and the cooldown used to be written HERE,
    # unconditionally, before this test. When every layer failed the function
    # correctly returned 1, but had already recorded the IP as blocked and put
    # it into a 30-minute cooldown — so a total failure produced an evidence
    # trail of success AND guaranteed the next six cron cycles would skip the
    # attacker entirely. Nothing is recorded now unless a real layer took it.
    if [ "$success_count" -le 0 ]; then
        # CRIT-1: If hosts.deny was appended during this attempt (advisory_count > 0),
        # but all packet-filter layers failed, remove it so we don't leave an untracked permanent deny line!
        if [ "$advisory_count" -gt 0 ] && [ -f /etc/hosts.deny ] && [ -w /etc/hosts.deny ]; then
            local hd_re
            hd_re=$(_ip_regex "$ip")
            sed -i "/^ALL:[[:space:]]*${hd_re}[[:space:]#]/d;/^ALL:[[:space:]]*${hd_re}\$/d" \
                /etc/hosts.deny 2>/dev/null
        fi
        # M9: the optimistic deadline written above belongs to a block that
        # never happened — take it back out.
        _unjournal_expiry "$ip"
        if [ "$advisory_count" -gt 0 ]; then
            echo "      ⚠️  ONLY hosts.deny accepted this block - your web server does NOT honour it."
            log_message "FAILED to block $ip on any packet filter (hosts.deny only): $reason"
        else
            log_message "FAILED to block $ip: $reason"
        fi
        echo "   ❌ Block FAILED - no firewall layer accepted $ip (not recorded, will retry next run)"
        return 1
    fi

    # Record in blocklist
    # 4th column tags the source product (shared log with Pro). Pro should write
    # "BotSurgeon-Pro" in the same position — see PRO-SIDE PATCH note above.
    # O4: tab-delimited. The reason is built from log-derived text and '|' can
    # appear in a request path, which used to shift every later column when the
    # history was read back.
    printf '%s\t%s\t%s\t%s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$ip" "$reason" "BotSurgeon-Basic" \
        >> "$DATA_DIR/blocked_ips.log"
    add_to_cooldown "$ip"

    # Persist firewall state (no CSF restart - csf -d handles its own persistence)
    _nft_persist
    if ! _has_firewall_manager; then
        _persist_iptables
    fi

    # O14: verify rather than infer.
    #
    # Every layer above reports success from a command's exit status, and C1 is
    # the proof that an exit status can be confidently wrong for a year. Ask the
    # authoritative source whether the address is actually in the enforcing set
    # now. This cannot cover CSF/firewalld/Imunify (no cheap, uniform query), so
    # a negative result is reported as "unverified", not as a failure — the aim
    # is that a silent regression of this kind shows up in the log next time.
    _verify_block_landed "$ip"

    ((BLOCKS_THIS_RUN++))
    log_message "BLOCKED: $ip via $success_count method(s) [${BLOCKS_THIS_RUN}/${MAX_BLOCKS_PER_RUN}]"
    [ "$MONITOR_MODE" = true ] && _heartbeat
    return 0
}

# Confirm a block is really in place on the layers we can interrogate exactly.
_verify_block_landed() {
    local ip="$1" verified=""

    if _nft_available && nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
        if _nft_set_has_ip "$(_nft_set_for_ip "$ip")" "$ip"; then
            verified="${verified}nft "
        fi
    fi
    if _ipt_has "$ip"; then
        verified="${verified}iptables "
    fi

    if [ -n "$verified" ]; then
        log_message "VERIFIED: $ip is enforced by: ${verified% }"
        return 0
    fi

    # Nothing we can query directly holds it. Expected when CSF/firewalld/
    # Imunify360 own the ruleset (they were the layers that accepted it), so
    # this is a log line, not a warning to the operator.
    log_message "NOTE: $ip block not independently verifiable (managed firewall layer)"
    return 1
}

# ==============================================================================
# SECTION 18: AUTOMATED THREAT RESPONSE
# ==============================================================================

auto_block_threats() {
    log_message "Starting automated threat response..."

    # Phase 1: High-connection IPs
    local threat_ips
    threat_ips=$(extract_ips_from_connections | grep -v '^$' | uniq -c | sort -rn | \
        awk -v threshold="$AUTO_BLOCK_THRESHOLD" '$1 > threshold {print $2 "|" $1}')

    if [ -n "$threat_ips" ]; then
        echo "🚨 HIGH-CONNECTION THREATS:"
        while IFS='|' read -r ip count; do
            [ -z "$ip" ] && continue
            echo "   🎯 $ip ($count connections)"

            if is_whitelisted_ip "$ip" || is_in_cooldown "$ip"; then
                continue
            fi

            local fp
            fp=$(fingerprint_ip "$ip" 2>/dev/null)
            local classification
            classification=$(echo "$fp" | cut -d'|' -f2)
            echo "      Fingerprint: $classification"

            block_ip_comprehensive "$ip" "Excessive connections: $count (threshold: $AUTO_BLOCK_THRESHOLD)" "conn"
        done <<< "$threat_ips"
        echo
    else
        echo "✅ No connection-based threats above threshold ($AUTO_BLOCK_THRESHOLD)"
        echo
    fi

    # Phase 2: Access log threat analysis
    analyze_access_log_threats

    # Phase 3: Domlog scanning
    analyze_domlogs

    # Finalize: batch reload firewalld if any rules were added
    finalize_firewall

    if [ "$BLOCKS_THIS_RUN" -gt 0 ]; then
        log_message "Run complete: $BLOCKS_THIS_RUN IP(s) blocked"
    fi
}

finalize_firewall() {
    if [ "$FIREWALLD_NEEDS_RELOAD" = true ]; then
        if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
            firewall-cmd --reload >/dev/null 2>&1
            log_message "firewalld: batch reload completed"
        fi
        FIREWALLD_NEEDS_RELOAD=false
    fi
}

# ==============================================================================
# SECTION 19: CPANEL INTEGRATION
# ==============================================================================

find_cpanel_user() {
    if [ "$CPANEL_MODE" = false ]; then
        echo "⚠️  cPanel not detected"
        return 1
    fi

    # M7: exact field comparison instead of interpolating a log-derived value
    # into an ERE. "$domain" is validated in analyze_traffic, and this is the
    # belt to that pair of braces: awk compares the whole first field as a
    # STRING, so no metacharacter in a hostname can ever widen the match and
    # resolve to somebody else's cPanel account.
    [ -n "$domain" ] || return 1
    user_found=$(awk -v d="${domain}:" '$1 == d { print $2; exit }' "$TRUEUSERDOMAINS" 2>/dev/null)
    [ -z "$user_found" ] && user_found=$(awk -v d="www.${domain}:" '$1 == d { print $2; exit }' "$TRUEUSERDOMAINS" 2>/dev/null)

    if [ -z "$user_found" ]; then
        echo "⚠️  User not found for domain: $domain"
        return 1
    fi
    return 0
}

throttle_user() {
    if [ "$CPANEL_MODE" = false ] || [ -z "$user_found" ]; then
        echo "⚠️  Cannot throttle - cPanel user not identified"
        return 1
    fi

    if command -v lvectl >/dev/null 2>&1; then
        log_message "Applying CloudLinux LVE limits to: $user_found"
        echo "   CloudLinux LVE: CPU=${THROTTLE_CPU}% IO=${THROTTLE_IO}KB/s EP=${THROTTLE_EP}"
        if [ "$DRY_RUN" = false ]; then
            # M23: check BOTH calls, and distinguish their failures.
            #
            # Neither status was looked at, so "✅ CloudLinux limits applied"
            # printed over a refused set-user (bad --speed value, unknown user,
            # LVE not loaded) or a failed apply-user. The two failures are not
            # the same and must not read the same: set-user failing means
            # nothing was configured, while apply-user failing means the limits
            # are SAVED but not in force - a reboot or a later `lvectl apply-all`
            # would silently start enforcing them. An operator throttling an
            # account mid-incident needs to know which of those they are in.
            local lve_set_rc=0 lve_apply_rc=0
            lvectl set-user "$user_found" \
                --speed="${THROTTLE_CPU}%" \
                --io="${THROTTLE_IO}" \
                --entry-processes="${THROTTLE_EP}" || lve_set_rc=$?

            if [ "$lve_set_rc" -ne 0 ]; then
                echo "   ❌ CloudLinux: lvectl set-user FAILED (exit $lve_set_rc) - no limits were applied."
                echo "      Check the values above and that LVE is active: lvectl list"
                log_message "ERROR: lvectl set-user failed for $user_found (exit $lve_set_rc) - not throttled"
                return 1
            fi

            lvectl apply-user "$user_found" || lve_apply_rc=$?
            if [ "$lve_apply_rc" -ne 0 ]; then
                echo "   ⚠️  CloudLinux: limits were SAVED but apply-user FAILED (exit $lve_apply_rc)."
                echo "      They are NOT in force yet, and may start applying after a reboot"
                echo "      or the next 'lvectl apply-all'. Re-run: lvectl apply-user $user_found"
                echo "      To undo entirely: lvectl delete-user $user_found && lvectl apply-user $user_found"
                log_message "WARNING: lvectl apply-user failed for $user_found (exit $lve_apply_rc) - limits saved but inactive"
                return 1
            fi

            echo "   ✅ CloudLinux limits applied"
            echo "   ↩️  Revert to package defaults: lvectl delete-user $user_found && lvectl apply-user $user_found"
        else
            echo "   🧪 DRY RUN: Would apply LVE limits"
        fi
    else
        # M7: there is NO safe per-user CPU/IO throttle on stock cPanel without
        # CloudLinux. We deliberately do NOT run 'modifyacct --maxpop/--maxftp/
        # --maxsql' — those are account FEATURE limits (mailbox/FTP/DB counts),
        # not resource throttles, and rewriting them corrupts the account with no
        # undo path. Refuse rather than pretend to throttle.
        echo "   ⚠️  Resource throttling requires CloudLinux (LVE); not available on this server."
        echo "      Refusing to alter account feature limits as a fake throttle."
        echo "      Block the abusive IP(s) instead (treatment option 3 or 4)."
        log_message "Throttle skipped for $user_found - no LVE present (modifyacct fallback removed)"
        return 1
    fi
}

block_aggressive_ips() {
    echo "🎯 Identifying aggressive IPs for: ${domain:-all domains}"

    if [ ! -f "$ACTIVE_LOG" ]; then
        echo "❌ Log file not accessible"
        return 1
    fi

    # M7: fixed-string match, not a regex. "$domain" is log-derived; feeding it
    # to grep as a BRE let metacharacters select lines from unrelated sites, so
    # the "aggressive IPs for this domain" list could contain — and block —
    # visitors of a different customer entirely. M19: the comparison below is
    # now plain string equality, which keeps that guarantee and is exact as
    # well — index() was literal, but a literal SUBSTRING match still crossed
    # tenants.
    # O2: read the shared window rather than re-tailing the log a fifth time.
    #
    # O1 (1.0.4): this used to take the client IP as $1. On cPanel the resolved
    # ACTIVE_LOG is /etc/apache2/logs/access_log, which is VHOST-PREFIXED —
    # "domain:port IP - - [date] ..." — so $1 is "domain:port", matched neither
    # IP pattern, and not one address was ever extracted. The single blocking
    # action in the interactive menu was a silent no-op on the exact platform it
    # exists for. (This is precisely why bs_parse scans the first three tokens
    # for the address; this function was the last one still counting fields by
    # hand.) The domain filter also ran against the WHOLE line, so a site name
    # appearing in a Referer or a query string pulled another customer's
    # visitors into this list — it is now matched against the vhost token only.
    local aggressive_ips
    aggressive_ips=$(_log_window_source | \
        awk -v want="$domain" '
        '"$AWK_LOGPARSE"'
        {
            if (!bs_parse()) next
            if (want != "") {
                split($0, tok, " ")
                # A vhost-prefixed log starts with "<domain>:<port>"; a plain
                # combined log starts with the client IP. When there is no vhost
                # token the log is already single-site, so every line belongs to
                # it and filtering would only ever throw away real data.
                #
                # M19: EXACT comparison of the vhost, not a substring search.
                # index(tok[1], want) accepted "evil-example.com:80" while
                # filtering for "example.com", so the interactive "block the
                # aggressive IPs for this domain" action could block visitors of
                # a DIFFERENT tenant on a shared cPanel box - anyone who simply
                # registered a domain ending in yours. Strip only the ":<port>"
                # suffix and compare the host, case-normalised because vhost
                # names are case-insensitive.
                # (No apostrophes in here: this awk program is single-quoted.)
                if (tok[1] != ip) {
                    vhost = tok[1]
                    sub(/:[0-9]+$/, "", vhost)
                    if (tolower(vhost) != tolower(want)) next
                }
            }
            print ip
        }' | sort | uniq -c | sort -nr | head -10)

    while read -r count ip; do
        [ -z "$count" ] || [ -z "$ip" ] && continue
        if [ "$count" -gt 500 ]; then
            echo "   🔴 $ip: $count requests - BLOCKING"
            block_ip_comprehensive "$ip" "Excessive requests: $count hits" "log"
        elif [ "$count" -gt 200 ]; then
            local fp
            fp=$(fingerprint_ip "$ip" 2>/dev/null)
            local fp_score
            fp_score=$(echo "$fp" | cut -d'|' -f1)
            local fp_class
            fp_class=$(echo "$fp" | cut -d'|' -f2)
            echo "   🟡 $ip: $count requests [$fp_class, score:$fp_score]"
        else
            echo "   🟢 $ip: $count requests"
        fi
    done <<< "$aggressive_ips"
}

# ==============================================================================
# SECTION 20: INTERACTIVE MODE
# ==============================================================================

take_action() {
    security_checks

    if [ -n "$domain" ] && [ -n "$user_found" ]; then
        echo "🏥 PATIENT ASSESSMENT:"
        echo "   Domain: $domain"
        echo "   cPanel User: $user_found"
        echo "   Request Volume: $req_count"
    else
        echo "🏥 PATIENT ASSESSMENT:"
        echo "   Analysis: Connection and log-based threat detection"
    fi

    # A treatment menu needs somebody to answer it. Piped, cron'd or run from
    # CI, the `read` below hit EOF, left $action empty and fell through to
    # "❌ Invalid selection" — a silent no-op dressed up as a user mistake, and
    # the most likely way for someone to cron this script wrongly and believe it
    # was working. Fail loudly and name the flag they actually want.
    if [ ! -t 0 ]; then
        echo
        echo "❌ No terminal available to read a treatment selection."
        echo "   Interactive triage needs a TTY. For unattended runs use:"
        echo "     $0 --auto      # analyse and block according to the thresholds"
        echo "     $0 --dry-run   # analyse and report, change nothing"
        log_message "Interactive mode without a TTY - no action taken (use --auto or --dry-run)"
        exit 1
    fi

    echo
    echo "💉 TREATMENT OPTIONS:"
    echo "1) 🚫 Suspend cPanel account (if identified)"
    echo "2) 🩺 Apply resource throttling"
    echo "3) 🛡️  Block aggressive IPs (for domain)"
    echo "4) 🤖 Full auto-scan (connections + access logs + domlogs)"
    echo "5) 🔍 Detailed connection analysis"
    echo "6) 🔬 Access log threat scan"
    echo "7) 🌐 Domlog scan (per-domain analysis)"
    echo "8) ❌ No treatment (monitor only)"

    # O-5: Release the lock across the blocking read so an idle/abandoned terminal
    # session does not block cron protection runs.
    release_lock
    read -rp "Select treatment [1-8]: " action
    case "$action" in
        1|2|3|4|5|6|7)
            acquire_lock 10
            if [ "$LOCK_HELD" != true ] && [ "$LOCK_STATE" = "contested" ]; then
                echo "⚠️  A scan took the lock while you were choosing - proceeding without it."
                echo "   State files may be rewritten under this action; re-check with --status after."
                log_message "WARNING: interactive action $action proceeded without the lock"
            fi
            ;;
    esac
    case "$action" in
        1)
            if [ -n "$user_found" ] && [ "$CPANEL_MODE" = true ]; then
                if [ "$DRY_RUN" = false ]; then
                    # M7: suspending an account takes a customer's whole site,
                    # mail and databases offline, and there is no undo here. It
                    # used to happen on a single keystroke, against a user
                    # resolved from a log-derived domain. Confirm explicitly and
                    # show exactly who is about to be suspended.
                    echo
                    echo "   ⚠️  About to SUSPEND cPanel account: $user_found"
                    echo "      Domain that led here: ${domain:-unknown}"
                    echo "      This takes the account's sites, mail and databases OFFLINE."
                    local confirm=""
                    printf '      Type the account name to confirm: '
                    read -r confirm || confirm=""
                    if [ "$confirm" != "$user_found" ]; then
                        echo "   ↩️  Aborted - nothing was suspended."
                        log_message "Suspend aborted by operator for $user_found"
                    elif /scripts/suspendacct "$user_found" "BotSurgeon: High resource usage"; then
                        log_message "Suspended: $user_found"
                        echo "   ✅ Account suspended"
                        echo "   ↩️  Undo with: /scripts/unsuspendacct $user_found"
                    else
                        echo "   ❌ Suspend FAILED (see the output above)"
                        log_message "Suspend FAILED for $user_found"
                    fi
                else
                    echo "   🧪 DRY RUN: Would suspend $user_found"
                fi
            else
                echo "❌ Cannot suspend - user not identified"
            fi
            ;;
        2) throttle_user ;;
        3) block_aggressive_ips ;;
        4)
            AUTO_MODE=true
            auto_block_threats
            ;;
        5) detailed_ip_analysis ;;
        6) analyze_access_log_threats ;;
        7) analyze_domlogs ;;
        8)
            echo "👀 No action taken"
            log_message "Manual review - no action taken"
            ;;
        *) echo "❌ Invalid selection" ;;
    esac
    finalize_firewall
}

detailed_ip_analysis() {
    echo "🔬 DETAILED IP ANALYSIS (Top 20):"
    echo

    extract_ips_from_connections | grep -v '^$' | uniq -c | sort -rn | head -20 | \
        while read -r count ip; do
            [ -z "$count" ] || [ -z "$ip" ] && continue

            local fp
            fp=$(fingerprint_ip "$ip" 2>/dev/null)
            local fp_score
            fp_score=$(echo "$fp" | cut -d'|' -f1)
            local fp_class
            fp_class=$(echo "$fp" | cut -d'|' -f2)
            local fp_reasons
            fp_reasons=$(echo "$fp" | cut -d'|' -f3)

            printf "%-4s conns | %-35s | Bot:%s (%s)\n" "$count" "$ip" "$fp_score" "$fp_class"
            [ -n "$fp_reasons" ] && [ "$fp_reasons" != "" ] && echo "                                              Signals: $fp_reasons"
        done
    echo
}

# ==============================================================================
# SECTION 21: CONTINUOUS MONITORING
# ==============================================================================

continuous_monitoring() {
    log_message "Starting continuous monitoring..."
    echo "🔄 CONTINUOUS MONITORING"
    echo "   Alert threshold: $CONNECTION_THRESHOLD connections"
    echo "   Block threshold: $AUTO_BLOCK_THRESHOLD connections"
    echo "   Log scan interval: every 5 cycles (2.5 min)"
    echo "   Press Ctrl+C to stop"
    echo

    local cycle=0
    local paused=false
    while true; do
        # MAJ-2 / C-5: refresh heartbeat timestamp at start of every cycle
        _heartbeat

        # N9: --disable had no effect on an already-running monitor: the flag was
        # only read once, at preflight, so a session started before the operator
        # disabled BotSurgeon carried on blocking indefinitely. Re-read it every
        # cycle and pause rather than exit, so --enable resumes the same session.
        # M15: through the trusted predicate. The bare `[ -f ... ]` this replaces
        # let any local user pause a running monitor by creating the path.
        if is_disabled; then
            if [ "$paused" = false ]; then
                echo "⏸️  BotSurgeon has been DISABLED - monitoring paused (no blocking)."
                echo "   Run '$0 --enable' to resume; Ctrl+C to stop."
                log_message "Monitor paused: disabled by admin"
                paused=true
            fi
            sleep 30
            continue
        fi
        if [ "$paused" = true ]; then
            echo "▶️  BotSurgeon re-enabled - monitoring resumed."
            log_message "Monitor resumed: re-enabled by admin"
            paused=false
        fi

        # M3: reset the per-run block budget each cycle. Without this a long-lived
        # monitor session hits MAX_BLOCKS_PER_RUN once and then only logs forever.
        BLOCKS_THIS_RUN=0

        # N14: the shared log-window snapshot is per-run state. In a session that
        # lives for hours it must be re-taken each cycle, or fingerprinting would
        # keep scoring against traffic from when the monitor started.
        _reset_log_window

        # M5: three more pieces of per-run state that a long-lived monitor left
        # frozen at session start. The block-budget reset and the window reset
        # above show the distinction was understood; these were simply missed.
        #
        # is_in_cooldown() is a pure presence test — it is only correct because
        # init_cooldown() has just pruned expired rows. Called once at preflight
        # and never again, every IP ever blocked stayed "in cooldown" for the
        # life of the session, so after its 24h nftables timeout expired it was
        # silently released and could NEVER be re-blocked. A multi-day monitor
        # therefore stopped protecting against exactly the addresses it had
        # already identified as hostile.
        init_cooldown
        # Likewise expire_blocks: without it, iptables and hosts.deny entries
        # placed during the session never reached their TTL at all.
        expire_blocks

        # OPT-1: rotate size-capped logs in multi-day sessions
        rotate_log "$LOG_FILE"
        if [ "$DRY_RUN" = false ]; then
            rotate_log "$DATA_DIR/blocked_ips.log"
        fi

        # OPT-1 / O-6 / O-2: reset caches so live configuration, firewall manager status,
        # Imunify360 state, iptables ACCEPT rules, and whitelist ownership changes take effect mid-session
        FW_MANAGER_CACHE=""
        IMUNIFY360_CACHE=""
        IPT_ACCEPT_SOURCES=""
        WHITELIST_TRUSTED=""
        PROXY_RANGES_TRUSTED=""

        # OPT-1: re-evaluate proxy heuristic mode dynamically in case proxies.conf changed
        local prev_proxy_mode="$PROXY_HEURISTIC_MODE"
        PROXY_RANGES_TRUSTED=unknown
        _resolve_proxy_heuristic_mode >/dev/null 2>&1
        if [ "$prev_proxy_mode" != "$PROXY_HEURISTIC_MODE" ]; then
            log_message "Proxy heuristic mode changed mid-session: $prev_proxy_mode -> $PROXY_HEURISTIC_MODE"
            echo "🛡️  CDN/proxy heuristic mode updated: $PROXY_HEURISTIC_MODE"
        fi

        # OPT-1: cap or reset rDNS cache to prevent unbounded growth in multi-day sessions
        if [ "$HAVE_ASSOC" = true ] && [ "${#RDNS_VERDICT_CACHE[@]}" -gt 1000 ]; then
            RDNS_VERDICT_CACHE=()
        fi

        local timestamp
        timestamp=$(date '+%H:%M:%S')
        local total_connections
        total_connections=$(get_total_connections)
        local server_load
        server_load=$(get_server_load)

        echo "[$timestamp] Load: $server_load | Connections: $total_connections"

        # MAJ-1: Check connections in bulk across all qualifying IPs exceeding threshold
        local conn_candidates
        conn_candidates=$(extract_ips_from_connections | grep -v '^$' | uniq -c | sort -rn | \
            awk -v block_thresh="$AUTO_BLOCK_THRESHOLD" -v warn_thresh="$CONNECTION_THRESHOLD" '
                $1 > block_thresh { print $2 "|" $1 "|block" }
                $1 > warn_thresh && $1 <= block_thresh { print $2 "|" $1 "|warn" }
            ')

        if [ -n "$conn_candidates" ]; then
            while IFS='|' read -r ip count action; do
                [ -z "$ip" ] && continue
                if [ "$action" = "block" ]; then
                    if is_whitelisted_ip "$ip"; then
                        echo "ℹ️  $ip has $count connections but is whitelisted - not blocking"
                    elif is_in_cooldown "$ip"; then
                        echo "⏳ $ip has $count connections - recently blocked, skipping"
                    else
                        echo "🚨 THREAT: $ip has $count connections"
                        local fp classification
                        fp=$(fingerprint_ip "$ip" 2>/dev/null)
                        classification=$(echo "$fp" | cut -d'|' -f2)
                        [ -n "$classification" ] && echo "      Fingerprint: $classification"
                        if block_ip_comprehensive "$ip" "Monitor: $count connections" "conn"; then
                            echo "   🚨 Auto-blocked"
                        fi
                    fi
                elif [ "$action" = "warn" ]; then
                    echo "⚠️  WARNING: $ip has $count connections"
                fi
            done <<< "$conn_candidates"
            finalize_firewall
        fi

        # Run log analysis every 5 cycles
        ((cycle++))
        if [ $((cycle % 5)) -eq 0 ]; then
            echo "--- Periodic log scan ---"
            _heartbeat
            # M5: refresh CDN/proxy detection on the same cadence. Computed once
            # at preflight, the exemption list was frozen at session start: an
            # edge that appeared later got no protection, and a stale entry kept
            # its block-immunity indefinitely — which, with the pre-1.0.3
            # thresholds, was an attacker-assignable exemption that never aged
            # out. It is derived from the log window, so re-run it after the
            # window has been re-taken above.
            detect_proxy_ips
            AUTO_MODE=true
            _heartbeat
            analyze_access_log_threats
            _heartbeat
            analyze_domlogs
            AUTO_MODE=false
            finalize_firewall
        fi

        sleep 30
    done
}

# ==============================================================================
# SECTION 22: MAIN EXECUTION
# ==============================================================================

main() {
    # C6: redirect the dry-run log HERE, not in security_preflight.
    #
    # check_disabled and _nft_load both run before preflight and both call
    # log_message, so a preview was appending to the live activity log — the
    # file an operator reads to reconstruct what the tool actually did — before
    # the redirect at the top of security_preflight ever took effect.
    if [ "$DRY_RUN" = true ]; then
        mkdir -p "$DATA_DIR" 2>/dev/null
        LOG_FILE="$DATA_DIR/botsurgeon-basic-dryrun.log"
    fi

    setup_traps

    # N8: before the lock, the watchdog and — critically — before _nft_load,
    # which would otherwise restore every persisted block on a disabled install.
    check_disabled

    acquire_lock
    [ "$MONITOR_MODE" = true ] && _heartbeat

    # M9: self-watchdog for unattended (cron) modes. If a run wedges on a hung
    # log read, a stuck iptables/nft call, or a slow DNS/firewall op, force-kill
    # it after MAX_RUNTIME so it releases the lock and future cron cycles are not
    # blocked forever. Not armed for --monitor (runs indefinitely by design) or
    # interactive mode (waits on user input at a prompt).
    # N13: --emergency raises MAX_BLOCKS_PER_RUN to 50, and every block costs an
    # rDNS verification plus the firewall work, so the mode that most needs to
    # finish was the most likely to be killed by its own watchdog. Give it room.
    # Only ever raises the limit — an operator who set a higher value keeps it.
    if [ "$EMERGENCY_MODE" = true ] && [ "$MAX_RUNTIME" -lt 900 ]; then
        MAX_RUNTIME=900
    fi

    if { [ "$AUTO_MODE" = true ] || [ "$EMERGENCY_MODE" = true ]; } && [ "$MONITOR_MODE" = false ]; then
        # N13: drop a marker before signalling, so the TERM handler can tell a
        # watchdog kill apart from an operator Ctrl-C or a `timeout`-wrapped
        # cron kill. "Received SIGTERM" told nobody which of the three it was.
        # M1: these were "/tmp/botsurgeon_basic_watchdog.$$" and
        # "..._wdsleep.$$" — guessable names that ROOT writes to with `>`, which
        # follows symlinks. A local user on a shared host can pre-create all
        # ~32k PID variants; the `rm -f` that preceded them narrowed the window
        # for the sleep file but did nothing for the marker, which is written
        # MAX_RUNTIME seconds later (300s of open season to re-plant the
        # symlink and have root truncate an arbitrary file). This is the same
        # class the N12 note fixed for the demo access log — fixed there, left
        # here. mktemp under the root-owned data directory removes both the
        # predictability and the /tmp exposure.
        WATCHDOG_MARKER=$(_mktemp_data watchdog) || WATCHDOG_MARKER=""
        WATCHDOG_SLEEPFILE=$(_mktemp_data wdsleep) || WATCHDOG_SLEEPFILE=""
        # mktemp creates the marker; the handler distinguishes a watchdog kill
        # by CONTENT, so start it empty and write a token when it actually fires.
        : > "$WATCHDOG_MARKER" 2>/dev/null
        # The sleep runs as a named child so _stop_watchdog can reap it (N17).
        # 'wait ... || exit 0' means a cancelled watchdog exits quietly instead
        # of signalling a main process that has already finished.
        # O-4: close lock file descriptor 9 so the watchdog subshell does not inherit
        # the lock if the parent process dies.
        (
            exec 9>&-
            sleep "$MAX_RUNTIME" &
            _wd_sleep=$!
            echo "$_wd_sleep" > "$WATCHDOG_SLEEPFILE" 2>/dev/null
            wait "$_wd_sleep" || exit 0
            # The marker already exists (mktemp created it), so "fired" is
            # signalled by CONTENT, not by existence.
            echo fired > "$WATCHDOG_MARKER" 2>/dev/null
            kill -TERM "$$" 2>/dev/null
        ) &
        WATCHDOG_PID=$!
    fi

    # Load persisted nftables rules
    _nft_load

    print_header
    security_preflight

    if [ "$EMERGENCY_MODE" = true ]; then
        log_message "🚨 EMERGENCY MODE"
        echo "🚨 EMERGENCY LOCKDOWN"
        AUTO_BLOCK_THRESHOLD=50
        LOG_THREAT_THRESHOLD=50
        CONNECTION_THRESHOLD=35
        MAX_BLOCKS_PER_RUN=50
        AUTO_MODE=true
        auto_block_threats
        exit 0
    fi

    if [ "$MONITOR_MODE" = true ]; then
        continuous_monitoring
        exit 0
    fi

    # Primary diagnostics
    analyze_connections
    analyze_traffic

    if [ "$AUTO_MODE" = true ]; then
        log_message "Running in automated mode"
        auto_block_threats
    elif [ "$DRY_RUN" = true ]; then
        # --dry-run on its own used to fall through to the interactive treatment
        # menu, so the one command that --help ("Preview mode - shows what would
        # be done") and README installation step 3 ("Preview what it would do")
        # both present as the safe first run previewed nothing at all. Piped or
        # run from cron it was worse: the menu read hit EOF, printed
        # "❌ Invalid selection" and exited having done nothing, which reads as a
        # user error rather than the no-op it was.
        #
        # It now runs exactly the passes --auto runs. AUTO_MODE is enabled for
        # the duration so the analysers report the block DECISIONS they would
        # take; DRY_RUN independently makes block_ip_comprehensive return 2
        # before it touches a firewall, records nothing and sets no cooldown. So
        # this shows precisely what --auto would do, and changes nothing.
        log_message "Dry-run preview of automated mode"
        AUTO_MODE=true
        auto_block_threats
        AUTO_MODE=false
        echo "⚗️  Preview complete - no firewall rule, cooldown entry or block record was written."
        echo "   Run the same scan for real with:  $0 --auto"
        echo "   Interactive triage menu (live actions):  $0"
    else
        if [ -n "$domain" ]; then
            find_cpanel_user
        fi
        take_action
    fi

    log_message "$SCRIPT_NAME session completed"
}

# Arguments are parsed HERE, after every function above is defined, so the
# recovery commands that exit from inside parse_arguments can use the whole
# script (acquire_lock, _safe_display, _ipt_del, ...). See the note in SECTION 3.
parse_arguments "$@"

main
exit 0

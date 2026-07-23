#!/usr/bin/env bash
#
# AutoRecon — Automated Bug Bounty Reconnaissance Script
# Usage: ./recon.sh <target-domain>
# Example: ./recon.sh example.com
#
# Phases:
#   1. Subdomain Enumeration   (crt.sh, subfinder)
#   2. Live Host Discovery      (dnsx + httpx)
#   3. Port Scanning            (naabu or nc)
#   4. URL Discovery            (gau + Wayback Machine)
#   5. JS Analysis              (download JS, extract endpoints & secrets)
#   6. Parameter Extraction     (grep-based pattern matching)
#   8. Nuclei Vulnerability Scan (CVEs, takeovers, misconfigs)
#   9. Report Generation        (structured output)
#

set -euo pipefail

# ── Configuration (overridable via env vars) ────────────────────────────
JS_LIMIT="${JS_LIMIT:-30}"             # Max JS files to download & analyze
CLEANUP_TEMP="${CLEANUP_TEMP:-true}"   # Remove intermediate files at end? (true/false)

# ── Colors ──────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ── Parse Input ─────────────────────────────────────────────────────────
TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
    echo -e "${RED}Usage:${NC} $0 <target-domain>"
    echo -e "  ${YELLOW}e.g.${NC}  $0 example.com"
    exit 1
fi
TARGET="${TARGET#http://}"
TARGET="${TARGET#https://}"
TARGET="${TARGET%%/*}"

OUTDIR="recon/$TARGET"
mkdir -p "$OUTDIR"

ERROR_LOG="$OUTDIR/errors.log"
: > "$ERROR_LOG"

# ── Log file — tee stderr for post-run debugging ────────────────────────
exec 2> >(tee -a "$OUTDIR/recon.log" >&2)

# ── Cleanup trap ────────────────────────────────────────────────────────
_cleanup() {
    if [[ "$CLEANUP_TEMP" == "true" ]]; then
        rm -f "$OUTDIR/raw_subs.txt" \
              "$OUTDIR/_wayback_subs.txt" \
              "$OUTDIR/scan_targets.txt" \
              "$OUTDIR/port_scan_targets.txt" 2>/dev/null || true
        rm -rf "$OUTDIR/js_downloads" 2>/dev/null || true
    fi
}
trap _cleanup EXIT

# ── Helper Functions ────────────────────────────────────────────────────
info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[-]${NC} $*" | tee -a "$ERROR_LOG" >&2; }

header() {
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  $*${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

check_tool() {
    if ! command -v "$1" &>/dev/null; then
        warn "$1 not found — will use fallback method"
        return 1
    fi
    return 0
}

# Abort early if jq is missing — several phases depend on it
if ! command -v jq &>/dev/null; then
    echo -e "${RED}[-]${NC} jq is required but not installed."
    echo "  Install: sudo apt install jq  (or brew install jq)"
    exit 1
fi

# Portability: some systems (macOS) lack GNU grep's -P (PCRE) flag.
# Detect it once so all phases can use GNU_PGREP=true or false.
if grep --version 2>/dev/null | grep -qi "gnu"; then
    if echo "test" | grep -oP 'test' >/dev/null 2>&1; then
        GNU_PGREP=true
    else
        GNU_PGREP=false
        warn "GNU grep found but PCRE (-P) flag is broken — falling back to -E"
    fi
else
    GNU_PGREP=false
    warn "GNU grep not detected — PCRE (-P) unavailable; falling back to -E"
fi

# Safe grep wrapper: uses -oP on GNU systems, plain -oE otherwise.
_grep_p() {
    if [[ "$GNU_PGREP" == "true" ]]; then
        grep -oP "$@"
    else
        # Without PCRE we lose look-arounds etc.  Best-effort with extended regex.
        grep -oE "$@"
    fi
}

# Service name mapping for common ports
_port_service() {
    case $1 in
        21)   echo "FTP";;      22)   echo "SSH";;
        25)   echo "SMTP";;     53)   echo "DNS";;
        80)   echo "HTTP";;     110)  echo "POP3";;
        123)  echo "NTP";;      143)  echo "IMAP";;
        443)  echo "HTTPS";;    465)  echo "SMTPS";;
        587)  echo "SMTP";;     993)  echo "IMAPS";;
        995)  echo "POP3S";;    1433) echo "MSSQL";;
        1521) echo "Oracle DB";;2049) echo "NFS";;
        2375) echo "Docker";;   3000) echo "HTTP-Alt";;
        3306) echo "MySQL";;    3389) echo "RDP";;
        4000) echo "HTTP-Alt";; 5000) echo "HTTP-Alt";;
        5432) echo "PostgreSQL";;6379) echo "Redis";;
        6443) echo "HTTPS-Alt";;8000) echo "HTTP-Alt";;
        8080) echo "HTTP-Alt";; 8443) echo "HTTPS-Alt";;
        8888) echo "HTTP-Alt";; 9000) echo "HTTP-Alt";;
        9090) echo "HTTP-Alt";; 9200) echo "Elasticsearch";;
        27017) echo "MongoDB";; 27018) echo "MongoDB";;
        *)    echo "Unknown";;
    esac
}

# ── Phase 1: Subdomain Enumeration ─────────────────────────────────────
phase_1_subdomains() {
    header "Phase 1: Subdomain Enumeration"
    local raw_subs="$OUTDIR/raw_subs.txt"
    local all_subs="$OUTDIR/subdomains.txt"
    : > "$raw_subs"
    : > "$all_subs"

    info "Querying crt.sh for certificate transparency logs..."
    local crt_output
    if ! crt_output=$(curl -sS --connect-timeout 10 --max-time 30 \
        "https://crt.sh/?q=%25.${TARGET}&output=json" 2>/dev/null); then
        err "crt.sh curl failed"
    else
        echo "$crt_output" | jq -r '.[].name_value // empty' 2>/dev/null \
            | sed 's/\*\.//g' | tr ',' '\n' | sed 's/^ *//;s/ *$//' \
            | grep -E "\.${TARGET}$" | sort -u >> "$raw_subs" || true
    fi
    ok "crt.sh: $(wc -l < "$raw_subs") subdomains found"

    if check_tool subfinder; then
        info "Running subfinder (30s timeout)..."
        timeout 30 subfinder -d "$TARGET" -silent 2>/dev/null >> "$raw_subs" || \
            warn "subfinder returned no results (expected if few API keys configured)"
        ok "subfinder done"
    fi

    # 1d. If still empty, try AlienVault OTX as a passive subdomain source
    local tmp_subs; tmp_subs=$(wc -l < "$raw_subs" 2>/dev/null || echo 0)
    if [[ "$tmp_subs" -eq 0 ]]; then
        info "Primary sources failed — querying AlienVault OTX for subdomains..."
        local otx_subs="$OUTDIR/_otx_subs.txt"
        curl -s --connect-timeout 10 --max-time 20 \
            -A "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0" \
            "https://otx.alienvault.com/api/v1/indicators/domain/$TARGET/url_list?limit=500" 2>/dev/null \
            | jq -r '.url_list[]?.url // empty' 2>/dev/null \
            | grep -oE "[a-zA-Z0-9._-]+\.${TARGET//./\.}" 2>/dev/null \
            | tr '[:upper:]' '[:lower:]' \
            | sort -u >> "$raw_subs" || true
        local otx_count; otx_count=$(wc -l < "$raw_subs" 2>/dev/null || echo 0)
        if [[ "$otx_count" -gt 0 ]]; then
            ok "OTX returned $otx_count subdomains"
        else
            warn "OTX also returned no subdomains"
        fi
    fi

    sort -u "$raw_subs" > "$all_subs"
    local total; total=$(wc -l < "$all_subs")
    info "Total unique subdomains: $total"
    if [[ "$total" -eq 0 ]]; then
        warn "No subdomains found — using root domain only"
        echo "$TARGET" > "$all_subs"
    fi
}

# ── Phase 2: Live Host Discovery ────────────────────────────────────────
phase_2_live_hosts() {
    header "Phase 2: Live Host Discovery"
    local all_subs="$OUTDIR/subdomains.txt"
    local dns_resolved="$OUTDIR/dns_resolved.txt"
    local live_hosts="$OUTDIR/live_hosts.txt"
    : > "$dns_resolved"
    : > "$live_hosts"

    if [[ ! -f "$all_subs" ]] || [[ ! -s "$all_subs" ]]; then
        warn "No subdomains to resolve"
        return
    fi

    if check_tool dnsx; then
        info "Resolving subdomains with dnsx..."
        dnsx -silent -l "$all_subs" 2>/dev/null > "$dns_resolved" || \
            err "dnsx resolution failed"
    else
        info "Resolving subdomains with dig (parallel)..."
        xargs -P 20 -I {} sh -c '
            if dig +short "{}" 2>/dev/null | grep -qE "^[0-9]"; then
                echo "{}"
            fi
        ' < "$all_subs" > "$dns_resolved" 2>/dev/null || err "dig resolution failed"
    fi
    ok "DNS resolved: $(wc -l < "$dns_resolved") subdomains"

    if check_tool httpx; then
        info "Probing for live HTTP hosts with httpx..."
        httpx -silent -l "$dns_resolved" \
            -status-code -title -tech-detect \
            -o "$OUTDIR/httpx_output.txt" 2>/dev/null || err "httpx probe failed"
        awk '{print $1}' "$OUTDIR/httpx_output.txt" > "$live_hosts" 2>/dev/null || true
    else
        info "Probing with curl (parallel 20)..."
        xargs -P 20 -I {} bash -c '
            for scheme in https http; do
                if curl -skL --connect-timeout 3 --max-time 5 -o /dev/null -w "%{http_code}" \
                    "${scheme}://$1" 2>/dev/null | grep -qE "^[0-9]"; then
                    echo "${scheme}://$1"
                    break
                fi
            done
        ' -- {} < "$dns_resolved" > "$live_hosts" 2>/dev/null || true
    fi
    ok "Live hosts: $(wc -l < "$live_hosts")"
}

# ── Phase 3: Port Scanning ──────────────────────────────────────────────
phase_3_port_scan() {
    header "Phase 3: Port Scanning"
    local live_hosts="$OUTDIR/live_hosts.txt"
    local open_ports="$OUTDIR/open_ports.txt"
    : > "$open_ports"

    if [[ ! -f "$live_hosts" ]] || [[ ! -s "$live_hosts" ]]; then
        warn "No live hosts to scan — scanning root domain"
        echo "$TARGET" > "$live_hosts"
    fi

    if check_tool naabu; then
        info "Running naabu port scanner..."
        local target_list="$OUTDIR/port_scan_targets.txt"
        sed 's|^https\?://||' "$live_hosts" | sort -u > "$target_list"
        naabu -silent -list "$target_list" -top-ports 1000 \
            -o "$open_ports" 2>/dev/null || err "naabu scan failed"
    else
        info "naabu not available — scanning common ports with nc..."
        local COMMON_PORTS=(80 443 8080 8443 3000 4000 5000 8000 8888 9000 9090 9200 6379 5432 3306 27017 22 21)
        local scan_hosts="$OUTDIR/scan_targets.txt"
        while IFS= read -r host; do
            hostname="${host#http*://}"; hostname="${hostname%%/*}"
            echo "$hostname" >> "$scan_hosts"
        done < "$live_hosts"

        if command -v nc &>/dev/null; then
            while IFS= read -r hostname; do
                for port in "${COMMON_PORTS[@]}"; do
                    echo "$hostname $port"
                done
            done < "$scan_hosts" \
            | xargs -P 20 -I {} bash -c '
                h="${1%% *}"; p="${1##* }"
                timeout 2 nc -z -w 2 "$h" "$p" 2>/dev/null && echo "$h:$p"
            ' _ {} >> "$open_ports" 2>/dev/null || err "nc scan failed"
        else
            while IFS= read -r hostname; do
                for port in "${COMMON_PORTS[@]}"; do
                    timeout 2 bash -c "echo >/dev/tcp/$hostname/$port" 2>/dev/null \
                        && echo "${hostname}:${port}" >> "$open_ports"
                done
            done < "$scan_hosts"
        fi
    fi
    sort -u "$open_ports" -o "$open_ports"
    ok "Open ports discovered: $(wc -l < "$open_ports")"
}

# ── Phase 4: URL Discovery (gau + Wayback) ──────────────────────────────
phase_4_url_discovery() {
    header "Phase 4: URL Discovery"
    local urls="$OUTDIR/urls.txt"
    : > "$urls"

    info "Fetching historical URLs from Wayback Machine..."
    local wb_urls="$OUTDIR/_wayback_urls.txt"
    : > "$wb_urls"
    # Main domain (with /* to capture all paths)
    curl -s --connect-timeout 10 --max-time 20 \
        "http://web.archive.org/cdx/search/cdx?url=$TARGET/*&output=json&fl=original&collapse=urlkey" 2>/dev/null \
        | jq -r '.[1:][] | .[] // empty' 2>/dev/null \
        >> "$wb_urls" || true
    # Subdomains (serial to avoid rate limiting)
    if [[ -f "$OUTDIR/subdomains.txt" && -s "$OUTDIR/subdomains.txt" ]]; then
        sort -u "$OUTDIR/subdomains.txt" | head -30 | while IFS= read -r sub; do
            [[ -z "$sub" ]] && continue
            curl -s --connect-timeout 10 --max-time 15 \
                "http://web.archive.org/cdx/search/cdx?url=$sub/*&output=json&fl=original&collapse=urlkey" 2>/dev/null \
                | jq -r '.[1:][] | .[] // empty' 2>/dev/null
        done >> "$wb_urls" 2>/dev/null || true
    fi
    sort -u "$wb_urls" -o "$wb_urls" 2>/dev/null || true
    local wb_count; wb_count=$(wc -l < "$wb_urls" 2>/dev/null || echo 0)
    if [[ "$wb_count" -gt 0 ]]; then
        cat "$wb_urls" >> "$urls"
        ok "Wayback Machine: $wb_count URLs"
    else
        warn "Wayback Machine returned 0 URLs (rate-limited or unreachable)"
    fi

    if check_tool gau; then
        info "Running gau for multi-source URL discovery (may take up to 60s)..."
        timeout 90 gau "$TARGET" --subs 2>/dev/null >> "$urls" || \
            warn "gau timed out or had errors (partial results may be present)"
        ok "gau URLs added"
    else
        info "gau not available — fetching URLs from AlienVault OTX..."
        curl -s --connect-timeout 10 --max-time 20 \
            -A "Mozilla/5.0" \
            "https://otx.alienvault.com/api/v1/indicators/domain/$TARGET/url_list?limit=500" 2>/dev/null \
            | jq -r '.url_list[]?.url // empty' 2>/dev/null \
            >> "$urls" || err "AlienVault OTX query failed"
        ok "AlienVault OTX URLs added"
    fi

    # Last resort: basic curl + grep href extraction from live hosts
    if [[ ! -s "$urls" ]]; then
        info "All URL sources returned nothing — extracting links from live hosts..."
        local host; local hrefs="$OUTDIR/_href_urls.txt"
        : > "$hrefs"
        if [[ -f "$OUTDIR/live_hosts.txt" && -s "$OUTDIR/live_hosts.txt" ]]; then
            while IFS= read -r host; do
                [[ -z "$host" ]] && continue
                curl -skL --connect-timeout 10 --max-time 10 --max-filesize 512000 \
                    -A "Mozilla/5.0" "$host" 2>/dev/null \
                    | _grep_p 'href="([^"]+)"' 2>/dev/null \
                    | sed 's/href="//;s/"//g' \
                    | while IFS= read -r path; do
                        if [[ "$path" == http* ]]; then
                            echo "$path"
                        elif [[ "$path" == /* ]]; then
                            echo "${host}${path}"
                        fi
                    done
            done < "$OUTDIR/live_hosts.txt" >> "$hrefs" 2>/dev/null || true
            sort -u "$hrefs" -o "$hrefs" 2>/dev/null
            local h_count; h_count=$(wc -l < "$hrefs" 2>/dev/null || echo 0)
            if [[ "$h_count" -gt 0 ]]; then
                cat "$hrefs" >> "$urls"
                ok "Link extraction: $h_count URLs"
            fi
        fi
    fi

    # Optional: active crawl with katana (timed out at 120s so it won't block the pipeline)
    if check_tool katana && [[ -f "$OUTDIR/live_hosts.txt" && -s "$OUTDIR/live_hosts.txt" ]]; then
        local ktemp="$OUTDIR/_katana_urls.txt"
        timeout 120 katana -list "$OUTDIR/live_hosts.txt" -silent -jc -kf all \
            -d 1 -c 5 -rl 500 -o "$ktemp" 2>/dev/null || true
        if [[ -s "$ktemp" ]]; then
            local k_count; k_count=$(wc -l < "$ktemp")
            ok "Katana: $k_count additional URLs"
            cat "$ktemp" >> "$urls"
        fi
    fi

    sort -u "$urls" -o "$urls"
    ok "Total unique URLs: $(wc -l < "$urls")"

    # ── Extract subdomains from discovered URLs and merge into subdomains.txt ──
    # This catches subdomains that crt.sh / subfinder may have missed
    local url_subs="$OUTDIR/_url_subs.txt"
    grep -oE "[a-zA-Z0-9._-]+\.${TARGET//./\.}" "$urls" 2>/dev/null \
        | sed 's|^https\?://||' \
        | tr '[:upper:]' '[:lower:]' \
        | sed 's/^\.//' \
        | sort -u > "$url_subs" || true

    if [[ -s "$url_subs" ]]; then
        local url_sub_count; url_sub_count=$(wc -l < "$url_subs")
        ok "Extracted $url_sub_count subdomains from URL data"
        cat "$url_subs" >> "$OUTDIR/subdomains.txt"
        sort -u "$OUTDIR/subdomains.txt" -o "$OUTDIR/subdomains.txt"
    fi
}

# ── Phase 5: JS Analysis ────────────────────────────────────────────────
phase_5_js_analysis() {
    header "Phase 5: JavaScript Analysis"
    local urls="$OUTDIR/urls.txt"
    local js_output="$OUTDIR/js_endpoints.txt"
    local js_secrets="$OUTDIR/js_secrets.txt"
    local js_files_list="$OUTDIR/js_files.txt"
    : > "$js_output"
    : > "$js_secrets"
    : > "$js_files_list"

    if [[ ! -f "$urls" ]] || [[ ! -s "$urls" ]]; then
        warn "No URLs to analyze for JS files"
        return
    fi

    info "Extracting JavaScript file URLs..."
    grep -iE '\.js(\?|$)' "$urls" 2>/dev/null \
        | grep -vE '\.json' \
        | sort -u | head -"$JS_LIMIT" > "$js_files_list" || true

    local js_count; js_count=$(wc -l < "$js_files_list" 2>/dev/null || echo 0)
    ok "Found $js_count JS files to analyze"

    if [[ "$js_count" -eq 0 ]]; then
        warn "No JS files found in URL list"
        return
    fi

    info "Downloading and analyzing JS files (parallel, up to $JS_LIMIT)..."
    local js_dir="$OUTDIR/js_downloads"
    mkdir -p "$js_dir"

    # Parallel download with xargs
    xargs -P 5 -I {} bash -c '
        js_url="{}"
        filename=$(basename "$js_url" | sed "s/?.*//" | sed "s/[^a-zA-Z0-9._-]/_/g")
        [[ -z "$filename" ]] && filename="unknown.js"

        if ! curl -sfL --connect-timeout 10 --max-time 20 \
            -A "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0" \
            -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
            -H "Accept-Language: en-US,en;q=0.5" \
            "$js_url" > "$1/$filename" 2>/dev/null; then
            echo "FAILED: $js_url" >> "$2"
            return
        fi
    ' _ "$js_dir" "$ERROR_LOG" < "$js_files_list" 2>/dev/null || true

    # Analyze downloaded files
    local f
    for f in "$js_dir"/*.js; do
        [[ -f "$f" ]] || continue

        # Extract full URLs from JS
        _grep_p '["'"'"'](https?://[^"'"'"' ]+)["'"'"']' "$f" 2>/dev/null \
            | sed 's/["'"'"']//g' \
            | awk -v fname="$(basename "$f")" '{print $0 "  [from JS: " fname "]"}' \
            >> "$js_output" || true

        # Extract relative API-like paths
        _grep_p '["'"'"'](/?[a-zA-Z0-9_/-]+/[a-zA-Z0-9_/-]+)["'"'"']' "$f" 2>/dev/null \
            | sed 's/["'"'"']//g' \
            | grep -vE '^\s*$|\.js|\.css|\.json|\.png|\.jpg|\.svg|\.ico' \
            | awk -v fname="$(basename "$f")" '{print $0 "  [from JS: " fname "]"}' \
            >> "$js_output" || true

        # Scan for secrets / API keys
        _grep_p '(?i)(api[_-]?key|secret|password|token|auth|jwt|bearer)\s*[=:]\s*["'"'"']?[a-zA-Z0-9_\-]{10,}["'"'"']?' \
            "$f" 2>/dev/null \
            | awk -v fname="$(basename "$f")" '{print $0 "  [from JS: " fname "]"}' \
            >> "$js_secrets" || true

        _grep_p 'AKIA[0-9A-Z]{16}' "$f" 2>/dev/null \
            | awk -v fname="$(basename "$f")" '{print $0 "  [AWS Key from JS: " fname "]"}' \
            >> "$js_secrets" || true

        _grep_p '(?:-----BEGIN[ A-Z]*PRIVATE KEY-----)' "$f" 2>/dev/null \
            | awk -v fname="$(basename "$f")" '{print $0 "  [Private Key from JS: " fname "]"}' \
            >> "$js_secrets" || true
    done

    sort -u "$js_output" -o "$js_output" 2>/dev/null
    sort -u "$js_secrets" -o "$js_secrets" 2>/dev/null

    ok "JS endpoints found: $(wc -l < "$js_output")"
    ok "JS secrets/potential keys found: $(wc -l < "$js_secrets")"
}

# ── Phase 6: Parameter & Endpoint Extraction ───────────────────────────
phase_6_extract_params() {
    header "Phase 6: Parameter & Endpoint Extraction"
    local urls="$OUTDIR/urls.txt"
    local params="$OUTDIR/interesting_params.txt"
    local endpoints="$OUTDIR/interesting_endpoints.txt"
    : > "$params"
    : > "$endpoints"

    [[ -f "$urls" && -s "$urls" ]] || { warn "No URLs to analyze"; return; }

    info "Extracting URLs with query parameters..."
    # Match ?param=value patterns: letters, numbers, underscores, hyphens, dots
    grep -E '\?[a-zA-Z0-9_.-]+=' "$urls" 2>/dev/null | sort -u > "$params" || true
    local param_count; param_count=$(wc -l < "$params" 2>/dev/null || echo 0)

    info "Categorizing parameters by vulnerability class..."
    local categorized="$OUTDIR/params_by_type.txt"
    : > "$categorized"

    grep -iE '(id|user_id|account_id|customer|order)' "$params" 2>/dev/null \
        | awk '{print $0 "  [IDOR candidate]"}' >> "$categorized" || true
    grep -iE '(url|redirect|next|return|dest|target|href|callback)' "$params" 2>/dev/null \
        | awk '{print $0 "  [Open Redirect candidate]"}' >> "$categorized" || true
    grep -iE '(file|path|doc|download|read|include|template)' "$params" 2>/dev/null \
        | awk '{print $0 "  [LFI/Path Traversal candidate]"}' >> "$categorized" || true
    grep -iE '(search|q|query|s|keyword|term|filter)' "$params" 2>/dev/null \
        | awk '{print $0 "  [SQLi/XSS candidate]"}' >> "$categorized" || true
    grep -iE '(token|key|api_key|secret|auth|jwt|session)' "$params" 2>/dev/null \
        | awk '{print $0 "  [Auth/Token candidate]"}' >> "$categorized" || true
    grep -iE '(file|upload|document|image|avatar|photo|media|attachment)' "$params" 2>/dev/null \
        | awk '{print $0 "  [File Upload candidate]"}' >> "$categorized" || true
    grep -iE '(callback|webhook|hook|notify|endpoint)' "$params" 2>/dev/null \
        | awk '{print $0 "  [SSRF candidate]"}' >> "$categorized" || true
    grep -iE '(price|cost|amount|quantity|discount|coupon|rate|fee)' "$params" 2>/dev/null \
        | awk '{print $0 "  [Business Logic candidate]"}' >> "$categorized" || true

    ok "URLs with parameters: $param_count"
    ok "Categorized: $(wc -l < "$categorized") entries"

    info "Extracting interesting endpoints..."
    {
        grep -iE '/api/|/v[0-9]/|/graphql|/rest|/gql' "$urls" 2>/dev/null || true
        grep -iE '/admin|/internal|/debug|/test|/staging|/dev|/management|/console|/panel' "$urls" 2>/dev/null || true
        grep -iE '/oauth|/login|/auth|/sso|/saml|/oidc|/callback|/token|/signin|/signup' "$urls" 2>/dev/null || true
        grep -iE '/upload|/download|/file|/attachment|/document|/media' "$urls" 2>/dev/null || true
        grep -iE '/\.git|/\.env|/robots\.txt|/sitemap\.xml|/crossdomain\.xml|/clientaccesspolicy\.xml' "$urls" 2>/dev/null || true
        grep -iE 'swagger|openapi|api-docs|redoc' "$urls" 2>/dev/null || true
    } | sort -u >> "$endpoints" || true

    ok "Interesting endpoints extracted"
}

# ── Phase 7: Nuclei Vulnerability Scan ──────────────────────────────────
phase_7_nuclei_scan() {
    header "Phase 7: Nuclei Vulnerability Scan"
    local live_hosts="$OUTDIR/live_hosts.txt"
    local nuclei_output="$OUTDIR/nuclei_results.txt"
    : > "$nuclei_output"

    if ! check_tool nuclei; then
        warn "nuclei not installed — skipping vulnerability scan"
        echo "# nuclei not installed — scan skipped" > "$nuclei_output"
        return
    fi

    [[ -f "$live_hosts" && -s "$live_hosts" ]] || { warn "No live hosts to scan"; return; }

    info "Updating nuclei templates..."
    nuclei -update-templates 2>/dev/null || err "nuclei template update failed"

    info "Scanning for vulnerabilities (critical/high/medium)..."
    nuclei -l "$live_hosts" \
        -severity critical,high,medium \
        -silent -o "$nuclei_output" 2>/dev/null || err "nuclei scan failed"
    ok "Nuclei findings (critical/high/medium): $(wc -l < "$nuclei_output")"

    local takeover_output="$OUTDIR/nuclei_takeover.txt"
    : > "$takeover_output"
    info "Checking for subdomain takeovers..."
    nuclei -l "$live_hosts" \
        -tags takeover -silent \
        -o "$takeover_output" 2>/dev/null || err "nuclei takeover check failed"
    local takeover_count; takeover_count=$(wc -l < "$takeover_output" 2>/dev/null || echo 0)
    if [[ "$takeover_count" -gt 0 ]]; then
        ok "Subdomain takeover candidates: $takeover_count — check $takeover_output!"
    else
        ok "No subdomain takeovers detected"
    fi

    cat "$takeover_output" >> "$nuclei_output" 2>/dev/null || true
    sort -u "$nuclei_output" -o "$nuclei_output"
    ok "Total nuclei findings: $(wc -l < "$nuclei_output")"
}

# ── Phase 8: Generate Report ────────────────────────────────────────────
phase_8_report() {
    header "Phase 8: Generating Report"
    local report="$OUTDIR/report.txt"

    {
        echo "=============================================="
        echo "  AutoRecon Report — $TARGET"
        echo "  Generated: $(date)"
        echo "=============================================="
        echo ""

        echo "- Subdomains:"
        if [[ -f "$OUTDIR/dns_resolved.txt" && -s "$OUTDIR/dns_resolved.txt" ]]; then
            while IFS= read -r sub; do [[ -n "$sub" ]] && echo "  - $sub"; done < "$OUTDIR/dns_resolved.txt"
        elif [[ -f "$OUTDIR/subdomains.txt" && -s "$OUTDIR/subdomains.txt" ]]; then
            while IFS= read -r sub; do [[ -n "$sub" ]] && echo "  - $sub"; done < "$OUTDIR/subdomains.txt"
        else
            echo "  (none found)"
        fi
        echo ""

        echo "- Live Hosts:"
        if [[ -f "$OUTDIR/live_hosts.txt" && -s "$OUTDIR/live_hosts.txt" ]]; then
            while IFS= read -r host; do [[ -n "$host" ]] && echo "  - $host"; done < "$OUTDIR/live_hosts.txt"
        else
            echo "  (none detected)"
        fi
        echo ""

        echo "- Open Ports:"
        if [[ -f "$OUTDIR/open_ports.txt" && -s "$OUTDIR/open_ports.txt" ]]; then
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                port="${line##*:}"
                echo "  - $port ($(_port_service "$port"))"
            done < "$OUTDIR/open_ports.txt"
        else
            echo "  (none detected)"
        fi
        echo ""

        echo "- Discovered Endpoints:"
        if [[ -f "$OUTDIR/interesting_endpoints.txt" && -s "$OUTDIR/interesting_endpoints.txt" ]]; then
            while IFS= read -r ep; do
                [[ -z "$ep" ]] && continue
                path=$(echo "$ep" | sed 's|^https\?://[^/]*||' | sed 's|\?.*$||')
                [[ -n "$path" ]] && echo "  - $path"
            done < "$OUTDIR/interesting_endpoints.txt" | sort -u
        else
            echo "  (none found via URL analysis)"
        fi
        echo ""

        echo "- JavaScript Analysis:"
        if [[ -f "$OUTDIR/js_endpoints.txt" && -s "$OUTDIR/js_endpoints.txt" ]]; then
            echo "  (endpoints found in JS — see $OUTDIR/js_endpoints.txt)"
            head -20 "$OUTDIR/js_endpoints.txt" | while IFS= read -r line; do
                [[ -n "$line" ]] && echo "  - $line"
            done
            local js_total; js_total=$(wc -l < "$OUTDIR/js_endpoints.txt" 2>/dev/null || echo 0)
            [[ "$js_total" -gt 20 ]] && echo "  ..  (and $((js_total - 20)) more — see full file)"
        else
            echo "  (none found)"
        fi
        if [[ -f "$OUTDIR/js_secrets.txt" && -s "$OUTDIR/js_secrets.txt" ]]; then
            echo ""
            echo "  [!] Potential Secrets in JS:"
            while IFS= read -r line; do [[ -n "$line" ]] && echo "  - $line"; done < "$OUTDIR/js_secrets.txt"
        fi
        echo ""

        echo "- Interesting Parameters (by vulnerability class):"
        if [[ -f "$OUTDIR/params_by_type.txt" && -s "$OUTDIR/params_by_type.txt" ]]; then
            while IFS= read -r line; do [[ -n "$line" ]] && echo "  - $line"; done < "$OUTDIR/params_by_type.txt"
        else
            echo "  (none found)"
        fi
        echo ""

        echo "- Nuclei Vulnerabilities:"
        if [[ -f "$OUTDIR/nuclei_results.txt" && -s "$OUTDIR/nuclei_results.txt" ]]; then
            while IFS= read -r line; do [[ -n "$line" ]] && echo "  - $line"; done < "$OUTDIR/nuclei_results.txt"
        else
            echo "  (none detected or skipped)"
        fi
        echo ""

        echo "=============================================="
        echo "  Summary"
        echo "=============================================="
        echo "  Subdomains discovered:    $(wc -l < "$OUTDIR/subdomains.txt" 2>/dev/null || echo 0)"
        echo "  Live hosts:               $(wc -l < "$OUTDIR/live_hosts.txt" 2>/dev/null || echo 0)"
        echo "  Open ports:               $(wc -l < "$OUTDIR/open_ports.txt" 2>/dev/null || echo 0)"
        echo "  URLs crawled:             $(wc -l < "$OUTDIR/urls.txt" 2>/dev/null || echo 0)"
        echo "  JS files analyzed:        $(wc -l < "$OUTDIR/js_files.txt" 2>/dev/null || echo 0)"
        echo "  JS endpoints found:       $(wc -l < "$OUTDIR/js_endpoints.txt" 2>/dev/null || echo 0)"
        echo "  JS secrets found:         $(wc -l < "$OUTDIR/js_secrets.txt" 2>/dev/null || echo 0)"
        echo "  Endpoints extracted:      $(wc -l < "$OUTDIR/interesting_endpoints.txt" 2>/dev/null || echo 0)"
        echo "  Parameters extracted:     $(wc -l < "$OUTDIR/interesting_params.txt" 2>/dev/null || echo 0)"
        echo "  Nuclei findings:          $(wc -l < "$OUTDIR/nuclei_results.txt" 2>/dev/null || echo 0)"
        echo ""
    } > "$report"

    ok "Report saved to: $report"
    cat "$report"
}

# ── Orchestrator ────────────────────────────────────────────────────────
main() {
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║    AutoRecon v2.0 — Bug Bounty Recon        ║${NC}"
    echo -e "${BOLD}║    Target: ${CYAN}$TARGET${NC}${BOLD}                    ║${NC}"
    echo -e "${BOLD}║    Output: ${CYAN}$OUTDIR${NC}${BOLD}                  ║${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"
    echo ""

    phase_1_subdomains
    phase_2_live_hosts
    phase_3_port_scan
    phase_4_url_discovery

    # ── Re-resolve and probe subdomains discovered from URL data ──
    # Phase 4 may have added new subdomains to subdomains.txt from URL hostnames.
    # Re-run live host discovery on the expanded list so downstream phases
    # (JS analysis, dir fuzz, nuclei) have live targets to work with.
    local dns_resolved="$OUTDIR/dns_resolved.txt"
    local live_hosts="$OUTDIR/live_hosts.txt"
    local all_subs="$OUTDIR/subdomains.txt"
    local old_resolved_count; old_resolved_count=$(wc -l < "$dns_resolved" 2>/dev/null || echo 0)
    local new_sub_count; new_sub_count=$(wc -l < "$all_subs" 2>/dev/null || echo 0)
    if [[ "$new_sub_count" -gt "$old_resolved_count" ]]; then
        info "Re-resolving $(($new_sub_count - $old_resolved_count)) new subdomains from URL data..."
        local extra="$OUTDIR/_extra_subs.txt"
        grep -vFf "$dns_resolved" "$all_subs" > "$extra" 2>/dev/null || true

        if [[ -s "$extra" ]]; then
            if check_tool dnsx; then
                dnsx -silent -l "$extra" 2>/dev/null >> "$dns_resolved" || true
            else
                xargs -P 20 -I {} sh -c '
                    if dig +short "{}" 2>/dev/null | grep -qE "^[0-9]"; then
                        echo "{}"
                    fi
                ' < "$extra" >> "$dns_resolved" 2>/dev/null || true
            fi
            sort -u "$dns_resolved" -o "$dns_resolved"

            # Probe the new resolved hosts
            if check_tool httpx; then
                httpx -silent -l "$dns_resolved" \
                    -status-code -title -tech-detect \
                    -o "$OUTDIR/httpx_output.txt" 2>/dev/null || true
                awk '{print $1}' "$OUTDIR/httpx_output.txt" > "$live_hosts" 2>/dev/null || true
            fi
            ok "Live hosts after re-scan: $(wc -l < "$live_hosts")"
        fi
    fi

    phase_5_js_analysis
    phase_6_extract_params
    phase_7_nuclei_scan
    phase_8_report

    echo ""
    echo -e "${GREEN}${BOLD}✓ Recon complete!${NC}"
    echo -e "  All output files: ${CYAN}$OUTDIR${NC}"
    echo -e "  Final report:      ${CYAN}$OUTDIR/report.txt${NC}"
    echo -e "  Debug log:         ${CYAN}$OUTDIR/recon.log${NC}"
    if [[ -s "$ERROR_LOG" ]]; then
        echo -e "  Errors:            ${RED}$ERROR_LOG${NC}"
    fi
}

main

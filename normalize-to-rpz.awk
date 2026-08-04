#!/usr/bin/awk -f
# Normalize a blocklist (any of: RPZ zone, hosts file, plain domain list,
# wildcard list) to a stream of bare lowercase domains, one per line.
#
# Handles, per line:
#   - comments (# or ;) and blank lines           -> dropped
#   - RPZ control lines ($TTL, SOA, @ ... NS ...) -> dropped
#   - RPZ entries "domain CNAME ."                 -> "domain"
#   - hosts entries "0.0.0.0 domain" / "127.0.0.1 domain" -> "domain"
#   - wildcard entries "*.domain"                  -> "domain"
#   - plain "domain"                               -> "domain"
#
# Output is bare domains; warren-dns-refresh.sh dedupes/sorts and wraps each
# into RPZ records (apex + wildcard). Keeping conversion and RPZ-wrapping
# separate keeps this script unit-testable on its own.

function emit(d) {
    # lowercase
    d = tolower(d)
    # strip a leading wildcard label
    sub(/^\*\./, "", d)
    # strip a trailing dot (FQDN form)
    sub(/\.$/, "", d)
    # strip an inline comment tail and surrounding whitespace
    sub(/[[:space:]]+#.*$/, "", d)
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", d)
    if (d == "") return
    # Validate: a plausible domain: labels of [a-z0-9_-], at least one dot,
    # no slashes/colons (rejects URLs, IPs-as-host garbage, SOA serials).
    if (d !~ /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$/) return
    print d
}

{
    line = $0
    # Drop comments and blanks early.
    sub(/\r$/, "", line)                       # CRLF tolerance
    if (line ~ /^[[:space:]]*$/) next
    if (line ~ /^[[:space:]]*[#;]/) next
    # Drop RPZ/zone control lines.
    if (line ~ /^[[:space:]]*\$/) next         # $TTL, $ORIGIN
    if (line ~ /^[[:space:]*@]/ && line ~ /SOA|NS|IN[[:space:]]/) next

    n = split(line, f, /[[:space:]]+/)

    # hosts format: "<ip> <domain> [domain...]"
    if (f[1] ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ || f[1] == "::1" || f[1] ~ /^::ffff:/) {
        for (i = 2; i <= n; i++) emit(f[i])
        next
    }

    # RPZ entry: "<domain> [IN] (CNAME|A|AAAA) ..." -> take the owner name.
    if (n >= 2 && (line ~ /[[:space:]](CNAME|A|AAAA|IN)[[:space:]]/ || line ~ /CNAME[[:space:]]*\.[[:space:]]*$/)) {
        emit(f[1])
        next
    }

    # Otherwise treat the first field as a bare/wildcard domain.
    emit(f[1])
}

import re
import math
from urllib.parse import urlparse, parse_qs

IP_PATTERN          = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
AT_IN_URL_PATTERN   = re.compile(r'https?://[^/]*@')
PUNYCODE_PATTERN    = re.compile(r'xn--[a-z0-9]+', re.IGNORECASE)
DOUBLE_DASH_PATTERN = re.compile(r'--')
REPEATED_CHAR_PATTERN = re.compile(r'(.)\1{4,}')

# Credential-harvesting path / query keywords
SUSPICIOUS_KEYWORDS = [
    "login", "logon", "signin", "sign-in", "verify", "verification",
    "secure", "security", "update", "confirm", "account", "banking",
    "credential", "authenticate", "password", "passwd", "reset",
    "recover", "invoice", "payment", "billing", "checkout", "ebayisapi",
    "webscr", "cmd=_",
]

# Brands to protect against typosquatting (all lowercase, no TLD)
PROTECTED_BRANDS = [
    "google", "gmail", "youtube", "facebook", "instagram", "whatsapp",
    "apple", "icloud", "microsoft", "outlook", "office365", "onedrive",
    "amazon", "aws", "paypal", "netflix", "twitter", "linkedin",
    "dropbox", "github", "gitlab", "steam", "discord", "coinbase",
    "binance", "bankofamerica", "wellsfargo", "chase", "citibank",
    "irs", "docusign", "fedex", "dhl", "ups", "usps",
]

# High-risk TLDs (statistically over-represented in phishing feeds)
HIGH_RISK_TLDS = frozenset([
    "xyz", "top", "club", "info", "work", "click", "loan", "gq", "tk",
    "cf", "ml", "buzz", "rest", "zip", "mov", "cam", "pw", "ru", "cn",
    "vip", "icu", "live", "online", "site", "website", "fun", "space",
    "shop", "store", "biz", "trade", "link", "download", "stream",
])

# Known URL-shortening / redirect proxies
URL_SHORTENERS = frozenset([
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "short.ly", "v.gd", "rb.gy",
    "shorturl.at", "tiny.cc", "bl.ink", "snip.ly",
])

# Tracking / analytics query parameters that are frequently abused in phishing
TRACKING_PARAMS = frozenset([
    "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
    "ref", "referral", "redirect", "redir", "url", "goto", "target",
    "dest", "destination", "return", "returnurl", "next", "continue",
    "forward", "out", "link", "go",
])

# Leet-speak substitution table for brand normalisation
_LEET_MAP = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
             "@": "a", "$": "s", "!": "i", "|": "l"}


def _normalise_leet(text: str) -> str:
    """Lowercase, then expand leet-speak characters to their alphabetic
    equivalents. Lowercasing MUST happen first so that the substitution
    table (which is keyed on lowercase/symbol characters) actually matches."""
    lowered = text.lower()
    return "".join(_LEET_MAP.get(c, c) for c in lowered)


_DOUBLE_TLDS = frozenset([
    "co.uk", "co.in", "co.jp", "co.nz", "co.za", "com.au", "com.br",
    "com.cn", "com.mx", "com.sg", "com.tr", "net.au", "org.uk",
    "gov.uk", "ac.uk", "me.uk", "org.au", "edu.au",
])


def _parse_domain_parts(raw_input: str) -> tuple:
    """
    Returns (scheme, subdomain, root_domain, tld, host, path, query) for
    any URL-like string, handling missing schemes, double eTLDs, and bare
    hostnames gracefully.
    """
    target = raw_input.strip()
    original_scheme = ""

    if target.startswith("https://"):
        original_scheme = "https"
    elif target.startswith("http://"):
        original_scheme = "http"

    if not target.startswith(("http://", "https://")):
        # No scheme present. Treat as "unknown/unspecified" rather than
        # silently assuming https — assuming https hides a real signal
        # (plenty of phishing links are bare hostnames pasted in chat/SMS
        # with no scheme at all, and that ambiguity is itself informative).
        parse_target = "https://" + target
    else:
        parse_target = target

    try:
        parsed = urlparse(parse_target)
        netloc = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query
    except Exception:
        netloc = target.lower()
        path = ""
        query = ""

    # Strip port number and any stray userinfo (user:pass@) the parser left in
    host = netloc.split("@")[-1].split(":")[0]

    labels = [l for l in host.split(".") if l]  # drop empty labels from trailing dots
    tld = ""
    root = ""
    subdomain = ""

    if len(labels) >= 2:
        potential_double = ".".join(labels[-2:])
        if potential_double in _DOUBLE_TLDS and len(labels) >= 3:
            tld = potential_double
            root = labels[-3]
            subdomain = ".".join(labels[:-3]) if len(labels) > 3 else ""
        else:
            tld = labels[-1]
            root = labels[-2]
            subdomain = ".".join(labels[:-2]) if len(labels) > 2 else ""
    elif len(labels) == 1:
        root = labels[0]
    # len(labels) == 0 -> host was empty/unparsable; everything stays ""

    return original_scheme, subdomain, root, tld, host, path, query


# ---------------------------------------------------------------------------
# Levenshtein distance (iterative, O(m*n) - fast enough for short brand names)
# ---------------------------------------------------------------------------
def _levenshtein(s1: str, s2: str) -> int:
    if s1 == s2:
        return 0
    if not s1:
        return len(s2)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(
                prev[j + 1] + 1,
                curr[j] + 1,
                prev[j] + (0 if c1 == c2 else 1),
            ))
        prev = curr
    return prev[-1]


def _is_allowlisted_brand_domain(root: str, subdomain: str, tld: str) -> bool:
    """
    Returns True when the root domain is an EXACT match for a protected
    brand on a standard commercial TLD (.com, .net, .org, .io, .co) — i.e.
    this really is e.g. microsoft.com or a legitimate subdomain of it
    (support.google.com, security.microsoft.com, etc.), not a lookalike.

    This is what was missing before: SUSPICIOUS_KEYWORDS were being scanned
    against the path/query of ANY domain, including verified real brand
    domains, so "microsoft.com/security" or "google.com/accounts" tripped
    the same keyword penalty as a phishing kit. A brand's own site is
    allowed to use words like "security" or "accounts" — that's normal.
    """
    normalised_root = _normalise_leet(root)
    if normalised_root not in PROTECTED_BRANDS:
        return False
    # Require the root to be an EXACT brand match (not just containing it -
    # exact match here is intentionally conservative so we don't accidentally
    # allowlist something like "microsoft-support" as if it were Microsoft).
    return normalised_root == root.lower()


def _detect_typosquat(root: str, subdomain: str, tld: str) -> tuple:
    """
    Returns (is_typosquat, matched_brand).

    Skips entirely if the domain is already allowlisted as a genuine brand
    domain (fixes false positives like microsoft.com / google.com).
    Otherwise checks leet-normalised root against each protected brand for
    edit-distance <= 1 (<=2 for brands longer than 8 characters), or as a
    substring with extra affixes (paypal-secure, amazon-support).
    """
    if _is_allowlisted_brand_domain(root, subdomain, tld):
        return False, ""

    normalised = _normalise_leet(root)
    for brand in PROTECTED_BRANDS:
        if normalised == brand:
            # Leet-normalised root matches a brand exactly, but root itself
            # is NOT the literal brand string (e.g. "micr0soft" -> "microsoft").
            # That's a textbook leet-speak impersonation, not a legitimate site.
            return True, brand
        threshold = 2 if len(brand) > 8 else 1
        if _levenshtein(normalised, brand) <= threshold:
            return True, brand
        if brand in normalised and normalised != brand:
            return True, brand
    return False, ""


# ---------------------------------------------------------------------------
# Shannon entropy scorer
# ---------------------------------------------------------------------------
def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def analyze_url_risk(url_string: str):
    """
    Performs zero-trust lexical decomposition and multi-layer threat scoring
    on the supplied URL string.

    Parameters
    ----------
    url_string : str
        Raw URL input from the user (scheme optional).

    Returns
    -------
    dict | None
        Threat intelligence report, or None for empty input.
    """
    if not url_string or not url_string.strip():
        return None

    raw = url_string.strip()

    # -- Domain decomposition --------------------------------------------
    original_scheme, subdomain, root, tld, host, path, query = _parse_domain_parts(raw)

    is_brand_verified = _is_allowlisted_brand_domain(root, subdomain, tld)

    # -- Structural flag identifiers --------------------------------------
    is_https     = original_scheme == "https"
    url_length   = len(raw)
    dot_count    = host.count(".")
    has_ip       = bool(IP_PATTERN.match(host))
    has_at       = bool(AT_IN_URL_PATTERN.search(raw if raw.startswith("http") else "https://" + raw))
    has_punycode = bool(PUNYCODE_PATTERN.search(host))
    has_dbl_dash = bool(DOUBLE_DASH_PATTERN.search(host))
    entropy      = _shannon_entropy(root)
    # Exact-match or proper-subdomain match only. The previous substring
    # check (`s in host`) caused short shortener domains like "t.co" to
    # false-positive on completely unrelated domains that merely contain
    # that substring (e.g. "microsoft.com" contains "t.co"). A shortener
    # match should only count if the host IS the shortener domain or is a
    # subdomain of it (e.g. "go.bit.ly" -> still bit.ly's service).
    is_shortener = host in URL_SHORTENERS or any(
        host == s or host.endswith("." + s) for s in URL_SHORTENERS
    )

    path_lower = path.lower()
    query_lower = query.lower()
    scan_zone = path_lower + "?" + query_lower

    # Credential-harvesting keyword scan — SKIPPED for verified brand domains.
    # This is the core fix for the Microsoft/Google false-positive bug:
    # a real brand's own site is allowed to have "security" or "accounts"
    # in its URL. Only scan for these on domains that are NOT a verified
    # brand match.
    if is_brand_verified:
        found_keywords = []
    else:
        found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in scan_zone]

    # High-risk TLD check
    is_high_risk_tld = tld in HIGH_RISK_TLDS

    # Typosquat / brand-impersonation check (already allowlist-aware)
    is_typosquat, spoofed_brand = _detect_typosquat(root, subdomain, tld)

    # Tracking / open-redirect parameter detection
    try:
        query_params = parse_qs(query, keep_blank_values=True)
        tracking_hits = [p for p in query_params if p.lower() in TRACKING_PARAMS]
        open_redirect = any(
            p.lower() in {"redirect", "redir", "url", "goto", "target",
                          "dest", "destination", "return", "returnurl",
                          "next", "continue", "forward", "out"}
            for p in query_params
        )
    except Exception:
        tracking_hits = []
        open_redirect = False

    # Excessive subdomain nesting
    subdomain_depth = len(subdomain.split(".")) if subdomain else 0

    # Hyphen-joined keyword stuffing in the hostname itself (e.g.
    # "account-update-login-confirm.com") — distinct from path/query
    # keyword scanning above, and NOT suppressed by brand allowlisting
    # since a real brand would never need to do this to its own apex domain.
    host_label_for_scan = (subdomain + "." + root).lower() if subdomain else root.lower()
    hyphen_segments = [seg for seg in host_label_for_scan.split("-") if seg]
    host_keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in host_label_for_scan]

    # -- Risk calculation - tiered, with compounding for stacked signals --
    risk_score = 0
    reasons = []

    # [CAT-1] Transport security (max 25 pts — lowered weight; HTTP alone
    # is weak evidence on its own and shouldn't dominate the score for an
    # otherwise clean domain)
    if not is_https:
        risk_score += 25
        reasons.append(
            "UNENCRYPTED TRANSPORT LAYER: No TLS/SSL negotiation detected. "
            "Plain-text HTTP exposes payload data to passive interception and "
            "active man-in-the-middle injection."
        )

    # [CAT-2] Raw IP endpoint (max 40 pts)
    if has_ip:
        risk_score += 40
        reasons.append(
            "BARE IP-ADDRESS ROUTING: Host resolves to a raw IPv4 address "
            "rather than a registered domain name, bypassing DNS-based "
            "reputation filters and certificate authority validation."
        )

    # [CAT-3] '@' redirection trick (max 35 pts)
    if has_at:
        risk_score += 35
        reasons.append(
            "USERINFO '@' REDIRECTION ATTACK: An '@' character is embedded in "
            "the authority component. Per RFC 3986, everything before '@' is "
            "treated as credentials, silently redirecting to the host that "
            "follows — a classic visual-deception vector."
        )

    # [CAT-4] IDN / Punycode homoglyph (max 35 pts)
    if has_punycode:
        risk_score += 35
        reasons.append(
            "IDN HOMOGLYPH / PUNYCODE ENCODING DETECTED: The hostname contains "
            "an ACE-prefix (xn--) label, indicating non-ASCII Unicode characters "
            "that can render identically to trusted ASCII domains in most browsers."
        )

    # [CAT-5] Typosquatting / brand impersonation (max 45 pts — raised, this
    # is one of the highest-confidence phishing signals available)
    if is_typosquat:
        risk_score += 45
        reasons.append(
            f"BRAND IMPERSONATION SIGNATURE: Root domain `{root}` matches "
            f"protected brand `{spoofed_brand}` within a minimal character-edit "
            "or character-substitution distance. High-confidence indicator of "
            "deliberate visual spoofing to harvest credentials under a trusted "
            "brand identity."
        )

    # [CAT-6] High-risk TLD (max 25 pts)
    if is_high_risk_tld:
        risk_score += 25
        reasons.append(
            f"HIGH-RISK TOP-LEVEL DOMAIN: `.{tld}` is statistically "
            "over-represented in phishing and malware distribution feeds. "
            "Legitimate enterprise services rarely operate under this TLD class."
        )

    # [CAT-7] URL shortener / proxy (max 30 pts)
    if is_shortener:
        risk_score += 30
        reasons.append(
            f"URL-SHORTENER PROXY DETECTED: `{host}` is a known link-redirection "
            "service. The true destination is concealed at scan time, defeating "
            "static reputation analysis."
        )

    # [CAT-8] Subdomain flooding (max 20 pts, scaled) — skipped for verified
    # brand domains, since legitimate orgs (e.g. support.google.com) commonly
    # use functional subdomains and shouldn't be penalized for it.
    if not is_brand_verified:
        if subdomain_depth >= 3:
            pts = min(20, subdomain_depth * 5)
            risk_score += pts
            reasons.append(
                f"SUBDOMAIN DEPTH ANOMALY: {subdomain_depth}-level subdomain "
                f"nesting (`{subdomain}.{root}.{tld}`) is a common DNS-cloaking "
                "technique used to embed legitimate-looking labels while routing "
                "to an attacker-controlled apex domain."
            )
        elif dot_count > 3:
            risk_score += 8
            reasons.append(
                f"ELEVATED DOT-COUNT: {dot_count} dot-delimited labels detected — "
                "moderately above baseline for authentic registered domains."
            )

    # [CAT-9] Credential-harvesting keywords in path/query (max 25 pts,
    # capped, suppressed for verified brands — see found_keywords above)
    if found_keywords:
        pts = min(25, len(found_keywords) * 8)
        risk_score += pts
        reasons.append(
            f"CREDENTIAL HARVESTING PATH SIGNATURES: {len(found_keywords)} "
            f"high-risk identifier(s) detected in path/query — "
            f"{found_keywords}. Frequently injected into phishing landing "
            "pages to mimic legitimate authentication flows."
        )

    # [CAT-9b] Credential-harvesting keywords stuffed directly into the
    # hostname itself, hyphen-joined (e.g. account-update-login-confirm.com).
    # This is a distinct, stronger signal than CAT-9: a domain that is
    # LITERALLY built from harvesting keywords is far more deliberate than a
    # single keyword appearing in a path. Not suppressed by brand allowlist
    # since real brands never need this pattern on their own apex domain.
    if len(host_keyword_hits) >= 2:
        pts = min(45, len(host_keyword_hits) * 15)
        risk_score += pts
        reasons.append(
            f"HOSTNAME KEYWORD-STUFFING PATTERN: {len(host_keyword_hits)} "
            f"credential/authentication terms found concatenated directly in "
            f"the hostname itself ({host_keyword_hits}). This hyphen-joined "
            "phrase-construction pattern is characteristic of disposable "
            "phishing-kit domains rather than organic brand names."
        )

    # [CAT-10] Open-redirect parameter (max 20 pts)
    if open_redirect:
        risk_score += 20
        reasons.append(
            "OPEN-REDIRECT PARAMETER DETECTED: A query parameter accepting an "
            "arbitrary destination URL (e.g. `redirect=`, `goto=`, `returnurl=`) "
            "is present. Attackers abuse these to chain trusted domains as "
            "laundering hops before delivering a malicious payload."
        )

    # [CAT-11] Tracking parameter cluster (soft signal, max 8 pts)
    if len(tracking_hits) >= 3:
        risk_score += 8
        reasons.append(
            f"HIGH-DENSITY TRACKING PARAMETER CLUSTER: {len(tracking_hits)} "
            f"analytics/attribution parameters detected "
            f"({', '.join(tracking_hits[:4])}). Individually benign, but dense "
            "parameter injection can obfuscate payload-delivery URLs within "
            "marketing-style link structures."
        )

    # [CAT-12] High Shannon entropy / DGA signal (max 18 pts) — skipped for
    # verified brands, and threshold slightly raised to reduce false positives
    # on legitimate but randomized-looking subdomains (CDNs, build hashes).
    if not is_brand_verified and entropy > 3.9 and not is_shortener and len(root) > 6:
        risk_score += 18
        reasons.append(
            f"HIGH-ENTROPY HOSTNAME SIGNATURE: Root label `{root}` yields a "
            f"Shannon entropy of {entropy:.2f} bits, above the DGA-correlated "
            "threshold. Algorithmically generated domain names are a common "
            "marker of C2 beaconing infrastructure."
        )

    # [CAT-13] URL length — low weight, tiered
    if url_length > 150:
        risk_score += 12
        reasons.append(
            f"EXTREME URL LENGTH: {url_length} characters. URLs this long are "
            "a statistical outlier in organic traffic and are routinely used to "
            "bury malicious parameters beyond the visible address-bar viewport."
        )
    elif url_length > 100:
        risk_score += 5
        reasons.append(
            f"ELEVATED URL LENGTH: {url_length} characters — moderately above "
            "the safe baseline, warranting additional path-level scrutiny."
        )

    # -- Compounding multiplier for stacked high-confidence signals --------
    # The previous version just summed category points, which let combos
    # like "high-risk TLD + suspicious keyword + suspicious keyword" cap out
    # in the 55-60% 'Suspicious' band even though three independent red
    # flags pointing the same direction should be treated as much more
    # damning together than any one of them alone. Count how many
    # HIGH-CONFIDENCE categories fired (deliberately excludes the soft/noisy
    # ones: URL length, tracking params, dot-count) and apply a small
    # multiplicative escalation on top of the additive base score.
    high_confidence_hits = sum([
        has_ip,
        has_at,
        has_punycode,
        is_typosquat,
        is_high_risk_tld,
        is_shortener,
        open_redirect,
        len(host_keyword_hits) >= 2,
        bool(found_keywords),
    ])

    if high_confidence_hits >= 3:
        risk_score = int(risk_score * 1.25)
        reasons.append(
            f"MULTI-VECTOR THREAT CONVERGENCE: {high_confidence_hits} "
            "independent high-confidence threat indicators co-occur on this "
            "single URL. Convergent signals are escalated beyond simple "
            "additive scoring, as combined techniques rarely appear together "
            "by coincidence in legitimate traffic."
        )
    elif high_confidence_hits == 2:
        risk_score = int(risk_score * 1.1)

    # -- Score ceiling -------------------------------------------------------
    risk_score = min(risk_score, 100)
    risk_score = max(risk_score, 0)

    # -- Threat classification boundaries -------------------------------------
    if risk_score <= 25:
        classification = "Safe"
        color = "#10B981"
    elif risk_score <= 60:
        classification = "Suspicious"
        color = "#F59E0B"
    else:
        classification = "Dangerous"
        color = "#EF4444"

    # -- Clean-bill-of-health log ---------------------------------------------
    if not reasons:
        reasons = [
            "ZERO THREAT SIGNATURES DETECTED: Lexical decomposition, entropy "
            "analysis, typosquat fingerprinting, and structural heuristics all "
            "returned negative. URL conforms to expected patterns of a "
            "legitimate, well-formed web resource."
        ]
    elif is_brand_verified and risk_score <= 25:
        reasons.insert(0,
            f"VERIFIED BRAND DOMAIN: Root domain `{root}` matches a recognized "
            "protected brand on a standard commercial TLD. Path/query keyword "
            "scanning and subdomain-depth penalties suppressed accordingly."
        )

    return {
        "url":            url_string,
        "is_https":       is_https,
        "length":         url_length,
        "dots":           dot_count,
        "has_ip":         has_ip,
        "found_keywords": found_keywords,
        "risk_score":     risk_score,
        "classification": classification,
        "color":          color,
        "reasons":        reasons,
    }
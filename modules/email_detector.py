

import os
import re
from urllib.parse import urlparse

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.base import BaseEstimator, TransformerMixin
import joblib

MODEL_PATH      = os.path.join("models", "phishing_model.pkl")
VECTORIZER_PATH = os.path.join("models", "vectorizer.pkl")

_MODEL_CACHE: dict = {"model": None, "vectorizer": None}


URL_REGEX             = re.compile(r'(https?://\S+)')
IP_HOST_REGEX         = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
AT_SYMBOL_TRICK_REGEX = re.compile(r'https?://[^/\s]*@')
IDN_PUNYCODE_REGEX    = re.compile(r'xn--[a-z0-9]+', re.IGNORECASE)   # homoglyph / IDN abuse
EXCESS_PUNCT_REGEX    = re.compile(r'[!?]{3,}')                        # e.g. "ACT NOW!!!"
OBFUSCATED_WORD_REGEX = re.compile(r'\b\w*[@0$1|]\w*\b')               # p@ssw0rd, l0gin, $ecure

BRAND_LOOKALIKE_REGEX = re.compile(
    r'(paypal|amazon|apple|microsoft|outlook|office365|netflix|google|'
    r'bankofamerica|wellsfargo|chase|irs|coinbase|docusign|instagram|'
    r'facebook|whatsapp|dropbox|linkedin|twitter|discord|steam|ebay)',
    re.IGNORECASE,
)

SUBDOMAIN_BRAND_SQUATTING_REGEX = re.compile(
    r'(?:secure|login|account|verify|update|auth|portal)\.'
    r'(?:paypal|amazon|apple|microsoft|netflix|google|chase|coinbase|irs|docusign)',
    re.IGNORECASE,
)

SUSPICIOUS_TLDS = frozenset([
    ".xyz", ".top", ".club", ".info", ".work", ".click", ".loan",
    ".gq", ".tk", ".cf", ".ml", ".buzz", ".rest", ".zip", ".mov",
    ".cam", ".pw", ".ru", ".cn", ".vip", ".icu",
])
URL_SHORTENERS = frozenset([
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "short.ly", "v.gd", "rb.gy",
    "shorturl.at",
])

_SHORTENER_ALTERNATION = '|'.join(re.escape(s) for s in URL_SHORTENERS)
BARE_SHORTENER_REGEX = re.compile(
    r'\b(?:[a-z0-9-]+\.)?(' + _SHORTENER_ALTERNATION + r')\b', re.IGNORECASE
)
_TLD_ALTERNATION = '|'.join(t.lstrip('.') for t in SUSPICIOUS_TLDS)
BARE_SUSPICIOUS_TLD_REGEX = re.compile(
    r'\b([a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:' + _TLD_ALTERNATION + r'))(?:/\S*)?\b',
    re.IGNORECASE,
)

URGENCY_PHRASES = [
    "urgent", "immediately", "right away", "act now", "act fast",
    "within 24 hours", "within 12 hours", "expires", "expire soon",
    "final warning", "failure to", "asap", "limited time", "last chance",
    "your account will be", "respond immediately", "don't delay",
]
SENSITIVE_CONTEXT_WORDS = [
    "account", "password", "credential", "identity", "bank", "login",
    "ssn", "social security", "details", "card number", "pin", "otp",
    "verification code", "one-time password", "passcode", "secret",
]
FINANCIAL_HARVEST_TERMS = [
    "social security number", "ssn", "credit card number", "cvv",
    "routing number", "account number", "pin number", "one-time password",
    " otp ", "wire transfer", "bank transfer", "iban", "swift code",
]
CRYPTO_FRAUD_TERMS = [
    "bitcoin", "crypto", "ethereum", "nft", "blockchain", "wallet address",
    "multiply your", "double your", "guaranteed profit", "passive income",
    "seed phrase", "private key", "recovery phrase",
]
FAKE_JOB_TERMS = [
    "work from home", "remote job offer", "weekly pay", "no experience needed",
    "earn from home", "unlimited earning", "apply now to earn", "reshipping",
]
INFORMATIONAL_SAFE_PHRASES = [
    "no action is required", "no action required", "this is only a reminder",
    "for your security, we recommend", "this is an automated notification",
    "your statement is now available", "your receipt", "has been processed successfully",
    "has been delivered", "has shipped", "track it using",
]


class _TextSelector(BaseEstimator, TransformerMixin):
    """Pass-through selector — returns text as-is for FeatureUnion."""
    def fit(self, X, y=None):
        return self
    def transform(self, X):
        return X

def train_fallback_model() -> None:
  
    phishing_samples = [
        # Credential harvesting
        "Dear user, your bank account has been locked. Click here immediately to verify your identity credentials.",
        "Security Alert: Suspicious login detected from an unknown device. Click to reset your password now.",
        "Dear Customer, someone attempted to change your password. Confirm your account details by clicking here.",
        "Your Apple-ID has been compromised. Confirm your identity and password at the verification link right away.",
        # Billing / subscription bait
        "URGENT: Your Netflix subscription payment declined. Update billing details now to avoid suspension.",
        "Final Warning: Your cloud storage space is full. Pay outstanding invoices within 24 hours to secure files.",
        "Invoice #4521 is overdue. Failure to settle payment within 24 hours will result in legal action. Pay now.",
        # Prize / lottery scam
        "CONGRATULATIONS! You have won a free $1000 Amazon gift card. Claim your reward voucher immediately here.",
        "You have been selected for an exclusive $500 Walmart gift card. Click the secure link to claim your prize.",
        # Tax / government impersonation
        "Your tax refund is waiting. Submit your SSN and banking details via the official portal link to claim funds.",
        "IRS Notice: You owe back taxes. Failure to respond immediately will result in legal proceedings. Call now.",
        # Payroll / HR bait
        "Attention Employee: Direct deposit routing updates required. Access the portal link to submit your details.",
        "Dear Employee, As part of our compliance review, all staff must confirm payroll information before Friday.",
        # Shipping fee scam
        "Your package is being held at customs. Pay a small clearance fee here to release your shipment within 12 hours.",
        "DHL Notice: Your parcel has been suspended. A delivery fee of $2.99 is required to release your shipment.",
        # Raw IP endpoint
        "Dear user, click http://192.168.5.21/login to confirm your account or it will be suspended within 24 hours.",
        # URL shortener
        "Check out this amazing offer at bit.ly/freecash now before it expires, limited time only!",
        # Lookalike domain
        "Your PayPal account is limited. Verify now at paypal-secure-login.xyz to restore full access immediately.",
        # IT helpdesk impersonation
        "IT Department Notice: Your mailbox storage is over quota. Reauthenticate your credentials to avoid suspension.",
        "Helpdesk Alert: Your VPN certificate has expired. Re-authenticate at the secure portal link before 5 PM today.",
        # BEC / gift-card fraud
        "Hi, I'm in back-to-back meetings and can't talk. Urgently buy 4 gift cards and send me the codes right away.",
        "This is the CEO. I need you to wire $47,000 to this vendor account immediately and keep this confidential.",
        # OTP hijack
        "Your one-time verification code is about to expire. Enter your OTP at the secure link to prevent account lockout.",
        # Crypto / investment fraud
        "Exclusive offer: Double your Bitcoin in 48 hours. Send your wallet address and seed phrase to claim your bonus.",
        "Join our blockchain passive income program. Guaranteed 300% returns. Enter your crypto wallet to get started.",
        # Fake job offer
        "Remote job opportunity: Earn $800/week reshipping packages from home. No experience needed. Apply now.",
        "Work-from-home alert: Earn unlimited income online. Submit your bank account details to receive your first payment.",
        # Multi-brand impersonation cluster
        "Microsoft and Google have flagged your account. Verify at microsoft-google-verify.top before your data is erased.",
        # Subdomain brand-squatting
        "Please re-enter your credentials at secure.paypal.verification-portal.ru to restore your account immediately.",
        # Obfuscated language
        "Pl3ase c0nfirm your p@ssword and l0gin at our s3cure p0rtal to av0id susp3nsion of your acc0unt right away.",
    ]

    legitimate_samples = [
        # Casual / social
        "Hey, are we still meeting up for lunch today at the standard cafeteria spot around noon?",
        "Hey, can you confirm what time works for you tomorrow? Either morning or afternoon is fine.",
        "Hi team, just a reminder that the weekly stand-up has moved to 10 AM starting next Monday.",
        # Work / project collaboration
        "Attached is the comprehensive project roadmap for Q3 review. Please look over the sprint tasks.",
        "Can you send over the updated spreadsheet containing last month's inventory reports?",
        "Hi John, Can you review the attached document before tomorrow's meeting? Thanks, Mark.",
        "Hi all, the meeting notes from yesterday's call have been uploaded to the shared drive.",
        "Hello, please verify that the numbers in the budget sheet are correct before I forward them to finance.",
        # HR / scheduling
        "Hello John, Your meeting has been scheduled for tomorrow at 2 PM. Regards, HR Team.",
        "Dear Employee, Your salary has been processed successfully. Regards, Finance Team.",
        "Welcome aboard! Your new employee onboarding portal access has been granted. Browse the handbook at your convenience.",
        # Utility / billing notification (informational)
        "Dear Customer, Your electricity bill for June 2026 is now available. Thank you, City Power Services.",
        "Your subscription receipt: $9.99 charged to your card ending in 4521 for Spotify Premium. Thanks for your support.",
        "Dear Member, your monthly statement is now available in your online banking portal. No immediate action is required.",
        # Package / delivery confirmation
        "Your Amazon package has been delivered successfully. Tracking Number: AMZ-45873291. Thank you for shopping with us.",
        "Dear Customer, Your order #88234 has shipped via FedEx and should arrive Thursday. Track it using the carrier app.",
        # Academic / institutional
        "Dear Student, The timetable for the upcoming semester has been published. Please check the student portal. Academic Office.",
        # Password / security reminder (informational — should NOT trigger)
        "Dear Customer, For your security, we recommend updating your password every 90 days. This is only a reminder. No action is required.",
        "Dear User, this is an automated notification that your software has been updated to version 4.2.1. No action is required.",
        # Medical / personal appointment
        "Reminder: Your dentist appointment is scheduled for July 2nd at 3:30 PM. Reply to confirm or call to reschedule.",
        # CI / DevOps notification
        "GitHub Actions: Your workflow 'CI Pipeline' completed successfully on branch main. View the run summary in your repository.",
        "Your pull request #312 has been approved by two reviewers and is ready to merge. No further action required.",
        # Slack / communication tool
        "Slack: You have 3 new messages in #general. Open Slack to catch up with your team.",
        # Newsletter / subscription confirmation
        "You're now subscribed to the Weekly Tech Digest. Expect your first issue next Monday. Unsubscribe anytime.",
        # Academic journal
        "Your manuscript submission #7841 has been received by the journal editorial office. A confirmation number is attached.",
        # Customer support resolution
        "Your support ticket #99123 has been resolved. If you have further questions, reply to this email. No action needed.",
        # Event reminder
        "Hi all, a friendly reminder that the company town hall is this Friday at 3 PM in the main auditorium.",
        # Finance team legit wire notification (internal)
        "Finance Team: The approved wire transfer of $47,000 to Vendor XYZ has been processed. Reference: TXN-20260612.",
        # Software license renewal (informational)
        "Your Adobe Creative Cloud license has been automatically renewed. Your next billing date is August 1, 2026.",
        # Gym / subscription
        "Thanks for visiting the gym today! Your session was logged. View your workout history in the mobile app.",
    ]

    texts  = phishing_samples + legitimate_samples
    labels = [1] * len(phishing_samples) + [0] * len(legitimate_samples)
    df     = pd.DataFrame({"text": texts, "label": labels})

   
    word_vectorizer = TfidfVectorizer(
        analyzer="word",
        stop_words="english",
        lowercase=True,
        ngram_range=(1, 3),   # unigram … trigram
        sublinear_tf=True,
        min_df=1,
        max_features=8000,
    )
    char_vectorizer = TfidfVectorizer(
        analyzer="char_wb",   
        lowercase=True,
        ngram_range=(3, 5),   
        sublinear_tf=True,
        min_df=1,
        max_features=4000,
    )

    combined_vectorizer = FeatureUnion([
        ("word", word_vectorizer),
        ("char", char_vectorizer),
    ])

    X = combined_vectorizer.fit_transform(df["text"])
    y = df["label"]

    model = LogisticRegression(
        C=0.8,
        class_weight="balanced",
        solver="lbfgs",
        max_iter=1000,
    )
    model.fit(X, y)

    os.makedirs("models", exist_ok=True)
    joblib.dump(model,                MODEL_PATH)
    joblib.dump(combined_vectorizer,  VECTORIZER_PATH)


def _load_artifacts():
    """Loads model + vectorizer once per process, training on first use."""
    if _MODEL_CACHE["model"] is None or _MODEL_CACHE["vectorizer"] is None:
        if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
            train_fallback_model()
        _MODEL_CACHE["model"]      = joblib.load(MODEL_PATH)
        _MODEL_CACHE["vectorizer"] = joblib.load(VECTORIZER_PATH)
    return _MODEL_CACHE["model"], _MODEL_CACHE["vectorizer"]


def _is_informational_reminder(lower_text: str) -> bool:
    """
    Returns True when the email exhibits strong markers of a benign
    informational / transactional message with no call-to-action.
    Used to suppress false positives on password-policy reminders,
    delivery confirmations, receipts, and automated system notices.
    """
    safe_hit_count = sum(1 for phrase in INFORMATIONAL_SAFE_PHRASES if phrase in lower_text)
    if safe_hit_count >= 2:
        return True
    aggressive_verbs = ["click here", "click the link", "verify now", "confirm now",
                        "update now", "access the portal", "login here", "log in now"]
    if safe_hit_count >= 1 and not any(v in lower_text for v in aggressive_verbs):
        return True
    return False

def _analyze_urls(raw_text: str):
    """Inspects every URL in the message for structural red flags."""
    triggers  = []
    critical  = False
    flagged   = set()

    for url in URL_REGEX.findall(raw_text):
        try:
            parsed = urlparse(url)
            host   = (parsed.hostname or "").lower()
        except ValueError:
            host = ""

        if not host:
            continue

        if IP_HOST_REGEX.match(host):
            triggers.append(
                f"🔴 Raw IP Address Endpoint: `{url}` — legitimate services never link directly to a bare IP address."
            )
            critical = True; flagged.add(host); continue

        if host in URL_SHORTENERS:
            triggers.append(
                f"🔴 Obfuscated Shortlink: `{url}` — true destination is concealed behind a URL-shortening proxy."
            )
            critical = True; flagged.add(host); continue

        if IDN_PUNYCODE_REGEX.search(host):
            triggers.append(
                f"🔴 IDN / Homoglyph Domain: `{url}` — Punycode encoding is used to visually mimic a trusted brand."
            )
            critical = True; flagged.add(host); continue

        if SUBDOMAIN_BRAND_SQUATTING_REGEX.search(host):
            triggers.append(
                f"🔴 Subdomain Brand-Squatting: `{url}` — a trusted brand name is embedded in a subdomain to deceive."
            )
            critical = True; flagged.add(host); continue

        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS) or "shared-" in host:
            triggers.append(
                f"🔴 High-Risk TLD Detected: `{url}` — top-level domain is statistically rare in legitimate business mail."
            )
            critical = True; flagged.add(host); continue

        if BRAND_LOOKALIKE_REGEX.search(host):
            triggers.append(
                f"🔴 Brand-Impersonation Domain: `{url}` — a known brand name is combined with a hyphenated lookalike host."
            )
            critical = True; flagged.add(host); continue

        if AT_SYMBOL_TRICK_REGEX.search(url):
            triggers.append(
                f"🔴 '@' Redirection Trick: `{url}` — text before '@' is decorative; the browser navigates to the true host after it."
            )
            critical = True; flagged.add(host); continue

        # --- Soft signals ---
        if host.count(".") >= 4:
            triggers.append(
                f"🟡 Excessive Subdomain Nesting: `{url}` — deep subdomain chains are a common cloaking technique."
            )
            flagged.add(host)

    for m in BARE_SHORTENER_REGEX.finditer(raw_text):
        h = m.group(1).lower()
        if h not in flagged:
            triggers.append(
                f"🔴 Bare Shortlink Reference: `{m.group(0)}` — shortener domain present without a URL scheme."
            )
            critical = True; flagged.add(h)

    for m in BARE_SUSPICIOUS_TLD_REGEX.finditer(raw_text):
        h = m.group(1).lower()
        if h not in flagged:
            triggers.append(
                f"🔴 Bare High-Risk Domain: `{m.group(0)}` — suspicious TLD present without a URL scheme."
            )
            critical = True; flagged.add(h)

    return triggers, critical


def _analyze_keywords(lower_text: str, raw_text: str):
    """
    Context-aware keyword / phrase heuristics.
    """
    triggers = []
    critical = False

    # ── Payroll / HR bait ────────────────────────────────────────────────────
    if "payroll" in lower_text and any(w in lower_text for w in ("confirm", "portal", "submit", "update")):
        triggers.append("🔴 High-Risk HR Bait: payroll verification / credential update request detected.")
        critical = True

    # ── Credential harvesting ─────────────────────────────────────────────────
    aggressive_verify = any(v in lower_text for v in (
        "verify now", "verify your", "confirm your", "validate your",
        "confirm account", "verify account", "click to verify",
    ))
    if aggressive_verify and any(w in lower_text for w in SENSITIVE_CONTEXT_WORDS):
        triggers.append("🔴 Credential Harvesting Signature: active verification demand paired with sensitive account terminology.")
        critical = True

    # ── Billing / payment data requests ──────────────────────────────────────
    if "update billing" in lower_text or "billing details" in lower_text or "update payment" in lower_text:
        triggers.append("🔴 Billing Data Solicitation: unsolicited request to update payment / billing details via embedded link.")
        critical = True

    # ── Financial data (SSN, card, OTP, routing) ─────────────────────────────
    if any(term in lower_text for term in FINANCIAL_HARVEST_TERMS):
        triggers.append("🔴 Sensitive Data Solicitation: message explicitly requests SSN, card number, PIN, OTP, or wire-transfer details.")
        critical = True

    # ── BEC / gift-card fraud ─────────────────────────────────────────────────
    gift_card = "gift card" in lower_text or "gift cards" in lower_text
    bec_pressure = any(p in lower_text for p in (
        "can't talk", "cant talk", "in a meeting", "don't tell", "keep this confidential",
        "urgent", "asap", "right away", "immediately", "send me the codes", "text me the codes",
    ))
    if gift_card and bec_pressure:
        triggers.append("🔴 BEC / Gift-Card Fraud Pattern: urgent, secretive request to procure gift cards and relay redemption codes.")
        critical = True

    # ── CEO / wire-transfer fraud ─────────────────────────────────────────────
    wire_keywords = ("wire", "transfer", "bank transfer", "iban", "swift")
    authority_spoofing = any(p in lower_text for p in ("ceo", "cfo", "president", "director", "executive"))
    if any(w in lower_text for w in wire_keywords) and authority_spoofing and "urgent" in lower_text:
        triggers.append("🔴 CEO / Wire-Transfer Fraud Signature: executive impersonation combined with urgent wire-transfer demand.")
        critical = True

    # ── Crypto / investment fraud ─────────────────────────────────────────────
    crypto_hits = [t for t in CRYPTO_FRAUD_TERMS if t in lower_text]
    if len(crypto_hits) >= 2:
        triggers.append(f"🔴 Cryptocurrency Fraud Indicators: {len(crypto_hits)} crypto-scam terms co-present ({', '.join(crypto_hits[:3])}).")
        critical = True

    # ── Fake job harvesting ───────────────────────────────────────────────────
    job_hits = [t for t in FAKE_JOB_TERMS if t in lower_text]
    if len(job_hits) >= 2:
        triggers.append(f"🔴 Fake Job-Offer Pattern: {len(job_hits)} work-from-home / easy-money signals co-present.")
        critical = True

    # ── Multi-brand impersonation clustering ──────────────────────────────────
    brand_hits = BRAND_LOOKALIKE_REGEX.findall(lower_text)
    unique_brands = {b.lower() for b in brand_hits}
    if len(unique_brands) >= 2:
        triggers.append(
            f"🔴 Multi-Brand Impersonation: {len(unique_brands)} brand names clustered ({', '.join(list(unique_brands)[:3])}) — "
            "a strong indicator of phishing lure construction."
        )
        critical = True

    # ── Obfuscated character substitution ────────────────────────────────────
    obf_matches = OBFUSCATED_WORD_REGEX.findall(lower_text)
    if len(obf_matches) >= 3:
        triggers.append(
            f"🔴 Obfuscated Text Detected: {len(obf_matches)} leet-speak / character-substitution tokens found — "
            "a common evasion technique."
        )
        critical = True

    # ── Redirection hook ─────────────────────────────────────────────────────
    if "click here" in lower_text or "access it here" in lower_text or "click the link below" in lower_text:
        triggers.append("🟡 Redirection Hook: message applies direct pressure on the recipient to follow an outbound link.")

    # ── Urgency cluster ───────────────────────────────────────────────────────
    urgency_hits = [p for p in URGENCY_PHRASES if p in lower_text]
    if len(urgency_hits) >= 2:
        triggers.append(
            f"🟡 High-Pressure Language Cluster: {len(urgency_hits)} urgency markers detected "
            f"({', '.join(urgency_hits[:3])}) — psychological pressure technique."
        )

    # ── Excessive punctuation ─────────────────────────────────────────────────
    exc_matches = EXCESS_PUNCT_REGEX.findall(raw_text)
    if len(exc_matches) >= 2:
        triggers.append(
            f"🟡 Excessive Punctuation: {len(exc_matches)} clusters of 3+ consecutive '!' or '?' — "
            "common visual alarm tactic in phishing lures."
        )

    return triggers, critical

def _compute_heuristic_risk(triggers: list[str]) -> float:
    """
    Converts the trigger list into a 0–100 numeric risk contribution.
    🔴 = +40 pts each (capped at 80), 🟡 = +12 pts each (capped at 36).
    """
    red_count    = sum(1 for t in triggers if t.startswith("🔴"))
    yellow_count = sum(1 for t in triggers if t.startswith("🟡"))
    red_score    = min(80.0, red_count    * 40.0)
    yellow_score = min(36.0, yellow_count * 12.0)
    return min(100.0, red_score + yellow_score)

def analyze_email_content(email_text: str) -> dict:
    """
    Analyze an email body for phishing indicators.
    """
    if not email_text or not email_text.strip():
        return {
            "verdict":    "Legitimate",
            "confidence": 100.0,
            "triggers":   ["🟢 Empty payload — nothing to analyse."],
        }

    model, vectorizer = _load_artifacts()
    lower_text = email_text.lower()

    if _is_informational_reminder(lower_text):
        vectorized = vectorizer.transform([email_text])
        proba      = model.predict_proba(vectorized)[0]
        classes    = list(model.classes_)
        phi_col    = classes.index(1) if 1 in classes else int(proba.argmax())
        ml_score   = float(proba[phi_col]) * 100

        if ml_score < 45:
            note = next(
                (p for p in INFORMATIONAL_SAFE_PHRASES if p in lower_text),
                "standard advisory language",
            )
            return {
                "verdict":    "Legitimate",
                "confidence": round(100 - ml_score * 0.5, 2),
                "triggers":   [
                    f"🟢 Informational Advisory: message contains '{note}' — "
                    "recognised as a benign transactional or security-policy notification."
                ],
            }

    # ── 2. Heuristic layer ────────────────────────────────────────────────────
    url_triggers,  url_critical  = _analyze_urls(email_text)
    kw_triggers,   kw_critical   = _analyze_keywords(lower_text, email_text)
    all_triggers   = url_triggers + kw_triggers
    has_critical   = url_critical or kw_critical

    heuristic_risk = _compute_heuristic_risk(all_triggers)

    # ── 3. ML predictor ───────────────────────────────────────────────────────
    vectorized  = vectorizer.transform([email_text])
    proba       = model.predict_proba(vectorized)[0]
    classes     = list(model.classes_)
    phi_col     = classes.index(1) if 1 in classes else int(proba.argmax())
    ml_score    = float(proba[phi_col]) * 100

    # ── 4. Hybrid scoring ─────────────────────────────────────────────────────
    # Blend heuristic risk (reflects signal density) with ML probability.
    # Hard critical hits guarantee Phishing; the confidence still reflects depth.
    if has_critical:
        verdict    = "Phishing"
        # Scale with signal density: 1 red flag → ~95 %, 3+ red flags → ~99 %
        red_depth  = sum(1 for t in all_triggers if t.startswith("🔴"))
        base_conf  = min(97.0, 90.0 + red_depth * 2.5)
        ml_boost   = (ml_score / 100) * (100 - base_conf)
        confidence = round(min(99.5, base_conf + ml_boost), 2)
    else:
        # Weighted blend: heuristic carries more weight than ML on small corpus
        combined = round((0.55 * ml_score) + (0.45 * heuristic_risk), 2)
        if combined >= 52:
            verdict    = "Phishing"
            confidence = round(min(94.0, combined), 2)
        else:
            verdict    = "Legitimate"
            confidence = round(min(99.0, 100 - combined), 2)

    if verdict == "Legitimate" and not all_triggers:
        if any(w in lower_text for w in ("bill", "receipt", "processed", "statement")):
            all_triggers.append(
                "🟢 Standard Transaction Notice: informational message with no interactive calls-to-action."
            )
        elif any(w in lower_text for w in ("reminder", "no action", "automated notification")):
            all_triggers.append(
                "🟢 Automated Advisory: routine reminder with zero external redirection requirements."
            )
        else:
            all_triggers.append(
                "🟢 Safe Baseline: natural conversational phrasing with no transactional or social-engineering pressure hooks."
            )
    return {
        "verdict":    verdict,
        "confidence": confidence,
        "triggers":   all_triggers,
    }
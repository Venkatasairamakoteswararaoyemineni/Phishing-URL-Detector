import re

# -------------------------
# URL ANALYZER
# -------------------------

def analyze_url(url):

    score = 0

    phishing_keywords = [
        "login",
        "verify",
        "secure",
        "update",
        "bank",
        "account",
        "signin",
        "confirm"
    ]

    # Long URL
    if len(url) > 75:
        score += 2

    # HTTP instead of HTTPS
    if "https" not in url:
        score += 3

    # IP Address Detection
    ip_pattern = r"(\\d{1,3}\\.){3}\\d{1,3}"

    if re.search(ip_pattern, url):
        score += 4

    # Multiple dots
    if url.count(".") > 3:
        score += 2

    # Suspicious symbols
    if "@" in url or "-" in url:
        score += 2

    # Keyword detection
    for word in phishing_keywords:

        if word in url.lower():
            score += 1

    # Final Classification
    if score >= 7:
        result = "PHISHING"

    elif score >= 4:
        result = "SUSPICIOUS"

    else:
        result = "SAFE"

    return result, score
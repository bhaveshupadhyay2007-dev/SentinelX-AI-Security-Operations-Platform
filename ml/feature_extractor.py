import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "password",
    "account",
    "secure",
    "update",
    "confirm",
    "payment",
    "signin",
    "bank",
    "wallet",
    "credential"
]


def extract_features(url):
    url = str(url).strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # Safely parse malformed URLs
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
    except ValueError:
        # Fallback for malformed URLs
        hostname = ""
        path = ""

    url_lower = url.lower()

    features = [
        len(url),
        len(hostname),
        len(path),
        url.count("."),
        url.count("/"),
        url.count("-"),
        url.count("_"),
        url.count("@"),
        url.count("?"),
        url.count("="),
        url.count("&"),
        sum(
            1
            for keyword in SUSPICIOUS_KEYWORDS
            if keyword in url_lower
        ),
        int(url.startswith("https://")),
        int(
            re.match(
                r"^(?:\d{1,3}\.){3}\d{1,3}$",
                hostname
            ) is not None
        ),
        int(
            any(
                hostname.lower().endswith(tld)
                for tld in [
                    ".tk",
                    ".ml",
                    ".ga",
                    ".cf",
                    ".top",
                    ".xyz",
                    ".click",
                    ".work"
                ]
            )
        ),
        hostname.count("."),
        len(
            [
                part
                for part in hostname.split(".")
                if part
            ]
        )
    ]

    return features
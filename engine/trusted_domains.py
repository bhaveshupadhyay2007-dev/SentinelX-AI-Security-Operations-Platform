from urllib.parse import urlparse


TRUSTED_DOMAINS = {
    "google.com",
    "github.com",
    "microsoft.com",
    "amazon.com",
    "amazon.in",
    "wikipedia.org",
    "youtube.com",
    "apple.com",
    "linkedin.com",
    "stackoverflow.com",
    "python.org",
    "mozilla.org",
    "reddit.com",
    "cloudflare.com",
    "nasa.gov",
    "openai.com",
}


def is_trusted_domain(url):
    url = str(url).strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower().strip(".")
    except ValueError:
        return False

    if not hostname:
        return False

    for domain in TRUSTED_DOMAINS:
        if hostname == domain or hostname.endswith("." + domain):
            return True

    return False
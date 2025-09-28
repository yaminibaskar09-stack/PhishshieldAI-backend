import tldextract
from urllib.parse import urlparse

def extract_url_features(url):
    """
    Extracts simple but useful features from a given URL.
    These features help the AI model decide if it's phishing or legitimate.
    """

    # Break down the URL
    parsed = urlparse(url)
    domain_info = tldextract.extract(url)

    # Feature engineering
    features = {
        # URL length
        "length": len(url),

        # Count of digits in the URL
        "num_digits": sum(c.isdigit() for c in url),

        # Count of special characters (like -, _, ?, =, &)
        "num_special_chars": sum(not c.isalnum() for c in url),

        # Does it use HTTPS?
        "has_https": 1 if url.startswith("https") else 0,

        # Number of subdomains (phishing often uses too many)
        "num_subdomains": len(domain_info.subdomain.split(".")) if domain_info.subdomain else 0,

        # Suspicious words (commonly found in phishing links)
        "contains_suspicious_words": int(any(
            word in url.lower() for word in
            ["login", "secure", "verify", "update", "confirm", "account", "banking", "password"]
        )),

        # The suffix (like com, org, net, info, xyz, etc.)
        "suffix": domain_info.suffix,
    }

    return features

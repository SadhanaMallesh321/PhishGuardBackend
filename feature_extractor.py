"""Feature extraction for the PhishGuard phishing detection model."""

import re
from urllib.parse import urlparse


EXPECTED_FEATURE_COUNT = 48

SUSPICIOUS_KEYWORDS = (
    "login", "verify", "secure", "account", "update", "bank",
    "confirm", "invoice", "password", "pay", "signin", "security",
    "webmail", "wallet", "alert", "claim", "urgent",
)

BRAND_NAMES = (
    "paypal", "apple", "google", "microsoft", "amazon",
    "netflix", "bank", "dropbox", "github", "facebook",
)


def extract_url_features(url: str) -> list[int]:
    """Create the 48-feature vector expected by the trained model."""

    features = [0] * EXPECTED_FEATURE_COUNT

    if not url:
        return features

    try:
        parsed = urlparse(url)
    except Exception:
        return features

    full_url = url.lower()
    hostname = (parsed.hostname or "").lower()
    path_text = parsed.path or ""
    query = parsed.query or ""

    hostname_parts = [part for part in hostname.split(".") if part]

    # 0 NumDots
    features[0] = hostname.count(".")

    # 1 SubdomainLevel
    features[1] = max(0, len(hostname_parts) - 2)

    # 2 PathLevel
    features[2] = len(
        [segment for segment in path_text.split("/") if segment]
    )

    # 3 UrlLength
    features[3] = len(url)

    # 4 NumDash
    features[4] = full_url.count("-")

    # 5 NumDashInHostname
    features[5] = hostname.count("-")

    # 6 AtSymbol
    features[6] = int("@" in url)

    # 7 TildeSymbol
    features[7] = int("~" in url)

    # 8 NumUnderscore
    features[8] = full_url.count("_")

    # 9 NumPercent
    features[9] = full_url.count("%")

    # 10 NumQueryComponents
    features[10] = len(query.split("&")) if query else 0

    # 11 NumAmpersand
    features[11] = query.count("&")

    # 12 NumHash
    features[12] = int("#" in url)

    # 13 NumNumericChars
    features[13] = sum(char.isdigit() for char in url)

    # 14 NoHttps
    features[14] = int(parsed.scheme.lower() != "https")

    # 15 RandomString
    features[15] = 0

    if hostname:
        # 16 IpAddress
        features[16] = int(
            bool(re.fullmatch(r"\d+(?:\.\d+){3}", hostname))
        )

        # 17 DomainInSubdomains
        features[17] = int(
            len(hostname_parts) > 2
            and any(
                part in BRAND_NAMES
                for part in hostname_parts[:-2]
            )
        )

        # 18 DomainInPaths
        features[18] = int(
            any(
                part and part in path_text.lower()
                for part in hostname_parts
            )
        )

        # 19 HttpsInHostname
        features[19] = int("https" in hostname)

        # 20 HostnameLength
        features[20] = len(hostname)

    # 21 PathLength
    features[21] = len(path_text)

    # 22 QueryLength
    features[22] = len(query)

    # 23 DoubleSlashInPath
    features[23] = int("//" in path_text[1:])

    # 24 NumSensitiveWords
    features[24] = sum(
        1 for keyword in SUSPICIOUS_KEYWORDS
        if keyword in full_url
    )

    # 25 EmbeddedBrandName
    features[25] = int(
        any(brand in full_url for brand in BRAND_NAMES)
    )

    # 26-47 are webpage/HTML features.
    # They remain 0 until page analysis is implemented.
    #
    # 26 PctExtHyperlinks
    # 27 PctExtResourceUrls
    # 28 ExtFavicon
    # 29 InsecureForms
    # 30 RelativeFormAction
    # 31 ExtFormAction
    # 32 AbnormalFormAction
    # 33 PctNullSelfRedirectHyperlinks
    # 34 FrequentDomainNameMismatch
    # 35 FakeLinkInStatusBar
    # 36 RightClickDisabled
    # 37 PopUpWindow
    # 38 SubmitInfoToEmail
    # 39 IframeOrFrame
    # 40 MissingTitle
    # 41 ImagesOnlyInForm
    # 42 SubdomainLevelRT
    # 43 UrlLengthRT
    # 44 PctExtResourceUrlsRT
    # 45 AbnormalExtFormActionR
    # 46 ExtMetaScriptLinkRT
    # 47 PctExtNullSelfRedirectHyperlinksRT

    return features


def apply_page_features(
    features: list[int],
    page_features: dict
) -> list[float]:
    """Add webpage/DOM-derived features to the 48-feature vector."""

    features = list(features)

    numeric = {}

    for key, value in page_features.items():
        try:
            numeric[key] = float(value)
        except (TypeError, ValueError):
            continue

    def bounded(
        name: str,
        minimum: float = 0.0,
        maximum: float = 1.0
    ) -> float:
        return max(
            minimum,
            min(maximum, numeric.get(name, 0.0))
        )

    if "sensitive_words" in page_features:
        features[24] = bounded("sensitive_words", 0.0, 20.0)

    if "embedded_brand" in page_features:
        features[25] = int(bool(bounded("embedded_brand")))

    features[26] = bounded("external_link_ratio")
    features[27] = bounded("external_resource_ratio")
    features[28] = int(
        bool(bounded("external_favicon"))
    )
    features[29] = int(
        bool(bounded("insecure_forms"))
    )
    features[30] = int(
        bool(bounded("relative_form_action"))
    )
    features[31] = int(
        bool(bounded("external_form_action"))
    )
    features[32] = int(
        bool(bounded("abnormal_form_action"))
    )
    features[33] = bounded(
        "null_self_redirect",
        0.0,
        20.0
    )

    features[34] = int(
        bool(bounded("domain_name_mismatch"))
    )

    features[35] = int(
        bool(bounded("fake_status_bar"))
    )

    features[36] = int(
        bool(bounded("right_click_disabled"))
    )

    features[37] = int(
        bool(bounded("popup_window"))
    )

    features[38] = int(
        bool(bounded("submit_info_to_email"))
    )

    features[39] = int(
        bool(bounded("iframe"))
    )

    features[40] = int(
        bool(bounded("missing_title"))
    )

    features[41] = int(
        bool(bounded("images_only_form"))
    )

    features[42] = bounded(
        "subdomain_level_rt",
        0.0,
        20.0
    )

    features[43] = bounded(
        "url_length_rt",
        0.0,
        20.0
    )

    features[44] = bounded(
        "external_resource_ratio_rt"
    )

    features[45] = int(
        bool(bounded("abnormal_ext_form_action_r"))
    )

    features[46] = bounded(
        "meta_script_link_ratio"
    )

    features[47] = bounded(
        "null_self_redirect_ratio_rt"
    )

    return features
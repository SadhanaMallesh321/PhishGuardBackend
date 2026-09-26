def generate_explanation(url, prediction, confidence, features):
    """
    Generate a human-readable explanation for the ML prediction.
    """

    reasons = []

    url_lower = url.lower()

    # URL-based indicators
    if "@" in url:
        reasons.append("the URL contains an @ symbol")

    if len(url) > 75:
        reasons.append("the URL is unusually long")

    if url.count("-") >= 2:
        reasons.append("the URL contains multiple hyphens")

    suspicious_words = [
        "login", "verify", "secure", "account",
        "update", "confirm", "password",
        "signin", "security", "urgent"
    ]

    found_words = [
        word for word in suspicious_words
        if word in url_lower
    ]

    if found_words:
        reasons.append(
            "the URL contains suspicious words such as "
            + ", ".join(found_words[:3])
        )

    # IP address indicator
    if features.get("IpAddress", 0):
        reasons.append(
            "the URL uses an IP address instead of a normal domain name"
        )

    # HTTPS indicator
    if features.get("NoHttps", 0):
        reasons.append("the website does not use HTTPS")

    # Domain/subdomain indicators
    if features.get("SubdomainLevel", 0) >= 2:
        reasons.append("the URL contains multiple subdomain levels")

    if features.get("NumDots", 0) >= 4:
        reasons.append(
            "the URL has an unusually complex domain structure with many dots"
        )

    # Form-related indicators
    if features.get("InsecureForms", 0):
        reasons.append("the page contains insecure forms")

    if features.get("ExternalFormAction", 0):
        reasons.append(
            "the page contains forms submitting information to another domain"
        )

    if features.get("AbnormalFormAction", 0):
        reasons.append("the page contains an abnormal form action")

    # Iframe indicator
    if features.get("IframeOrFrame", 0):
        reasons.append("the page contains iframe or frame elements")

    # Generate final explanation
    if prediction.lower() == "phishing":

        if reasons:
            summary = (
                f"This website is classified as phishing with "
                f"{confidence * 100:.0f}% confidence because "
                + "; ".join(reasons[:4])
                + "."
            )
        else:
            summary = (
                f"This website is classified as phishing with "
                f"{confidence * 100:.0f}% confidence because the machine "
                "learning model detected characteristics associated with "
                "phishing websites."
            )

    else:

        if reasons:
            summary = (
                "The website is classified as legitimate by the machine "
                "learning model. However, some indicators were detected: "
                + "; ".join(reasons[:3])
                + "."
            )
        else:
            summary = (
                "This website is classified as legitimate because the "
                "analyzed URL and webpage features do not show significant "
                "phishing characteristics."
            )

    return summary
def generate_ai_summary(url, prediction, confidence, explanation):
    """
    Generate a short, user-friendly AI-style summary
    based on the ML prediction and explanation.
    """

    confidence_percent = confidence * 100

    if prediction.lower() == "phishing":

        if confidence_percent >= 90:
            risk_level = "high risk"
        elif confidence_percent >= 70:
            risk_level = "moderate to high risk"
        else:
            risk_level = "potential risk"

        summary = (
            f"PhishGuard detected this website as potentially dangerous. "
            f"The machine learning model classified it as phishing with "
            f"{confidence_percent:.0f}% confidence, indicating {risk_level}. "
            f"{explanation} Avoid entering passwords, banking details, "
            f"or other personal information on this website."
        )

    else:

        if confidence_percent >= 90:
            confidence_message = "high confidence"
        elif confidence_percent >= 70:
            confidence_message = "good confidence"
        else:
            confidence_message = "limited confidence"

        summary = (
            f"PhishGuard classified this website as legitimate with "
            f"{confidence_percent:.0f}% confidence. The analysis found "
            f"no significant phishing characteristics. "
            f"This result is provided with {confidence_message}; "
            f"continue to use normal security precautions."
        )

    return summary
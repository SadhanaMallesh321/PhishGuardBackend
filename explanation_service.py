
def generate_explanation(url, prediction, confidence, features, language="english"):
    """Generate a human-readable explanation in the selected language."""

    reasons = []
    url_lower = url.lower()

    # Collect URL-based indicators
    if "@" in url:
        reasons.append("at")

    if len(url) > 75:
        reasons.append("long")

    if url.count("-") >= 2:
        reasons.append("hyphens")

    suspicious_words = [
        "login", "verify", "secure", "account",
        "update", "confirm", "password",
        "signin", "security", "urgent"
    ]

    found_words = [word for word in suspicious_words if word in url_lower]

    if found_words:
        reasons.append("words:" + ", ".join(found_words[:3]))

    if features.get("IpAddress", 0):
        reasons.append("ip")

    if features.get("NoHttps", 0):
        reasons.append("https")

    if features.get("SubdomainLevel", 0) >= 2:
        reasons.append("subdomains")

    if features.get("NumDots", 0) >= 4:
        reasons.append("dots")

    if features.get("InsecureForms", 0):
        reasons.append("insecure_forms")

    if features.get("ExternalFormAction", 0):
        reasons.append("external_forms")

    if features.get("AbnormalFormAction", 0):
        reasons.append("abnormal_forms")

    if features.get("IframeOrFrame", 0):
        reasons.append("iframes")

    # Translate the detected indicators
    translations = {
        "english": {
            "at": "the URL contains an @ symbol",
            "long": "the URL is unusually long",
            "hyphens": "the URL contains multiple hyphens",
            "ip": "the URL uses an IP address instead of a normal domain name",
            "https": "the website does not use HTTPS",
            "subdomains": "the URL contains multiple subdomain levels",
            "dots": "the domain structure contains many dots",
            "insecure_forms": "the page contains insecure forms",
            "external_forms": "forms submit information to another domain",
            "abnormal_forms": "the page contains an abnormal form action",
            "iframes": "the page contains iframe or frame elements",
            "words": "the URL contains suspicious words such as"
        },
        "kannada": {
            "at": "URL ನಲ್ಲಿ @ ಚಿಹ್ನೆ ಇದೆ",
            "long": "URL ಅಸಾಮಾನ್ಯವಾಗಿ ಉದ್ದವಾಗಿದೆ",
            "hyphens": "URL ನಲ್ಲಿ ಹಲವು ಹೈಫನ್‌ಗಳಿವೆ",
            "ip": "ಸಾಮಾನ್ಯ ಡೊಮೇನ್ ಬದಲಿಗೆ URL IP ವಿಳಾಸವನ್ನು ಬಳಸುತ್ತದೆ",
            "https": "ವೆಬ್‌ಸೈಟ್ HTTPS ಬಳಸುವುದಿಲ್ಲ",
            "subdomains": "URL ನಲ್ಲಿ ಹಲವು ಉಪಡೊಮೇನ್ ಹಂತಗಳಿವೆ",
            "dots": "ಡೊಮೇನ್ ರಚನೆಯಲ್ಲಿ ಅಸಾಮಾನ್ಯವಾಗಿ ಹಲವು ಚುಕ್ಕೆಗಳಿವೆ",
            "insecure_forms": "ಪುಟದಲ್ಲಿ ಸುರಕ್ಷಿತವಲ್ಲದ ಫಾರ್ಮ್‌ಗಳಿವೆ",
            "external_forms": "ಫಾರ್ಮ್‌ಗಳು ಮಾಹಿತಿಯನ್ನು ಬೇರೆ ಡೊಮೇನ್‌ಗೆ ಕಳುಹಿಸುತ್ತವೆ",
            "abnormal_forms": "ಪುಟದಲ್ಲಿ ಅಸಾಮಾನ್ಯ ಫಾರ್ಮ್ ಕ್ರಿಯೆಯಿದೆ",
            "iframes": "ಪುಟದಲ್ಲಿ iframe ಅಥವಾ frame ಅಂಶಗಳಿವೆ",
            "words": "URL ನಲ್ಲಿ ಅನುಮಾನಾಸ್ಪದ ಪದಗಳಿವೆ"
        },
        "hindi": {
            "at": "URL में @ चिह्न है",
            "long": "URL असामान्य रूप से लंबा है",
            "hyphens": "URL में कई हाइफ़न हैं",
            "ip": "URL सामान्य डोमेन के बजाय IP पते का उपयोग करता है",
            "https": "वेबसाइट HTTPS का उपयोग नहीं करती",
            "subdomains": "URL में कई सबडोमेन स्तर हैं",
            "dots": "डोमेन संरचना में असामान्य रूप से कई बिंदु हैं",
            "insecure_forms": "पेज में असुरक्षित फ़ॉर्म हैं",
            "external_forms": "फ़ॉर्म जानकारी दूसरे डोमेन पर भेजते हैं",
            "abnormal_forms": "पेज में असामान्य फ़ॉर्म कार्रवाई है",
            "iframes": "पेज में iframe या frame तत्व हैं",
            "words": "URL में संदिग्ध शब्द हैं"
        }
    }

    language = language if language in translations else "english"
    t = translations[language]

    translated_reasons = []
    for reason in reasons:
        if reason.startswith("words:"):
            words = reason.split(":", 1)[1]
            translated_reasons.append(f"{t['words']} {words}")
        else:
            translated_reasons.append(t[reason])

    percent = confidence * 100

    if language == "kannada":
        if prediction.lower() == "phishing":
            if translated_reasons:
                return (
                    f"ಈ ವೆಬ್‌ಸೈಟ್ ಫಿಶಿಂಗ್ ಎಂದು ಗುರುತಿಸಲಾಗಿದೆ. "
                    f"ವಿಶ್ವಾಸದ ಮಟ್ಟ {percent:.0f}%. ಕಾರಣಗಳು: "
                    + "; ".join(translated_reasons[:4]) + "."
                )
            return (
                f"ಈ ವೆಬ್‌ಸೈಟ್ ಫಿಶಿಂಗ್ ಎಂದು ಗುರುತಿಸಲಾಗಿದೆ. "
                f"ವಿಶ್ವಾಸದ ಮಟ್ಟ {percent:.0f}%. "
                "ಯಂತ್ರ ಕಲಿಕೆ ಮಾದರಿಯು ಫಿಶಿಂಗ್ ಲಕ್ಷಣಗಳನ್ನು ಪತ್ತೆಹಚ್ಚಿದೆ."
            )

        if translated_reasons:
            return (
                "ಯಂತ್ರ ಕಲಿಕೆ ಮಾದರಿಯು ಈ ವೆಬ್‌ಸೈಟ್ ಅನ್ನು ಸುರಕ್ಷಿತವೆಂದು "
                "ವರ್ಗೀಕರಿಸಿದೆ. ಆದರೂ ಕೆಲವು ಸೂಚನೆಗಳು ಕಂಡುಬಂದಿವೆ: "
                + "; ".join(translated_reasons[:3]) + "."
            )
        return "URL ಮತ್ತು ವೆಬ್‌ಪುಟದ ವಿಶ್ಲೇಷಣೆಯಲ್ಲಿ ಗಮನಾರ್ಹ ಫಿಶಿಂಗ್ ಲಕ್ಷಣಗಳು ಕಂಡುಬಂದಿಲ್ಲ."

    if language == "hindi":
        if prediction.lower() == "phishing":
            if translated_reasons:
                return (
                    f"इस वेबसाइट को फ़िशिंग के रूप में पहचाना गया है। "
                    f"विश्वास स्तर {percent:.0f}% है। कारण: "
                    + "; ".join(translated_reasons[:4]) + "."
                )
            return (
                f"इस वेबसाइट को फ़िशिंग के रूप में पहचाना गया है। "
                f"विश्वास स्तर {percent:.0f}% है। "
                "मशीन लर्निंग मॉडल ने फ़िशिंग से जुड़े संकेत पाए हैं।"
            )

        if translated_reasons:
            return (
                "मशीन लर्निंग मॉडल ने इस वेबसाइट को वैध बताया है। "
                "हालाँकि, कुछ संकेत मिले हैं: "
                + "; ".join(translated_reasons[:3]) + "."
            )
        return "URL और वेबपेज के विश्लेषण में फ़िशिंग के महत्वपूर्ण संकेत नहीं मिले।"

    if prediction.lower() == "phishing":
        if translated_reasons:
            return (
                f"This website is classified as phishing with "
                f"{percent:.0f}% confidence because "
                + "; ".join(translated_reasons[:4]) + "."
            )
        return (
            f"This website is classified as phishing with "
            f"{percent:.0f}% confidence because the machine learning "
            "model detected characteristics associated with phishing websites."
        )

    if translated_reasons:
        return (
            "The website is classified as legitimate by the machine learning "
            "model. However, some indicators were detected: "
            + "; ".join(translated_reasons[:3]) + "."
        )

    return (
        "This website is classified as legitimate because the analyzed URL "
        "and webpage features do not show significant phishing characteristics."
    )

def generate_ai_summary(url, prediction, confidence, explanation, language="english"):
    """Generate a user-friendly summary in the selected language."""

    confidence_percent = confidence * 100
    is_phishing = prediction.lower() == "phishing"

    if language == "kannada":
        if is_phishing:
            risk = (
                "ಹೆಚ್ಚಿನ ಅಪಾಯ" if confidence_percent >= 90
                else "ಮಧ್ಯಮದಿಂದ ಹೆಚ್ಚಿನ ಅಪಾಯ" if confidence_percent >= 70
                else "ಸಂಭಾವ್ಯ ಅಪಾಯ"
            )
            return (
                f"PhishGuard ಈ ವೆಬ್‌ಸೈಟ್ ಅಪಾಯಕಾರಿಯಾಗಿರಬಹುದು ಎಂದು ಗುರುತಿಸಿದೆ. "
                f"ಫಿಶಿಂಗ್ ಸಾಧ್ಯತೆಯ ವಿಶ್ವಾಸದ ಮಟ್ಟ {confidence_percent:.0f}%; "
                f"ಅಪಾಯದ ಮಟ್ಟ: {risk}. {explanation} "
                "ಈ ವೆಬ್‌ಸೈಟ್‌ನಲ್ಲಿ ಪಾಸ್‌ವರ್ಡ್, ಬ್ಯಾಂಕಿಂಗ್ ವಿವರಗಳು ಅಥವಾ "
                "ವೈಯಕ್ತಿಕ ಮಾಹಿತಿಯನ್ನು ನಮೂದಿಸಬೇಡಿ."
            )

        confidence_text = (
            "ಹೆಚ್ಚಿನ ವಿಶ್ವಾಸ" if confidence_percent >= 90
            else "ಉತ್ತಮ ವಿಶ್ವಾಸ" if confidence_percent >= 70
            else "ಸೀಮಿತ ವಿಶ್ವಾಸ"
        )
        return (
            f"PhishGuard ಈ ವೆಬ್‌ಸೈಟ್ ಅನ್ನು ಸುರಕ್ಷಿತವೆಂದು ವರ್ಗೀಕರಿಸಿದೆ. "
            f"ವಿಶ್ವಾಸದ ಮಟ್ಟ {confidence_percent:.0f}%. "
            "ಗಮನಾರ್ಹ ಫಿಶಿಂಗ್ ಲಕ್ಷಣಗಳು ಕಂಡುಬಂದಿಲ್ಲ. "
            f"ವಿಶ್ವಾಸದ ಮಟ್ಟ: {confidence_text}. ಆದರೂ ಎಚ್ಚರಿಕೆಯಿಂದಿರಿ."
        )

    if language == "hindi":
        if is_phishing:
            risk = (
                "उच्च जोखिम" if confidence_percent >= 90
                else "मध्यम से उच्च जोखिम" if confidence_percent >= 70
                else "संभावित जोखिम"
            )
            return (
                f"PhishGuard ने इस वेबसाइट को संभावित रूप से खतरनाक पाया है। "
                f"फ़िशिंग वर्गीकरण का विश्वास स्तर {confidence_percent:.0f}% है; "
                f"जोखिम स्तर: {risk}। {explanation} "
                "इस वेबसाइट पर पासवर्ड, बैंकिंग विवरण या व्यक्तिगत जानकारी दर्ज न करें।"
            )

        confidence_text = (
            "उच्च विश्वास" if confidence_percent >= 90
            else "अच्छा विश्वास" if confidence_percent >= 70
            else "सीमित विश्वास"
        )
        return (
            f"PhishGuard ने इस वेबसाइट को वैध बताया है। विश्वास स्तर "
            f"{confidence_percent:.0f}% है। फ़िशिंग के महत्वपूर्ण संकेत "
            f"नहीं मिले। विश्वास स्तर: {confidence_text}। फिर भी सावधानी बरतें।"
        )

    if is_phishing:
        risk_level = (
            "high risk" if confidence_percent >= 90
            else "moderate to high risk" if confidence_percent >= 70
            else "potential risk"
        )
        return (
            "PhishGuard detected this website as potentially dangerous. "
            f"The machine learning model classified it as phishing with "
            f"{confidence_percent:.0f}% confidence, indicating {risk_level}. "
            f"{explanation} Avoid entering passwords, banking details, "
            "or other personal information on this website."
        )

    confidence_message = (
        "high confidence" if confidence_percent >= 90
        else "good confidence" if confidence_percent >= 70
        else "limited confidence"
    )
    return (
        f"PhishGuard classified this website as legitimate with "
        f"{confidence_percent:.0f}% confidence. The analysis found "
        f"no significant phishing characteristics. This result is provided "
        f"with {confidence_message}; continue to use normal security precautions."
    )
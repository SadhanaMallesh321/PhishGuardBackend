import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin


def analyze_page(url):
    result = {
        "external_link_ratio": 0.0,
        "external_resource_ratio": 0.0,
        "external_favicon": 0,
        "insecure_forms": 0,
        "relative_form_action": 0,
        "external_form_action": 0,
        "abnormal_form_action": 0,
        "null_self_redirect": 0,
        "iframe": 0,
        "missing_title": 0,
        "images_only_form": 0,
        "meta_script_link_ratio": 0.0,
    }

    try:
        response = requests.get(
            url,
            timeout=10,
            headers={
                "User-Agent": "Mozilla/5.0"
            },
            allow_redirects=True
        )

        html = response.text
        soup = BeautifulSoup(html, "html.parser")

        page_url = response.url
        page_domain = urlparse(page_url).netloc.lower()

        # --------------------------------
        # 1. External hyperlinks
        # --------------------------------
        links = soup.find_all("a", href=True)

        if links:
            external_links = 0

            for link in links:
                href = urljoin(page_url, link["href"])
                domain = urlparse(href).netloc.lower()

                if domain and domain != page_domain:
                    external_links += 1

            result["external_link_ratio"] = (
                external_links / len(links)
            )

        # --------------------------------
        # 2. External resources
        # --------------------------------
        resources = []

        resources += soup.find_all("img", src=True)
        resources += soup.find_all("script", src=True)
        resources += soup.find_all("link", href=True)

        if resources:
            external_resources = 0

            for resource in resources:

                if resource.name == "script":
                    value = resource.get("src")

                elif resource.name == "img":
                    value = resource.get("src")

                else:
                    value = resource.get("href")

                if not value:
                    continue

                resource_url = urljoin(page_url, value)
                resource_domain = urlparse(
                    resource_url
                ).netloc.lower()

                if (
                    resource_domain
                    and resource_domain != page_domain
                ):
                    external_resources += 1

            result["external_resource_ratio"] = (
                external_resources / len(resources)
            )

        # --------------------------------
        # 3. Favicon
        # --------------------------------
        favicon = soup.find(
            "link",
            rel=lambda value:
            value and "icon" in str(value).lower()
        )

        if favicon:
            favicon_url = favicon.get("href")

            if favicon_url:
                favicon_url = urljoin(
                    page_url,
                    favicon_url
                )

                favicon_domain = urlparse(
                    favicon_url
                ).netloc.lower()

                if favicon_domain and favicon_domain != page_domain:
                    result["external_favicon"] = 1

        # --------------------------------
        # 4. Forms
        # --------------------------------
        forms = soup.find_all("form")

        for form in forms:

            action = form.get("action", "").strip()

            # No action / empty action
            if not action:
                result["null_self_redirect"] = 1

            # Relative action
            elif not action.startswith(("http://", "https://")):
                result["relative_form_action"] = 1

            else:
                action_url = urljoin(
                    page_url,
                    action
                )

                action_domain = urlparse(
                    action_url
                ).netloc.lower()

                # External form action
                if action_domain and action_domain != page_domain:
                    result["external_form_action"] = 1

                # Insecure form
                if action_url.startswith("http://"):
                    result["insecure_forms"] = 1

        # --------------------------------
        # 5. Iframe
        # --------------------------------
        if soup.find("iframe") or soup.find("frame"):
            result["iframe"] = 1

        # --------------------------------
        # 6. Missing title
        # --------------------------------
        title = soup.find("title")

        if not title or not title.get_text(strip=True):
            result["missing_title"] = 1

        # --------------------------------
        # 7. Images inside forms
        # --------------------------------
        for form in forms:

            inputs = form.find_all("input")
            images = form.find_all("img")

            if images and inputs:
                image_inputs = [
                    i for i in inputs
                    if i.get("type", "").lower() == "image"
                ]

                if image_inputs:
                    result["images_only_form"] = 1

        # --------------------------------
        # 8. Meta / Script / Link ratio
        # --------------------------------
        meta_count = len(soup.find_all("meta"))
        script_count = len(soup.find_all("script"))
        link_count = len(soup.find_all("link"))

        total_elements = (
            meta_count +
            script_count +
            link_count
        )

        if total_elements:
            result["meta_script_link_ratio"] = (
                total_elements / max(1, len(soup.find_all()))
            )


        return result  
      

    except Exception as e:    
        print("Page analysis error:", e)

        result["analysis_failed"] = 1

        return result
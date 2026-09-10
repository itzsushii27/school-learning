from flask import Flask, request, Response, render_template
import requests
from urllib.parse import urljoin, urlparse, quote
import ipaddress
import socket
import re

app = Flask(__name__)

TIMEOUT = 15
MAX_BYTES = 8 * 1024 * 1024
USER_AGENT = "VercelWebProxy/1.0"

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "content-encoding",
}


def is_public_host(host):
    """Prevent requests to localhost/private/internal addresses."""
    if not host:
        return False

    try:
        addresses = socket.getaddrinfo(host, None)

        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])

            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_unspecified
            ):
                return False

        return True

    except Exception:
        return False


def normalize_url(url):
    url = (url or "").strip()

    if not url:
        raise ValueError("Missing URL.")

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("Invalid URL.")

    if not is_public_host(parsed.hostname):
        raise ValueError("That host is not allowed.")

    return url


def proxy_url(target):
    return "/proxy?url=" + quote(target, safe="")


def rewrite_html(html, base_url):
    """
    Rewrite common HTML URLs so navigation remains inside
    the Vercel proxy instead of going directly to the target.
    """

    attribute_pattern = re.compile(
        r'(?P<prefix>\b(?:href|src|action|poster|cite|data-src)\s*=\s*)'
        r'(?P<quote>["\'])'
        r'(?P<url>.*?)'
        r'(?P=quote)',
        re.IGNORECASE | re.DOTALL,
    )

    def replace_attribute(match):
        raw_url = match.group("url").strip()

        if not raw_url:
            return match.group(0)

        if raw_url.startswith(
            (
                "#",
                "javascript:",
                "data:",
                "mailto:",
                "tel:",
            )
        ):
            return match.group(0)

        absolute_url = urljoin(base_url, raw_url)

        try:
            absolute_url = normalize_url(absolute_url)
        except ValueError:
            return match.group(0)

        return (
            match.group("prefix")
            + match.group("quote")
            + proxy_url(absolute_url)
            + match.group("quote")
        )

    html = attribute_pattern.sub(replace_attribute, html)

    # Rewrite CSS url(...) references.
    def replace_css_url(match):
        raw_url = match.group(2).strip()

        if raw_url.startswith(("data:", "#")):
            return match.group(0)

        absolute_url = urljoin(base_url, raw_url)

        try:
            absolute_url = normalize_url(absolute_url)
        except ValueError:
            return match.group(0)

        return "url('" + proxy_url(absolute_url) + "')"

    html = re.sub(
        r"url\(\s*(['\"]?)(.*?)\1\s*\)",
        replace_css_url,
        html,
        flags=re.IGNORECASE,
    )

    # Rewrite <base href="...">.
    def replace_base(match):
        absolute_url = urljoin(base_url, match.group(3))

        try:
            absolute_url = normalize_url(absolute_url)
        except ValueError:
            return match.group(0)

        return (
            match.group(1)
            + match.group(2)
            + proxy_url(absolute_url)
            + match.group(2)
        )

    html = re.sub(
        r'(<base\b[^>]*\bhref\s*=\s*)(["\'])(.*?)(\2)',
        replace_base,
        html,
        flags=re.IGNORECASE | re.DOTALL,
    )

    # Small JavaScript bridge for window.open().
    bridge = f"""
<script>
window.__PROXY_BASE__ = {base_url!r};
window.__PROXY_PREFIX__ = "/proxy?url=";

(function () {{
    const originalOpen = window.open;

    window.open = function (url, target, features) {{
        try {{
            if (
                url &&
                !/^(javascript:|data:|mailto:|tel:|#)/i.test(url)
            ) {{
                const absolute = new URL(
                    url,
                    window.__PROXY_BASE__
                ).href;

                url =
                    window.__PROXY_PREFIX__ +
                    encodeURIComponent(absolute);
            }}
        }} catch (error) {{
            // Leave the URL unchanged if it cannot be parsed.
        }}

        return originalOpen.call(
            window,
            url,
            target,
            features
        );
    }};
}})();
</script>
"""

    if re.search(r"</head\s*>", html, re.IGNORECASE):
        html = re.sub(
            r"</head\s*>",
            bridge + "</head>",
            html,
            count=1,
            flags=re.IGNORECASE,
        )
    else:
        html = bridge + html

    return html


@app.get("/")
def index():
    return render_template("index.html")


@app.route("/proxy", methods=["GET", "POST"])
def proxy():
    try:
        target = normalize_url(request.args.get("url", ""))

    except ValueError as error:
        return (
            render_template(
                "error.html",
                message=str(error),
            ),
            400,
        )

    try:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": request.headers.get(
                "Accept",
                "*/*",
            ),
            "Accept-Language": request.headers.get(
                "Accept-Language",
                "en-US,en;q=0.8",
            ),
        }

        if request.headers.get("Referer"):
            headers["Referer"] = request.headers["Referer"]

        body = (
            request.get_data()
            if request.method == "POST"
            else None
        )

        response = requests.request(
            method=request.method,
            url=target,
            headers=headers,
            data=body,
            timeout=TIMEOUT,
            allow_redirects=True,
            stream=True,
        )

        content_type = response.headers.get(
            "Content-Type",
            "",
        )

        body = response.raw.read(
            MAX_BYTES + 1
        )

        if len(body) > MAX_BYTES:
            return "Response too large.", 413

        # HTML gets rewritten so links stay inside the proxy.
        if "text/html" in content_type.lower():
            encoding = response.encoding or "utf-8"

            html = body.decode(
                encoding,
                errors="replace",
            )

            html = rewrite_html(
                html,
                response.url,
            )

            body = html.encode("utf-8")

            content_type = "text/html; charset=utf-8"

        output_headers = {}

        for key, value in response.headers.items():
            if key.lower() in HOP_BY_HOP:
                continue

            if key.lower() == "location":
                continue

            output_headers[key] = value

        # Keep redirects inside the Vercel domain.
        if (
            300 <= response.status_code < 400
            and response.headers.get("Location")
        ):
            destination = urljoin(
                response.url,
                response.headers["Location"],
            )

            try:
                destination = normalize_url(
                    destination
                )

                output_headers["Location"] = proxy_url(
                    destination
                )

            except ValueError:
                pass

        return Response(
            body,
            status=response.status_code,
            headers=output_headers,
        )

    except requests.RequestException as error:
        return (
            render_template(
                "error.html",
                message=f"Could not fetch that site: {error}",
            ),
            502,
        )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
    )

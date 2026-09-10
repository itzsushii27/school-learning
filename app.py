from flask import Flask, request, Response, render_template
import requests
from urllib.parse import urljoin, urlparse, quote
import ipaddress
import socket
import re

app = Flask(__name__)

TIMEOUT = 20
MAX_BYTES = 12 * 1024 * 1024

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

# Headers that should NOT be copied from the destination server.
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
    """
    Prevent the proxy from connecting to private/local addresses.
    """

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
        raise ValueError("No URL was provided.")

    # Allow users to type example.com instead of https://example.com
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


def proxy_url(url):
    return "/proxy?url=" + quote(url, safe="")


def rewrite_html(html, base_url):
    """
    Rewrite common URLs in HTML so they continue going through
    the Vercel proxy.
    """

    pattern = re.compile(
        r'(?P<prefix>\b'
        r'(?:href|src|action|poster|cite|data-src|data-href)'
        r'\s*=\s*)'
        r'(?P<quote>["\'])'
        r'(?P<url>.*?)'
        r'(?P=quote)',
        re.IGNORECASE | re.DOTALL,
    )

    def replace(match):
        original = match.group("url").strip()

        if not original:
            return match.group(0)

        # Don't mess with anchors, JavaScript, data URLs, etc.
        if original.startswith(
            (
                "#",
                "javascript:",
                "data:",
                "mailto:",
                "tel:",
            )
        ):
            return match.group(0)

        absolute = urljoin(base_url, original)

        try:
            absolute = normalize_url(absolute)
        except ValueError:
            return match.group(0)

        return (
            match.group("prefix")
            + match.group("quote")
            + proxy_url(absolute)
            + match.group("quote")
        )

    html = pattern.sub(replace, html)

    # Rewrite CSS url(...)
    def replace_css(match):
        original = match.group(2).strip()

        if not original:
            return match.group(0)

        if original.startswith(("data:", "#")):
            return match.group(0)

        absolute = urljoin(base_url, original)

        try:
            absolute = normalize_url(absolute)
        except ValueError:
            return match.group(0)

        return "url('" + proxy_url(absolute) + "')"

    html = re.sub(
        r"url\(\s*(['\"]?)(.*?)\1\s*\)",
        replace_css,
        html,
        flags=re.IGNORECASE,
    )

    # Rewrite <base href>
    def replace_base(match):
        original = match.group(3)

        absolute = urljoin(base_url, original)

        try:
            absolute = normalize_url(absolute)
        except ValueError:
            return match.group(0)

        return (
            match.group(1)
            + match.group(2)
            + proxy_url(absolute)
            + match.group(2)
        )

    html = re.sub(
        r'(<base\b[^>]*\bhref\s*=\s*)(["\'])(.*?)(\2)',
        replace_base,
        html,
        flags=re.IGNORECASE | re.DOTALL,
    )

    # Inject a small JavaScript bridge.
    bridge = f"""
<script>
window.__PROXY_BASE__ = {base_url!r};
window.__PROXY_PREFIX__ = "/proxy?url=";

(function () {{
    const originalOpen = window.open;

    window.open = function(url, target, features) {{
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
        }} catch (e) {{}}

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
        target = normalize_url(
            request.args.get("url", "")
        )

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
                "en-US,en;q=0.9",
            ),
            # IMPORTANT:
            # Don't ask the destination to gzip/brotli the
            # response. This makes proxying much simpler.
            "Accept-Encoding": "identity",
        }

        # Forward a few useful browser headers.
        if request.headers.get("Referer"):
            headers["Referer"] = request.headers["Referer"]

        if request.headers.get("Content-Type"):
            headers["Content-Type"] = request.headers["Content-Type"]

        request_body = None

        if request.method == "POST":
            request_body = request.get_data()

        upstream = requests.request(
            method=request.method,
            url=target,
            headers=headers,
            data=request_body,
            timeout=TIMEOUT,
            allow_redirects=True,
            stream=False,
        )

        content_type = upstream.headers.get(
            "Content-Type",
            "",
        )

        # requests has already decompressed the response if
        # the server ignored Accept-Encoding: identity and
        # returned compression anyway.
        body = upstream.content

        if len(body) > MAX_BYTES:
            return (
                "The destination response is too large.",
                413,
            )

        # -------------------------
        # HTML
        # -------------------------

        if "text/html" in content_type.lower():

            encoding = (
                upstream.encoding
                or "utf-8"
            )

            html = body.decode(
                encoding,
                errors="replace",
            )

            html = rewrite_html(
                html,
                upstream.url,
            )

            body = html.encode("utf-8")

            content_type = (
                "text/html; charset=utf-8"
            )

        # -------------------------
        # Response headers
        # -------------------------

        output_headers = {}

        for key, value in upstream.headers.items():

            key_lower = key.lower()

            if key_lower in HOP_BY_HOP:
                continue

            if key_lower == "location":
                continue

            # These can interfere with displaying proxied
            # pages inside our domain.
            if key_lower in {
                "content-security-policy",
                "content-security-policy-report-only",
                "x-frame-options",
            }:
                continue

            output_headers[key] = value

        # Set the correct content type after rewriting HTML.
        output_headers["Content-Type"] = content_type

        # -------------------------
        # Redirects
        # -------------------------

        if (
            300 <= upstream.status_code < 400
            and upstream.headers.get("Location")
        ):

            destination = urljoin(
                upstream.url,
                upstream.headers["Location"],
            )

            try:

                destination = normalize_url(
                    destination
                )

                output_headers["Location"] = (
                    proxy_url(destination)
                )

            except ValueError:
                pass

        return Response(
            body,
            status=upstream.status_code,
            headers=output_headers,
        )

    except requests.RequestException as error:

        return (
            render_template(
                "error.html",
                message=(
                    "The proxy could not fetch that page: "
                    + str(error)
                ),
            ),
            502,
        )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
    )

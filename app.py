from flask import Flask, request, Response, render_template, redirect
import requests
from urllib.parse import urljoin, quote, urlparse
import ipaddress
import socket
import re

app = Flask(__name__)

TIMEOUT = 30
MAX_BYTES = 25 * 1024 * 1024

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

# Headers which belong to the connection between client and proxy,
# rather than the upstream server.
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
}

# Headers that can prevent proxied pages from loading.
STRIP_RESPONSE_HEADERS = {
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
}


# ---------------------------------------------------------
# SECURITY
# ---------------------------------------------------------

def is_public_host(host):
    if not host:
        return False

    try:
        addresses = socket.getaddrinfo(
            host,
            None,
            type=socket.SOCK_STREAM,
        )

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

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(
            "Only HTTP and HTTPS URLs are supported."
        )

    if not parsed.hostname:
        raise ValueError("Invalid URL.")

    if not is_public_host(parsed.hostname):
        raise ValueError("That host is not allowed.")

    return url


def proxy_url(url):
    return "/proxy?url=" + quote(url, safe="")


# ---------------------------------------------------------
# REQUEST HEADERS
# ---------------------------------------------------------

def build_upstream_headers():
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

        # Let requests handle compression.
        "Accept-Encoding": "gzip, deflate, br",
    }

    # Forward useful browser headers.
    forward = [
        "Referer",
        "Origin",
        "Authorization",
        "X-Requested-With",
        "Cache-Control",
        "Pragma",
        "DNT",
        "Sec-Fetch-Dest",
        "Sec-Fetch-Mode",
        "Sec-Fetch-Site",
        "Sec-Fetch-User",
    ]

    for name in forward:
        value = request.headers.get(name)

        if value:
            headers[name] = value

    content_type = request.headers.get("Content-Type")

    if content_type:
        headers["Content-Type"] = content_type

    return headers


# ---------------------------------------------------------
# HTML / CSS REWRITING
# ---------------------------------------------------------

URL_ATTRIBUTES = re.compile(
    r'(?P<prefix>\b'
    r'(?:href|src|action|poster|cite|'
    r'data-src|data-href|data-url|'
    r'formaction)'
    r'\s*=\s*)'
    r'(?P<quote>["\'])'
    r'(?P<url>.*?)'
    r'(?P=quote)',
    re.IGNORECASE | re.DOTALL,
)


def rewrite_one_url(original, base_url):
    original = original.strip()

    if not original:
        return None

    if original.startswith(
        (
            "#",
            "javascript:",
            "data:",
            "mailto:",
            "tel:",
            "blob:",
        )
    ):
        return None

    absolute = urljoin(base_url, original)

    try:
        absolute = normalize_url(absolute)
    except ValueError:
        return None

    return proxy_url(absolute)


def rewrite_html(html, base_url):

    # href/src/action/etc.
    def replace_attribute(match):
        original = match.group("url")

        rewritten = rewrite_one_url(
            original,
            base_url,
        )

        if rewritten is None:
            return match.group(0)

        return (
            match.group("prefix")
            + match.group("quote")
            + rewritten
            + match.group("quote")
        )

    html = URL_ATTRIBUTES.sub(
        replace_attribute,
        html,
    )

    # CSS url(...)
    def replace_css(match):
        original = match.group(2).strip()

        rewritten = rewrite_one_url(
            original,
            base_url,
        )

        if rewritten is None:
            return match.group(0)

        return "url('" + rewritten + "')"

    html = re.sub(
        r"url\(\s*(['\"]?)(.*?)\1\s*\)",
        replace_css,
        html,
        flags=re.IGNORECASE,
    )

    # <base href="">
    def replace_base(match):
        original = match.group(3)

        rewritten = rewrite_one_url(
            original,
            base_url,
        )

        if rewritten is None:
            return match.group(0)

        return (
            match.group(1)
            + match.group(2)
            + rewritten
            + match.group(2)
        )

    html = re.sub(
        r'(<base\b[^>]*\bhref\s*=\s*)'
        r'(["\'])(.*?)(\2)',
        replace_base,
        html,
        flags=re.IGNORECASE | re.DOTALL,
    )

    # -----------------------------------------------------
    # Browser bridge
    # -----------------------------------------------------

    bridge = f"""
<script>
window.__PROXY_BASE__ = {base_url!r};
window.__PROXY_PREFIX__ = "/proxy?url=";

(function () {{
    function proxyURL(value) {{
        try {{
            if (!value) return value;

            if (
                /^(javascript:|data:|mailto:|tel:|blob:|#)/i
                .test(value)
            ) {{
                return value;
            }}

            const absolute =
                new URL(
                    value,
                    window.__PROXY_BASE__
                ).href;

            return (
                window.__PROXY_PREFIX__ +
                encodeURIComponent(absolute)
            );
        }} catch (e) {{
            return value;
        }}
    }}

    // window.open
    const originalOpen = window.open;

    window.open = function(url, target, features) {{
        return originalOpen.call(
            window,
            proxyURL(url),
            target,
            features
        );
    }};

    // Location navigation
    try {{
        const originalAssign =
            window.location.assign.bind(window.location);

        window.location.assign = function(url) {{
            originalAssign(proxyURL(url));
        }};
    }} catch (e) {{}}

    // Fetch
    const originalFetch = window.fetch;

    window.fetch = function(input, init) {{
        try {{
            if (typeof input === "string") {{
                input = proxyURL(input);
            }} else if (
                input &&
                input.url
            ) {{
                input = new Request(
                    proxyURL(input.url),
                    input
                );
            }}
        }} catch (e) {{}}

        return originalFetch.call(
            this,
            input,
            init
        );
    }};

    // XMLHttpRequest
    const originalOpenXHR =
        XMLHttpRequest.prototype.open;

    XMLHttpRequest.prototype.open =
        function(method, url) {{

            arguments[1] = proxyURL(url);

            return originalOpenXHR.apply(
                this,
                arguments
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


# ---------------------------------------------------------
# RESPONSE HEADERS
# ---------------------------------------------------------

def build_response_headers(upstream):
    output = {}

    for key, value in upstream.headers.items():
        lower = key.lower()

        if lower in HOP_BY_HOP:
            continue

        if lower in STRIP_RESPONSE_HEADERS:
            continue

        # requests can receive upstream cookies containing
        # Domain/Path attributes intended for another host.
        if lower == "set-cookie":
            value = re.sub(
                r";\s*domain=[^;]+",
                "",
                value,
                flags=re.IGNORECASE,
            )

            value = re.sub(
                r";\s*path=/",
                "; Path=/",
                value,
                flags=re.IGNORECASE,
            )

        output[key] = value

    return output


# ---------------------------------------------------------
# PROXY
# ---------------------------------------------------------

@app.route("/proxy", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
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
        headers = build_upstream_headers()

        body = None

        if request.method in {
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        }:
            body = request.get_data()

        # Forward the browser's cookies.
        if request.headers.get("Cookie"):
            headers["Cookie"] = request.headers["Cookie"]

        upstream = requests.request(
            method=request.method,
            url=target,
            headers=headers,
            data=body,
            timeout=TIMEOUT,
            allow_redirects=False,
            stream=True,
        )

        # -------------------------------------------------
        # Redirect
        # -------------------------------------------------

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

                return redirect(
                    proxy_url(destination),
                    code=upstream.status_code,
                )

            except ValueError:
                pass

        # -------------------------------------------------
        # Read response
        # -------------------------------------------------

        content_type = upstream.headers.get(
            "Content-Type",
            "",
        )

        # For now HTML is buffered because it needs rewriting.
        if "text/html" in content_type.lower():

            body = upstream.content

            if len(body) > MAX_BYTES:
                upstream.close()

                return (
                    "The destination response is too large.",
                    413,
                )

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

            output_headers = build_response_headers(
                upstream
            )

            output_headers["Content-Type"] = (
                "text/html; charset=utf-8"
            )

            output_headers.pop(
                "Content-Encoding",
                None,
            )

            output_headers.pop(
                "Content-Length",
                None,
            )

            upstream.close()

            return Response(
                body,
                status=upstream.status_code,
                headers=output_headers,
            )

        # -------------------------------------------------
        # Everything else
        #
        # Images, video, JS, CSS, fonts, JSON, API
        # responses, etc.
        # -------------------------------------------------

        data = upstream.content

        if len(data) > MAX_BYTES:
            upstream.close()

            return (
                "The destination response is too large.",
                413,
            )

        output_headers = build_response_headers(
            upstream
        )

        output_headers.pop(
            "Content-Length",
            None,
        )

        upstream.close()

        return Response(
            data,
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


# ---------------------------------------------------------
# HOME
# ---------------------------------------------------------

@app.get("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
    )

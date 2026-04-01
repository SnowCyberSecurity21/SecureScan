import ssl
import socket
from datetime import datetime
from fastapi import FastAPI, Query, HTTPException
import requests
from urllib.parse import urlparse
import ssl
import socket

app = FastAPI(title="SecureScan", version="4.0")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120 SecureScan"
}


def ssl_cert_matches_domain(domain: str) -> bool:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=7) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        # CN va SAN tekshiruvi
        names = []

        for t in cert.get("subject", []):
            if t[0][0] == "commonName":
                names.append(t[0][1])

        for san in cert.get("subjectAltName", []):
            if san[0] == "DNS":
                names.append(san[1])

        return any(
            domain == name or (name.startswith("*.") and domain.endswith(name[1:]))
            for name in names
        )

    except Exception:
        return False


def real_https(domain: str) -> bool:
    try:
        r = requests.get(
            f"https://{domain}",
            timeout=10,
            headers=HEADERS,
            verify=True,
            allow_redirects=True
        )

        # 1️⃣ Final URL https bo‘lishi shart
        if not r.url.startswith("https://"):
            return False

        # 2️⃣ Status code normal
        if r.status_code >= 400:
            return False

        # 3️⃣ Real HTML
        ct = r.headers.get("Content-Type", "").lower()
        if "text/html" not in ct:
            return False

        # 4️⃣ Sertifikat domen bilan mos
        if not ssl_cert_matches_domain(domain):
            return False

        return True

    except requests.exceptions.RequestException:
        return False

def analyze_ssl(domain: str):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=7) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))

        not_after = cert.get("notAfter")
        expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (expires_at - datetime.utcnow()).days

        self_signed = issuer == subject

        return {
            "issuer": issuer.get("organizationName", "Unknown"),
            "expires_at": expires_at.isoformat(),
            "days_left": days_left,
            "self_signed": self_signed
        }

    except Exception as e:
        return {
            "error": str(e)
        }


from fastapi import Query, HTTPException
from urllib.parse import urlparse

@app.get("/scan")
def scan(url: str = Query(...)):
    parsed = urlparse(url if "://" in url else f"http://{url}")
    domain = parsed.netloc or parsed.path

    if not domain:
        raise HTTPException(status_code=400, detail="Noto‘g‘ri URL")

    # 1️⃣ HTTPS real tekshiruv (sizdagi funksiya)
    https_ok = real_https(domain)

    # 2️⃣ SSL tahlil
    ssl_info = analyze_ssl(domain)

    # 3️⃣ Ball hisoblash
    score = 0
    if https_ok:
        score += 60
    if ssl_info.get("certificate_valid"):
        score += 40

    return {
        "domain": domain,
        "final_protocol": "https" if https_ok else "http",
        "checks": {
            "Real HTTPS (cert + content + final url)": https_ok,
            "SSL analysis": ssl_info
        },
        "security_score": score
    }


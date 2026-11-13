"""TLS: certificate, chain trust, protocol versions and weak cipher acceptance.

Only performs normal TLS handshakes (one per protocol / cipher group tested).
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from secaudit.context import AuditContext
from secaudit.models import SectionResult, Severity

PROTOCOLS = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]

WEAK_CIPHER_GROUPS = [
    ("NULL / anonymous", "aNULL:eNULL", Severity.HIGH),
    ("EXPORT", "EXPORT", Severity.HIGH),
    ("RC4", "RC4", Severity.HIGH),
    ("3DES (SWEET32)", "3DES", Severity.MEDIUM),
    ("Static RSA key exchange (no forward secrecy)", "kRSA", Severity.LOW),
    ("CBC-mode with SHA-1 MAC", "SHA1:!aNULL:!eNULL:!RC4:!3DES:!kRSA", Severity.INFO),
]

LOCAL_LIMIT_MARKERS = ("NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE", "NO_CIPHER_MATCH",
                       "unsupported protocol", "No cipher can be selected")


def _connect(host: str, port: int, ctx: ssl.SSLContext, timeout: float, sni: str) -> ssl.SSLSocket:
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        return ctx.wrap_socket(sock, server_hostname=sni)
    except Exception:
        sock.close()
        raise


def _name_attr(name: x509.Name, oid) -> str | None:
    vals = name.get_attributes_for_oid(oid)
    return vals[0].value if vals else None


def _describe_key(pub) -> tuple[str, int | None]:
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"ECDSA ({pub.curve.name})", pub.key_size
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", 448
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size
    return type(pub).__name__, None


def parse_cert(der: bytes) -> dict:
    cert = x509.load_der_x509_certificate(der)
    now = datetime.now(timezone.utc)
    try:
        sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        dns_names = sans.get_values_for_type(x509.DNSName)
        ip_names = [str(i) for i in sans.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        dns_names, ip_names = [], []
    try:
        scts = len(cert.extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS).value)
    except (x509.ExtensionNotFound, ValueError):
        scts = 0
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        ocsp = [d.access_location.value for d in aia if d.access_method.dotted_string == "1.3.6.1.5.5.7.48.1"]
    except x509.ExtensionNotFound:
        ocsp = []
    try:
        cert.extensions.get_extension_for_oid(ExtensionOID.TLS_FEATURE)
        must_staple = True
    except x509.ExtensionNotFound:
        must_staple = False
    key_type, key_bits = _describe_key(cert.public_key())
    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else cert.signature_algorithm_oid._name
    return {
        "subject_cn": _name_attr(cert.subject, NameOID.COMMON_NAME),
        "subject_org": _name_attr(cert.subject, NameOID.ORGANIZATION_NAME),
        "issuer_cn": _name_attr(cert.issuer, NameOID.COMMON_NAME),
        "issuer_org": _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        "self_signed": cert.issuer == cert.subject,
        "san_dns": dns_names,
        "san_ip": ip_names,
        "serial": format(cert.serial_number, "x"),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_left": (not_after - now).days,
        "lifetime_days": (not_after - not_before).days,
        "signature_hash": sig,
        "key_type": key_type,
        "key_bits": key_bits,
        "sct_count": scts,
        "ocsp_urls": ocsp,
        "must_staple": must_staple,
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(":"),
    }


def _hostname_matches(host: str, names: list[str]) -> bool:
    host = host.lower()
    for n in names:
        n = n.lower()
        if n == host:
            return True
        if n.startswith("*.") and host.count(".") == n.count(".") and host.endswith(n[1:]):
            return True
    return False


def run(ctx: AuditContext) -> SectionResult:
    res = SectionResult("tls")
    t = ctx.target
    port = t.port if t.port and t.scheme_hint == "https" else 443
    host, sni = t.host, t.host
    timeout = min(ctx.config.timeout, 10)

    # 1. Trusted handshake with defaults
    verified = True
    verify_error = None
    default = ssl.create_default_context()
    default.set_alpn_protocols(["h2", "http/1.1"])
    try:
        s = _connect(host, port, default, timeout, sni)
    except ssl.SSLCertVerificationError as e:
        verified, verify_error = False, e.verify_message or str(e)
        s = None
    except (OSError, ssl.SSLError) as e:
        reason = "connection refused / port closed" if isinstance(e, (ConnectionRefusedError,)) else str(e)
        res.errors.append(f"No TLS service reachable on {host}:{port} ({reason})")
        res.data["available"] = False
        return res

    if s is None:
        insecure = ssl.create_default_context()
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE
        insecure.set_alpn_protocols(["h2", "http/1.1"])
        try:
            s = _connect(host, port, insecure, timeout, sni)
        except (OSError, ssl.SSLError) as e:
            res.errors.append(f"TLS connection failed: {e}")
            res.data["available"] = False
            return res

    with s:
        der = s.getpeercert(binary_form=True)
        cipher = s.cipher()
        res.data.update(
            available=True,
            port=port,
            negotiated_protocol=s.version(),
            negotiated_cipher=cipher[0] if cipher else None,
            cipher_bits=cipher[2] if cipher else None,
            alpn=s.selected_alpn_protocol(),
            trusted=verified,
            verify_error=verify_error,
        )
        chain = []
        getter = getattr(s, "get_verified_chain", None) if verified else getattr(s, "get_unverified_chain", None)
        if getter:
            try:
                for c in getter() or []:
                    cd = c.public_bytes() if hasattr(c, "public_bytes") else c
                    if isinstance(cd, str):
                        cd = ssl.PEM_cert_to_DER_cert(cd)
                    info = parse_cert(cd)
                    chain.append({k: info[k] for k in ("subject_cn", "issuer_cn", "not_after", "key_type", "key_bits", "signature_hash")})
            except Exception:  # chain introspection is best-effort
                pass
        res.data["chain"] = chain

    cert = parse_cert(der) if der else {}
    res.data["certificate"] = cert
    ctx.tls_cert_sans = cert.get("san_dns", [])

    # 2. Protocol versions
    protocols = {}
    for label, version in PROTOCOLS:
        protocols[label] = _try_protocol(host, port, sni, version, timeout)
    res.data["protocols"] = protocols

    # 3. Weak cipher groups (TLS <= 1.2 only; TLS 1.3 suites are all strong)
    weak = {}
    max_legacy = ssl.TLSVersion.TLSv1_2
    for label, cipherstr, _ in WEAK_CIPHER_GROUPS:
        weak[label] = _try_cipher(host, port, sni, cipherstr, max_legacy, timeout)
    res.data["weak_ciphers"] = weak

    _findings(ctx, res, cert, protocols, weak, verified, verify_error)
    return res


def _insecure_ctx() -> ssl.SSLContext:
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _classify(e: Exception) -> str:
    msg = str(e)
    if any(m in msg for m in LOCAL_LIMIT_MARKERS) and "alert" not in msg.lower():
        return "untestable"
    return "no"


def _try_protocol(host: str, port: int, sni: str | None, version: ssl.TLSVersion, timeout: float) -> str:
    c = _insecure_ctx()
    try:
        c.minimum_version = version
        c.maximum_version = version
        if version < ssl.TLSVersion.TLSv1_2:
            c.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return "untestable"
    try:
        with _connect(host, port, c, timeout, sni):
            return "yes"
    except ssl.SSLError as e:
        return _classify(e)
    except OSError:
        return "no"


def _try_cipher(host: str, port: int, sni: str | None, ciphers: str, max_version: ssl.TLSVersion, timeout: float) -> str:
    c = _insecure_ctx()
    try:
        c.maximum_version = max_version
        c.minimum_version = ssl.TLSVersion.TLSv1
        c.set_ciphers(ciphers + ":@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return "untestable"
    try:
        with _connect(host, port, c, timeout, sni) as s:
            return "yes:" + (s.cipher() or ("?",))[0]
    except ssl.SSLError as e:
        return _classify(e)
    except OSError:
        return "no"


def _findings(ctx, res, cert, protocols, weak, verified, verify_error) -> None:
    host = ctx.target.host
    if not verified:
        sev = Severity.HIGH
        title = "TLS certificate is not trusted"
        if cert.get("self_signed"):
            title = "TLS certificate is self-signed"
        res.add("tls.untrusted", title, sev, "TLS", detail=verify_error or "",
                recommendation="Use a certificate from a publicly trusted CA and serve the full intermediate chain.")
    if cert:
        names = cert["san_dns"] or ([cert["subject_cn"]] if cert.get("subject_cn") else [])
        if not ctx.target.is_ip and not _hostname_matches(host, names):
            res.add("tls.hostname", "Certificate does not cover this hostname", Severity.HIGH, "TLS",
                    evidence=f"{host} not in {', '.join(names[:10])}")
        days = cert["days_left"]
        if days < 0:
            res.add("tls.expired", f"TLS certificate expired {-days} days ago", Severity.CRITICAL, "TLS",
                    evidence=cert["not_after"], recommendation="Renew the certificate immediately and automate renewal.")
        elif days < 14:
            res.add("tls.expiring", f"TLS certificate expires in {days} days", Severity.HIGH, "TLS",
                    evidence=cert["not_after"], recommendation="Renew now; verify auto-renewal (e.g. certbot timer) works.")
        elif days < 30:
            res.add("tls.expiring", f"TLS certificate expires in {days} days", Severity.MEDIUM, "TLS",
                    evidence=cert["not_after"], recommendation="Confirm automated renewal is in place.")
        if cert["key_type"] == "RSA" and (cert["key_bits"] or 0) < 2048:
            res.add("tls.weak-key", f"Weak RSA key ({cert['key_bits']} bits)", Severity.HIGH, "TLS",
                    recommendation="Use RSA ≥ 2048 bits or ECDSA P-256.")
        if cert["signature_hash"] in ("sha1", "md5"):
            res.add("tls.weak-sig", f"Certificate signed with {cert['signature_hash'].upper()}", Severity.MEDIUM, "TLS")
        if any(n.startswith("*.") for n in cert["san_dns"]):
            res.add("tls.wildcard", "Wildcard certificate in use", Severity.INFO, "TLS",
                    detail="A key compromise on any host sharing it affects all subdomains.",
                    evidence=", ".join(n for n in cert["san_dns"] if n.startswith("*."))[:200])
        if cert["sct_count"] == 0 and verified:
            res.add("tls.no-sct", "No embedded Certificate Transparency SCTs", Severity.INFO, "TLS",
                    detail="SCTs may still be delivered via TLS extension or OCSP.")

    if protocols.get("TLSv1.0") == "yes":
        res.add("tls.tls10", "Deprecated TLS 1.0 is enabled", Severity.MEDIUM, "TLS",
                recommendation="Disable TLS 1.0 and 1.1 (RFC 8996); allow only TLS 1.2 and 1.3.")
    if protocols.get("TLSv1.1") == "yes":
        res.add("tls.tls11", "Deprecated TLS 1.1 is enabled", Severity.MEDIUM, "TLS",
                recommendation="Disable TLS 1.0 and 1.1 (RFC 8996); allow only TLS 1.2 and 1.3.")
    if protocols.get("TLSv1.3") == "no":
        res.add("tls.no13", "TLS 1.3 is not supported", Severity.LOW, "TLS",
                recommendation="Enable TLS 1.3 for better security and performance.")
    for label, _, sev in WEAK_CIPHER_GROUPS:
        state = weak.get(label, "")
        if state.startswith("yes"):
            res.add("tls.cipher." + label.split()[0].lower(), f"Weak cipher class accepted: {label}", sev, "TLS",
                    evidence=state.split(":", 1)[1],
                    recommendation="Restrict to AEAD suites with ECDHE (e.g. Mozilla 'intermediate' profile).")
    if res.data.get("alpn") != "h2":
        res.add("tls.no-h2", "HTTP/2 not offered via ALPN", Severity.INFO, "TLS")

"""TLS certificate handling.

Modes:
  self-signed (default): NetWatch creates its own certificate in /data/tls and
                         reuses it. It is regenerated only when it nears expiry
                         or the host's names/IPs change.
  custom:                use TLS_CERT_FILE / TLS_KEY_FILE (e.g. from your own CA
                         or Let's Encrypt).
  off:                   plain HTTP.
"""
import datetime
import ipaddress
import logging
import os
import socket

log = logging.getLogger("netwatch.tls")
CERT_NAME, KEY_NAME = "netwatch.crt", "netwatch.key"
VALID_DAYS = 825
RENEW_BEFORE_DAYS = 30


def local_names(extra=()):
    """Hostnames and IPs this host is reached by, plus TLS_HOSTNAMES."""
    names, ips = {"localhost"}, {"127.0.0.1"}
    host = socket.gethostname()
    if host:
        names.add(host.lower())
    try:  # primary LAN address (no packets are sent)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            ips.add(s.getsockname()[0])
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(host, None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    for item in extra:
        item = item.strip().lower()
        if not item:
            continue
        try:
            ips.add(str(ipaddress.ip_address(item)))
        except ValueError:
            names.add(item)
    return sorted(names), sorted(ips)


def ensure_self_signed(directory, extra_names=()):
    """Return (cert_path, key_path), creating/renewing the certificate if needed."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    os.makedirs(directory, mode=0o700, exist_ok=True)
    cert_path, key_path = os.path.join(directory, CERT_NAME), os.path.join(directory, KEY_NAME)
    names, ips = local_names(extra_names)
    wanted = set(names) | set(ips)

    if os.path.exists(cert_path) and os.path.exists(key_path):
        try:
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            have = {n.lower() for n in san.get_values_for_type(x509.DNSName)} | \
                   {str(i) for i in san.get_values_for_type(x509.IPAddress)}
            remaining = cert.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)
            if wanted <= have and remaining.days > RENEW_BEFORE_DAYS:
                return cert_path, key_path
            log.info("Regenerating certificate (%s)",
                     "names/IPs changed" if not wanted <= have else "expiring soon")
        except Exception as e:
            log.warning("Existing certificate unreadable (%s); regenerating", e.__class__.__name__)

    key = ec.generate_private_key(ec.SECP256R1())
    host = (names[1] if len(names) > 1 else names[0]) if names else "netwatch"
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"NetWatch ({host})"[:64]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetWatch self-signed"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    san = [x509.DNSName(n) for n in names] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False,
                                     content_commitment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=False, crl_sign=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    tmp_key = key_path + ".tmp"
    with open(os.open(tmp_key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    os.replace(tmp_key, key_path)
    with open(cert_path + ".tmp", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    os.replace(cert_path + ".tmp", cert_path)
    log.info("Created self-signed certificate for %s", ", ".join(names + ips))
    return cert_path, key_path


def describe(cert_path):
    """Fingerprint and validity for display, so users can verify on first connect."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    fp = cert.fingerprint(hashes.SHA256()).hex().upper()
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = san.get_values_for_type(x509.DNSName) + [str(i) for i in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        names = []
    return {
        "sha256": ":".join(fp[i:i + 2] for i in range(0, len(fp), 2)),
        "expires": cert.not_valid_after_utc.timestamp(),
        "names": names,
        "issuer": cert.issuer.rfc4514_string(),
    }

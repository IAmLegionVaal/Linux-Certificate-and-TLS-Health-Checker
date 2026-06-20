# Linux Certificate and TLS Health Checker

A read-only Bash toolkit for auditing local X.509 certificate files and testing remote TLS endpoints.

## Checks performed

- Certificate subject, issuer, serial number, validity dates, and fingerprints
- Expiry status and configurable warning thresholds
- Subject Alternative Names and Extended Key Usage
- PEM and DER certificate parsing
- Local certificate file permissions and ownership
- Remote TLS handshake, negotiated protocol, cipher, certificate chain, and verification result
- Optional tests for TLS 1.2 and TLS 1.3 support
- Text, CSV, and JSON reports

## Usage

Audit common local certificate locations:

```bash
chmod +x src/certificate_tls_health.sh
sudo ./src/certificate_tls_health.sh
```

Audit a specific path and remote endpoint:

```bash
sudo ./src/certificate_tls_health.sh --path /etc/nginx/certs --host example.com --port 443 --warn-days 30
```

## Safety

The script does not modify trust stores, certificates, keys, permissions, services, or TLS configuration. Private-key contents are never displayed or copied.

## Privacy

Certificate subjects, internal names, IP addresses, and endpoint details may be sensitive. Review reports before sharing.

## Requirements

- Bash 4+
- OpenSSL
- GNU `find`, `stat`, and `date`

## Author

Dewald Pretorius — L2 IT Support Engineer

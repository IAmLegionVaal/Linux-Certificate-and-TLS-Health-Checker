# Linux Certificate and TLS Health Checker

A Linux support toolkit for auditing certificate and TLS health and applying selected guarded repairs.

## Diagnostic script

```bash
chmod +x src/certificate_tls_health.sh
sudo ./src/certificate_tls_health.sh --path /etc/nginx/certs --host example.com --port 443
```

## Repair script

```bash
chmod +x src/certificate_tls_repair.sh
sudo ./src/certificate_tls_repair.sh --fix-permissions /etc/nginx/certs --dry-run
```

Supported repairs include:

```bash
sudo ./src/certificate_tls_repair.sh --fix-permissions /etc/nginx/certs
sudo ./src/certificate_tls_repair.sh --install-ca ./company-root.pem
sudo ./src/certificate_tls_repair.sh --renew-certbot example.com
sudo ./src/certificate_tls_repair.sh --restart-service nginx.service
```

## What the repair does

- Corrects standard certificate and private-key modes below one selected directory.
- Installs one validated PEM CA certificate into a supported Debian- or RHEL-style trust store.
- Renews one selected Certbot certificate name.
- Restarts and verifies one selected TLS-using systemd service.
- Captures post-repair certificate, permission and service evidence.
- Supports dry-run, confirmation prompts, logs and clear exit codes.

## Safety

The tool never displays or copies private-key contents. Trust-store installation, certificate renewal and service restart are explicit actions. Review service configuration and certificate identity before applying changes.

## Author

Dewald Pretorius — L2 IT Support Engineer

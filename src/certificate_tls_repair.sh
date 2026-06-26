#!/usr/bin/env bash
set -u

FIX_PATH=""
INSTALL_CA=""
RESTART_SERVICE=""
RENEW_CERTBOT=false
CERTBOT_NAME=""
DRY_RUN=false
ASSUME_YES=false
OUTPUT_DIR=""
FAILURES=0
ACTIONS=0

usage() {
  cat <<'EOF'
Usage: certificate_tls_repair.sh [options]

  --fix-permissions PATH     Correct certificate/key ownership and standard modes below PATH.
  --install-ca CERT          Install one PEM CA certificate into the system trust store.
  --restart-service UNIT     Restart and verify one TLS-using systemd service.
  --renew-certbot NAME       Renew one Certbot certificate name.
  --dry-run                  Show commands without changing the system.
  --yes                      Skip confirmation prompts.
  --output DIR               Save logs, backups and verification output in DIR.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --fix-permissions) FIX_PATH="${2:-}"; shift 2 ;;
    --install-ca) INSTALL_CA="${2:-}"; shift 2 ;;
    --restart-service) RESTART_SERVICE="${2:-}"; shift 2 ;;
    --renew-certbot) RENEW_CERTBOT=true; CERTBOT_NAME="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    --yes) ASSUME_YES=true; shift ;;
    --output) OUTPUT_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [ -z "$FIX_PATH" ] && [ -z "$INSTALL_CA" ] && [ -z "$RESTART_SERVICE" ] && ! $RENEW_CERTBOT; then echo "Choose at least one repair action." >&2; exit 2; fi
[ -z "$FIX_PATH" ] || [ -d "$FIX_PATH" ] || { echo "Directory not found: $FIX_PATH" >&2; exit 2; }
[ -z "$INSTALL_CA" ] || [ -f "$INSTALL_CA" ] || { echo "Certificate not found: $INSTALL_CA" >&2; exit 2; }
if [ -n "$RESTART_SERVICE" ]; then systemctl cat "$RESTART_SERVICE" >/dev/null 2>&1 || { echo "Unit not found: $RESTART_SERVICE" >&2; exit 2; }; fi
if $RENEW_CERTBOT; then command -v certbot >/dev/null 2>&1 || { echo "certbot is required." >&2; exit 3; }; [ -n "$CERTBOT_NAME" ] || { echo "Certificate name is required." >&2; exit 2; }; fi
command -v openssl >/dev/null 2>&1 || { echo "OpenSSL is required." >&2; exit 3; }

STAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="${OUTPUT_DIR:-./certificate-repair-$STAMP}"
BACKUP_DIR="$OUTPUT_DIR/backup"
mkdir -p "$OUTPUT_DIR" "$BACKUP_DIR"
LOG="$OUTPUT_DIR/repair.log"
VERIFY="$OUTPUT_DIR/verification.txt"
: > "$LOG"

log(){ printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$LOG"; }
confirm(){ $ASSUME_YES && return 0; read -r -p "$1 [y/N]: " answer; case "$answer" in y|Y|yes|YES) return 0;; *) return 1;; esac; }
run_action(){ local d="$1"; shift; ACTIONS=$((ACTIONS+1)); log "$d"; if $DRY_RUN; then
    { printf 'DRY-RUN:'; printf ' %q' "$@"; printf '\n'; } >>"$LOG"
    return 0
  fi; if "$@" >>"$LOG" 2>&1; then log "SUCCESS: $d"; else FAILURES=$((FAILURES+1)); log "WARNING: $d failed"; return 1; fi; }
run_root(){ local d="$1"; shift; if [ "$(id -u)" -eq 0 ]; then run_action "$d" "$@"; else run_action "$d" sudo "$@"; fi; }
verify(){ { echo "Collected: $(date -Is)"; [ -n "$FIX_PATH" ] && find "$FIX_PATH" -maxdepth 2 -type f \( -name '*.crt' -o -name '*.pem' -o -name '*.key' \) -printf '%m %u:%g %p\n' 2>/dev/null; [ -n "$INSTALL_CA" ] && openssl x509 -in "$INSTALL_CA" -noout -subject -issuer -dates -fingerprint -sha256 2>&1; [ -n "$RESTART_SERVICE" ] && systemctl status "$RESTART_SERVICE" --no-pager -l 2>&1; $RENEW_CERTBOT && certbot certificates 2>&1; } >"$VERIFY"; }

verify
confirm "Apply the selected certificate and TLS repairs?" || { log "Repair cancelled."; exit 10; }

if [ -n "$FIX_PATH" ]; then
  while IFS= read -r file; do
    case "$file" in *.key) run_root "Securing private key $file" chmod 600 "$file" || true ;; *.crt|*.pem) run_root "Setting certificate mode on $file" chmod 644 "$file" || true ;; esac
    run_root "Setting root ownership on $file" chown root:root "$file" || true
  done < <(find "$FIX_PATH" -xdev -type f \( -name '*.crt' -o -name '*.pem' -o -name '*.key' \) -print 2>/dev/null)
fi

if [ -n "$INSTALL_CA" ]; then
  openssl x509 -in "$INSTALL_CA" -noout >/dev/null 2>&1 || { log "Certificate parsing failed."; exit 20; }
  NAME=$(basename "$INSTALL_CA"); NAME="${NAME%.*}.crt"
  if [ -d /usr/local/share/ca-certificates ] && command -v update-ca-certificates >/dev/null 2>&1; then
    run_root "Installing CA certificate" install -o root -g root -m 644 "$INSTALL_CA" "/usr/local/share/ca-certificates/$NAME" || true
    run_root "Updating CA trust" update-ca-certificates || true
  elif [ -d /etc/pki/ca-trust/source/anchors ] && command -v update-ca-trust >/dev/null 2>&1; then
    run_root "Installing CA certificate" install -o root -g root -m 644 "$INSTALL_CA" "/etc/pki/ca-trust/source/anchors/$NAME" || true
    run_root "Updating CA trust" update-ca-trust extract || true
  else
    FAILURES=$((FAILURES+1)); log "WARNING: supported trust-store updater not found."
  fi
fi

if $RENEW_CERTBOT; then run_root "Renewing Certbot certificate $CERTBOT_NAME" certbot renew --cert-name "$CERTBOT_NAME" || true; fi
if [ -n "$RESTART_SERVICE" ]; then run_root "Restarting $RESTART_SERVICE" systemctl restart "$RESTART_SERVICE" || true; fi
$DRY_RUN || sleep 2
verify
if [ -n "$RESTART_SERVICE" ]; then systemctl is-active --quiet "$RESTART_SERVICE" || { FAILURES=$((FAILURES+1)); log "WARNING: service is not active."; }; fi
[ "$FAILURES" -eq 0 ] || exit 20
log "Repair completed successfully. Actions performed: $ACTIONS"

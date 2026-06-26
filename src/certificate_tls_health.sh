#!/usr/bin/env bash
set -u

TARGET_PATH=""
HOST=""
PORT=443
WARN_DAYS=30
OUTPUT_DIR=""

usage() {
  echo "Usage: certificate_tls_health.sh [--path DIR_OR_FILE] [--host HOST] [--port N] [--warn-days N] [--output DIR]"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --path) TARGET_PATH="${2:-}"; shift 2 ;;
    --host) HOST="${2:-}"; shift 2 ;;
    --port) PORT="${2:-443}"; shift 2 ;;
    --warn-days) WARN_DAYS="${2:-30}"; shift 2 ;;
    --output) OUTPUT_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

[[ "$PORT" =~ ^[0-9]+$ ]] || { echo "--port must be numeric" >&2; exit 2; }
[[ "$WARN_DAYS" =~ ^[0-9]+$ ]] || { echo "--warn-days must be numeric" >&2; exit 2; }
command -v openssl >/dev/null 2>&1 || { echo "OpenSSL is required." >&2; exit 1; }

STAMP="$(date +%Y%m%d_%H%M%S)"
OUTPUT_DIR="${OUTPUT_DIR:-./certificate-health-$STAMP}"
mkdir -p "$OUTPUT_DIR"
REPORT="$OUTPUT_DIR/certificate-health.txt"
CSV="$OUTPUT_DIR/certificates.csv"
JSON="$OUTPUT_DIR/summary.json"
ERRORS="$OUTPUT_DIR/command-errors.log"
REMOTE_CERT="$OUTPUT_DIR/remote-leaf-certificate.pem"
: > "$REPORT"
: > "$ERRORS"
echo 'source,subject,issuer,serial,not_before,not_after,days_remaining,sha256_fingerprint,owner,mode,status' > "$CSV"

section() {
  local title="$1"
  shift
  {
    printf '\n===== %s =====\n' "$title"
    "$@"
  } >> "$REPORT" 2>> "$ERRORS" || true
}

csv_escape() {
  local value="$1"
  value="${value//\"/\"\"}"
  printf '"%s"' "$value"
}

parse_certificate() {
  local cert="$1"
  local source_label="$2"
  local inform="PEM"
  local subject issuer serial not_before not_after fingerprint expiry_epoch now_epoch days owner mode status

  if ! openssl x509 -in "$cert" -noout >/dev/null 2>>"$ERRORS"; then
    if openssl x509 -inform DER -in "$cert" -noout >/dev/null 2>>"$ERRORS"; then
      inform="DER"
    else
      return 1
    fi
  fi

  subject="$(openssl x509 -inform "$inform" -in "$cert" -noout -subject -nameopt RFC2253 2>>"$ERRORS" | sed 's/^subject=//')"
  issuer="$(openssl x509 -inform "$inform" -in "$cert" -noout -issuer -nameopt RFC2253 2>>"$ERRORS" | sed 's/^issuer=//')"
  serial="$(openssl x509 -inform "$inform" -in "$cert" -noout -serial 2>>"$ERRORS" | sed 's/^serial=//')"
  not_before="$(openssl x509 -inform "$inform" -in "$cert" -noout -startdate 2>>"$ERRORS" | sed 's/^notBefore=//')"
  not_after="$(openssl x509 -inform "$inform" -in "$cert" -noout -enddate 2>>"$ERRORS" | sed 's/^notAfter=//')"
  fingerprint="$(openssl x509 -inform "$inform" -in "$cert" -noout -fingerprint -sha256 2>>"$ERRORS" | sed 's/^sha256 Fingerprint=//')"
  expiry_epoch="$(date -d "$not_after" +%s 2>>"$ERRORS" || echo 0)"
  now_epoch="$(date +%s)"
  days=$(( (expiry_epoch - now_epoch) / 86400 ))

  owner="unknown"
  mode="unknown"
  if [[ -e "$cert" ]]; then
    owner="$(stat -c '%U:%G' "$cert" 2>>"$ERRORS" || echo unknown)"
    mode="$(stat -c '%a' "$cert" 2>>"$ERRORS" || echo unknown)"
  fi

  status="OK"
  if [[ "$days" -lt 0 ]]; then
    status="EXPIRED"
  elif [[ "$days" -le "$WARN_DAYS" ]]; then
    status="EXPIRING_SOON"
  fi

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(csv_escape "$source_label")" \
    "$(csv_escape "$subject")" \
    "$(csv_escape "$issuer")" \
    "$(csv_escape "$serial")" \
    "$(csv_escape "$not_before")" \
    "$(csv_escape "$not_after")" \
    "$days" \
    "$(csv_escape "$fingerprint")" \
    "$(csv_escape "$owner")" \
    "$(csv_escape "$mode")" \
    "$(csv_escape "$status")" >> "$CSV"

  {
    printf '\n--- Certificate: %s ---\n' "$source_label"
    openssl x509 -inform "$inform" -in "$cert" -noout -subject -issuer -serial -dates -fingerprint -sha256 -ext subjectAltName -ext extendedKeyUsage 2>/dev/null || true
    printf 'Days remaining: %s\nStatus: %s\nOwner: %s\nMode: %s\n' "$days" "$status" "$owner" "$mode"
  } >> "$REPORT"
}

section "Collection metadata" bash -c 'date -Is; hostname -f 2>/dev/null || hostname; openssl version -a'

SCAN_TARGETS=()
if [[ -n "$TARGET_PATH" ]]; then
  SCAN_TARGETS+=("$TARGET_PATH")
else
  for path in /etc/ssl/certs /etc/pki/tls/certs /usr/local/share/ca-certificates; do
    [[ -e "$path" ]] && SCAN_TARGETS+=("$path")
  done
fi

LOCAL_SCANNED=0
for target in "${SCAN_TARGETS[@]}"; do
  if [[ -f "$target" ]]; then
    if parse_certificate "$target" "$target"; then
      LOCAL_SCANNED=$((LOCAL_SCANNED + 1))
    fi
  elif [[ -d "$target" ]]; then
    while IFS= read -r cert; do
      if parse_certificate "$cert" "$cert"; then
        LOCAL_SCANNED=$((LOCAL_SCANNED + 1))
      fi
      [[ "$LOCAL_SCANNED" -ge 500 ]] && break
    done < <(find "$target" -type f \( -iname '*.pem' -o -iname '*.crt' -o -iname '*.cer' -o -iname '*.der' \) -print 2>>"$ERRORS")
  fi
  [[ "$LOCAL_SCANNED" -ge 500 ]] && break
done

REMOTE_TESTED=false
REMOTE_HANDSHAKE=false
TLS12=false
TLS13=false
VERIFY_CODE="not-tested"

if [[ -n "$HOST" ]]; then
  REMOTE_TESTED=true
  SNI="$HOST"
  CONNECT_TARGET="$HOST:$PORT"

  {
    printf '\n===== Remote TLS endpoint: %s =====\n' "$CONNECT_TARGET"
    timeout 15 openssl s_client -connect "$CONNECT_TARGET" -servername "$SNI" -showcerts -verify_return_error </dev/null
  } >> "$REPORT" 2>> "$ERRORS" || true

  if timeout 15 openssl s_client -connect "$CONNECT_TARGET" -servername "$SNI" </dev/null > "$OUTPUT_DIR/remote-handshake.txt" 2>>"$ERRORS"; then
    REMOTE_HANDSHAKE=true
  fi

  awk '/-----BEGIN CERTIFICATE-----/{capture=1} capture{print} /-----END CERTIFICATE-----/{exit}' "$OUTPUT_DIR/remote-handshake.txt" > "$REMOTE_CERT"
  if [[ -s "$REMOTE_CERT" ]]; then
    parse_certificate "$REMOTE_CERT" "$CONNECT_TARGET"
  fi

  if timeout 10 openssl s_client -tls1_2 -connect "$CONNECT_TARGET" -servername "$SNI" </dev/null 2>/dev/null | grep -q 'Protocol.*TLSv1.2'; then
    TLS12=true
  fi
  if timeout 10 openssl s_client -tls1_3 -connect "$CONNECT_TARGET" -servername "$SNI" </dev/null 2>/dev/null | grep -q 'Protocol.*TLSv1.3'; then
    TLS13=true
  fi

  VERIFY_CODE="$(grep -E 'Verify return code:' "$OUTPUT_DIR/remote-handshake.txt" | tail -n1 | sed 's/^[[:space:]]*//' || true)"
fi

EXPIRED="$(awk -F, 'NR>1 && $11 ~ /EXPIRED/ {c++} END {print c+0}' "$CSV")"
EXPIRING="$(awk -F, 'NR>1 && $11 ~ /EXPIRING_SOON/ {c++} END {print c+0}' "$CSV")"
TOTAL="$(awk 'END {print NR-1}' "$CSV")"
OVERALL="Healthy"
if [[ "$EXPIRED" -gt 0 || "$EXPIRING" -gt 0 ]] || { $REMOTE_TESTED && ! $REMOTE_HANDSHAKE; }; then
  OVERALL="Attention required"
fi

VERIFY_JSON="${VERIFY_CODE//\\/\\\\}"
VERIFY_JSON="${VERIFY_JSON//\"/\\\"}"

cat > "$JSON" <<EOF
{
  "collected_at": "$(date -Is)",
  "hostname": "$(hostname -f 2>/dev/null || hostname)",
  "warning_threshold_days": $WARN_DAYS,
  "certificates_parsed": $TOTAL,
  "expired_certificates": $EXPIRED,
  "certificates_expiring_soon": $EXPIRING,
  "remote_host": "$HOST",
  "remote_port": $PORT,
  "remote_handshake_successful": $REMOTE_HANDSHAKE,
  "tls_1_2_supported": $TLS12,
  "tls_1_3_supported": $TLS13,
  "verification_result": "$VERIFY_JSON",
  "overall_status": "$OVERALL"
}
EOF

printf '\nCertificate and TLS health collection completed: %s\n' "$OUTPUT_DIR" | tee -a "$REPORT"

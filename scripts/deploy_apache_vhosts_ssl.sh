#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# deploy_apache_vhosts_ssl.sh
# -----------------------------------------------------------------------------
# Purpose:
#   One-shot, idempotent-ish setup of Apache on Ubuntu/Debian with multiple
#   name-based vhosts and self-signed TLS (per-site certificates).
#
# What it does:
#   1) Installs Apache + OpenSSL
#   2) Enables required Apache modules (ssl, rewrite, headers)
#   3) Creates document roots for each site you pass as an argument
#   4) Generates a self-signed cert for each site with SAN support
#   5) Creates an Apache vhost that redirects HTTP->HTTPS and serves HTTPS
#   6) Disables the default site and reloads Apache
#   7) Prints test instructions (curl/hosts-file) and helpful tips
#
# Usage:
#   sudo bash deploy_apache_vhosts_ssl.sh example1.local example2.local
#
# Notes:
#   - This script targets Ubuntu/Debian on EC2. For Amazon Linux, paths/packages
#     differ (httpd instead of apache2). See the README section at the bottom.
#   - You must point your chosen hostnames to the EC2 public IP (via your
#     laptop's /etc/hosts or --resolve in curl) for vhost routing + SNI.
# -----------------------------------------------------------------------------
set -euo pipefail

# ----------------------------- Helper functions -------------------------------
log() { echo -e "\033[1;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
err() { echo -e "\033[1;31m[✗]\033[0m $*"; }

need_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    err "Please run as root (use sudo)."
    exit 1
  fi
}

# Try to fetch EC2 public IP for tips at the end (best effort)
get_public_ip() {
  local token
  local ip=""
  if command -v curl >/dev/null 2>&1; then
    token=$(curl -s -m 1 -X PUT "http://169.254.169.254/latest/api/token" \
      -H "X-aws-ec2-metadata-token-ttl-seconds: 60" || true)
    if [[ -n "${token}" ]]; then
      ip=$(curl -s -m 1 -H "X-aws-ec2-metadata-token: ${token}" \
        http://169.254.169.254/latest/meta-data/public-ipv4 || true)
    fi
    if [[ -z "${ip}" ]]; then
      ip=$(curl -s -m 2 http://checkip.amazonaws.com 2>/dev/null || true)
    fi
    ip=${ip//$'\n'/}
  fi
  echo "$ip"
}

# ------------------------------- Pre-flight ----------------------------------
need_root

if [[ $# -lt 1 ]]; then
  cat >&2 <<USAGE
Usage: sudo bash $0 <site1> [site2 site3 ...]

Example:
  sudo bash $0 vhost1.local vhost2.local

Tip: later, add to your laptop's /etc/hosts:
  <EC2_PUBLIC_IP> vhost1.local vhost2.local
USAGE
  exit 1
fi

# Validate site names (very loose check; allow dots and hyphens)
for site in "$@"; do
  if [[ ! "$site" =~ ^[a-zA-Z0-9.-]+$ ]]; then
    err "Invalid site name: $site (use letters, numbers, dots, hyphens)"
    exit 1
  fi
done

# Detect Debian/Ubuntu
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
else
  err "/etc/os-release not found; unsupported OS."
  exit 1
fi

case "${ID_LIKE:-}${ID:-}" in
  *debian*|*ubuntu*|*Ubuntu*|*Debian*)
    PKG_INSTALL="apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 openssl"
    APACHE_SERVICE="apache2"
    APACHE_CTL="apache2ctl"
    SITES_AVAILABLE="/etc/apache2/sites-available"
    SITES_ENABLED="/etc/apache2/sites-enabled"
    APACHE_LOG_DIR="\${APACHE_LOG_DIR:-/var/log/apache2}"
    ENABLE_SSL_MOD="a2enmod ssl"
    ENABLE_HDR_MOD="a2enmod headers"
    ENABLE_RW_MOD="a2enmod rewrite"
    ENABLE_SITE_CMD="a2ensite"
    DISABLE_SITE_CMD="a2dissite"
    ;;
  *)
    err "This script currently supports Ubuntu/Debian. Detected: ${ID:-unknown}"
    exit 1
    ;;
esac

# ------------------------------- Installation --------------------------------
log "Installing Apache + OpenSSL..."
eval "$PKG_INSTALL"

log "Enabling Apache modules (ssl, headers, rewrite)..."
$ENABLE_SSL_MOD >/dev/null || true
$ENABLE_HDR_MOD >/dev/null || true
$ENABLE_RW_MOD  >/dev/null || true

# ----------------------------- Per-site setup --------------------------------
for SITE in "$@"; do
  log "Configuring site: $SITE"

  DOCROOT="/var/www/$SITE/public_html"
  SSLDIR="/etc/ssl/$SITE"
  CONF_FILE="$SITES_AVAILABLE/$SITE.conf"

  # 1) Document root
  if [[ ! -d "$DOCROOT" ]]; then
    log "Creating docroot at $DOCROOT"
    mkdir -p "$DOCROOT"
    cat > "$DOCROOT/index.html" <<HTML
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>$SITE — It works (HTTPS)!</title>
  </head>
  <body>
    <h1>$SITE</h1>
    <p>If you see this over <strong>https://$SITE</strong>, your vhost + SSL is live.</p>
  </body>
</html>
HTML
  fi
  chown -R www-data:www-data "/var/www/$SITE"
  chmod -R 755 "/var/www/$SITE"

  # 2) Self-signed cert with SAN
  if [[ ! -f "$SSLDIR/cert.pem" || ! -f "$SSLDIR/key.pem" ]]; then
    log "Generating self-signed cert for $SITE (398 days)..."
    mkdir -p "$SSLDIR"
    # OpenSSL 1.1.1+ supports -addext for SANs
    openssl req -x509 -newkey rsa:2048 -sha256 -days 398 -nodes \
      -keyout "$SSLDIR/key.pem" \
      -out "$SSLDIR/cert.pem" \
      -subj "/CN=$SITE" \
      -addext "subjectAltName=DNS:$SITE" >/dev/null 2>&1
    chmod 600 "$SSLDIR/key.pem"
  else
    warn "Certificate already exists for $SITE, keeping existing files."
  fi

  # 3) Apache vhost (HTTP -> HTTPS redirect + HTTPS server)
  log "Writing vhost config: $CONF_FILE"
  cat > "$CONF_FILE" <<APACHECONF
# Auto-generated by deploy_apache_vhosts_ssl.sh for $SITE

# 80: redirect all traffic to HTTPS
<VirtualHost *:80>
    ServerName $SITE
    ServerAdmin admin@$SITE
    DocumentRoot $DOCROOT
    ErrorLog \${APACHE_LOG_DIR}/$SITE-error.log
    CustomLog \${APACHE_LOG_DIR}/$SITE-access.log combined

    # Redirect HTTP to HTTPS
    RewriteEngine On
    RewriteCond %{HTTPS} !=on
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
</VirtualHost>

# 443: serve the site with TLS
<VirtualHost *:443>
    ServerName $SITE
    ServerAdmin admin@$SITE
    DocumentRoot $DOCROOT

    ErrorLog \${APACHE_LOG_DIR}/$SITE-ssl-error.log
    CustomLog \${APACHE_LOG_DIR}/$SITE-ssl-access.log combined

    SSLEngine on
    SSLCertificateFile $SSLDIR/cert.pem
    SSLCertificateKeyFile $SSLDIR/key.pem

    <Directory $DOCROOT>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    # Helpful security headers (tweak as needed)
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    # Caution: HSTS can lock clients to HTTPS; avoid for self-signed testing
    # Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</VirtualHost>
APACHECONF

  # 4) Enable the site
  $ENABLE_SITE_CMD "$(basename "$CONF_FILE")" >/dev/null || true

done

# 5) Disable Apache default site to prevent ambiguity
$DISABLE_SITE_CMD 000-default >/dev/null || true

# 6) Test config + reload
log "Testing Apache config..."
if ! $APACHE_CTL configtest; then
  err "Apache config test failed. Fix issues and re-run."
  exit 1
fi

log "Reloading Apache..."
systemctl enable --now "$APACHE_SERVICE" >/dev/null
systemctl reload "$APACHE_SERVICE"

# ------------------------------- Post-run tips --------------------------------
IP=$(get_public_ip)

cat <<TIP

Done. ${#@} site(s) configured.

Next steps (from your laptop):
  1) Point the names to your EC2 public IP so vhosts + SNI work.
     - Edit /etc/hosts (Linux/macOS) or C:\\Windows\\System32\\drivers\\etc\\hosts (Windows)
     - Add a line like:
         $([[ -n "$IP" ]] && echo "$IP" || echo "<EC2_PUBLIC_IP>") $*

  2) Visit https://<yoursite> in a browser and accept the self-signed warning.

  3) Or use curl without editing hosts (uses SNI + Host header):
       curl -k --resolve ${1}:443:${IP:-<EC2_PUBLIC_IP>} https://${1}/

Useful Apache commands:
  sudo $APACHE_CTL -t             # test config
  sudo systemctl reload $APACHE_SERVICE  # reload config without dropping connections
  sudo $ENABLE_SITE_CMD <site>.conf && sudo systemctl reload $APACHE_SERVICE
  sudo $DISABLE_SITE_CMD <site>.conf && sudo systemctl reload $APACHE_SERVICE

Logs per site:
  $APACHE_LOG_DIR/<site>-access.log
  $APACHE_LOG_DIR/<site>-error.log

TIP

# ------------------------------ Mini README ----------------------------------
: <<'README'

Q: Why self-signed *per site*?
A: Browsers require SAN (Subject Alternative Name) matching the hostname.
   When your client connects using a hostname (via /etc/hosts or --resolve),
   SNI (Server Name Indication) lets Apache choose the right cert/vhost.

Q: Why disable HSTS in tests?
A: With self-signed certs, HSTS can "pin" HTTPS and cause scary errors
   until the HSTS cache expires. Enable HSTS only after a trusted cert.

Q: Where are the certs/keys?
A: /etc/ssl/<site>/cert.pem and key.pem (chmod 600 for the key).

Q: How do I add a new site later?
A: Re-run the script with the new name. It will create the docroot, cert,
   and vhost, then enable it and reload Apache.

Q: What about UFW / Security Groups?
A: On EC2, open ports 80 and 443 in your instance's Security Group.
   UFW is optional; if you use it: allow 'Apache Full'.

Q: How would this differ on Amazon Linux (httpd)?
A: Packages and paths change (httpd, /etc/httpd/conf.d). If you need that,
   clone this script and adjust variables for yum/dnf + httpd.

README

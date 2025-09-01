# Apache Vhost + SSL Deployer (Self-Signed)

This project provides a Bash script to **automatically set up Apache with multiple vhosts and self-signed SSL certificates**.  
Useful for testing/dev environments when you don’t own a real domain.

---

## 🚀 Features
- Installs Apache + OpenSSL (Ubuntu/Debian)
- Enables required Apache modules (`ssl`, `rewrite`, `headers`)
- Creates per-site docroots under `/var/www/<site>/public_html/`
- Generates **self-signed SSL certificates with SAN** for each site
- Sets up vhosts:
  - Port 80 → HTTPS redirect
  - Port 443 → TLS with security headers
- Disables default Apache site, enables your custom sites
- Prints testing instructions (curl / hosts file setup)

---

## 📦 Usage

```bash
# Clone the repo
git clone https://github.com/SahilDx777/apache-vhost-ssl-deployer.git
cd apache-vhost-ssl-deployer

# Make the script executable
chmod +x deploy_apache_vhosts_ssl.sh

# Run with your desired site names, Make sure you provide the names after you select the script!
sudo ./deploy_apache_vhosts_ssl.sh vhost1.local vhost2.local


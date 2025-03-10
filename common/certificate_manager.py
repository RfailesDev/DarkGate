# proxy/certificate_manager.py
import ssl
import os
import logging
import subprocess
from datetime import datetime
import OpenSSL.crypto

logger = logging.getLogger(__name__)


class CertificateManager:
    def __init__(self, cert_dir="/certs", db_path="/data/certs.db"):
        self.cert_dir = cert_dir
        self.db_path = db_path
        os.makedirs(cert_dir, exist_ok=True)

    def create_ssl_context(self, domain, cert_path, key_path):
        """Create an SSL context for a domain."""
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            logger.error(f"Certificate files for {domain} not found")
            return None

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        try:
            context.load_cert_chain(cert_path, key_path)
            return context
        except Exception as e:
            logger.error(f"Error creating SSL context for {domain}: {e}")
            return None

    def get_certificate_info(self, cert_path):
        """Get information about a certificate."""
        if not os.path.exists(cert_path):
            logger.error(f"Certificate file not found: {cert_path}")
            return None

        try:
            with open(cert_path, 'r') as f:
                cert_data = f.read()

            cert = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, cert_data
            )

            # Extract info
            subject = cert.get_subject()
            issuer = cert.get_issuer()
            not_before = datetime.strptime(cert.get_notBefore().decode(), "%Y%m%d%H%M%SZ")
            not_after = datetime.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ")

            return {
                "subject": {
                    "CN": subject.CN,
                    "O": subject.O,
                },
                "issuer": {
                    "CN": issuer.CN,
                    "O": issuer.O,
                },
                "valid_from": not_before.isoformat(),
                "valid_until": not_after.isoformat(),
                "is_valid": datetime.now() > not_before and datetime.now() < not_after
            }
        except Exception as e:
            logger.error(f"Error getting certificate info: {e}")
            return None

    def request_letsencrypt_cert(self, domain, email):
        """Request a Let's Encrypt certificate for a domain."""
        domain_dir = os.path.join(self.cert_dir, domain)
        os.makedirs(domain_dir, exist_ok=True)

        try:
            # Using certbot for Let's Encrypt certificates
            cmd = [
                "certbot", "certonly", "--standalone",
                "-d", domain,
                "--email", email,
                "--agree-tos", "--non-interactive",
                "--cert-path", f"{domain_dir}/cert.pem",
                "--key-path", f"{domain_dir}/privkey.pem",
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                logger.error(f"Certbot error: {result.stderr}")
                return False

            logger.info(f"Certificate successfully obtained for {domain}")
            return True
        except Exception as e:
            logger.error(f"Error requesting Let's Encrypt certificate: {e}")
            return False

    def save_uploaded_cert(self, domain, cert_data, key_data):
        """Save an uploaded certificate."""
        domain_dir = os.path.join(self.cert_dir, domain)
        os.makedirs(domain_dir, exist_ok=True)

        cert_path = os.path.join(domain_dir, "cert.pem")
        key_path = os.path.join(domain_dir, "privkey.pem")

        try:
            # Validate certificate and private key
            cert = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, cert_data
            )
            key = OpenSSL.crypto.load_privatekey(
                OpenSSL.crypto.FILETYPE_PEM, key_data
            )

            # Check if the private key matches the certificate
            context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
            context.use_privatekey(key)
            context.use_certificate(cert)
            context.check_privatekey()

            # Save the files
            with open(cert_path, 'wb') as f:
                f.write(cert_data)

            with open(key_path, 'wb') as f:
                f.write(key_data)

            logger.info(f"Certificate and key saved for {domain}")
            return True
        except Exception as e:
            logger.error(f"Error saving certificate: {e}")
            return False

    def list_certificates(self):
        """List all certificates in the cert directory."""
        certificates = []

        if not os.path.exists(self.cert_dir):
            return certificates

        for domain in os.listdir(self.cert_dir):
            domain_dir = os.path.join(self.cert_dir, domain)
            cert_path = os.path.join(domain_dir, "cert.pem")

            if os.path.isfile(cert_path):
                cert_info = self.get_certificate_info(cert_path)
                if cert_info:
                    certificates.append({
                        "domain": domain,
                        "info": cert_info
                    })

        return certificates
# proxy/proxy_server.py
import asyncio
import ssl
import logging
import json
import os
from aiohttp import web, ClientSession, TCPConnector, ClientConnectorError, ServerTimeoutError
from urllib.parse import urljoin
import signal

# Исправленные импорты
from DarkGate.common.rule_manager import RuleManager
from DarkGate.common.certificate_manager import CertificateManager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DynamicProxy:
    def __init__(self, rule_manager, cert_manager):
        self.rule_manager = rule_manager
        self.cert_manager = cert_manager
        self.rules = {}  # Domain -> {port, https_mode}
        self.ssl_contexts = {}  # Domain -> SSL context

        # Initial rule loading
        self.rules = self.rule_manager.get_rules()

        # Load certificates
        self.load_certificates()

        # Create web application
        self.app = web.Application()
        self.app.add_routes([
            web.get('/{tail:.*}', self.handle_request),
            web.post('/{tail:.*}', self.handle_request),
            web.put('/{tail:.*}', self.handle_request),
            web.delete('/{tail:.*}', self.handle_request),
            web.patch('/{tail:.*}', self.handle_request),
            web.options('/{tail:.*}', self.handle_request),
            web.head('/{tail:.*}', self.handle_request),
        ])

        # Setup rule update listener
        self.setup_rule_listener()

        # Setup signal handlers
        self.setup_signal_handlers()

    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
        for s in signals:
            asyncio.get_event_loop().add_signal_handler(
                s, lambda s=s: asyncio.create_task(self.shutdown(s))
            )

    async def shutdown(self, signal):
        """Perform a graceful shutdown on receiving a signal."""
        logger.info(f"Received exit signal {signal.name}...")
        logger.info("Shutting down HTTP/HTTPS servers")
        asyncio.get_event_loop().stop()

    async def handle_request(self, request):
        """Handle an incoming HTTP/HTTPS request."""
        host = request.headers.get('Host')
        if not host:
            return web.Response(status=400, text="Missing Host header")

        # Extract domain (remove port if present)
        domain = host.split(':')[0]

        # Find matching rule
        rule = self.find_rule(domain)
        if not rule:
            return web.Response(status=404, text=f"No rule found for domain: {domain}")

        target_port = rule['port']
        https_mode = rule.get('https_mode', 'http')

        # Construct target URL
        protocol = "https" if https_mode == "https_proxy" else "http"
        target_url = f"{protocol}://localhost:{target_port}{request.path_qs}"

        # Forward the request
        try:
            return await self.forward_request(request, target_url, https_mode)
        except (ClientConnectorError, ServerTimeoutError, asyncio.TimeoutError) as e:
            logger.error(f"Error forwarding request to {target_url}: {type(e).__name__} - {e}")
            return web.Response(status=502, text=f"Proxy error: {type(e).__name__}")
        except Exception as e:
            logger.exception(f"Unexpected error forwarding request to {target_url}: {e}")
            return web.Response(status=500, text="Internal Proxy Error")

    def find_rule(self, domain):
        """Find the most specific matching rule for a domain."""
        # Direct match
        if domain in self.rules:
            return self.rules[domain]

        # Subdomain matching (from most specific to least)
        parts = domain.split('.')
        for i in range(1, len(parts)):
            wildcard_domain = f"*.{'.'.join(parts[i:])}"
            if wildcard_domain in self.rules:
                return self.rules[wildcard_domain]

        return None

    async def forward_request(self, request, target_url, https_mode):
        """Forward the request to the target URL."""
        # Copy all headers
        headers = {k: v for k, v in request.headers.items()}

        # Get request body if present
        body = await request.read() if request.can_read_body else None

        # Configure SSL verification based on the HTTPS mode
        ssl_verify = https_mode == "https_proxy"

        async with ClientSession(connector=TCPConnector(ssl=ssl_verify)) as session:
            method = request.method

            # Create appropriate request to target
            try:
                async with session.request(
                        method=method,
                        url=target_url,
                        headers=headers,
                        data=body,
                        allow_redirects=False,
                        timeout=30,  # Set a reasonable timeout
                ) as resp:
                    # Read response body
                    response_body = await resp.read()

                    # Create response with same status, headers, and body
                    response = web.Response(
                        status=resp.status,
                        body=response_body
                    )

                    # Copy response headers
                    for header, value in resp.headers.items():
                        response.headers[header] = value

                    return response
            except (ClientConnectorError, ServerTimeoutError, asyncio.TimeoutError) as e:
                logger.error(f"Error connecting to target {target_url}: {type(e).__name__} - {e}")
                raise  # Re-raise to be handled by handle_request
            except Exception as e:
                logger.exception(f"Unexpected error during request to {target_url}: {e}")
                raise

    def setup_rule_listener(self):
        """Setup listener for rule updates from admin panel."""
        asyncio.create_task(self._rule_listener())

    async def _rule_listener(self):
        """Listen for rule updates via a socket."""
        server = await asyncio.start_server(
            self._handle_rule_update, '0.0.0.0', 8899
        )

        logger.info("Rule update listener started on port 8899")

        async with server:
            await server.serve_forever()

    async def _handle_rule_update(self, reader, writer):
        """Handle incoming rule update."""
        data = await reader.read(10240)  # Allow for larger rule sets
        message = data.decode()

        client_addr = writer.get_extra_info('peername')
        logger.info(f"Received rule update from {client_addr}")

        try:
            # Expecting JSON data with updated rules
            updated_rules = json.loads(message)
            self.rules = updated_rules
            logger.info(f"Rules updated successfully: {len(self.rules)} rules")
            writer.write(b"Rules updated successfully")
        except Exception as e:
            logger.error(f"Error updating rules: {e}")
            writer.write(f"Error: {str(e)}".encode())

        await writer.drain()
        writer.close()
        await writer.wait_closed()

    def load_certificates(self):
        """Load SSL certificates for HTTPS support."""
        certificates = self.cert_manager.list_certificates()

        for cert in certificates:
            domain = cert['domain']
            cert_path = f"/certs/{domain}/cert.pem"
            key_path = f"/certs/{domain}/privkey.pem"

            # Create SSL context for this domain
            context = self.cert_manager.create_ssl_context(domain, cert_path, key_path)
            if context:
                self.ssl_contexts[domain] = context
                logger.info(f"Loaded certificate for {domain}")

    def get_ssl_context_for_domain(self, domain):
        """Get the SSL context for a specific domain."""
        # Direct match
        if domain in self.ssl_contexts:
            return self.ssl_contexts[domain]

        # Try wildcard certificates
        parts = domain.split('.')
        for i in range(1, len(parts)):
            wildcard_domain = f"*.{'.'.join(parts[i:])}"
            if wildcard_domain in self.ssl_contexts:
                return self.ssl_contexts[wildcard_domain]

        return None

    def create_sni_context(self):
        """Create an SSL context with SNI support."""
        # Create a default context
        default_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

        # Check if we have any certificates
        if not self.ssl_contexts:
            logger.warning("No SSL certificates available for HTTPS")
            return default_context

        # Use the first certificate as default
        first_domain = next(iter(self.ssl_contexts))
        default_context = self.ssl_contexts[first_domain]

        # Create an SNI callback
        def sni_callback(ssl_socket, server_name, ssl_context):
            if not server_name:
                return

            domain = server_name.decode('utf-8')
            context = self.get_ssl_context_for_domain(domain)

            if context:
                ssl_socket.context = context
            else:
                logger.warning(f"No SSL certificate for {domain}, using default")

        # Set the SNI callback
        default_context.set_servername_callback(sni_callback)

        return default_context

    async def start_server(self):
        """Start the HTTP and HTTPS servers."""
        # Start HTTP server
        runner_http = web.AppRunner(self.app)
        await runner_http.setup()
        site_http = web.TCPSite(runner_http, '0.0.0.0', 80)
        await site_http.start()
        logger.info("HTTP server started on port 80")

        # Start HTTPS server with SNI support
        sni_context = self.create_sni_context()

        runner_https = web.AppRunner(self.app)
        await runner_https.setup()
        site_https = web.TCPSite(runner_https, '0.0.0.0', 443, ssl_context=sni_context)
        await site_https.start()
        logger.info("HTTPS server started on port 443")
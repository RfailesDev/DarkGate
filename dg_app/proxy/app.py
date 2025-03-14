import asyncio
import logging

from dg_app.proxy.proxy_server import DynamicProxy  # Исправлено
from dg_app.common.rule_manager import RuleManager  # Исправлено
from dg_app.common.certificate_manager import CertificateManager  # Исправлено

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def main():
    rule_manager = RuleManager(db_path='/data/rules.db')
    cert_manager = CertificateManager(cert_dir='/certs')
    proxy = DynamicProxy(rule_manager, cert_manager)
    await proxy.start_server()
    while True:
        await asyncio.sleep(3600)

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down proxy server...")
    except Exception as e:
        logger.error(f"Error in main loop: {e}")

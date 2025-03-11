# proxy/app.py
import asyncio
import logging

# ИСПРАВЛЕННЫЕ ИМПОРТЫ (относительный импорт)
from .proxy_server import DynamicProxy  # . означает "в текущей директории"
from ..common.rule_manager import RuleManager
from ..common.certificate_manager import CertificateManager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def main():
    # Initialize components
    rule_manager = RuleManager(db_path='/data/rules.db')
    cert_manager = CertificateManager(cert_dir='/certs')

    # Initialize proxy with loaded rules
    proxy = DynamicProxy(rule_manager, cert_manager)

    # Start the proxy server
    await proxy.start_server()

    # Keep the server running
    while True:
        await asyncio.sleep(3600)


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down proxy server...")
    except Exception as e:
        logger.error(f"Error in main loop: {e}")
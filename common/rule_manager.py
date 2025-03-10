# proxy/rule_manager.py
import json
import logging
import asyncio
import sqlite3
from contextlib import closing

logger = logging.getLogger(__name__)


class RuleManager:
    def __init__(self, db_path="/data/rules.db"):
        self.db_path = db_path
        self.rules = {}  # In-memory rules
        self.init_db()
        self.load_rules_from_db()

    def init_db(self):
        """Initialize the database schema if it doesn't exist."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            with closing(conn.cursor()) as cursor:
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    target_port INTEGER NOT NULL,
                    https_mode TEXT DEFAULT 'http',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                conn.commit()

    def load_rules_from_db(self):
        """Load rules from database into memory."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            with closing(conn.cursor()) as cursor:
                cursor.execute('SELECT domain, target_port, https_mode FROM rules')
                rows = cursor.fetchall()

                # Clear current rules
                self.rules = {}

                # Load new rules
                for row in rows:
                    self.rules[row['domain']] = {
                        'port': row['target_port'],
                        'https_mode': row['https_mode']
                    }

                logger.info(f"Loaded {len(self.rules)} rules from database")
                return self.rules

    def get_rules(self):
        """Get all rules."""
        return self.rules

    def get_rule(self, domain):
        """Get a specific rule."""
        return self.rules.get(domain)

    async def notify_rule_change(self, host='127.0.0.1', port=8899):
        """Notify the proxy server of a rule change."""
        try:
            # Convert rules to JSON
            rules_json = json.dumps(self.rules)

            # Send to proxy server via socket
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(rules_json.encode())
            await writer.drain()

            # Wait for response
            data = await reader.read(100)
            response = data.decode()
            logger.info(f"Proxy server response: {response}")

            writer.close()
            await writer.wait_closed()
            return True
        except Exception as e:
            logger.error(f"Error notifying proxy of rule change: {e}")
            return False
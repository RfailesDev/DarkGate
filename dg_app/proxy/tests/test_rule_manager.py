# proxy/tests/test_rule_manager.py
import unittest
import os
import sqlite3
import tempfile
import sys

#sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))) # Устарело
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))) # Исправлено

from dg_app.common.rule_manager import RuleManager  # Исправлено


class TestRuleManager(unittest.TestCase):
    def setUp(self):
        # Create a temporary database file
        self.db_fd, self.db_path = tempfile.mkstemp()
        self.rule_manager = RuleManager(db_path=self.db_path)

    def tearDown(self):
        # Close the file and remove it
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_init_db(self):
        # Verify the database was initialized
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='rules'")
            table_exists = cursor.fetchone() is not None
            self.assertTrue(table_exists)

    def test_load_rules_from_db(self):
        # Add rules directly to the database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO rules (domain, target_port, https_mode) VALUES (?, ?, ?)',
                ('example.com', 8080, 'http')
            )
            cursor.execute(
                'INSERT INTO rules (domain, target_port, https_mode) VALUES (?, ?, ?)',
                ('*.example.org', 8081, 'https_terminate')
            )
            conn.commit()

        # Load rules from database
        rules = self.rule_manager.load_rules_from_db()

        # Verify rules were loaded correctly
        self.assertEqual(len(rules), 2)
        self.assertIn('example.com', rules)
        self.assertIn('*.example.org', rules)
        self.assertEqual(rules['example.com']['port'], 8080)
        self.assertEqual(rules['*.example.org']['https_mode'], 'https_terminate')

    def test_get_rules(self):
        # Add a rule directly to the database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO rules (domain, target_port, https_mode) VALUES (?, ?, ?)',
                ('example.com', 8080, 'http')
            )
            conn.commit()

        # Reload rules from database
        self.rule_manager.load_rules_from_db()

        # Get rules
        rules = self.rule_manager.get_rules()

        # Verify rules
        self.assertEqual(len(rules), 1)
        self.assertIn('example.com', rules)
        self.assertEqual(rules['example.com']['port'], 8080)

    def test_get_rule(self):
        # Add a rule directly to the in-memory dictionary
        self.rule_manager.rules = {
            'example.com': {'port': 8080, 'https_mode': 'http'}
        }

        # Get a specific rule
        rule = self.rule_manager.get_rule('example.com')

        # Verify rule
        self.assertIsNotNone(rule)
        self.assertEqual(rule['port'], 8080)
        self.assertEqual(rule['https_mode'], 'http')

        # Get a non-existent rule
        rule = self.rule_manager.get_rule('nonexistent.com')

        # Verify rule is None
        self.assertIsNone(rule)
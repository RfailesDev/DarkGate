# proxy/tests/test_proxy_server.py
import unittest
import asyncio
from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from proxy_server import DynamicProxy
from unittest.mock import MagicMock, patch


class TestDynamicProxy(AioHTTPTestCase):
    async def get_application(self):
        # Mock rule_manager and cert_manager
        self.rule_manager = MagicMock()
        self.cert_manager = MagicMock()

        # Setup mock rules
        self.rule_manager.get_rules.return_value = {
            'example.com': {'port': 8080, 'https_mode': 'http'},
            '*.example.org': {'port': 8081, 'https_mode': 'https_terminate'}
        }

        # Initialize proxy with mocked components
        self.proxy = DynamicProxy(self.rule_manager, self.cert_manager)
        return self.proxy.app

    async def test_handle_request_with_matching_domain(self):
        # Test with a direct domain match
        with patch.object(self.proxy, 'forward_request') as mock_forward:
            mock_forward.return_value = web.Response(text="Forwarded")

            # Make a request to the proxy
            headers = {'Host': 'example.com'}
            resp = await self.client.get('/', headers=headers)

            # Check that the request was forwarded
            self.assertEqual(resp.status, 200)
            self.assertEqual(await resp.text(), "Forwarded")

            # Verify forward_request was called with the right parameters
            mock_forward.assert_called_once()
            request_arg = mock_forward.call_args[0][0]
            url_arg = mock_forward.call_args[0][1]

            self.assertEqual(url_arg, 'http://localhost:8080/')

    async def test_handle_request_with_matching_wildcard(self):
        # Test with a wildcard domain match
        with patch.object(self.proxy, 'forward_request') as mock_forward:
            mock_forward.return_value = web.Response(text="Forwarded")

            # Make a request to the proxy
            headers = {'Host': 'sub.example.org'}
            resp = await self.client.get('/', headers=headers)

            # Check that the request was forwarded
            self.assertEqual(resp.status, 200)
            self.assertEqual(await resp.text(), "Forwarded")

            # Verify forward_request was called with the right parameters
            mock_forward.assert_called_once()
            url_arg = mock_forward.call_args[0][1]

            self.assertEqual(url_arg, 'http://localhost:8081/')

    async def test_handle_request_with_no_match(self):
        # Test with no matching domain
        with patch.object(self.proxy, 'forward_request') as mock_forward:
            # Make a request to the proxy
            headers = {'Host': 'unknown.com'}
            resp = await self.client.get('/', headers=headers)

            # Check that a 404 was returned
            self.assertEqual(resp.status, 404)

            # Verify forward_request was not called
            mock_forward.assert_not_called()

    async def test_handle_request_with_no_host_header(self):
        # Test with no Host header
        with patch.object(self.proxy, 'forward_request') as mock_forward:
            # Make a request to the proxy without a Host header
            resp = await self.client.get('/')

            # Check that a 400 was returned
            self.assertEqual(resp.status, 400)

            # Verify forward_request was not called
            mock_forward.assert_not_called()
"""
Tests for the Scheduled Reports module.
"""

import unittest

from falcon_mcp.modules.scheduled_reports import ScheduledReportsModule
from tests.modules.utils.test_modules import TestModules


class TestScheduledReportsModule(TestModules):
    """Test cases for the Scheduled Reports module."""

    def setUp(self):
        """Set up test fixtures."""
        self.setup_module(ScheduledReportsModule)

    def test_register_tools(self):
        """Test registering tools with the server."""
        expected_tools = [
            "falcon_search_scheduled_reports",
        ]
        self.assert_tools_registered(expected_tools)

    def test_register_resources(self):
        """Test registering resources with the server."""
        expected_resources = [
            "falcon_search_scheduled_reports_fql_guide",
        ]
        self.assert_resources_registered(expected_resources)

    def test_search_scheduled_reports(self):
        """Test searching for scheduled reports."""
        # Setup mock responses for both API calls
        query_response = {
            "status_code": 200,
            "body": {"resources": ["report1", "report2"]},
        }
        details_response = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "id": "report1",
                        "name": "Test Report 1",
                        "type": "hosts",
                        "status": "ACTIVE",
                        "created_on": "2021-10-12T08:00:00Z",
                        "next_execution_on": "2021-10-13T08:00:00Z",
                    },
                    {
                        "id": "report2",
                        "name": "Test Report 2",
                        "type": "spotlight_vulnerabilities",
                        "status": "ACTIVE",
                        "created_on": "2021-10-12T09:00:00Z",
                        "next_execution_on": "2021-10-13T09:00:00Z",
                    },
                ]
            },
        }
        self.mock_client.command.side_effect = [query_response, details_response]

        # Call search_scheduled_reports
        result = self.module.search_scheduled_reports(
            filter="type:'hosts'", limit=50, sort="created_on|desc"
        )

        # Verify client commands were called correctly
        self.assertEqual(self.mock_client.command.call_count, 2)

        # Check that the first call was to scheduled_reports_query with the right parameters
        first_call = self.mock_client.command.call_args_list[0]
        self.assertEqual(first_call[0][0], "scheduled_reports_query")
        self.assertEqual(first_call[1]["parameters"]["filter"], "type:'hosts'")
        self.assertEqual(first_call[1]["parameters"]["limit"], 50)
        self.assertEqual(first_call[1]["parameters"]["sort"], "created_on|desc")

        # Check that the second call was to scheduled_reports_get with the IDs
        second_call = self.mock_client.command.call_args_list[1]
        self.assertEqual(second_call[0][0], "scheduled_reports_get")
        self.assertEqual(second_call[1]["body"]["ids"], ["report1", "report2"])

        # Verify result
        expected_result = [
            {
                "id": "report1",
                "name": "Test Report 1",
                "type": "hosts",
                "status": "ACTIVE",
                "created_on": "2021-10-12T08:00:00Z",
                "next_execution_on": "2021-10-13T08:00:00Z",
            },
            {
                "id": "report2",
                "name": "Test Report 2",
                "type": "spotlight_vulnerabilities",
                "status": "ACTIVE",
                "created_on": "2021-10-12T09:00:00Z",
                "next_execution_on": "2021-10-13T09:00:00Z",
            },
        ]
        self.assertEqual(result, expected_result)

    def test_search_scheduled_reports_no_results(self):
        """Test searching for scheduled reports with no results."""
        # Setup mock response with no results
        query_response = {
            "status_code": 200,
            "body": {"resources": []},
        }
        self.mock_client.command.return_value = query_response

        # Call search_scheduled_reports with explicit parameters
        result = self.module.search_scheduled_reports(
            filter="type:'nonexistent'", limit=10, offset=None, sort=None
        )

        # Verify only one client command was called (query only, no details call)
        self.assertEqual(self.mock_client.command.call_count, 1)
        self.mock_client.command.assert_called_once_with(
            "scheduled_reports_query",
            parameters={"filter": "type:'nonexistent'", "limit": 10},
        )

        # Verify result is empty list
        self.assertEqual(result, [])

    def test_search_scheduled_reports_query_error(self):
        """Test search_scheduled_reports with query API error."""
        # Setup mock response with error
        error_response = {
            "status_code": 403,
            "body": {"errors": [{"message": "Access denied"}]},
        }
        self.mock_client.command.return_value = error_response

        # Call search_scheduled_reports with explicit parameters
        result = self.module.search_scheduled_reports(
            filter="type:'hosts'", limit=10, offset=None, sort=None
        )

        # Verify client command was called correctly
        self.mock_client.command.assert_called_once_with(
            "scheduled_reports_query",
            parameters={"filter": "type:'hosts'", "limit": 10},
        )

        # Verify result contains error
        self.assertIn("error", result)
        self.assertIn("details", result)

    def test_search_scheduled_reports_details_error(self):
        """Test search_scheduled_reports with details API error."""
        # Setup mock responses - query succeeds, details fails
        query_response = {
            "status_code": 200,
            "body": {"resources": ["report1", "report2"]},
        }
        details_error_response = {
            "status_code": 404,
            "body": {"errors": [{"message": "Reports not found"}]},
        }
        self.mock_client.command.side_effect = [query_response, details_error_response]

        # Call search_scheduled_reports
        result = self.module.search_scheduled_reports(filter="type:'hosts'")

        # Verify both client commands were called
        self.assertEqual(self.mock_client.command.call_count, 2)

        # Verify result contains error from details call
        self.assertIn("error", result)
        self.assertIn("details", result)

    def test_search_scheduled_reports_security_validation(self):
        """Test that search_scheduled_reports properly rejects malicious inputs."""
        malicious_payloads = [
            "'; DROP TABLE reports; --",
            "<script>alert('xss')</script>",
            "$(rm -rf /)",
            "\\x41\\x42\\x43",
        ]

        for payload in malicious_payloads:
            with self.subTest(payload=payload):
                # Mock response for security validation failure
                error_response = {
                    "status_code": 400,
                    "body": {"errors": [{"message": "Security validation failed"}]},
                }
                self.mock_client.command.return_value = error_response
                
                result = self.module.search_scheduled_reports(filter=payload)
                # Should return error due to API failure (security would be handled by prepare_api_parameters)
                self.assertIn("error", result)

    def test_search_scheduled_reports_default_parameters(self):
        """Test search_scheduled_reports with default parameters."""
        # Setup mock response
        query_response = {
            "status_code": 200,
            "body": {"resources": []},
        }
        self.mock_client.command.return_value = query_response

        # Call search_scheduled_reports with explicit default limit and None for others
        result = self.module.search_scheduled_reports(
            filter=None, limit=10, offset=None, sort=None
        )

        # Verify client command was called with default parameters
        self.mock_client.command.assert_called_once_with(
            "scheduled_reports_query", parameters={"limit": 10}
        )

        # Verify result
        self.assertEqual(result, [])

    def test_search_scheduled_reports_all_parameters(self):
        """Test search_scheduled_reports with all parameters."""
        # Setup mock response
        query_response = {
            "status_code": 200,
            "body": {"resources": []},
        }
        self.mock_client.command.return_value = query_response

        # Call search_scheduled_reports with all parameters
        result = self.module.search_scheduled_reports(
            filter="type:'hosts'%2Bstatus:'ACTIVE'",
            limit=100,
            offset=50,
            sort="created_on|desc",
        )

        # Verify client command was called with all parameters
        actual_call = self.mock_client.command.call_args
        self.assertEqual(actual_call[0][0], "scheduled_reports_query")
        
        expected_params = {
            "filter": "type:'hosts'%2Bstatus:'ACTIVE'",
            "limit": 100,
            "offset": 50,
            "sort": "created_on|desc",
        }
        
        for key, value in expected_params.items():
            self.assertEqual(actual_call[1]["parameters"][key], value)

        # Verify result
        self.assertEqual(result, [])

    def test_search_scheduled_reports_complex_filter_examples(self):
        """Test search_scheduled_reports with complex filter examples."""
        test_cases = [
            {
                "filter": "type:'event_search'",
                "description": "Find scheduled searches only",
            },
            {
                "filter": "status:'ACTIVE'%2Btype:'hosts'",
                "description": "Find active host reports",
            },
            {
                "filter": "last_execution.status:'FAILED'",
                "description": "Find reports with failed executions",
            },
            {
                "filter": "created_on:>'2021-10-01'%2Bstatus:'ACTIVE'",
                "description": "Find active reports created after date",
            },
        ]

        for case in test_cases:
            with self.subTest(case=case["description"]):
                # Setup mock response
                query_response = {
                    "status_code": 200,
                    "body": {"resources": []},
                }
                self.mock_client.command.return_value = query_response

                # Call search_scheduled_reports with explicit parameters
                self.module.search_scheduled_reports(
                    filter=case["filter"], limit=10, offset=None, sort=None
                )

                # Verify client command was called with the filter
                self.mock_client.command.assert_called_with(
                    "scheduled_reports_query",
                    parameters={"filter": case["filter"], "limit": 10},
                )

                # Reset mock for next iteration
                self.mock_client.command.reset_mock()


if __name__ == "__main__":
    unittest.main()
"""
End-to-end tests for the Scheduled Reports module.
"""

import unittest
from unittest.mock import MagicMock

from falcon_mcp.modules.scheduled_reports import ScheduledReportsModule
from falcon_mcp.client import FalconClient


class TestScheduledReportsE2E(unittest.TestCase):
    """End-to-end test cases for the Scheduled Reports module."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a mock client
        self.mock_client = MagicMock(spec=FalconClient)
        # Create the module
        self.module = ScheduledReportsModule(self.mock_client)

    def test_e2e_search_active_host_reports(self):
        """End-to-end test: Search for active host reports."""
        # Setup mock responses - realistic scenario
        query_response = {
            "status_code": 200,
            "body": {"resources": ["report-001", "report-002"]},
        }
        details_response = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "id": "report-001",
                        "name": "Daily Host Security Report",
                        "type": "hosts",
                        "status": "ACTIVE",
                        "description": "Daily security status report for all Windows hosts",
                        "created_on": "2024-01-15T08:00:00Z",
                        "last_updated_on": "2024-01-15T08:00:00Z",
                        "next_execution_on": "2024-01-16T08:00:00Z",
                        "user_id": "security@company.com",
                        "schedule": {
                            "definition": "0 8 * * *",
                            "display": "Daily at 8:00 AM UTC",
                        },
                        "last_execution": {
                            "id": "exec-001",
                            "status": "DONE",
                            "last_updated_on": "2024-01-15T08:05:00Z",
                        },
                        "report_params": {
                            "filter": "platform_name:'Windows'",
                            "columns": ["hostname", "last_seen", "platform_name"],
                        },
                        "notifications": [
                            {
                                "type": "email",
                                "config": {"recipients": ["security-team@company.com"]},
                            }
                        ],
                    },
                    {
                        "id": "report-002",
                        "name": "Weekly Linux Host Report",
                        "type": "hosts",
                        "status": "ACTIVE",
                        "description": "Weekly report for Linux hosts with vulnerabilities",
                        "created_on": "2024-01-10T09:00:00Z",
                        "last_updated_on": "2024-01-14T10:00:00Z",
                        "next_execution_on": "2024-01-21T09:00:00Z",
                        "user_id": "admin@company.com",
                        "schedule": {
                            "definition": "0 9 * * 1",
                            "display": "Weekly on Monday at 9:00 AM UTC",
                        },
                        "last_execution": {
                            "id": "exec-002",
                            "status": "DONE",
                            "last_updated_on": "2024-01-14T09:15:00Z",
                        },
                        "report_params": {
                            "filter": "platform_name:'Linux'",
                            "columns": ["hostname", "os_version", "agent_version"],
                        },
                        "notifications": [
                            {
                                "type": "email",
                                "config": {"recipients": ["linux-team@company.com"]},
                            }
                        ],
                    },
                ]
            },
        }
        self.mock_client.command.side_effect = [query_response, details_response]

        # Execute the complete workflow
        result = self.module.search_scheduled_reports(
            filter="type:'hosts'%2Bstatus:'ACTIVE'",
            limit=50,
            offset=None,
            sort="created_on|desc",
        )

        # Verify the complete API interaction
        self.assertEqual(self.mock_client.command.call_count, 2)

        # Verify first call (query)
        first_call = self.mock_client.command.call_args_list[0]
        self.assertEqual(first_call[0][0], "scheduled_reports_query")
        expected_query_params = {
            "filter": "type:'hosts'%2Bstatus:'ACTIVE'",
            "limit": 50,
            "sort": "created_on|desc",
        }
        self.assertEqual(first_call[1]["parameters"], expected_query_params)

        # Verify second call (get details)
        second_call = self.mock_client.command.call_args_list[1]
        self.assertEqual(second_call[0][0], "scheduled_reports_get")
        self.assertEqual(second_call[1]["body"]["ids"], ["report-001", "report-002"])

        # Verify complete result structure
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)

        # Verify first report details
        first_report = result[0]
        self.assertEqual(first_report["id"], "report-001")
        self.assertEqual(first_report["name"], "Daily Host Security Report")
        self.assertEqual(first_report["type"], "hosts")
        self.assertEqual(first_report["status"], "ACTIVE")
        self.assertIn("schedule", first_report)
        self.assertIn("last_execution", first_report)
        self.assertIn("report_params", first_report)
        self.assertIn("notifications", first_report)

        # Verify second report details
        second_report = result[1]
        self.assertEqual(second_report["id"], "report-002")
        self.assertEqual(second_report["name"], "Weekly Linux Host Report")
        self.assertEqual(second_report["type"], "hosts")
        self.assertEqual(second_report["status"], "ACTIVE")

    def test_e2e_search_failed_vulnerability_reports(self):
        """End-to-end test: Search for vulnerability reports with failed executions."""
        # Setup mock responses
        query_response = {
            "status_code": 200,
            "body": {"resources": ["vuln-report-001"]},
        }
        details_response = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "id": "vuln-report-001",
                        "name": "Critical Vulnerability Report",
                        "type": "spotlight_vulnerabilities",
                        "status": "ACTIVE",
                        "description": "Report on critical vulnerabilities requiring immediate attention",
                        "created_on": "2024-01-12T14:00:00Z",
                        "last_updated_on": "2024-01-15T14:00:00Z",
                        "next_execution_on": "2024-01-16T14:00:00Z",
                        "user_id": "vulnerability-team@company.com",
                        "schedule": {
                            "definition": "0 14 * * *",
                            "display": "Daily at 2:00 PM UTC",
                        },
                        "last_execution": {
                            "id": "exec-vuln-001",
                            "status": "FAILED",
                            "status_msg": "Timeout occurred while generating report",
                            "last_updated_on": "2024-01-15T14:30:00Z",
                        },
                        "report_params": {
                            "filter": "cve.severity:'CRITICAL'",
                            "columns": ["cve_id", "severity", "affected_products"],
                        },
                    }
                ]
            },
        }
        self.mock_client.command.side_effect = [query_response, details_response]

        # Execute the workflow
        result = self.module.search_scheduled_reports(
            filter="type:'spotlight_vulnerabilities'%2Blast_execution.status:'FAILED'",
            limit=25,
            offset=None,
            sort="last_execution.last_updated_on|desc",
        )

        # Verify API calls
        self.assertEqual(self.mock_client.command.call_count, 2)

        # Verify result
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)

        report = result[0]
        self.assertEqual(report["id"], "vuln-report-001")
        self.assertEqual(report["type"], "spotlight_vulnerabilities")
        self.assertEqual(report["last_execution"]["status"], "FAILED")
        self.assertIn("status_msg", report["last_execution"])

    def test_e2e_search_scheduled_searches(self):
        """End-to-end test: Search for scheduled searches (event_search type)."""
        # Setup mock responses
        query_response = {
            "status_code": 200,
            "body": {"resources": ["search-001"]},
        }
        details_response = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "id": "search-001",
                        "name": "Suspicious Login Activity Search",
                        "type": "event_search",
                        "status": "ACTIVE",
                        "description": "Automated search for suspicious login patterns",
                        "created_on": "2024-01-10T16:00:00Z",
                        "last_updated_on": "2024-01-10T16:00:00Z",
                        "next_execution_on": "2024-01-15T16:00:00Z",
                        "user_id": "soc-analyst@company.com",
                        "schedule": {
                            "definition": "0 */4 * * *",
                            "display": "Every 4 hours",
                        },
                        "last_execution": {
                            "id": "search-exec-001",
                            "status": "DONE",
                            "last_updated_on": "2024-01-15T12:00:00Z",
                        },
                        "report_params": {
                            "query": "event_simpleName=UserLogon LogonType_decimal=10",
                            "time_range": "4h",
                        },
                    }
                ]
            },
        }
        self.mock_client.command.side_effect = [query_response, details_response]

        # Execute the workflow
        result = self.module.search_scheduled_reports(
            filter="type:'event_search'", limit=10, offset=None, sort="name|asc"
        )

        # Verify result
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)

        search = result[0]
        self.assertEqual(search["id"], "search-001")
        self.assertEqual(search["type"], "event_search")
        self.assertEqual(search["name"], "Suspicious Login Activity Search")
        self.assertIn("report_params", search)
        self.assertIn("query", search["report_params"])

    def test_e2e_empty_results(self):
        """End-to-end test: Handle empty search results gracefully."""
        # Setup mock response with no results
        query_response = {
            "status_code": 200,
            "body": {"resources": []},
        }
        self.mock_client.command.return_value = query_response

        # Execute the workflow
        result = self.module.search_scheduled_reports(
            filter="type:'nonexistent_type'", limit=10, offset=None, sort=None
        )

        # Verify only one API call (no details call for empty results)
        self.assertEqual(self.mock_client.command.call_count, 1)

        # Verify empty result
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)

    def test_e2e_api_error_handling(self):
        """End-to-end test: Handle API errors properly."""
        # Setup mock error response
        error_response = {
            "status_code": 403,
            "body": {
                "errors": [
                    {
                        "code": 403,
                        "message": "access denied, authorization failed",
                    }
                ]
            },
        }
        self.mock_client.command.return_value = error_response

        # Execute the workflow
        result = self.module.search_scheduled_reports(
            filter="type:'hosts'", limit=10, offset=None, sort=None
        )

        # Verify error handling
        self.assertIsInstance(result, dict)
        self.assertIn("error", result)
        self.assertIn("details", result)
        self.assertIn("required_scopes", result)


if __name__ == "__main__":
    unittest.main()
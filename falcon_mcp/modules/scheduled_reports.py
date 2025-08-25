"""
Scheduled Reports module for Falcon MCP Server

This module provides tools for accessing CrowdStrike Falcon scheduled reports and searches.
"""

from textwrap import dedent
from typing import Any, Dict, List

from mcp.server import FastMCP
from mcp.server.fastmcp.resources import TextResource
from pydantic import AnyUrl, Field

from falcon_mcp.common.errors import handle_api_response
from falcon_mcp.common.logging import get_logger
from falcon_mcp.common.utils import prepare_api_parameters
from falcon_mcp.modules.base import BaseModule
from falcon_mcp.resources.scheduled_reports import SEARCH_SCHEDULED_REPORTS_FQL_DOCUMENTATION

logger = get_logger(__name__)


class ScheduledReportsModule(BaseModule):
    """Module for accessing CrowdStrike Falcon scheduled reports and searches."""

    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """
        self._add_tool(
            server=server,
            method=self.search_scheduled_reports,
            name="search_scheduled_reports",
        )

    def register_resources(self, server: FastMCP) -> None:
        """Register resources with the MCP server.

        Args:
            server: MCP server instance
        """
        search_scheduled_reports_fql_resource = TextResource(
            uri=AnyUrl("falcon://scheduled-reports/search/fql-guide"),
            name="falcon_search_scheduled_reports_fql_guide",
            description="Contains the guide for the `filter` param of the `falcon_search_scheduled_reports` tool.",
            text=SEARCH_SCHEDULED_REPORTS_FQL_DOCUMENTATION,
        )

        self._add_resource(
            server,
            search_scheduled_reports_fql_resource,
        )

    def search_scheduled_reports(
        self,
        filter: str | None = Field(
            default=None,
            description="FQL Syntax formatted string used to limit the results. IMPORTANT: use the `falcon://scheduled-reports/search/fql-guide` resource when building this filter parameter.",
            examples={
                "type:'hosts'",
                "status:'ACTIVE'",
                "type:'event_search'",
                "last_execution.status:'FAILED'",
            },
        ),
        limit: int = Field(
            default=10,
            ge=1,
            le=500,
            description="Maximum number of records to return. (Max: 500)",
        ),
        offset: int | None = Field(
            default=None,
            description="Starting index of overall result set from which to return ids.",
        ),
        sort: str | None = Field(
            default=None,
            description=dedent("""
                Sort scheduled reports using these options:

                created_on: When the report was created
                last_updated_on: When the report was last updated
                name: Report name (alphabetical)
                next_execution_on: Next scheduled execution time
                status: Report status
                type: Report type
                user_id: Creator username

                Sort either asc (ascending) or desc (descending).
                Format: 'field|direction'

                Examples: 'created_on|desc', 'name|asc', 'next_execution_on|asc'
            """).strip(),
            examples={"created_on|desc", "name|asc", "next_execution_on|asc"},
        ),
    ) -> List[Dict[str, Any]]:
        """Search for scheduled reports and searches in your CrowdStrike environment.

        This tool combines two API operations to provide comprehensive scheduled report information:
        1. First searches for report IDs matching your filter criteria
        2. Then retrieves detailed information for each matching report

        IMPORTANT: You must use the `falcon://scheduled-reports/search/fql-guide` resource
        when building the filter parameter. This resource contains comprehensive documentation
        for all available filter options and syntax.

        Returns:
            List of scheduled report details including metadata, schedules, and execution status
        """
        # Prepare parameters for the query operation
        query_params = prepare_api_parameters({
            "filter": filter,
            "limit": limit,
            "offset": offset,
            "sort": sort,
        })

        # First, get the list of scheduled report IDs
        query_operation = "scheduled_reports_query"
        query_response = self.client.command(query_operation, parameters=query_params)

        # Handle the query response
        report_ids = handle_api_response(
            query_response,
            operation=query_operation,
            error_message="Failed to search scheduled reports",
            default_result=[],
        )

        # If handle_api_response returns an error dict, return it
        if self._is_error(report_ids):
            return report_ids

        # If no IDs found, return empty list
        if not report_ids:
            return []

        # Now get the detailed information for each report ID
        return self._base_get_by_ids(
            operation="scheduled_reports_get",
            ids=report_ids,
        )

"""
Scheduled Reports FQL documentation for Falcon MCP Server

This resource provides comprehensive FQL documentation for the scheduled reports module.
"""

SEARCH_SCHEDULED_REPORTS_FQL_DOCUMENTATION = """
# FQL Filter Guide for Scheduled Reports Search

This guide covers the Falcon Query Language (FQL) syntax for filtering scheduled reports and searches using the `falcon_search_scheduled_reports` tool.

## Basic FQL Syntax

FQL filters follow the pattern: `filter=field_name:'value'`

- Values must be enclosed in single quotes
- No space between the colon and the value
- Case-sensitive for most fields

## Available Filter Fields

### Entity Metadata Filters

#### `created_on`
Filter by the date and time a scheduled report/search entity was created.
- **Type**: Timestamp (ISO 8601 format)
- **Supports**: Comparison operators (<, >)
- **Examples**:
  - `created_on:'2021-10-12'` - Created on specific date
  - `created_on:<'2021-10-12'` - Created before date
  - `created_on:>'2021-10-12T03:00'` - Created after specific time

#### `last_updated_on`
Filter by the date and time a scheduled report/search entity was last updated.
- **Type**: Timestamp (ISO 8601 format)
- **Supports**: Comparison operators (<, >)
- **Examples**:
  - `last_updated_on:'2021-10-12'` - Updated on specific date
  - `last_updated_on:>'2021-10-12'` - Updated after date

#### `name`
Filter by exact matches to the full scheduled report/search entity name.
- **Type**: String (case-sensitive)
- **Supports**: Multi-value, negation
- **Examples**:
  - `name:'My Test Report'` - Exact name match
  - `name:['Report 1','Report 2']` - Multiple names
  - `name:!'My Test Report'` - Exclude specific name

#### `description`
Filter by single terms found in the description (case-insensitive).
- **Type**: String (lowercase required)
- **Supports**: Multi-value, negation
- **Examples**:
  - `description:'process'` - Contains "process"
  - `description:!'security'` - Does not contain "security"
  - `description:['process','data']` - Contains either term

#### `user_id`
Filter by the username (typically email) of the person who created the entity.
- **Type**: String
- **Supports**: Multi-value, negation
- **Examples**:
  - `user_id:'john.doe@company.com'` - Specific user
  - `user_id:!'admin@company.com'` - Exclude admin user

### Status and Scheduling Filters

#### `status`
Filter by the current status of the scheduled report/search entity.
- **Type**: String (must be uppercase)
- **Supports**: Multi-value, negation
- **Possible Values**:
  - `ACTIVE` - Actively scheduling executions
  - `PENDING` - Being saved
  - `STOPPED` - Inactive
  - `UPDATING` - Changes being saved
- **Examples**:
  - `status:'ACTIVE'` - Only active reports
  - `status:['STOPPED','UPDATING']` - Multiple statuses
  - `status:!'ACTIVE'` - Exclude active reports

#### `next_execution_on`
Filter by the date and time of the next scheduled execution.
- **Type**: Timestamp (ISO 8601 format)
- **Supports**: Comparison operators (<, >)
- **Examples**:
  - `next_execution_on:<'2021-11-01'` - Executes before date
  - `next_execution_on:>'2021-10-15T12:00'` - Executes after time

#### `start_on`
Filter by the configured start date for execution scheduling.
- **Type**: Timestamp (ISO 8601 format)
- **Supports**: Comparison operators (<, >)
- **Examples**:
  - `start_on:<'2021-10-01'` - Starts before date

#### `stop_on`
Filter by the configured end date for execution scheduling.
- **Type**: Timestamp (ISO 8601 format)
- **Supports**: Comparison operators (<, >)
- **Examples**:
  - `stop_on:'2021-12-31'` - Ends on specific date

### Report Type Filters

#### `type`
Filter by the data source type of the scheduled report or search.
- **Type**: String (must be lowercase)
- **Supports**: Multi-value, negation
- **Possible Values**:
  - `cloud_security_posture_detections_ioa` - Cloud Security IOA posture
  - `cloud_security_posture_detections_iom` - Cloud Security IOM posture
  - `cloud_security_image_vulnerabilities` - Cloud Security image vulnerabilities
  - `cloud_security_container_vulnerabilities` - Cloud Security container vulnerabilities
  - `cloud_security_container_details` - Cloud Security container details
  - `cloud_security_image_detections` - Cloud Security image detections
  - `dashboard` - Dashboard reports
  - `discover_applications` - Assets applications
  - `event_search` - Scheduled searches
  - `filevantage` - FileVantage monitored changes
  - `hosts` - Hosts reports
  - `spotlight_installed_patches` - Vulnerability management installed patches
  - `spotlight_remediations` - Vulnerability management remediations
  - `spotlight_vulnerabilities` - Vulnerability management vulnerabilities
  - `spotlight_vulnerability_logic` - Vulnerability management vulnerabilities with evidence
- **Examples**:
  - `type:'event_search'` - Only scheduled searches
  - `type:['hosts','spotlight_vulnerabilities']` - Multiple types
  - `type:!'dashboard'` - Exclude dashboard reports

### Execution Status Filters

#### `last_execution.status`
Filter by the status of the last execution.
- **Type**: String (must be uppercase)
- **Supports**: Multi-value, negation
- **Possible Values**:
  - `PENDING` - Execution was triggered
  - `PROCESSING` - Report being generated
  - `DONE` - Successfully completed
  - `FAILED` - Generation failed
  - `FAILED_NOTIFICATION` - Notification sending failed
  - `NO_DATA` - No data available
- **Examples**:
  - `last_execution.status:'FAILED'` - Failed executions
  - `last_execution.status:['PENDING','DONE']` - Multiple statuses
  - `last_execution.status:!'PENDING'` - Exclude pending

#### `last_execution.last_updated_on`
Filter by the date and time of the last execution update.
- **Type**: Timestamp (ISO 8601 format)
- **Supports**: Comparison operators (<, >)
- **Examples**:
  - `last_execution.last_updated_on:'2021-09-22'` - Last executed on date
  - `last_execution.last_updated_on:>'2021-09-22T11:30'` - After specific time

### Sharing and Permissions

#### `shared_with`
Filter by users who have been granted access to the scheduled report.
- **Type**: String (UUID format)
- **Supports**: Multi-value, negation
- **Note**: Only applies to scheduled reports, not searches
- **Examples**:
  - `shared_with:'26eab16d-0b73-452d-b807-afc58f097aad'` - Shared with user
  - `shared_with:!'26eab16d-0b73-452d-b807-afc58f097aad'` - Not shared with user

### Expiration Filters

#### `expiration_on`
Filter by when stopped entities will be permanently deleted (30 days after stopping).
- **Type**: Timestamp (ISO 8601 format)
- **Supports**: Comparison operators (<, >)
- **Examples**:
  - `expiration_on:'2021-12-15'` - Expires on date
  - `expiration_on:>'2021-11-15T18'` - Expires after time

## Advanced FQL Features

### Comparison Operators
- **`<`** - Before/less than: `created_on:<'2021-10-12'`
- **`>`** - After/greater than: `last_updated_on:>'2021-10-12'`

### Multiple Values
Two formats supported:
- **Brackets**: `status:['ACTIVE','PENDING']`
- **Repeated**: `status:'ACTIVE',status:'PENDING'`

### Negation
Use `!` to exclude values:
- **Single**: `status:!'STOPPED'`
- **Multiple**: `status:!['STOPPED','UPDATING']`

### Multiple Filters
Combine with URL-encoded `+` (%2B):
```
filter=type:'hosts'%2Bstatus:'ACTIVE'
```

### Timestamp Formats
Supports partial timestamps:
- **Date only**: `2021-10-12`
- **Date + hour**: `2021-10-12T03`
- **Date + hour/minute**: `2021-10-12T03:27`
- **Full timestamp**: `2021-10-12T03:27:45.123Z`

## Common Filter Examples

### Find Active Host Reports
```
filter=type:'hosts'%2Bstatus:'ACTIVE'
```

### Find Failed Executions from Last Week
```
filter=last_execution.status:'FAILED'%2Blast_execution.last_updated_on:>'2021-10-15'
```

### Find Scheduled Searches Only
```
filter=type:'event_search'
```

### Find Reports Created by Specific User
```
filter=user_id:'admin@company.com'%2Bstatus:'ACTIVE'
```

### Find Vulnerability Reports
```
filter=type:['spotlight_vulnerabilities','spotlight_remediations','spotlight_installed_patches']
```

### Find Reports Expiring Soon
```
filter=expiration_on:<'2021-12-31'%2Bstatus:'STOPPED'
```

## Notes
- All timestamp values are in UTC
- String comparisons are case-sensitive unless noted
- Use the resource URI `falcon://scheduled-reports/search/fql-guide` when building filters
- Always test filters with simple values first, then add complexity
"""
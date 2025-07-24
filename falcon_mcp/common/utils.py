"""
Common utility functions for Falcon MCP Server

This module provides common utility functions for the Falcon MCP server.
"""
import re
from typing import Dict, Any, List, Optional, Union

from .errors import is_success_response, _format_error_response
from .logging import get_logger

logger = get_logger(__name__)


def filter_none_values(data: Dict[str, Any]) -> Dict[str, Any]:
    """Remove None values from a dictionary.

    Args:
        data: Dictionary to filter

    Returns:
        Dict[str, Any]: Dictionary with None values removed
    """
    return {k: v for k, v in data.items() if v is not None}


def prepare_api_parameters(params: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare parameters for Falcon API requests.

    Args:
        params: Raw parameters

    Returns:
        Dict[str, Any]: Prepared parameters
    """
    # Remove None values
    filtered = filter_none_values(params)

    # Handle special parameter formatting if needed
    if "filter" in filtered and isinstance(filtered["filter"], dict):
        # Convert filter dict to FQL string if needed
        pass

    return filtered


def extract_resources(response: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract resources from an API response.

    Args:
        response: API response

    Returns:
        List[Dict[str, Any]]: List of resources
    """
    if isinstance(response, dict):
        body = response.get("body", {})
        if isinstance(body, dict):
            resources = body.get("resources", [])
            if isinstance(resources, list):
                return resources

    # Return empty list if we can't extract resources
    return []


def extract_first_resource(resources: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Extract the first resource from a list.

    Args:
        resources: List of resources

    Returns:
        Optional[Dict[str, Any]]: First resource or None
    """
    if not resources:
        return None

    return resources[0]


class InputValidationError(ValueError):
    """Custom exception for input validation errors."""
    pass


def sanitize_input(input_str: str, input_type: str = "general", max_length: int = 255) -> str:
    """Enhanced input sanitization with context-specific validation.

    Args:
        input_str: Input string to sanitize
        input_type: Type of input for context-specific validation
        max_length: Maximum allowed length

    Returns:
        Sanitized string with dangerous characters removed

    Raises:
        InputValidationError: If input fails validation
    """
    if not isinstance(input_str, str):
        input_str = str(input_str)

    # Check for null bytes and other control characters
    if '\x00' in input_str:
        raise InputValidationError("Input contains null bytes")

    # Remove dangerous control characters
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', input_str)

    # Context-specific validation
    if input_type == "entity_id":
        # Validate entity ID format - only alphanumeric, hyphens, underscores
        if not re.match(r'^[a-zA-Z0-9_-]+$', sanitized):
            raise InputValidationError(f"Invalid entity ID format: {sanitized}")
    
    elif input_type == "email":
        # Basic email validation
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', sanitized):
            raise InputValidationError(f"Invalid email format: {sanitized}")
    
    elif input_type == "ip_address":
        # Validate IPv4 and IPv6 addresses
        ipv4_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        if not (re.match(ipv4_pattern, sanitized) or re.match(ipv6_pattern, sanitized)):
            raise InputValidationError(f"Invalid IP address format: {sanitized}")
    
    elif input_type == "domain":
        # Validate domain name format
        if not re.match(r'^[a-zA-Z0-9.-]+$', sanitized):
            raise InputValidationError(f"Invalid domain format: {sanitized}")
    
    elif input_type == "fql_filter":
        # Special handling for FQL filters - remove potentially dangerous characters
        # but preserve FQL syntax characters
        dangerous_chars = ['<', '>', '{', '}', ';', '\\', '`', '|']
        for char in dangerous_chars:
            if char in sanitized:
                raise InputValidationError(f"FQL filter contains dangerous character: {char}")
    
    elif input_type == "graphql_identifier":
        # GraphQL identifiers should only contain alphanumeric, underscore, dash
        if not re.match(r'^[a-zA-Z0-9_-]+$', sanitized):
            raise InputValidationError(f"Invalid GraphQL identifier: {sanitized}")
    
    elif input_type == "general":
        # General sanitization - remove quotes, backslashes, script tags
        sanitized = re.sub(r'[<>{}();\'"`\\]', '', sanitized)
    
    # Additional safety: limit length to prevent excessively long inputs
    if len(sanitized) > max_length:
        raise InputValidationError(f"Input too long: {len(sanitized)} > {max_length}")

    return sanitized


def validate_json_input(json_data: str, max_depth: int = 10, max_keys: int = 100) -> dict:
    """Validate and safely parse JSON input.
    
    Args:
        json_data: JSON string to validate
        max_depth: Maximum nesting depth allowed
        max_keys: Maximum number of keys allowed
        
    Returns:
        Parsed JSON data
        
    Raises:
        InputValidationError: If JSON is invalid or exceeds limits
    """
    import json
    
    try:
        # Parse JSON
        data = json.loads(json_data)
    except json.JSONDecodeError as e:
        raise InputValidationError(f"Invalid JSON: {e}")
    
    # Check depth and key count recursively
    def check_structure(obj, depth=0, key_count=0):
        if depth > max_depth:
            raise InputValidationError(f"JSON depth exceeds limit: {depth} > {max_depth}")
        
        if isinstance(obj, dict):
            key_count += len(obj)
            if key_count > max_keys:
                raise InputValidationError(f"JSON key count exceeds limit: {key_count} > {max_keys}")
            
            for key, value in obj.items():
                # Validate key format
                if not isinstance(key, str) or len(key) > 100:
                    raise InputValidationError(f"Invalid JSON key: {key}")
                key_count = check_structure(value, depth + 1, key_count)
        
        elif isinstance(obj, list):
            for item in obj:
                key_count = check_structure(item, depth + 1, key_count)
        
        return key_count
    
    check_structure(data)
    return data


def validate_url(url: str) -> str:
    """Validate URL format and prevent dangerous schemes.
    
    Args:
        url: URL to validate
        
    Returns:
        Validated URL
        
    Raises:
        InputValidationError: If URL is invalid or uses dangerous scheme
    """
    if not isinstance(url, str):
        raise InputValidationError("URL must be a string")
    
    # Check for dangerous schemes
    dangerous_schemes = ['javascript:', 'data:', 'vbscript:', 'file:', 'ftp:']
    url_lower = url.lower()
    
    for scheme in dangerous_schemes:
        if url_lower.startswith(scheme):
            raise InputValidationError(f"Dangerous URL scheme: {scheme}")
    
    # Basic URL format validation
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    if not url_pattern.match(url):
        raise InputValidationError(f"Invalid URL format: {url}")
    
    return url

"""
Base module for Falcon MCP Server

This module provides the base class for all Falcon MCP server modules.
"""
import re
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List

from mcp import Resource
from mcp.server import FastMCP

from falcon_mcp.common.errors import handle_api_response
from falcon_mcp.common.utils import prepare_api_parameters
from falcon_mcp.client import FalconClient
from falcon_mcp.common.logging import get_logger

logger = get_logger(__name__)


class ToolSecurityScanner:
    """Security scanner for tool descriptions to prevent tool poisoning attacks."""
    
    # Patterns that could indicate prompt injection or malicious instructions
    DANGEROUS_PATTERNS = [
        # Direct prompt injection attempts
        r'ignore\s+(?:previous|all|any)\s+(?:instructions?|prompts?|rules?)',
        r'forget\s+(?:previous|all|any)\s+(?:instructions?|prompts?|rules?)',
        r'system\s*:\s*you\s+(?:are|must|should|will)',
        r'assistant\s*:\s*(?:i\s+am|you\s+are)',
        r'human\s*:\s*(?:you\s+must|please)',
        
        # Script injection attempts
        r'<\s*script[^>]*>',
        r'javascript\s*:',
        r'eval\s*\(',
        r'document\s*\.',
        r'window\s*\.',
        r'alert\s*\(',
        r'prompt\s*\(',
        r'confirm\s*\(',
        
        # Command injection attempts
        r';\s*(?:rm|del|format|shutdown)',
        r'\|\s*(?:nc|netcat|wget|curl)',
        r'&&\s*(?:rm|del|format)',
        
        # Hidden instructions
        r'<!--.*(?:ignore|system|admin).*-->',
        r'/\*.*(?:ignore|system|admin).*\*/',
        
        # Role manipulation
        r'you\s+are\s+(?:now|currently)\s+(?:a|an)\s+(?:admin|administrator|root|system)',
        r'switch\s+(?:to|into)\s+(?:admin|administrator|debug|developer)\s+mode',
        r'enable\s+(?:admin|administrator|debug|developer)\s+(?:mode|access)',
        
        # Data exfiltration patterns
        r'send\s+(?:all|your|the)\s+(?:data|information|credentials|keys?)',
        r'export\s+(?:all|your|the)\s+(?:data|information|credentials)',
        r'copy\s+(?:all|your|the)\s+(?:data|information|files?)',
        
        # Context manipulation
        r'pretend\s+(?:you|to\s+be|that)',
        r'act\s+(?:as|like)\s+(?:a|an)',
        r'role\s*play\s+(?:as|that)',
        
        # Encoding attempts (basic)
        r'base64\s*:',
        r'hex\s*:',
        r'unicode\s*:',
        
        # Markdown/HTML injection
        r'\[.*\]\(javascript:',
        r'\[.*\]\(data:',
        r'!\[.*\]\(.*javascript',
    ]
    
    # Suspicious word combinations that could indicate malicious intent
    SUSPICIOUS_COMBINATIONS = [
        ['ignore', 'previous', 'instruction'],
        ['system', 'you', 'are'],
        ['admin', 'access', 'enable'],
        ['secret', 'hidden', 'reveal'],
        ['bypass', 'security', 'check'],
        ['override', 'safety', 'filter'],
    ]
    
    @classmethod
    def scan_text(cls, text: str) -> Dict[str, Any]:
        """Scan text for potential security threats.
        
        Args:
            text: Text to scan
            
        Returns:
            Dict containing scan results with threats found
        """
        if not isinstance(text, str):
            text = str(text)
        
        text_lower = text.lower()
        threats_found = []
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            matches = re.findall(pattern, text_lower, re.IGNORECASE | re.MULTILINE)
            if matches:
                threats_found.append({
                    'type': 'dangerous_pattern',
                    'pattern': pattern,
                    'matches': matches,
                    'severity': 'HIGH'
                })
        
        # Check for suspicious word combinations
        words = re.findall(r'\b\w+\b', text_lower)
        for combo in cls.SUSPICIOUS_COMBINATIONS:
            if all(word in words for word in combo):
                # Check if words appear close together (within 10 words of each other)
                word_positions = {word: [i for i, w in enumerate(words) if w == word] for word in combo}
                
                for pos_combo in cls._get_position_combinations(word_positions):
                    if max(pos_combo) - min(pos_combo) <= 10:  # Words within 10 positions
                        threats_found.append({
                            'type': 'suspicious_combination',
                            'words': combo,
                            'severity': 'MEDIUM'
                        })
                        break
        
        # Check for excessive repetition (possible attempt to confuse)
        repeated_phrases = re.findall(r'(\b\w+(?:\s+\w+){1,3}\b)(?:\s+\1){2,}', text_lower)
        if repeated_phrases:
            threats_found.append({
                'type': 'excessive_repetition',
                'phrases': repeated_phrases,
                'severity': 'LOW'
            })
        
        # Check for unusual character patterns
        if re.search(r'[^\x20-\x7E\n\r\t]', text):  # Non-printable characters
            threats_found.append({
                'type': 'non_printable_characters',
                'severity': 'MEDIUM'
            })
        
        return {
            'is_safe': len(threats_found) == 0,
            'threats': threats_found,
            'threat_count': len(threats_found),
            'max_severity': cls._get_max_severity(threats_found)
        }
    
    @classmethod
    def _get_position_combinations(cls, word_positions: Dict[str, List[int]]) -> List[List[int]]:
        """Generate all combinations of word positions."""
        import itertools
        
        if not word_positions:
            return []
        
        # Get all combinations of positions for each word
        position_lists = list(word_positions.values())
        return list(itertools.product(*position_lists))
    
    @classmethod
    def _get_max_severity(cls, threats: List[Dict[str, Any]]) -> str:
        """Get the maximum severity level from a list of threats."""
        if not threats:
            return 'NONE'
        
        severity_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}
        max_severity = max(threats, key=lambda t: severity_order.get(t.get('severity', 'LOW'), 1))
        return max_severity.get('severity', 'LOW')


class BaseModule(ABC):
    """Base class for all Falcon MCP server modules."""

    def __init__(self, client: FalconClient):
        """Initialize the module.

        Args:
            client: Falcon API client
        """
        self.client = client
        self.tools = []  # List to track registered tools
        self.resources = [] # List to track registered resources
        self.security_scanner = ToolSecurityScanner()

    @abstractmethod
    def register_tools(self, server: FastMCP) -> None:
        """Register tools with the MCP server.

        Args:
            server: MCP server instance
        """

    def register_resources(self, server: FastMCP) -> None:
        """Register resources with the MCP Server.

        Args:
            server: MCP server instance
        """

    def _scan_tool_security(self, method: Callable, name: str) -> bool:
        """Scan a tool method for security threats.
        
        Args:
            method: The tool method to scan
            name: Tool name for logging
            
        Returns:
            bool: True if tool is safe, False if threats detected
        """
        texts_to_scan = []
        
        # Scan docstring
        if hasattr(method, '__doc__') and method.__doc__:
            texts_to_scan.append(('docstring', method.__doc__))
        
        # Scan method name
        texts_to_scan.append(('method_name', name))
        
        # Scan annotations if present
        if hasattr(method, '__annotations__'):
            for param, annotation in method.__annotations__.items():
                if hasattr(annotation, 'description'):
                    texts_to_scan.append(('parameter_description', str(annotation.description)))
        
        all_threats = []
        
        for text_type, text in texts_to_scan:
            scan_result = self.security_scanner.scan_text(text)
            if not scan_result['is_safe']:
                all_threats.extend(scan_result['threats'])
                logger.warning(
                    f"Security threats detected in tool '{name}' {text_type}: "
                    f"{scan_result['threat_count']} threats, max severity: {scan_result['max_severity']}"
                )
                
                # Log specific threats for investigation
                for threat in scan_result['threats']:
                    logger.warning(f"Threat in {name}: {threat}")
        
        # Determine if tool should be blocked
        high_severity_threats = [t for t in all_threats if t.get('severity') == 'HIGH']
        
        if high_severity_threats:
            logger.error(f"BLOCKING tool '{name}' due to {len(high_severity_threats)} HIGH severity threats")
            return False
        
        # Allow tools with only low/medium threats but log them
        if all_threats:
            medium_threats = [t for t in all_threats if t.get('severity') == 'MEDIUM']
            low_threats = [t for t in all_threats if t.get('severity') == 'LOW']
            
            logger.warning(
                f"Tool '{name}' has potential security concerns: "
                f"{len(medium_threats)} medium, {len(low_threats)} low severity threats. "
                f"Allowing but monitoring."
            )
        
        return True

    def _add_tool(self, server: FastMCP, method: Callable, name: str) -> None:
        """Add a tool to the MCP server and track it with security scanning.

        Args:
            server: MCP server instance
            method: Method to register
            name: Tool name
        """
        # Perform security scan
        if not self._scan_tool_security(method, name):
            logger.error(f"Tool '{name}' blocked due to security threats")
            raise ValueError(f"Tool '{name}' failed security scan")
        
        prefixed_name = f"falcon_{name}"
        server.add_tool(method, name=prefixed_name)
        self.tools.append(prefixed_name)
        logger.debug("Added tool: %s", prefixed_name)

    def _add_resource(self, server: FastMCP, resource: Resource) -> None:
        """Add a resource to the MCP server and track it with security validation.

        Args:
            server: MCP server instance
            resource: Resource object
        """
        # Validate resource URI for security
        uri_str = str(resource.uri)
        
        # Check for path traversal attempts
        if ".." in uri_str or "~" in uri_str:
            raise ValueError(f"Invalid resource URI: contains path traversal: {uri_str}")
        
        # Ensure URI starts with falcon:// scheme
        if not uri_str.startswith("falcon://"):
            raise ValueError(f"Invalid resource URI: must start with falcon://: {uri_str}")
        
        # Scan resource content if it's a text resource
        if hasattr(resource, 'text') and resource.text:
            scan_result = self.security_scanner.scan_text(resource.text)
            if not scan_result['is_safe']:
                high_threats = [t for t in scan_result['threats'] if t.get('severity') == 'HIGH']
                if high_threats:
                    logger.error(f"BLOCKING resource '{uri_str}' due to HIGH severity security threats")
                    raise ValueError(f"Resource '{uri_str}' failed security scan")
                else:
                    logger.warning(f"Resource '{uri_str}' has potential security concerns but allowing")
        
        server.add_resource(resource=resource)
        self.resources.append(resource.uri)
        logger.debug("Added resource: %s", resource.uri)

    def _base_get_by_ids(
        self,
        operation: str,
        ids: List[str],
        id_key: str = "ids",
        **additional_params
    ) -> List[Dict[str, Any]]|Dict[str, Any]:
        """Helper method for API operations that retrieve entities by IDs.

        Args:
            operation: The API operation name
            ids: List of entity IDs
            id_key: The key name for IDs in the request body (default: "ids")
            **additional_params: Additional parameters to include in the request body

        Returns:
            List of entity details or error dict
        """
        # Validate IDs for security
        if not isinstance(ids, list):
            raise ValueError("IDs must be provided as a list")
        
        for entity_id in ids:
            if not isinstance(entity_id, str):
                raise ValueError(f"All IDs must be strings, got: {type(entity_id)}")
            
            # Basic validation - no control characters or excessive length
            if len(entity_id) > 255:
                raise ValueError(f"Entity ID too long: {len(entity_id)} characters")
            
            if re.search(r'[\x00-\x1f\x7f-\x9f]', entity_id):
                raise ValueError(f"Entity ID contains control characters: {entity_id}")

        # Build the request body with dynamic ID key and additional parameters
        body_params = {id_key: ids}
        body_params.update(additional_params)

        body = prepare_api_parameters(body_params)

        # Make the API request
        response = self.client.command(operation, body=body)

        # Handle the response
        return handle_api_response(
            response,
            operation=operation,
            error_message="Failed to perform operation",
            default_result=[]
        )

    def _is_error(self, response: Any) -> bool:
        return isinstance(response, dict) and "error" in response

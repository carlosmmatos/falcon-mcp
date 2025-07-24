"""
Security utilities and middleware for Falcon MCP Server

This module provides security features including rate limiting, request validation,
and security event logging to protect against MCP-specific attacks.
"""
import json
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Set
import hashlib
import re

from falcon_mcp.common.logging import get_logger

logger = get_logger(__name__)


class SecurityEventLogger:
    """Centralized security event logging for monitoring and alerting."""
    
    def __init__(self):
        self.security_logger = get_logger("falcon_mcp.security")
    
    def log_security_event(
        self,
        event_type: str,
        details: Dict[str, Any],
        severity: str = "INFO",
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> None:
        """Log security-related events for monitoring.
        
        Args:
            event_type: Type of security event
            details: Event details
            severity: Event severity (INFO, WARNING, CRITICAL)
            client_ip: Client IP address if available
            user_agent: User agent string if available
        """
        log_entry = {
            "event_type": event_type,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details,
            "severity": severity,
            "client_ip": client_ip,
            "user_agent": user_agent
        }
        
        if severity == "CRITICAL":
            self.security_logger.critical(json.dumps(log_entry))
        elif severity == "WARNING":
            self.security_logger.warning(json.dumps(log_entry))
        else:
            self.security_logger.info(json.dumps(log_entry))
    
    def log_tool_execution(
        self,
        tool_name: str,
        execution_time: float,
        success: bool,
        error: Optional[str] = None,
        client_ip: Optional[str] = None
    ) -> None:
        """Log tool execution events."""
        self.log_security_event(
            "tool_execution",
            {
                "tool": tool_name,
                "execution_time": execution_time,
                "success": success,
                "error": error
            },
            severity="WARNING" if not success else "INFO",
            client_ip=client_ip
        )
    
    def log_rate_limit_violation(
        self,
        client_ip: str,
        endpoint: str,
        current_count: int,
        limit: int
    ) -> None:
        """Log rate limit violations."""
        self.log_security_event(
            "rate_limit_violation",
            {
                "endpoint": endpoint,
                "current_count": current_count,
                "limit": limit
            },
            severity="WARNING",
            client_ip=client_ip
        )
    
    def log_suspicious_request(
        self,
        reason: str,
        details: Dict[str, Any],
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> None:
        """Log suspicious request patterns."""
        self.log_security_event(
            "suspicious_request",
            {"reason": reason, **details},
            severity="WARNING",
            client_ip=client_ip,
            user_agent=user_agent
        )


class RateLimiter:
    """Token bucket rate limiter for preventing abuse."""
    
    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        """Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests allowed in the time window
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(deque)  # IP -> deque of timestamps
        self.blocked_ips = {}  # IP -> block_until_timestamp
        
    def is_allowed(self, client_ip: str) -> bool:
        """Check if request from client IP is allowed.
        
        Args:
            client_ip: Client IP address
            
        Returns:
            bool: True if request is allowed, False if rate limited
        """
        current_time = time.time()
        
        # Check if IP is currently blocked
        if client_ip in self.blocked_ips:
            if current_time < self.blocked_ips[client_ip]:
                return False
            else:
                # Block expired, remove it
                del self.blocked_ips[client_ip]
        
        # Clean old requests outside the window
        request_times = self.requests[client_ip]
        cutoff_time = current_time - self.window_seconds
        
        while request_times and request_times[0] < cutoff_time:
            request_times.popleft()
        
        # Check if within rate limit
        if len(request_times) >= self.max_requests:
            # Block this IP for the remainder of the window
            self.blocked_ips[client_ip] = current_time + self.window_seconds
            return False
        
        # Add current request
        request_times.append(current_time)
        return True
    
    def get_remaining_requests(self, client_ip: str) -> int:
        """Get remaining requests for client IP."""
        current_time = time.time()
        request_times = self.requests[client_ip]
        cutoff_time = current_time - self.window_seconds
        
        # Clean old requests
        while request_times and request_times[0] < cutoff_time:
            request_times.popleft()
        
        return max(0, self.max_requests - len(request_times))


class MCPSecurityValidator:
    """Security validator for MCP-specific threats."""
    
    def __init__(self):
        self.security_logger = SecurityEventLogger()
        
        # Suspicious patterns in requests
        self.suspicious_patterns = [
            r'\.\./',  # Path traversal
            r'<script',  # Script injection
            r'javascript:',  # JavaScript URLs
            r'data:.*base64',  # Data URLs with base64
            r'eval\s*\(',  # Code evaluation
            r'exec\s*\(',  # Code execution
            r'system\s*\(',  # System calls
        ]
    
    def validate_request_content(
        self,
        content: str,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> bool:
        """Validate request content for suspicious patterns.
        
        Args:
            content: Request content to validate
            client_ip: Client IP for logging
            user_agent: User agent for logging
            
        Returns:
            bool: True if content is safe, False if suspicious
        """
        if not isinstance(content, str):
            return True
        
        content_lower = content.lower()
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, content_lower):
                self.security_logger.log_suspicious_request(
                    f"Suspicious pattern detected: {pattern}",
                    {"pattern": pattern, "content_snippet": content[:200]},
                    client_ip=client_ip,
                    user_agent=user_agent
                )
                return False
        
        return True
    
    def validate_json_rpc_request(
        self,
        request_data: Dict[str, Any],
        client_ip: Optional[str] = None
    ) -> bool:
        """Validate JSON-RPC request structure and content.
        
        Args:
            request_data: Parsed JSON-RPC request
            client_ip: Client IP for logging
            
        Returns:
            bool: True if request is valid, False if invalid
        """
        # Check for required JSON-RPC fields
        if not isinstance(request_data, dict):
            self.security_logger.log_suspicious_request(
                "Invalid JSON-RPC format: not a dictionary",
                {"request_type": type(request_data).__name__},
                client_ip=client_ip
            )
            return False
        
        # Check for excessively large requests
        if len(str(request_data)) > 1024 * 1024:  # 1MB limit
            self.security_logger.log_suspicious_request(
                "Request too large",
                {"size": len(str(request_data))},
                client_ip=client_ip
            )
            return False
        
        # Check for deeply nested structures (potential DoS)
        max_depth = 20
        if self._get_dict_depth(request_data) > max_depth:
            self.security_logger.log_suspicious_request(
                "Request too deeply nested",
                {"max_depth": max_depth},
                client_ip=client_ip
            )
            return False
        
        return True
    
    def _get_dict_depth(self, obj: Any, depth: int = 0) -> int:
        """Calculate maximum nesting depth of a dictionary/list structure."""
        if depth > 50:  # Prevent infinite recursion
            return depth
        
        if isinstance(obj, dict):
            return max([self._get_dict_depth(v, depth + 1) for v in obj.values()], default=depth)
        elif isinstance(obj, list):
            return max([self._get_dict_depth(item, depth + 1) for item in obj], default=depth)
        else:
            return depth


class MCPSecurityMiddleware:
    """Security middleware for MCP server endpoints."""
    
    def __init__(
        self,
        rate_limit_requests: int = 60,
        rate_limit_window: int = 60,
        enable_request_validation: bool = True,
        allowed_origins: Optional[Set[str]] = None
    ):
        """Initialize security middleware.
        
        Args:
            rate_limit_requests: Max requests per window
            rate_limit_window: Rate limit window in seconds
            enable_request_validation: Enable request content validation
            allowed_origins: Set of allowed origins for CORS
        """
        self.rate_limiter = RateLimiter(rate_limit_requests, rate_limit_window)
        self.validator = MCPSecurityValidator()
        self.enable_request_validation = enable_request_validation
        self.allowed_origins = allowed_origins or {"http://localhost", "http://127.0.0.1"}
        self.security_logger = SecurityEventLogger()
    
    def validate_request(
        self,
        request_body: str,
        headers: Dict[str, str],
        client_ip: str
    ) -> Dict[str, Any]:
        """Validate incoming request.
        
        Args:
            request_body: Request body content
            headers: Request headers
            client_ip: Client IP address
            
        Returns:
            Dict with validation results
        """
        result = {
            "allowed": True,
            "reason": None,
            "status_code": 200,
            "response_headers": {}
        }
        
        # Rate limiting
        if not self.rate_limiter.is_allowed(client_ip):
            remaining_requests = self.rate_limiter.get_remaining_requests(client_ip)
            self.security_logger.log_rate_limit_violation(
                client_ip, "mcp_endpoint", 0, self.rate_limiter.max_requests
            )
            
            result.update({
                "allowed": False,
                "reason": "Rate limit exceeded",
                "status_code": 429,
                "response_headers": {
                    "Retry-After": str(self.rate_limiter.window_seconds),
                    "X-RateLimit-Remaining": str(remaining_requests)
                }
            })
            return result
        
        # Content validation
        if self.enable_request_validation:
            user_agent = headers.get("user-agent", "")
            
            if not self.validator.validate_request_content(request_body, client_ip, user_agent):
                result.update({
                    "allowed": False,
                    "reason": "Suspicious content detected",
                    "status_code": 400
                })
                return result
        
        # CORS validation
        origin = headers.get("origin", "")
        if origin and origin not in self.allowed_origins:
            self.security_logger.log_suspicious_request(
                "Disallowed origin",
                {"origin": origin, "allowed_origins": list(self.allowed_origins)},
                client_ip=client_ip
            )
            
            result.update({
                "allowed": False,
                "reason": "Origin not allowed",
                "status_code": 403
            })
            return result
        
        # Add security headers
        result["response_headers"].update({
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin"
        })
        
        return result


def create_security_config(
    enable_rate_limiting: bool = True,
    rate_limit_requests: int = 100,
    rate_limit_window: int = 60,
    enable_request_validation: bool = True,
    allowed_origins: Optional[Set[str]] = None,
    log_level: str = "INFO"
) -> Dict[str, Any]:
    """Create security configuration for MCP server.
    
    Args:
        enable_rate_limiting: Enable rate limiting
        rate_limit_requests: Max requests per window
        rate_limit_window: Rate limit window in seconds
        enable_request_validation: Enable request validation
        allowed_origins: Allowed origins for CORS
        log_level: Security logging level
        
    Returns:
        Security configuration dictionary
    """
    return {
        "enable_rate_limiting": enable_rate_limiting,
        "rate_limit_requests": rate_limit_requests,
        "rate_limit_window": rate_limit_window,
        "enable_request_validation": enable_request_validation,
        "allowed_origins": allowed_origins or {"http://localhost", "http://127.0.0.1"},
        "log_level": log_level
    }
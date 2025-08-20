"""Security utilities for MCP Atlassian.

This module provides security-related functions including input validation,
sanitization, and security checks to prevent injection attacks and other
security vulnerabilities.
"""

import logging
import re
from typing import Any, Optional
from urllib.parse import urlparse, quote

logger = logging.getLogger("mcp-atlassian.security")

# JQL injection patterns to block
JQL_DANGEROUS_PATTERNS = [
    r"(?i)(script|javascript|onerror|onclick|onload|eval|alert|document\.|window\.)",  # XSS attempts
    r"(?i)(exec|system|eval|__import__|compile|globals|locals|vars|dir)",  # Python injection
    r"(?i)(\-\-|\;|\/\*|\*\/|xp_|sp_|exec\s|execute\s)",  # SQL injection patterns
    r"(?i)(\.\.\/|\.\.\\|%2e%2e|%252e%252e)",  # Path traversal
    r"(?i)(<\s*script|<\s*iframe|<\s*object|<\s*embed)",  # HTML injection
    r"(?i)(\$\{|\#\{|%\{)",  # Template injection
]

# URL validation patterns
SAFE_URL_SCHEMES = ["http", "https"]
ATLASSIAN_DOMAINS = [
    "atlassian.net",
    "atlassian.com", 
    "jira.com",
    "confluence.com",
    "statuspage.io",
    "trello.com"
]


class SecurityError(Exception):
    """Base exception for security-related errors."""
    pass


class InputValidationError(SecurityError):
    """Exception raised when input validation fails."""
    pass


def validate_jql_query(jql: str, max_length: int = 10000) -> str:
    """Validate and sanitize a JQL query to prevent injection attacks.
    
    Args:
        jql: The JQL query string to validate
        max_length: Maximum allowed length for the query
        
    Returns:
        The validated JQL query
        
    Raises:
        InputValidationError: If the JQL query contains dangerous patterns
    """
    if not jql:
        return ""
    
    # Check length
    if len(jql) > max_length:
        raise InputValidationError(
            f"JQL query exceeds maximum length of {max_length} characters"
        )
    
    # Check for dangerous patterns
    for pattern in JQL_DANGEROUS_PATTERNS:
        if re.search(pattern, jql):
            logger.error(f"Potentially dangerous JQL pattern detected: {pattern}")
            raise InputValidationError(
                "JQL query contains potentially dangerous patterns"
            )
    
    # Check for balanced quotes and parentheses
    if jql.count('"') % 2 != 0:
        raise InputValidationError("JQL query has unbalanced quotes")
    
    if jql.count('(') != jql.count(')'):
        raise InputValidationError("JQL query has unbalanced parentheses")
    
    # Warn if query contains unusual characters
    unusual_chars = re.findall(r'[^\w\s\-\.\,\(\)\"\'\=\!\<\>\:\~\@\[\]]', jql)
    if unusual_chars:
        logger.warning(f"JQL query contains unusual characters: {set(unusual_chars)}")
    
    return jql


def validate_cql_query(cql: str, max_length: int = 10000) -> str:
    """Validate and sanitize a CQL (Confluence Query Language) query.
    
    Args:
        cql: The CQL query string to validate
        max_length: Maximum allowed length for the query
        
    Returns:
        The validated CQL query
        
    Raises:
        InputValidationError: If the CQL query contains dangerous patterns
    """
    # CQL uses similar validation to JQL
    return validate_jql_query(cql, max_length)


def sanitize_html_content(content: str, allow_basic_formatting: bool = True) -> str:
    """Sanitize HTML content to prevent XSS attacks.
    
    Args:
        content: The HTML content to sanitize
        allow_basic_formatting: Whether to allow basic formatting tags
        
    Returns:
        Sanitized HTML content
    """
    if not content:
        return ""
    
    # Remove script tags and their content
    content = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.DOTALL | re.IGNORECASE)
    
    # Remove event handlers
    content = re.sub(r'\s*on\w+\s*=\s*["\'][^"\']*["\']', '', content, flags=re.IGNORECASE)
    content = re.sub(r'\s*on\w+\s*=\s*[^\s>]+', '', content, flags=re.IGNORECASE)
    
    # Remove javascript: protocol
    content = re.sub(r'javascript:', '', content, flags=re.IGNORECASE)
    
    # Remove data: URLs that could contain scripts
    content = re.sub(r'data:text/html[^"\']*', '', content, flags=re.IGNORECASE)
    
    if not allow_basic_formatting:
        # Strip all HTML tags
        content = re.sub(r'<[^>]+>', '', content)
    else:
        # Remove dangerous tags but keep basic formatting
        dangerous_tags = ['iframe', 'object', 'embed', 'form', 'input', 'button', 'meta', 'link', 'base']
        for tag in dangerous_tags:
            content = re.sub(f'<{tag}[^>]*>.*?</{tag}>', '', content, flags=re.DOTALL | re.IGNORECASE)
            content = re.sub(f'<{tag}[^>]*/?>', '', content, flags=re.IGNORECASE)
    
    return content


def validate_url(url: str, allowed_domains: Optional[list[str]] = None) -> str:
    """Validate a URL to ensure it's safe to use.
    
    Args:
        url: The URL to validate
        allowed_domains: Optional list of allowed domains
        
    Returns:
        The validated URL
        
    Raises:
        InputValidationError: If the URL is invalid or potentially dangerous
    """
    if not url:
        raise InputValidationError("URL cannot be empty")
    
    try:
        parsed = urlparse(url)
    except Exception as e:
        raise InputValidationError(f"Invalid URL format: {e}")
    
    # Check scheme
    if parsed.scheme not in SAFE_URL_SCHEMES:
        raise InputValidationError(
            f"URL scheme '{parsed.scheme}' not allowed. Must be one of {SAFE_URL_SCHEMES}"
        )
    
    # Check for localhost/private IPs (prevent SSRF)
    if parsed.hostname:
        hostname_lower = parsed.hostname.lower()
        if hostname_lower in ['localhost', '127.0.0.1', '0.0.0.0', '::1']:
            raise InputValidationError("URLs pointing to localhost are not allowed")
        
        # Check for private IP ranges
        if re.match(r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)', hostname_lower):
            raise InputValidationError("URLs pointing to private IP addresses are not allowed")
    
    # Check against allowed domains if specified
    if allowed_domains and parsed.hostname:
        if not any(parsed.hostname.endswith(domain) for domain in allowed_domains):
            raise InputValidationError(
                f"URL domain '{parsed.hostname}' not in allowed list"
            )
    
    return url


def validate_atlassian_url(url: str) -> str:
    """Validate that a URL is a legitimate Atlassian URL.
    
    Args:
        url: The URL to validate
        
    Returns:
        The validated URL
        
    Raises:
        InputValidationError: If the URL is not a valid Atlassian URL
    """
    parsed = urlparse(validate_url(url))
    
    if not parsed.hostname:
        raise InputValidationError("URL must have a hostname")
    
    # Allow any subdomain of Atlassian domains
    is_atlassian = any(
        parsed.hostname.endswith(f".{domain}") or parsed.hostname == domain
        for domain in ATLASSIAN_DOMAINS
    )
    
    # Also allow custom/self-hosted instances if they don't look suspicious
    if not is_atlassian:
        # Log for monitoring but don't block - could be self-hosted
        logger.info(f"Non-Atlassian domain detected: {parsed.hostname}")
        
        # Still check for obvious issues
        if len(parsed.hostname) > 255:
            raise InputValidationError("Hostname too long")
        
        # Check for suspicious patterns in custom domains
        suspicious_patterns = [
            r'[^a-zA-Z0-9\-\.]',  # Non-standard characters
            r'\.\.+',  # Multiple dots
            r'^-|-$',  # Leading/trailing hyphens
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, parsed.hostname):
                raise InputValidationError(f"Suspicious hostname pattern: {pattern}")
    
    return url


def sanitize_filename(filename: str, max_length: int = 255) -> str:
    """Sanitize a filename to prevent path traversal and other attacks.
    
    Args:
        filename: The filename to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized filename
    """
    if not filename:
        return "unnamed"
    
    # Remove path components
    filename = filename.replace('/', '_').replace('\\', '_')
    filename = filename.replace('..', '_')
    
    # Remove null bytes
    filename = filename.replace('\x00', '')
    
    # Remove control characters
    filename = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', filename)
    
    # Limit length
    if len(filename) > max_length:
        # Keep extension if present
        parts = filename.rsplit('.', 1)
        if len(parts) == 2 and len(parts[1]) <= 10:
            base = parts[0][:max_length - len(parts[1]) - 1]
            filename = f"{base}.{parts[1]}"
        else:
            filename = filename[:max_length]
    
    # Ensure filename is not empty after sanitization
    if not filename or filename == '.':
        filename = "unnamed"
    
    return filename


def validate_field_name(field_name: str, max_length: int = 255) -> str:
    """Validate a field name to prevent injection attacks.
    
    Args:
        field_name: The field name to validate
        max_length: Maximum allowed length
        
    Returns:
        Validated field name
        
    Raises:
        InputValidationError: If the field name is invalid
    """
    if not field_name:
        raise InputValidationError("Field name cannot be empty")
    
    if len(field_name) > max_length:
        raise InputValidationError(f"Field name exceeds maximum length of {max_length}")
    
    # Allow only alphanumeric, underscore, dash, and dot
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', field_name):
        raise InputValidationError(
            "Field name can only contain letters, numbers, underscore, dash, and dot"
        )
    
    # Check for suspicious patterns
    suspicious = ['__', '..', '--', 'eval', 'exec', 'system']
    for pattern in suspicious:
        if pattern in field_name.lower():
            raise InputValidationError(f"Field name contains suspicious pattern: {pattern}")
    
    return field_name


def mask_sensitive_data(data: Any, fields_to_mask: Optional[list[str]] = None) -> Any:
    """Recursively mask sensitive data in dictionaries and lists.
    
    Args:
        data: The data structure to mask
        fields_to_mask: List of field names to mask (defaults to common sensitive fields)
        
    Returns:
        Data with sensitive fields masked
    """
    if fields_to_mask is None:
        fields_to_mask = [
            'password', 'token', 'secret', 'api_key', 'apikey', 
            'auth', 'authorization', 'credential', 'private_key',
            'access_token', 'refresh_token', 'client_secret'
        ]
    
    fields_to_mask_lower = [f.lower() for f in fields_to_mask]
    
    if isinstance(data, dict):
        masked = {}
        for key, value in data.items():
            key_lower = key.lower()
            if any(field in key_lower for field in fields_to_mask_lower):
                masked[key] = "***REDACTED***"
            else:
                masked[key] = mask_sensitive_data(value, fields_to_mask)
        return masked
    elif isinstance(data, list):
        return [mask_sensitive_data(item, fields_to_mask) for item in data]
    else:
        return data


def validate_project_key(key: str) -> str:
    """Validate a Jira project key.
    
    Args:
        key: The project key to validate
        
    Returns:
        Validated project key
        
    Raises:
        InputValidationError: If the project key is invalid
    """
    if not key:
        raise InputValidationError("Project key cannot be empty")
    
    # Jira project keys are typically 2-10 uppercase letters
    if not re.match(r'^[A-Z]{2,10}$', key):
        raise InputValidationError(
            "Project key must be 2-10 uppercase letters"
        )
    
    return key


def validate_issue_key(key: str) -> str:
    """Validate a Jira issue key.
    
    Args:
        key: The issue key to validate
        
    Returns:
        Validated issue key
        
    Raises:
        InputValidationError: If the issue key is invalid
    """
    if not key:
        raise InputValidationError("Issue key cannot be empty")
    
    # Jira issue keys are typically PROJECT-NUMBER
    if not re.match(r'^[A-Z]{2,10}-\d{1,10}$', key):
        raise InputValidationError(
            "Issue key must be in format PROJECT-NUMBER (e.g., PROJ-123)"
        )
    
    return key
"""Helper utilities — shared functions used across modules.

Provides:
- YAML config loading
- String manipulation
- Secret masking
- File operations
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml

from src.utils.logger import get_logger

logger = get_logger(__name__)


def load_yaml_config(config_path: Path) -> dict[str, Any]:
    """Load a YAML configuration file.

    Args:
        config_path: Path to the YAML file.

    Returns:
        Parsed YAML as dict.

    Raises:
        FileNotFoundError: If config file doesn't exist.
        yaml.YAMLError: If YAML is invalid.
    """
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path) as f:
        config = yaml.safe_load(f)

    logger.debug("Loaded YAML config", path=str(config_path))
    return config or {}


def mask_secret(secret: str, visible_chars: int = 4) -> str:
    """Mask a secret string for safe logging.

    Args:
        secret: The secret to mask.
        visible_chars: Number of characters to show at start and end.

    Returns:
        Masked secret string.

    Examples:
        >>> mask_secret("sk-1234567890abcdef")
        "sk-1************cdef"
        >>> mask_secret("short")
        "*****"
    """
    if not secret:
        return ""

    if len(secret) <= visible_chars * 2:
        return "*" * len(secret)

    return f"{secret[:visible_chars]}{'*' * (len(secret) - visible_chars * 2)}{secret[-visible_chars:]}"


def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate a string to a maximum length.

    Args:
        text: String to truncate.
        max_length: Maximum length (including suffix).
        suffix: Suffix to add if truncated.

    Returns:
        Truncated string.
    """
    if len(text) <= max_length:
        return text

    return text[: max_length - len(suffix)] + suffix


def generate_hash(*args: str) -> str:
    """Generate a deterministic hash from string arguments.

    Args:
        *args: String arguments to hash.

    Returns:
        16-character hex hash.
    """
    combined = ":".join(args)
    return hashlib.sha256(combined.encode()).hexdigest()[:16]


def safe_read_file(file_path: Path, encoding: str = "utf-8") -> str | None:
    """Safely read a file, returning None on error.

    Args:
        file_path: Path to the file.
        encoding: File encoding.

    Returns:
        File content or None if read failed.
    """
    try:
        return file_path.read_text(encoding=encoding)
    except Exception as e:
        logger.warning("Failed to read file", path=str(file_path), error=str(e))
        return None


def safe_write_file(file_path: Path, content: str, encoding: str = "utf-8") -> bool:
    """Safely write to a file, returning success status.

    Args:
        file_path: Path to the file.
        content: Content to write.
        encoding: File encoding.

    Returns:
        True if write succeeded.
    """
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding=encoding)
        return True
    except Exception as e:
        logger.error("Failed to write file", path=str(file_path), error=str(e))
        return False


def parse_severity_threshold(threshold: str) -> int:
    """Parse severity threshold string to numeric weight.

    Args:
        threshold: Severity string (critical, high, medium, low, info).

    Returns:
        Numeric weight for comparison.
    """
    weights = {
        "critical": 10,
        "high": 8,
        "medium": 5,
        "low": 2,
        "info": 1,
    }
    return weights.get(threshold.lower(), 5)


def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format.

    Args:
        size_bytes: Size in bytes.

    Returns:
        Formatted size string (e.g., "1.5 MB").
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


def extract_cve_from_text(text: str) -> list[str]:
    """Extract CVE identifiers from text.

    Args:
        text: Text to search.

    Returns:
        List of CVE identifiers found.
    """
    import re

    pattern = r"CVE-\d{4}-\d{4,}"
    return re.findall(pattern, text)


def extract_cwe_from_text(text: str) -> list[str]:
    """Extract CWE identifiers from text.

    Args:
        text: Text to search.

    Returns:
        List of CWE identifiers found.
    """
    import re

    pattern = r"CWE-\d+"
    return re.findall(pattern, text)
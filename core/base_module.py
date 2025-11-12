"""
Base module class for all vulnerability scanner modules
Each module is completely independent and self-contained
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
import os
import json
from core.logger import get_logger

logger = get_logger(__name__)


class BaseModule(ABC):
    """
    Base class for all scanner modules

    Each module must:
    1. Load payloads from TXT files
    2. Load detection patterns from TXT files
    3. Implement scan() method
    4. Return standardized results
    """

    def __init__(self, module_path: str):
        """
        Initialize module

        Args:
            module_path: Path to module directory (e.g., "modules/xss")
        """
        self.module_path = module_path
        self.name = os.path.basename(module_path)

        # Load configuration
        self.config = self._load_config()

        # Load payloads and patterns from TXT files
        self.payloads = self._load_payloads()
        self.patterns = self._load_patterns()
        self.indicators = self._load_indicators()

        logger.info(f"Module '{self.name}' initialized: {len(self.payloads)} payloads, {len(self.patterns)} patterns")

    def _load_config(self) -> Dict[str, Any]:
        """Load module configuration from config.json"""
        config_path = os.path.join(self.module_path, "config.json")

        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    logger.debug(f"Loaded config for module '{self.name}'")
                    return config
            except Exception as e:
                logger.warning(f"Error loading config for '{self.name}': {e}")

        # Default config
        return {
            "name": self.name.upper(),
            "description": f"{self.name} vulnerability scanner",
            "severity": "Medium",
            "enabled": True,
            "max_payloads": 100,
            "timeout": 20
        }

    def _load_txt_file(self, filename: str) -> List[str]:
        """
        Load lines from TXT file

        Args:
            filename: Name of file in module directory

        Returns:
            List of non-empty lines
        """
        file_path = os.path.join(self.module_path, filename)

        if not os.path.exists(file_path):
            logger.warning(f"File not found: {file_path}")
            return []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                logger.debug(f"Loaded {len(lines)} lines from {filename}")
                return lines
        except Exception as e:
            logger.error(f"Error reading {file_path}: {e}")
            return []

    def _load_payloads(self) -> List[str]:
        """Load payloads from payloads.txt"""
        payloads = self._load_txt_file("payloads.txt")

        # Limit payloads based on config
        max_payloads = self.config.get("max_payloads", 100)
        if len(payloads) > max_payloads:
            logger.warning(f"Limiting payloads from {len(payloads)} to {max_payloads}")
            payloads = payloads[:max_payloads]

        return payloads

    def _load_patterns(self) -> List[str]:
        """Load detection patterns from patterns.txt"""
        return self._load_txt_file("patterns.txt")

    def _load_indicators(self) -> List[str]:
        """Load success indicators from indicators.txt (optional)"""
        return self._load_txt_file("indicators.txt")

    @abstractmethod
    def scan(self, targets: List[Dict[str, Any]], http_client: Any) -> List[Dict[str, Any]]:
        """
        Scan targets for vulnerabilities

        Args:
            targets: List of target URLs with parameters
                [
                    {
                        'url': 'http://example.com/page.php',
                        'params': {'id': '1', 'name': 'test'}
                    }
                ]
            http_client: HTTP client instance for making requests

        Returns:
            List of results
                [
                    {
                        'vulnerability': True,
                        'type': 'XSS',
                        'severity': 'High',
                        'url': 'http://...',
                        'parameter': 'id',
                        'payload': '<script>...',
                        'evidence': '...',
                        'description': '...'
                    }
                ]
        """
        pass

    def is_enabled(self) -> bool:
        """Check if module is enabled"""
        return self.config.get("enabled", True)

    def get_name(self) -> str:
        """Get module name"""
        return self.config.get("name", self.name.upper())

    def get_description(self) -> str:
        """Get module description"""
        return self.config.get("description", "")

    def get_severity(self) -> str:
        """Get default severity level"""
        return self.config.get("severity", "Medium")

    def extract_response_context(self, response_text: str, trigger: str,
                                 chars_before: int = 100, chars_after: int = 50) -> str:
        """
        Extract response context around trigger with highlighting

        Args:
            response_text: Full response text
            trigger: The trigger/payload to find
            chars_before: Characters to show before trigger (default 100)
            chars_after: Characters to show after trigger (default 50)

        Returns:
            Context string with **trigger** highlighted
        """
        try:
            if not trigger or not response_text:
                return ""

            # Find trigger position (case insensitive)
            trigger_lower = trigger.lower()
            response_lower = response_text.lower()

            pos = response_lower.find(trigger_lower)
            if pos == -1:
                return ""

            # Extract context
            start = max(0, pos - chars_before)
            end = min(len(response_text), pos + len(trigger) + chars_after)

            context = response_text[start:end]

            # Highlight the trigger by wrapping it with **
            # Find trigger in context (case insensitive)
            context_lower = context.lower()
            trigger_pos = context_lower.find(trigger_lower)

            if trigger_pos != -1:
                # Preserve original case of trigger in context
                actual_trigger = context[trigger_pos:trigger_pos + len(trigger)]
                context = (context[:trigger_pos] +
                          f"**{actual_trigger}**" +
                          context[trigger_pos + len(trigger):])

            return context

        except Exception as e:
            logger.debug(f"Error extracting response context: {e}")
            return ""

    def create_result(self, vulnerable: bool = False, url: str = "", parameter: str = "",
                     payload: str = "", evidence: str = "", description: str = "",
                     **kwargs) -> Dict[str, Any]:
        """
        Create standardized result dictionary

        Args:
            vulnerable: Whether vulnerability was found
            url: Target URL
            parameter: Vulnerable parameter
            payload: Payload used
            evidence: Evidence of vulnerability
            description: Description
            **kwargs: Additional fields

        Returns:
            Standardized result dictionary
        """
        result = {
            'vulnerability': vulnerable,
            'type': self.get_name(),
            'severity': self.get_severity(),
            'url': url,
            'parameter': parameter,
            'payload': payload,
            'evidence': evidence,
            'description': description or self.get_description(),
            'module': self.name
        }

        # Add any additional fields
        result.update(kwargs)

        return result

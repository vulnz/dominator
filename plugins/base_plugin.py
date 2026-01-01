"""
Base Plugin Interface for Dominator Third-Party Tool Integration

Provides a common interface for integrating external security tools.
All third-party plugins should inherit from BasePlugin.
"""

import subprocess
import shutil
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class PluginResult:
    """Standardized result format for all plugins"""
    # Core fields (required)
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    url: str
    module: str  # Plugin name

    # Classification
    cwe: str = ""
    cwe_name: str = ""
    owasp: str = ""
    owasp_name: str = ""
    cvss: str = ""
    cvss_vector: str = ""

    # Details
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    # HTTP Details
    parameter: str = ""
    payload: str = ""
    method: str = ""
    request: str = ""
    response: str = ""

    # Plugin-specific
    plugin_name: str = ""  # Source plugin (wpscan, nuclei, etc.)
    plugin_category: str = "third-party"  # Always third-party for plugins
    raw_finding: Dict[str, Any] = field(default_factory=dict)

    # Metadata
    confidence: str = "high"
    verified: bool = False
    timestamp: str = ""
    tags: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)

    def to_finding_format(self) -> Dict[str, Any]:
        """Convert to Dominator finding format for unified reporting"""
        return {
            'type': self.title,
            'severity': self.severity,
            'url': self.url,
            'module': f"[{self.plugin_name}] {self.module}",
            'description': self.description,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'cwe': self.cwe,
            'cwe_name': self.cwe_name,
            'owasp': self.owasp,
            'owasp_name': self.owasp_name,
            'cvss': self.cvss,
            'cvss_vector': self.cvss_vector,
            'parameter': self.parameter,
            'payload': self.payload,
            'method': self.method,
            'request': self.request,
            'response': self.response,
            'references': self.references,
            'confidence': self.confidence,
            'verified': self.verified,
            'tags': self.tags + [f'plugin:{self.plugin_name}', 'third-party'],
            'source': 'third-party',
            'plugin': self.plugin_name,
            'timestamp': self.timestamp
        }


class BasePlugin(ABC):
    """Base class for all third-party plugins"""

    # Plugin metadata (override in subclasses)
    NAME = "base_plugin"
    DISPLAY_NAME = "Base Plugin"
    VERSION = "1.0.0"
    AUTHOR = "Dominator Team"
    DESCRIPTION = "Base plugin class"
    CATEGORY = "Utility"
    EXECUTABLE = ""  # The command-line tool name

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.enabled = True
        self.results: List[PluginResult] = []
        self.errors: List[str] = []
        self._executable_path: Optional[str] = None

    @property
    def is_available(self) -> bool:
        """Check if the plugin's executable is available"""
        if self._executable_path:
            return True
        self._executable_path = shutil.which(self.EXECUTABLE)
        return self._executable_path is not None

    def get_executable(self) -> Optional[str]:
        """Get the path to the plugin executable"""
        if not self._executable_path:
            self._executable_path = shutil.which(self.EXECUTABLE)
        return self._executable_path

    @abstractmethod
    def should_run(self, target_profile: Dict[str, Any]) -> bool:
        """
        Determine if this plugin should run based on target profile.

        Args:
            target_profile: Target profiling data (technologies, CMS, etc.)

        Returns:
            True if plugin should run, False otherwise
        """
        pass

    @abstractmethod
    def run(self, target: str, options: Dict[str, Any] = None) -> List[PluginResult]:
        """
        Run the plugin against a target.

        Args:
            target: Target URL or host
            options: Additional options for the plugin

        Returns:
            List of PluginResult findings
        """
        pass

    @abstractmethod
    def parse_output(self, output: str, target: str) -> List[PluginResult]:
        """
        Parse the plugin output into standardized results.

        Args:
            output: Raw output from the plugin (usually JSON)
            target: Target URL for context

        Returns:
            List of PluginResult findings
        """
        pass

    def run_command(self, args: List[str], timeout: int = 300) -> tuple:
        """
        Execute a command and return output.

        Args:
            args: Command arguments
            timeout: Timeout in seconds

        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        try:
            # Hide console window on Windows
            import sys
            kwargs = {
                'capture_output': True,
                'text': True,
                'timeout': timeout,
                'encoding': 'utf-8',
                'errors': 'ignore'
            }
            if sys.platform == 'win32':
                kwargs['creationflags'] = 0x08000000  # CREATE_NO_WINDOW
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = 0
                kwargs['startupinfo'] = startupinfo

            result = subprocess.run(args, **kwargs)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            self.errors.append(f"Command timed out after {timeout}s")
            return "", f"Timeout after {timeout}s", -1
        except Exception as e:
            self.errors.append(f"Command error: {e}")
            return "", str(e), -1

    def get_info(self) -> Dict[str, Any]:
        """Get plugin information"""
        return {
            'name': self.NAME,
            'display_name': self.DISPLAY_NAME,
            'version': self.VERSION,
            'author': self.AUTHOR,
            'description': self.DESCRIPTION,
            'category': self.CATEGORY,
            'executable': self.EXECUTABLE,
            'available': self.is_available,
            'enabled': self.enabled
        }


class PluginManager:
    """Manages all third-party plugins"""

    def __init__(self):
        self.plugins: Dict[str, BasePlugin] = {}
        self._load_plugins()

    def _load_plugins(self):
        """Load all available plugins"""
        from .wpscan_plugin import WPScanPlugin
        from .nuclei_plugin import NucleiPlugin

        # Register plugins
        plugins = [
            WPScanPlugin(),
            NucleiPlugin(),
        ]

        for plugin in plugins:
            self.plugins[plugin.NAME] = plugin
            logger.info(f"Loaded plugin: {plugin.DISPLAY_NAME} v{plugin.VERSION}")

    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """Get a plugin by name"""
        return self.plugins.get(name)

    def get_available_plugins(self) -> List[Dict[str, Any]]:
        """Get list of all available plugins with their info"""
        return [p.get_info() for p in self.plugins.values()]

    def get_applicable_plugins(self, target_profile: Dict[str, Any]) -> List[BasePlugin]:
        """Get plugins that should run based on target profile"""
        applicable = []
        for plugin in self.plugins.values():
            if plugin.enabled and plugin.is_available:
                if plugin.should_run(target_profile):
                    applicable.append(plugin)
                    logger.info(f"Plugin {plugin.NAME} is applicable for target")
        return applicable

    def run_applicable_plugins(self, target: str, target_profile: Dict[str, Any],
                                options: Dict[str, Any] = None) -> List[PluginResult]:
        """Run all applicable plugins and collect results"""
        all_results = []
        applicable = self.get_applicable_plugins(target_profile)

        for plugin in applicable:
            logger.info(f"Running plugin: {plugin.DISPLAY_NAME}")
            try:
                results = plugin.run(target, options)
                all_results.extend(results)
                logger.info(f"Plugin {plugin.NAME} found {len(results)} findings")
            except Exception as e:
                logger.error(f"Plugin {plugin.NAME} failed: {e}")

        return all_results

    def enable_plugin(self, name: str) -> bool:
        """Enable a plugin"""
        if name in self.plugins:
            self.plugins[name].enabled = True
            return True
        return False

    def disable_plugin(self, name: str) -> bool:
        """Disable a plugin"""
        if name in self.plugins:
            self.plugins[name].enabled = False
            return True
        return False

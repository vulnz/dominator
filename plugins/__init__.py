"""
Dominator Third-Party Plugins

This package provides integration with external security tools like:
- WPScan (WordPress vulnerability scanner)
- Nuclei (Template-based vulnerability scanner)
- Nmap (Network scanner)

All plugins follow a common interface and their results are parsed
into the Dominator finding format for unified reporting.
"""

from .base_plugin import BasePlugin, PluginResult, PluginManager
from .wpscan_plugin import WPScanPlugin
from .nuclei_plugin import NucleiPlugin

__all__ = [
    'BasePlugin',
    'PluginResult',
    'PluginManager',
    'WPScanPlugin',
    'NucleiPlugin'
]

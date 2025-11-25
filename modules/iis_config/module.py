"""
IIS Configuration Exposure Scanner
Discovers exposed IIS configuration files and Windows-specific misconfigurations
"""

from core.base_module import BaseModule
from core.logger import get_logger
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse
import re

logger = get_logger(__name__)


class IISConfigScanner(BaseModule):
    """Scans for IIS configuration exposure and Windows server misconfigurations"""

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        self.module_name = "IIS Config Scanner"
        self.logger = logger

        # IIS-specific sensitive files
        self.sensitive_files = [
            # Web.config files
            {'path': '/web.config', 'risk': 'Critical', 'type': 'config', 'desc': 'Main IIS configuration file'},
            {'path': '/Web.config', 'risk': 'Critical', 'type': 'config', 'desc': 'Main IIS configuration file'},
            {'path': '/WEB.CONFIG', 'risk': 'Critical', 'type': 'config', 'desc': 'Main IIS configuration file'},

            # Common app directories
            {'path': '/App_Data/web.config', 'risk': 'Critical', 'type': 'config', 'desc': 'App_Data config'},
            {'path': '/bin/web.config', 'risk': 'High', 'type': 'config', 'desc': 'Bin directory config'},

            # ASP.NET specific
            {'path': '/global.asax', 'risk': 'Medium', 'type': 'source', 'desc': 'ASP.NET application file'},
            {'path': '/Global.asax', 'risk': 'Medium', 'type': 'source', 'desc': 'ASP.NET application file'},
            {'path': '/machine.config', 'risk': 'Critical', 'type': 'config', 'desc': 'Machine-wide .NET config'},

            # Connection strings and app settings
            {'path': '/connectionstrings.config', 'risk': 'Critical', 'type': 'secrets', 'desc': 'Database connection strings'},
            {'path': '/appsettings.config', 'risk': 'High', 'type': 'secrets', 'desc': 'Application settings'},
            {'path': '/appsettings.json', 'risk': 'High', 'type': 'secrets', 'desc': '.NET Core settings'},
            {'path': '/appsettings.Development.json', 'risk': 'High', 'type': 'secrets', 'desc': 'Development settings'},
            {'path': '/appsettings.Production.json', 'risk': 'Critical', 'type': 'secrets', 'desc': 'Production settings'},

            # Backup and temp config files
            {'path': '/web.config.bak', 'risk': 'Critical', 'type': 'backup', 'desc': 'Backup config file'},
            {'path': '/web.config.old', 'risk': 'Critical', 'type': 'backup', 'desc': 'Old config file'},
            {'path': '/web.config.txt', 'risk': 'Critical', 'type': 'backup', 'desc': 'Text copy of config'},
            {'path': '/web.config~', 'risk': 'Critical', 'type': 'backup', 'desc': 'Editor backup config'},
            {'path': '/web.config.save', 'risk': 'Critical', 'type': 'backup', 'desc': 'Saved config file'},
            {'path': '/_web.config', 'risk': 'Critical', 'type': 'backup', 'desc': 'Hidden config file'},

            # IIS metadata
            {'path': '/_vti_inf.html', 'risk': 'Low', 'type': 'info', 'desc': 'FrontPage extensions info'},
            {'path': '/_vti_bin/', 'risk': 'Medium', 'type': 'info', 'desc': 'FrontPage bin directory'},
            {'path': '/_vti_pvt/', 'risk': 'High', 'type': 'info', 'desc': 'FrontPage private directory'},
            {'path': '/_vti_cnf/', 'risk': 'Medium', 'type': 'info', 'desc': 'FrontPage config directory'},
            {'path': '/_vti_log/', 'risk': 'Medium', 'type': 'info', 'desc': 'FrontPage log directory'},
            {'path': '/_vti_txt/', 'risk': 'Medium', 'type': 'info', 'desc': 'FrontPage text directory'},

            # ASP/ASPX source disclosure
            {'path': '/default.asp', 'risk': 'Low', 'type': 'info', 'desc': 'Default ASP page'},
            {'path': '/default.aspx', 'risk': 'Low', 'type': 'info', 'desc': 'Default ASPX page'},
            {'path': '/iisstart.htm', 'risk': 'Info', 'type': 'info', 'desc': 'Default IIS start page'},
            {'path': '/iisstart.asp', 'risk': 'Info', 'type': 'info', 'desc': 'Default IIS start page'},

            # Short filename (8.3) disclosure
            {'path': '/web~1.con', 'risk': 'High', 'type': 'shortname', 'desc': 'Short filename for web.config'},
            {'path': '/WEB~1.CON', 'risk': 'High', 'type': 'shortname', 'desc': 'Short filename for web.config'},

            # Trace and debug
            {'path': '/trace.axd', 'risk': 'High', 'type': 'debug', 'desc': 'ASP.NET trace handler'},
            {'path': '/elmah.axd', 'risk': 'High', 'type': 'debug', 'desc': 'ELMAH error logging'},
            {'path': '/ScriptResource.axd', 'risk': 'Low', 'type': 'info', 'desc': 'Script resource handler'},
            {'path': '/WebResource.axd', 'risk': 'Low', 'type': 'info', 'desc': 'Web resource handler'},

            # Glimpse and diagnostics
            {'path': '/glimpse.axd', 'risk': 'High', 'type': 'debug', 'desc': 'Glimpse diagnostics'},
            {'path': '/miniprofiler-resources/', 'risk': 'Medium', 'type': 'debug', 'desc': 'MiniProfiler resources'},

            # Exchange/SharePoint specific
            {'path': '/ews/', 'risk': 'Medium', 'type': 'info', 'desc': 'Exchange Web Services'},
            {'path': '/autodiscover/autodiscover.xml', 'risk': 'Medium', 'type': 'info', 'desc': 'Autodiscover config'},
            {'path': '/_layouts/', 'risk': 'Medium', 'type': 'info', 'desc': 'SharePoint layouts'},

            # IIS virtual directories
            {'path': '/aspnet_client/', 'risk': 'Low', 'type': 'info', 'desc': 'ASP.NET client scripts'},
            {'path': '/scripts/', 'risk': 'Low', 'type': 'info', 'desc': 'Scripts directory'},
        ]

    def scan(self, targets: List[Dict[str, Any]], http_client: Any = None) -> List[Dict[str, Any]]:
        """Scan for IIS configuration exposure"""
        self.logger.info(f"Starting {self.module_name} scan on {len(targets)} targets")

        results = []
        tested_bases = set()

        for target in targets:
            url = target.get('url') if isinstance(target, dict) else target
            if not url:
                continue

            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            if base_url in tested_bases:
                continue
            tested_bases.add(base_url)

            # Test each sensitive file
            for file_info in self.sensitive_files:
                if self.payload_limit and len(results) >= self.payload_limit:
                    break

                test_url = urljoin(base_url, file_info['path'])
                finding = self._test_file(http_client, test_url, file_info, base_url)
                if finding:
                    results.append(finding)

        self.logger.info(f"{self.module_name} scan complete: {len(results)} findings")
        return results

    def _test_file(self, http_client, test_url: str, file_info: dict, base_url: str) -> Dict[str, Any]:
        """Test a specific IIS file/path"""
        try:
            response = http_client.get(test_url)
            if not response or response.status_code == 404:
                return None

            content = response.text
            is_vulnerable = False
            evidence = ""
            severity = file_info['risk']

            if response.status_code == 200:
                # Check for web.config content
                if 'web.config' in file_info['path'].lower():
                    config_indicators = [
                        '<configuration', '<system.web', '<connectionStrings',
                        '<appSettings', '<authentication', '<authorization',
                        'machineKey', '<compilation', '<httpHandlers'
                    ]
                    for indicator in config_indicators:
                        if indicator in content:
                            is_vulnerable = True
                            evidence = f"IIS web.config exposed with '{indicator}' section"
                            severity = 'Critical'

                            # Check for especially sensitive content
                            if 'connectionString' in content.lower():
                                evidence += " - Contains database connection strings!"
                            if 'machineKey' in content:
                                evidence += " - Contains machine key (can forge auth tokens)!"
                            if 'password' in content.lower():
                                evidence += " - Contains passwords!"
                            break

                # Check for trace.axd
                elif 'trace.axd' in file_info['path']:
                    if '<trace' in content.lower() or 'request details' in content.lower():
                        is_vulnerable = True
                        evidence = "ASP.NET trace enabled - exposes request details and stack traces"
                        severity = 'High'

                # Check for ELMAH
                elif 'elmah.axd' in file_info['path']:
                    if 'error log' in content.lower() or '<error' in content.lower():
                        is_vulnerable = True
                        evidence = "ELMAH error log exposed - shows application errors"
                        severity = 'High'

                # Check for global.asax
                elif 'global.asax' in file_info['path'].lower():
                    if '<%' in content or 'Application_' in content:
                        is_vulnerable = True
                        evidence = "Global.asax source code exposed"
                        severity = 'Medium'

                # Check for appsettings.json
                elif 'appsettings' in file_info['path'].lower():
                    if '{' in content and (':' in content or '"' in content):
                        is_vulnerable = True
                        evidence = "Application settings JSON exposed"
                        if 'connectionstring' in content.lower() or 'password' in content.lower():
                            severity = 'Critical'
                            evidence += " - Contains secrets!"

                # FrontPage extensions
                elif '_vti_' in file_info['path']:
                    is_vulnerable = True
                    evidence = "FrontPage extensions found - may allow unauthorized access"

                # Default response for 200 status
                if not is_vulnerable and response.status_code == 200 and len(content) > 0:
                    is_vulnerable = True
                    evidence = f"File accessible ({len(content)} bytes)"
                    if severity in ['Critical', 'High']:
                        severity = 'Medium'  # Downgrade if we can't confirm sensitive content

            elif response.status_code == 403:
                # File exists but forbidden - still useful info
                is_vulnerable = True
                evidence = "File/directory exists (403 Forbidden)"
                severity = 'Info'

            elif response.status_code == 500:
                # Server error might indicate IIS
                if 'iis' in response.text.lower() or 'asp.net' in response.text.lower():
                    is_vulnerable = True
                    evidence = "IIS/ASP.NET error page exposed"
                    severity = 'Low'

            if is_vulnerable:
                return self.create_result(
                    vulnerable=True,
                    url=test_url,
                    parameter='IIS Config',
                    payload=file_info['path'],
                    evidence=evidence,
                    severity=severity,
                    method='GET',
                    additional_info={
                        'injection_type': f'IIS {file_info["type"].upper()} Exposure',
                        'file_type': file_info['type'],
                        'description': file_info['desc'],
                        'status_code': response.status_code,
                        'cwe': self._get_cwe(file_info['type']),
                        'owasp': 'A05:2021',
                        'cvss': self._get_cvss(severity)
                    }
                )

        except Exception as e:
            self.logger.debug(f"Error testing {test_url}: {e}")

        return None

    def _get_cwe(self, file_type: str) -> str:
        """Get CWE for file type"""
        cwe_map = {
            'config': 'CWE-16',  # Configuration
            'secrets': 'CWE-200',  # Information Exposure
            'backup': 'CWE-530',  # Exposure through Backup
            'source': 'CWE-540',  # Source Code Exposure
            'debug': 'CWE-215',  # Debug Info Exposure
            'info': 'CWE-200',  # Information Exposure
            'shortname': 'CWE-200',  # Information Exposure
        }
        return cwe_map.get(file_type, 'CWE-200')

    def _get_cvss(self, severity: str) -> float:
        """Get CVSS score for severity"""
        cvss_map = {
            'Critical': 9.8,
            'High': 7.5,
            'Medium': 5.3,
            'Low': 3.1,
            'Info': 0.0
        }
        return cvss_map.get(severity, 5.0)


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return IISConfigScanner(module_path, payload_limit=payload_limit)

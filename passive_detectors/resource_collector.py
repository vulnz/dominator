"""
Resource Collector - Passive detection of various resources
Collects credit cards, phones, emails, social networks, subdomains, etc.
"""

import re
import json
from typing import List, Dict, Any, Set
from urllib.parse import urlparse, urljoin
import requests

class ResourceCollector:
    """Passive resource collection from web responses"""
    
    def __init__(self):
        self.patterns = self._load_patterns()
    
    def _load_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load all resource patterns"""
        return {
            'credit_cards': self._get_credit_card_patterns(),
            'phone_numbers': self._get_phone_patterns(),
            'email_addresses': self._get_email_patterns(),
            'social_networks': self._get_social_patterns(),
            'subdomains': self._get_subdomain_patterns(),
            'ip_addresses': self._get_ip_patterns(),
            'urls': self._get_url_patterns(),
            'api_keys': self._get_api_key_patterns(),
            'crypto_addresses': self._get_crypto_patterns(),
            'documents': self._get_document_patterns(),
            'images': self._get_image_patterns(),
            'databases': self._get_database_patterns(),
            'cloud_services': self._get_cloud_patterns(),
            'development': self._get_development_patterns(),
            'network_info': self._get_network_info_patterns(),
            'geographic': self._get_geographic_patterns(),
            'financial': self._get_financial_patterns(),
            'personal_data': self._get_personal_data_patterns(),
            'technical': self._get_technical_patterns(),
            'business': self._get_business_patterns(),
            'security': self._get_security_patterns(),
            'media': self._get_media_patterns(),
            'infrastructure': self._get_infrastructure_patterns(),
            'compliance': self._get_compliance_patterns(),
            'analytics': self._get_analytics_patterns(),
            'communication': self._get_communication_patterns(),
            'backup_storage': self._get_backup_storage_patterns(),
            'monitoring': self._get_monitoring_patterns(),
            'certificates': self._get_certificate_patterns(),
            'version_control': self._get_version_control_patterns()
        }
    
    def analyze(self, response_text: str, url: str, headers: Dict[str, str]) -> Dict[str, List[Dict[str, Any]]]:
        """Analyze response for all types of resources"""
        found_resources = {}
        
        for category, patterns in self.patterns.items():
            resources = self._find_resources(response_text, url, headers, patterns, category)
            if resources:
                found_resources[category] = resources
        
        return found_resources
    
    def _find_resources(self, response_text: str, url: str, headers: Dict[str, str], 
                       patterns: List[Dict[str, Any]], category: str) -> List[Dict[str, Any]]:
        """Find resources using patterns"""
        found = []
        
        for pattern_info in patterns:
            pattern = pattern_info['pattern']
            name = pattern_info['name']
            severity = pattern_info.get('severity', 'Info')
            description = pattern_info.get('description', f'{name} found')
            
            # Search in response text
            matches = re.finditer(pattern, response_text, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                resource = {
                    'type': category,
                    'name': name,
                    'value': match.group(0),
                    'severity': severity,
                    'description': description,
                    'url': url,
                    'context': self._get_context(response_text, match.start(), match.end()),
                    'position': match.start()
                }
                
                # Add additional processing for specific types
                if category == 'credit_cards':
                    resource['masked_value'] = self._mask_credit_card(match.group(0))
                elif category == 'phone_numbers':
                    resource['formatted_value'] = self._format_phone(match.group(0))
                elif category == 'subdomains':
                    resource['domain'] = self._extract_domain(match.group(0))
                
                found.append(resource)
            
            # Search in headers for relevant patterns
            if category in ['api_keys', 'security', 'technical']:
                for header_name, header_value in headers.items():
                    header_matches = re.finditer(pattern, f"{header_name}: {header_value}", re.IGNORECASE)
                    for match in header_matches:
                        resource = {
                            'type': category,
                            'name': f'{name} (Header)',
                            'value': match.group(0),
                            'severity': severity,
                            'description': f'{description} found in HTTP headers',
                            'url': url,
                            'context': f"Header: {header_name}",
                            'position': 0
                        }
                        found.append(resource)
        
        return found
    
    def _get_context(self, text: str, start: int, end: int, context_size: int = 50) -> str:
        """Get context around found match"""
        context_start = max(0, start - context_size)
        context_end = min(len(text), end + context_size)
        context = text[context_start:context_end]
        
        # Clean up context
        context = re.sub(r'\s+', ' ', context).strip()
        
        if context_start > 0:
            context = "..." + context
        if context_end < len(text):
            context = context + "..."
        
        return context
    
    def _mask_credit_card(self, card_number: str) -> str:
        """Mask credit card number for security"""
        digits = re.sub(r'\D', '', card_number)
        if len(digits) >= 8:
            return digits[:4] + '*' * (len(digits) - 8) + digits[-4:]
        return '*' * len(digits)
    
    def _format_phone(self, phone: str) -> str:
        """Format phone number"""
        digits = re.sub(r'\D', '', phone)
        if len(digits) == 10:
            return f"({digits[:3]}) {digits[3:6]}-{digits[6:]}"
        elif len(digits) == 11 and digits[0] == '1':
            return f"+1 ({digits[1:4]}) {digits[4:7]}-{digits[7:]}"
        return phone
    
    def _extract_domain(self, subdomain: str) -> str:
        """Extract main domain from subdomain"""
        try:
            parsed = urlparse(f"http://{subdomain}")
            parts = parsed.netloc.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])
            return subdomain
        except:
            return subdomain
    
    # Pattern definitions
    def _get_credit_card_patterns(self) -> List[Dict[str, Any]]:
        """Credit card patterns"""
        return [
            {
                'name': 'Visa Card',
                'pattern': r'\b4[0-9]{12}(?:[0-9]{3})?\b',
                'severity': 'High',
                'description': 'Visa credit card number detected'
            },
            {
                'name': 'MasterCard',
                'pattern': r'\b5[1-5][0-9]{14}\b',
                'severity': 'High',
                'description': 'MasterCard credit card number detected'
            },
            {
                'name': 'American Express',
                'pattern': r'\b3[47][0-9]{13}\b',
                'severity': 'High',
                'description': 'American Express card number detected'
            },
            {
                'name': 'Discover Card',
                'pattern': r'\b6(?:011|5[0-9]{2})[0-9]{12}\b',
                'severity': 'High',
                'description': 'Discover card number detected'
            }
        ]
    
    def _get_phone_patterns(self) -> List[Dict[str, Any]]:
        """Phone number patterns"""
        return [
            {
                'name': 'US Phone Number',
                'pattern': r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
                'severity': 'Medium',
                'description': 'US phone number detected'
            },
            {
                'name': 'International Phone',
                'pattern': r'\+[1-9]\d{1,14}\b',
                'severity': 'Medium',
                'description': 'International phone number detected'
            },
            {
                'name': 'Russian Phone',
                'pattern': r'\+7[-.\s]?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{2})[-.\s]?([0-9]{2})\b',
                'severity': 'Medium',
                'description': 'Russian phone number detected'
            }
        ]
    
    def _get_email_patterns(self) -> List[Dict[str, Any]]:
        """Email patterns"""
        return [
            {
                'name': 'Email Address',
                'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'severity': 'Low',
                'description': 'Email address detected'
            },
            {
                'name': 'Admin Email',
                'pattern': r'\b(?:admin|administrator|root|support)@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'severity': 'Medium',
                'description': 'Administrative email address detected'
            }
        ]
    
    def _get_social_patterns(self) -> List[Dict[str, Any]]:
        """Social network patterns"""
        return [
            {
                'name': 'Facebook Profile',
                'pattern': r'(?:https?://)?(?:www\.)?facebook\.com/[A-Za-z0-9._%+-]+',
                'severity': 'Info',
                'description': 'Facebook profile link detected'
            },
            {
                'name': 'Twitter Profile',
                'pattern': r'(?:https?://)?(?:www\.)?twitter\.com/[A-Za-z0-9_]+',
                'severity': 'Info',
                'description': 'Twitter profile link detected'
            },
            {
                'name': 'LinkedIn Profile',
                'pattern': r'(?:https?://)?(?:www\.)?linkedin\.com/in/[A-Za-z0-9-]+',
                'severity': 'Info',
                'description': 'LinkedIn profile link detected'
            },
            {
                'name': 'Instagram Profile',
                'pattern': r'(?:https?://)?(?:www\.)?instagram\.com/[A-Za-z0-9_.]+',
                'severity': 'Info',
                'description': 'Instagram profile link detected'
            },
            {
                'name': 'YouTube Channel',
                'pattern': r'(?:https?://)?(?:www\.)?youtube\.com/(?:channel/|user/|c/)[A-Za-z0-9_-]+',
                'severity': 'Info',
                'description': 'YouTube channel link detected'
            },
            {
                'name': 'GitHub Profile',
                'pattern': r'(?:https?://)?(?:www\.)?github\.com/[A-Za-z0-9_-]+',
                'severity': 'Info',
                'description': 'GitHub profile link detected'
            },
            {
                'name': 'Telegram',
                'pattern': r'(?:https?://)?(?:www\.)?t\.me/[A-Za-z0-9_]+',
                'severity': 'Info',
                'description': 'Telegram link detected'
            },
            {
                'name': 'VKontakte Profile',
                'pattern': r'(?:https?://)?(?:www\.)?vk\.com/[A-Za-z0-9_.]+',
                'severity': 'Info',
                'description': 'VKontakte profile link detected'
            }
        ]
    
    def _get_subdomain_patterns(self) -> List[Dict[str, Any]]:
        """Subdomain patterns"""
        return [
            {
                'name': 'Subdomain',
                'pattern': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
                'severity': 'Info',
                'description': 'Subdomain detected'
            },
            {
                'name': 'Admin Subdomain',
                'pattern': r'\b(?:admin|administrator|manage|control|panel)\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
                'severity': 'Medium',
                'description': 'Administrative subdomain detected'
            },
            {
                'name': 'API Subdomain',
                'pattern': r'\b(?:api|rest|graphql|service)\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
                'severity': 'Medium',
                'description': 'API subdomain detected'
            }
        ]
    
    def _get_ip_patterns(self) -> List[Dict[str, Any]]:
        """IP address patterns"""
        return [
            {
                'name': 'IPv4 Address',
                'pattern': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                'severity': 'Low',
                'description': 'IPv4 address detected'
            },
            {
                'name': 'Private IPv4',
                'pattern': r'\b(?:10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.(?:[0-9]{1,3}\.)[0-9]{1,3}|192\.168\.(?:[0-9]{1,3}\.)[0-9]{1,3})\b',
                'severity': 'Medium',
                'description': 'Private IPv4 address detected'
            },
            {
                'name': 'IPv6 Address',
                'pattern': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
                'severity': 'Low',
                'description': 'IPv6 address detected'
            }
        ]
    
    def _get_url_patterns(self) -> List[Dict[str, Any]]:
        """URL patterns"""
        return [
            {
                'name': 'HTTP URL',
                'pattern': r'https?://[^\s<>"\']+',
                'severity': 'Info',
                'description': 'HTTP URL detected'
            },
            {
                'name': 'FTP URL',
                'pattern': r'ftp://[^\s<>"\']+',
                'severity': 'Low',
                'description': 'FTP URL detected'
            },
            {
                'name': 'File URL',
                'pattern': r'file://[^\s<>"\']+',
                'severity': 'Medium',
                'description': 'File URL detected'
            }
        ]
    
    def _get_api_key_patterns(self) -> List[Dict[str, Any]]:
        """API key patterns"""
        return [
            {
                'name': 'AWS Access Key',
                'pattern': r'AKIA[0-9A-Z]{16}',
                'severity': 'Critical',
                'description': 'AWS Access Key detected'
            },
            {
                'name': 'Google API Key',
                'pattern': r'AIza[0-9A-Za-z\\-_]{35}',
                'severity': 'High',
                'description': 'Google API Key detected'
            },
            {
                'name': 'GitHub Token',
                'pattern': r'ghp_[0-9a-zA-Z]{36}',
                'severity': 'High',
                'description': 'GitHub Personal Access Token detected'
            },
            {
                'name': 'Slack Token',
                'pattern': r'xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}',
                'severity': 'High',
                'description': 'Slack API Token detected'
            },
            {
                'name': 'Generic API Key',
                'pattern': r'(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token)["\']?\s*[:=]\s*["\']?[0-9a-zA-Z]{20,}',
                'severity': 'High',
                'description': 'Generic API key detected'
            }
        ]
    
    def _get_crypto_patterns(self) -> List[Dict[str, Any]]:
        """Cryptocurrency patterns"""
        return [
            {
                'name': 'Bitcoin Address',
                'pattern': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
                'severity': 'Medium',
                'description': 'Bitcoin address detected'
            },
            {
                'name': 'Ethereum Address',
                'pattern': r'\b0x[a-fA-F0-9]{40}\b',
                'severity': 'Medium',
                'description': 'Ethereum address detected'
            },
            {
                'name': 'Litecoin Address',
                'pattern': r'\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b',
                'severity': 'Medium',
                'description': 'Litecoin address detected'
            }
        ]
    
    def _get_document_patterns(self) -> List[Dict[str, Any]]:
        """Document patterns"""
        return [
            {
                'name': 'PDF Document',
                'pattern': r'[^\s<>"\']+\.pdf\b',
                'severity': 'Info',
                'description': 'PDF document link detected'
            },
            {
                'name': 'Word Document',
                'pattern': r'[^\s<>"\']+\.(?:doc|docx)\b',
                'severity': 'Info',
                'description': 'Word document link detected'
            },
            {
                'name': 'Excel Document',
                'pattern': r'[^\s<>"\']+\.(?:xls|xlsx)\b',
                'severity': 'Info',
                'description': 'Excel document link detected'
            },
            {
                'name': 'PowerPoint Document',
                'pattern': r'[^\s<>"\']+\.(?:ppt|pptx)\b',
                'severity': 'Info',
                'description': 'PowerPoint document link detected'
            }
        ]
    
    def _get_image_patterns(self) -> List[Dict[str, Any]]:
        """Image patterns"""
        return [
            {
                'name': 'Image File',
                'pattern': r'[^\s<>"\']+\.(?:jpg|jpeg|png|gif|bmp|svg|webp)\b',
                'severity': 'Info',
                'description': 'Image file detected'
            }
        ]
    
    def _get_database_patterns(self) -> List[Dict[str, Any]]:
        """Database patterns"""
        return [
            {
                'name': 'Database Connection String',
                'pattern': r'(?:mongodb|mysql|postgresql|oracle|mssql)://[^\s<>"\']+',
                'severity': 'High',
                'description': 'Database connection string detected'
            },
            {
                'name': 'SQL File',
                'pattern': r'[^\s<>"\']+\.sql\b',
                'severity': 'Medium',
                'description': 'SQL file detected'
            }
        ]
    
    def _get_cloud_patterns(self) -> List[Dict[str, Any]]:
        """Cloud service patterns"""
        return [
            {
                'name': 'AWS S3 Bucket',
                'pattern': r'[a-z0-9.-]+\.s3\.amazonaws\.com',
                'severity': 'Medium',
                'description': 'AWS S3 bucket detected'
            },
            {
                'name': 'Google Cloud Storage',
                'pattern': r'[a-z0-9.-]+\.storage\.googleapis\.com',
                'severity': 'Medium',
                'description': 'Google Cloud Storage bucket detected'
            },
            {
                'name': 'Azure Blob Storage',
                'pattern': r'[a-z0-9.-]+\.blob\.core\.windows\.net',
                'severity': 'Medium',
                'description': 'Azure Blob Storage detected'
            }
        ]
    
    def _get_development_patterns(self) -> List[Dict[str, Any]]:
        """Development patterns"""
        return [
            {
                'name': 'Git Repository',
                'pattern': r'\.git(?:/|\\)',
                'severity': 'High',
                'description': 'Git repository detected'
            },
            {
                'name': 'Environment File',
                'pattern': r'\.env\b',
                'severity': 'High',
                'description': 'Environment file detected'
            },
            {
                'name': 'Config File',
                'pattern': r'[^\s<>"\']+\.(?:config|conf|cfg|ini)\b',
                'severity': 'Medium',
                'description': 'Configuration file detected'
            }
        ]
    
    def _get_network_info_patterns(self) -> List[Dict[str, Any]]:
        """Network information patterns"""
        return [
            {
                'name': 'MAC Address',
                'pattern': r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b',
                'severity': 'Low',
                'description': 'MAC address detected'
            },
            {
                'name': 'Port Number',
                'pattern': r':\d{2,5}\b',
                'severity': 'Info',
                'description': 'Port number detected'
            }
        ]
    
    def _get_geographic_patterns(self) -> List[Dict[str, Any]]:
        """Geographic patterns"""
        return [
            {
                'name': 'GPS Coordinates',
                'pattern': r'[-+]?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?),\s*[-+]?(?:180(?:\.0+)?|(?:(?:1[0-7]\d)|(?:[1-9]?\d))(?:\.\d+)?)',
                'severity': 'Medium',
                'description': 'GPS coordinates detected'
            },
            {
                'name': 'ZIP Code',
                'pattern': r'\b\d{5}(?:-\d{4})?\b',
                'severity': 'Low',
                'description': 'ZIP code detected'
            }
        ]
    
    def _get_financial_patterns(self) -> List[Dict[str, Any]]:
        """Financial patterns"""
        return [
            {
                'name': 'IBAN',
                'pattern': r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b',
                'severity': 'High',
                'description': 'IBAN number detected'
            },
            {
                'name': 'SSN',
                'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
                'severity': 'Critical',
                'description': 'Social Security Number detected'
            }
        ]
    
    def _get_personal_data_patterns(self) -> List[Dict[str, Any]]:
        """Personal data patterns"""
        return [
            {
                'name': 'Passport Number',
                'pattern': r'\b[A-Z]{1,2}\d{6,9}\b',
                'severity': 'High',
                'description': 'Passport number detected'
            },
            {
                'name': 'Driver License',
                'pattern': r'\b[A-Z]\d{7,8}\b',
                'severity': 'High',
                'description': 'Driver license number detected'
            }
        ]
    
    def _get_technical_patterns(self) -> List[Dict[str, Any]]:
        """Technical patterns"""
        return [
            {
                'name': 'JWT Token',
                'pattern': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*',
                'severity': 'Medium',
                'description': 'JWT token detected'
            },
            {
                'name': 'Base64 Data',
                'pattern': r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
                'severity': 'Info',
                'description': 'Base64 encoded data detected'
            }
        ]
    
    def _get_business_patterns(self) -> List[Dict[str, Any]]:
        """Business patterns"""
        return [
            {
                'name': 'Tax ID',
                'pattern': r'\b\d{2}-\d{7}\b',
                'severity': 'Medium',
                'description': 'Tax ID number detected'
            },
            {
                'name': 'Company Registration',
                'pattern': r'\b(?:LLC|Inc|Corp|Ltd)\b',
                'severity': 'Info',
                'description': 'Company registration info detected'
            }
        ]
    
    def _get_security_patterns(self) -> List[Dict[str, Any]]:
        """Security patterns"""
        return [
            {
                'name': 'Private Key',
                'pattern': r'-----BEGIN (?:RSA )?PRIVATE KEY-----',
                'severity': 'Critical',
                'description': 'Private key detected'
            },
            {
                'name': 'Certificate',
                'pattern': r'-----BEGIN CERTIFICATE-----',
                'severity': 'Medium',
                'description': 'Certificate detected'
            }
        ]
    
    def _get_media_patterns(self) -> List[Dict[str, Any]]:
        """Media patterns"""
        return [
            {
                'name': 'Video File',
                'pattern': r'[^\s<>"\']+\.(?:mp4|avi|mov|wmv|flv|webm)\b',
                'severity': 'Info',
                'description': 'Video file detected'
            },
            {
                'name': 'Audio File',
                'pattern': r'[^\s<>"\']+\.(?:mp3|wav|ogg|flac|aac)\b',
                'severity': 'Info',
                'description': 'Audio file detected'
            }
        ]
    
    def _get_infrastructure_patterns(self) -> List[Dict[str, Any]]:
        """Infrastructure patterns"""
        return [
            {
                'name': 'Docker Image',
                'pattern': r'[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*:[a-z0-9]+(?:[._-][a-z0-9]+)*',
                'severity': 'Info',
                'description': 'Docker image reference detected'
            },
            {
                'name': 'Kubernetes Config',
                'pattern': r'apiVersion:\s*[^\s]+',
                'severity': 'Medium',
                'description': 'Kubernetes configuration detected'
            }
        ]
    
    def _get_compliance_patterns(self) -> List[Dict[str, Any]]:
        """Compliance patterns"""
        return [
            {
                'name': 'GDPR Reference',
                'pattern': r'\bGDPR\b',
                'severity': 'Info',
                'description': 'GDPR reference detected'
            },
            {
                'name': 'PCI DSS',
                'pattern': r'\bPCI\s*DSS\b',
                'severity': 'Info',
                'description': 'PCI DSS reference detected'
            }
        ]
    
    def _get_analytics_patterns(self) -> List[Dict[str, Any]]:
        """Analytics patterns"""
        return [
            {
                'name': 'Google Analytics',
                'pattern': r'UA-\d+-\d+',
                'severity': 'Info',
                'description': 'Google Analytics ID detected'
            },
            {
                'name': 'Google Tag Manager',
                'pattern': r'GTM-[A-Z0-9]+',
                'severity': 'Info',
                'description': 'Google Tag Manager ID detected'
            }
        ]
    
    def _get_communication_patterns(self) -> List[Dict[str, Any]]:
        """Communication patterns"""
        return [
            {
                'name': 'Skype Username',
                'pattern': r'skype:[a-zA-Z0-9._-]+',
                'severity': 'Info',
                'description': 'Skype username detected'
            },
            {
                'name': 'Discord Invite',
                'pattern': r'discord\.gg/[a-zA-Z0-9]+',
                'severity': 'Info',
                'description': 'Discord invite link detected'
            }
        ]
    
    def _get_backup_storage_patterns(self) -> List[Dict[str, Any]]:
        """Backup and storage patterns"""
        return [
            {
                'name': 'Backup File',
                'pattern': r'[^\s<>"\']+\.(?:bak|backup|old|orig)\b',
                'severity': 'Medium',
                'description': 'Backup file detected'
            },
            {
                'name': 'Archive File',
                'pattern': r'[^\s<>"\']+\.(?:zip|rar|tar|gz|7z)\b',
                'severity': 'Low',
                'description': 'Archive file detected'
            }
        ]
    
    def _get_monitoring_patterns(self) -> List[Dict[str, Any]]:
        """Monitoring patterns"""
        return [
            {
                'name': 'Monitoring URL',
                'pattern': r'(?:https?://)?(?:www\.)?(?:newrelic|datadog|splunk|elastic)\.com/[^\s<>"\']*',
                'severity': 'Info',
                'description': 'Monitoring service URL detected'
            }
        ]
    
    def _get_certificate_patterns(self) -> List[Dict[str, Any]]:
        """Certificate patterns"""
        return [
            {
                'name': 'SSL Certificate',
                'pattern': r'-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----',
                'severity': 'Medium',
                'description': 'SSL certificate detected'
            }
        ]
    
    def _get_version_control_patterns(self) -> List[Dict[str, Any]]:
        """Version control patterns"""
        return [
            {
                'name': 'Git Commit Hash',
                'pattern': r'\b[a-f0-9]{40}\b',
                'severity': 'Info',
                'description': 'Git commit hash detected'
            },
            {
                'name': 'SVN URL',
                'pattern': r'svn://[^\s<>"\']+',
                'severity': 'Medium',
                'description': 'SVN repository URL detected'
            }
        ]

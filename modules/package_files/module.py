"""
Package Files Discovery Scanner
Discovers exposed package manager and configuration files
"""

from core.base_module import BaseModule
from core.logger import get_logger
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse
import re
import json

logger = get_logger(__name__)


class PackageFilesScanner(BaseModule):
    """Scans for exposed package manager and configuration files"""

    def __init__(self, module_path: str, payload_limit: int = None):
        super().__init__(module_path, payload_limit=payload_limit)
        self.module_name = "Package Files Scanner"
        self.logger = logger

        # Package files to check with their parsers
        self.package_files = [
            # JavaScript/Node.js
            {
                'path': '/package.json',
                'type': 'npm',
                'icon': '📦',
                'name': 'NPM Package',
                'parser': self._parse_package_json,
                'severity': 'Medium'
            },
            {
                'path': '/package-lock.json',
                'type': 'npm',
                'icon': '🔒',
                'name': 'NPM Lock File',
                'parser': self._parse_package_lock,
                'severity': 'Low'
            },
            {
                'path': '/yarn.lock',
                'type': 'yarn',
                'icon': '🧶',
                'name': 'Yarn Lock File',
                'parser': self._parse_yarn_lock,
                'severity': 'Low'
            },

            # Python
            {
                'path': '/requirements.txt',
                'type': 'pip',
                'icon': '🐍',
                'name': 'Python Requirements',
                'parser': self._parse_requirements_txt,
                'severity': 'Medium'
            },
            {
                'path': '/Pipfile',
                'type': 'pipenv',
                'icon': '🐍',
                'name': 'Pipenv File',
                'parser': self._parse_pipfile,
                'severity': 'Medium'
            },
            {
                'path': '/pyproject.toml',
                'type': 'poetry',
                'icon': '🐍',
                'name': 'Poetry/PEP 517 Config',
                'parser': self._parse_pyproject,
                'severity': 'Medium'
            },

            # PHP
            {
                'path': '/composer.json',
                'type': 'composer',
                'icon': '🎼',
                'name': 'Composer Package',
                'parser': self._parse_composer_json,
                'severity': 'Medium'
            },
            {
                'path': '/composer.lock',
                'type': 'composer',
                'icon': '🔒',
                'name': 'Composer Lock File',
                'parser': self._parse_composer_lock,
                'severity': 'Low'
            },

            # Java/Maven
            {
                'path': '/pom.xml',
                'type': 'maven',
                'icon': '☕',
                'name': 'Maven POM',
                'parser': self._parse_pom_xml,
                'severity': 'Medium'
            },
            {
                'path': '/build.gradle',
                'type': 'gradle',
                'icon': '🐘',
                'name': 'Gradle Build',
                'parser': self._parse_gradle,
                'severity': 'Medium'
            },

            # Ruby
            {
                'path': '/Gemfile',
                'type': 'bundler',
                'icon': '💎',
                'name': 'Ruby Gemfile',
                'parser': self._parse_gemfile,
                'severity': 'Medium'
            },
            {
                'path': '/Gemfile.lock',
                'type': 'bundler',
                'icon': '🔒',
                'name': 'Gemfile Lock',
                'parser': self._parse_gemfile_lock,
                'severity': 'Low'
            },

            # Docker
            {
                'path': '/Dockerfile',
                'type': 'docker',
                'icon': '🐳',
                'name': 'Dockerfile',
                'parser': self._parse_dockerfile,
                'severity': 'High'
            },
            {
                'path': '/docker-compose.yml',
                'type': 'docker',
                'icon': '🐳',
                'name': 'Docker Compose',
                'parser': self._parse_docker_compose,
                'severity': 'High'
            },
            {
                'path': '/docker-compose.yaml',
                'type': 'docker',
                'icon': '🐳',
                'name': 'Docker Compose',
                'parser': self._parse_docker_compose,
                'severity': 'High'
            },
            {
                'path': '/.dockerignore',
                'type': 'docker',
                'icon': '🐳',
                'name': 'Docker Ignore',
                'parser': self._parse_dockerignore,
                'severity': 'Low'
            },

            # .NET
            {
                'path': '/packages.config',
                'type': 'nuget',
                'icon': '🔷',
                'name': 'NuGet Packages',
                'parser': self._parse_nuget_config,
                'severity': 'Medium'
            },
            {
                'path': '/*.csproj',
                'type': 'dotnet',
                'icon': '🔷',
                'name': '.NET Project',
                'parser': self._parse_csproj,
                'severity': 'Medium'
            },

            # Go
            {
                'path': '/go.mod',
                'type': 'go',
                'icon': '🐹',
                'name': 'Go Modules',
                'parser': self._parse_go_mod,
                'severity': 'Medium'
            },
            {
                'path': '/go.sum',
                'type': 'go',
                'icon': '🐹',
                'name': 'Go Sum',
                'parser': self._parse_go_sum,
                'severity': 'Low'
            },

            # Rust
            {
                'path': '/Cargo.toml',
                'type': 'cargo',
                'icon': '🦀',
                'name': 'Rust Cargo',
                'parser': self._parse_cargo_toml,
                'severity': 'Medium'
            },
        ]

    def scan(self, targets: List[Dict[str, Any]], http_client: Any = None) -> List[Dict[str, Any]]:
        """Scan for exposed package files"""
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

            # Test each package file
            for file_info in self.package_files:
                if self.payload_limit and len(results) >= self.payload_limit:
                    break

                # Skip wildcard patterns for now
                if '*' in file_info['path']:
                    continue

                test_url = urljoin(base_url, file_info['path'])
                finding = self._test_file(http_client, test_url, file_info, base_url)
                if finding:
                    results.append(finding)

        self.logger.info(f"{self.module_name} scan complete: {len(results)} findings")
        return results

    def _test_file(self, http_client, test_url: str, file_info: dict, base_url: str) -> Dict[str, Any]:
        """Test a specific package file"""
        try:
            response = http_client.get(test_url)
            if not response or response.status_code != 200:
                return None

            content = response.text
            if not content or len(content) < 5:
                return None

            # Validate content matches expected format
            if not self._validate_content(content, file_info['type']):
                return None

            # Parse content for fancy display
            parsed_data = file_info['parser'](content)
            if not parsed_data:
                return None

            # Create fancy formatted output
            fancy_output = self._format_fancy_output(file_info, parsed_data, content)

            # Check for sensitive data
            sensitive_findings = self._check_sensitive_data(content, file_info['type'])
            severity = 'High' if sensitive_findings else file_info['severity']

            return self.create_result(
                vulnerable=True,
                url=test_url,
                parameter='Package File',
                payload=file_info['path'],
                evidence=fancy_output,
                severity=severity,
                method='GET',
                exploitation_steps=self._generate_exploit_steps(test_url, file_info, parsed_data, sensitive_findings),
                additional_info={
                    'injection_type': f'{file_info["name"]} Exposure',
                    'file_type': file_info['type'],
                    'icon': file_info['icon'],
                    'parsed_data': parsed_data,
                    'sensitive_findings': sensitive_findings,
                    'raw_content_preview': content[:500] + ('...' if len(content) > 500 else ''),
                    'cwe': 'CWE-200',
                    'owasp': 'A01:2021',
                    'description': f'{file_info["name"]} file exposed - reveals dependencies and project structure'
                }
            )

        except Exception as e:
            self.logger.debug(f"Error testing {test_url}: {e}")

        return None

    def _validate_content(self, content: str, file_type: str) -> bool:
        """Validate content matches expected format"""
        content_lower = content.lower()

        validators = {
            'npm': lambda c: '{' in c and ('name' in c or 'dependencies' in c or 'version' in c),
            'pip': lambda c: any(line.strip() and not line.startswith('#') for line in c.split('\n')),
            'pipenv': lambda c: '[packages]' in c or '[dev-packages]' in c,
            'poetry': lambda c: '[tool.poetry]' in c or '[project]' in c,
            'composer': lambda c: '{' in c and ('require' in c or 'name' in c),
            'maven': lambda c: '<project' in content_lower and '<dependencies' in content_lower or '<groupId' in content_lower,
            'gradle': lambda c: 'dependencies' in c or 'plugins' in c,
            'bundler': lambda c: 'gem ' in content_lower or 'source' in content_lower,
            'docker': lambda c: 'FROM ' in c.upper() or 'RUN ' in c.upper() or 'services:' in c,
            'nuget': lambda c: '<packages' in content_lower,
            'dotnet': lambda c: '<Project' in c,
            'go': lambda c: 'module ' in c or 'require ' in c or 'go ' in c,
            'cargo': lambda c: '[package]' in c or '[dependencies]' in c,
            'yarn': lambda c: '# yarn lockfile' in content_lower or content.startswith('__metadata:'),
        }

        validator = validators.get(file_type, lambda c: True)
        return validator(content)

    def _format_fancy_output(self, file_info: dict, parsed_data: dict, raw_content: str) -> str:
        """Format fancy output for the finding"""
        icon = file_info['icon']
        name = file_info['name']

        output = f"\n{'═' * 60}\n"
        output += f"  {icon} {name} FOUND\n"
        output += f"{'═' * 60}\n\n"

        if parsed_data.get('name'):
            output += f"  📛 Name: {parsed_data['name']}\n"
        if parsed_data.get('version'):
            output += f"  🏷️  Version: {parsed_data['version']}\n"
        if parsed_data.get('description'):
            output += f"  📝 Description: {parsed_data['description'][:100]}\n"

        if parsed_data.get('dependencies'):
            deps = parsed_data['dependencies']
            output += f"\n  📦 Dependencies ({len(deps)} total):\n"
            output += f"  {'─' * 40}\n"
            for i, (pkg, ver) in enumerate(list(deps.items())[:15]):
                output += f"  │ {pkg}: {ver}\n"
            if len(deps) > 15:
                output += f"  │ ... and {len(deps) - 15} more\n"

        if parsed_data.get('dev_dependencies'):
            dev_deps = parsed_data['dev_dependencies']
            output += f"\n  🔧 Dev Dependencies ({len(dev_deps)} total):\n"
            output += f"  {'─' * 40}\n"
            for i, (pkg, ver) in enumerate(list(dev_deps.items())[:10]):
                output += f"  │ {pkg}: {ver}\n"
            if len(dev_deps) > 10:
                output += f"  │ ... and {len(dev_deps) - 10} more\n"

        if parsed_data.get('scripts'):
            scripts = parsed_data['scripts']
            output += f"\n  ⚡ Scripts:\n"
            output += f"  {'─' * 40}\n"
            for name, cmd in list(scripts.items())[:8]:
                output += f"  │ {name}: {cmd[:60]}\n"

        if parsed_data.get('docker_info'):
            docker = parsed_data['docker_info']
            output += f"\n  🐳 Docker Info:\n"
            output += f"  {'─' * 40}\n"
            if docker.get('base_image'):
                output += f"  │ Base Image: {docker['base_image']}\n"
            if docker.get('exposed_ports'):
                output += f"  │ Exposed Ports: {', '.join(map(str, docker['exposed_ports']))}\n"
            if docker.get('env_vars'):
                output += f"  │ ENV Variables: {len(docker['env_vars'])} defined\n"

        if parsed_data.get('repository'):
            output += f"\n  🔗 Repository: {parsed_data['repository']}\n"
        if parsed_data.get('author'):
            output += f"  👤 Author: {parsed_data['author']}\n"
        if parsed_data.get('license'):
            output += f"  📜 License: {parsed_data['license']}\n"

        output += f"\n{'═' * 60}\n"

        return output

    def _parse_package_json(self, content: str) -> dict:
        """Parse package.json"""
        try:
            data = json.loads(content)
            return {
                'name': data.get('name'),
                'version': data.get('version'),
                'description': data.get('description'),
                'dependencies': data.get('dependencies', {}),
                'dev_dependencies': data.get('devDependencies', {}),
                'scripts': data.get('scripts', {}),
                'repository': data.get('repository', {}).get('url') if isinstance(data.get('repository'), dict) else data.get('repository'),
                'author': data.get('author'),
                'license': data.get('license'),
                'main': data.get('main'),
                'engines': data.get('engines', {})
            }
        except:
            return None

    def _parse_package_lock(self, content: str) -> dict:
        """Parse package-lock.json"""
        try:
            data = json.loads(content)
            deps = {}
            if 'packages' in data:
                for pkg, info in list(data['packages'].items())[:50]:
                    if pkg and pkg != '':
                        deps[pkg.replace('node_modules/', '')] = info.get('version', 'unknown')
            elif 'dependencies' in data:
                for pkg, info in list(data['dependencies'].items())[:50]:
                    deps[pkg] = info.get('version', 'unknown')
            return {
                'name': data.get('name'),
                'version': data.get('version'),
                'dependencies': deps,
                'lockfile_version': data.get('lockfileVersion')
            }
        except:
            return None

    def _parse_yarn_lock(self, content: str) -> dict:
        """Parse yarn.lock"""
        deps = {}
        current_pkg = None
        for line in content.split('\n')[:200]:
            if line and not line.startswith(' ') and not line.startswith('#'):
                current_pkg = line.split('@')[0].strip('"')
            elif 'version' in line and current_pkg:
                version = line.split('"')[1] if '"' in line else line.split()[-1]
                deps[current_pkg] = version
        return {'dependencies': deps}

    def _parse_requirements_txt(self, content: str) -> dict:
        """Parse requirements.txt"""
        deps = {}
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('-'):
                # Handle different formats: pkg==ver, pkg>=ver, pkg
                match = re.match(r'^([a-zA-Z0-9_-]+)\s*([<>=!]+\s*[\d.]+)?', line)
                if match:
                    pkg = match.group(1)
                    ver = match.group(2) or '*'
                    deps[pkg] = ver.strip()
        return {'dependencies': deps}

    def _parse_pipfile(self, content: str) -> dict:
        """Parse Pipfile"""
        deps = {}
        dev_deps = {}
        section = None
        for line in content.split('\n'):
            line = line.strip()
            if line == '[packages]':
                section = 'packages'
            elif line == '[dev-packages]':
                section = 'dev-packages'
            elif '=' in line and section:
                parts = line.split('=', 1)
                pkg = parts[0].strip()
                ver = parts[1].strip().strip('"\'')
                if section == 'packages':
                    deps[pkg] = ver
                else:
                    dev_deps[pkg] = ver
        return {'dependencies': deps, 'dev_dependencies': dev_deps}

    def _parse_pyproject(self, content: str) -> dict:
        """Parse pyproject.toml"""
        deps = {}
        name = None
        version = None
        for line in content.split('\n'):
            if 'name = ' in line:
                name = line.split('=')[1].strip().strip('"\'')
            elif 'version = ' in line:
                version = line.split('=')[1].strip().strip('"\'')
            elif '=' in line and ('"' in line or "'" in line):
                parts = line.split('=', 1)
                if len(parts) == 2:
                    pkg = parts[0].strip()
                    if not pkg.startswith('[') and not pkg.startswith('#'):
                        deps[pkg] = parts[1].strip().strip('"\'')
        return {'name': name, 'version': version, 'dependencies': deps}

    def _parse_composer_json(self, content: str) -> dict:
        """Parse composer.json"""
        try:
            data = json.loads(content)
            return {
                'name': data.get('name'),
                'version': data.get('version'),
                'description': data.get('description'),
                'dependencies': data.get('require', {}),
                'dev_dependencies': data.get('require-dev', {}),
                'scripts': data.get('scripts', {}),
                'license': data.get('license'),
                'authors': data.get('authors', [])
            }
        except:
            return None

    def _parse_composer_lock(self, content: str) -> dict:
        """Parse composer.lock"""
        try:
            data = json.loads(content)
            deps = {}
            for pkg in data.get('packages', [])[:50]:
                deps[pkg.get('name', 'unknown')] = pkg.get('version', '*')
            return {'dependencies': deps}
        except:
            return None

    def _parse_pom_xml(self, content: str) -> dict:
        """Parse Maven pom.xml"""
        deps = {}
        # Simple regex parsing
        group_ids = re.findall(r'<groupId>([^<]+)</groupId>', content)
        artifact_ids = re.findall(r'<artifactId>([^<]+)</artifactId>', content)
        versions = re.findall(r'<version>([^<]+)</version>', content)

        for i, artifact in enumerate(artifact_ids[:20]):
            group = group_ids[i] if i < len(group_ids) else ''
            version = versions[i] if i < len(versions) else '*'
            deps[f"{group}:{artifact}"] = version

        name_match = re.search(r'<name>([^<]+)</name>', content)
        version_match = re.search(r'<version>([^<]+)</version>', content)

        return {
            'name': name_match.group(1) if name_match else None,
            'version': version_match.group(1) if version_match else None,
            'dependencies': deps
        }

    def _parse_gradle(self, content: str) -> dict:
        """Parse build.gradle"""
        deps = {}
        for line in content.split('\n'):
            match = re.search(r"['\"]([^'\"]+:[^'\"]+:[^'\"]+)['\"]", line)
            if match:
                parts = match.group(1).split(':')
                if len(parts) >= 2:
                    deps[f"{parts[0]}:{parts[1]}"] = parts[2] if len(parts) > 2 else '*'
        return {'dependencies': deps}

    def _parse_gemfile(self, content: str) -> dict:
        """Parse Gemfile"""
        deps = {}
        for line in content.split('\n'):
            match = re.search(r"gem\s+['\"]([^'\"]+)['\"](?:,\s*['\"]([^'\"]+)['\"])?", line)
            if match:
                deps[match.group(1)] = match.group(2) or '*'
        return {'dependencies': deps}

    def _parse_gemfile_lock(self, content: str) -> dict:
        """Parse Gemfile.lock"""
        deps = {}
        in_gems = False
        for line in content.split('\n'):
            if line.strip() == 'GEM':
                in_gems = True
            elif line.strip() == '' and in_gems:
                in_gems = False
            elif in_gems and line.startswith('    ') and not line.startswith('      '):
                match = re.match(r'\s+(\S+)\s+\(([^)]+)\)', line)
                if match:
                    deps[match.group(1)] = match.group(2)
        return {'dependencies': deps}

    def _parse_dockerfile(self, content: str) -> dict:
        """Parse Dockerfile"""
        base_image = None
        exposed_ports = []
        env_vars = []
        commands = []

        for line in content.split('\n'):
            line = line.strip()
            if line.upper().startswith('FROM '):
                base_image = line[5:].strip().split(' ')[0]
            elif line.upper().startswith('EXPOSE '):
                ports = re.findall(r'\d+', line)
                exposed_ports.extend(ports)
            elif line.upper().startswith('ENV '):
                env_vars.append(line[4:].split('=')[0].strip())
            elif line.upper().startswith('RUN '):
                commands.append(line[4:][:100])

        return {
            'docker_info': {
                'base_image': base_image,
                'exposed_ports': exposed_ports,
                'env_vars': env_vars,
                'commands': commands[:10]
            }
        }

    def _parse_docker_compose(self, content: str) -> dict:
        """Parse docker-compose.yml"""
        services = []
        images = []
        ports = []

        for line in content.split('\n'):
            if 'image:' in line:
                images.append(line.split('image:')[1].strip())
            elif re.match(r'\s+\w+:', line) and not ':' in line.split(':')[1]:
                services.append(line.strip().rstrip(':'))
            elif 'ports:' in line.lower() or re.match(r'\s+-\s+["\']?\d+', line):
                port_match = re.findall(r'\d+:\d+|\d+', line)
                ports.extend(port_match)

        return {
            'docker_info': {
                'services': services[:10],
                'images': images[:10],
                'exposed_ports': ports[:10]
            }
        }

    def _parse_dockerignore(self, content: str) -> dict:
        """Parse .dockerignore"""
        patterns = [line.strip() for line in content.split('\n') if line.strip() and not line.startswith('#')]
        return {'ignore_patterns': patterns}

    def _parse_nuget_config(self, content: str) -> dict:
        """Parse NuGet packages.config"""
        deps = {}
        for match in re.finditer(r'id="([^"]+)"[^>]*version="([^"]+)"', content):
            deps[match.group(1)] = match.group(2)
        return {'dependencies': deps}

    def _parse_csproj(self, content: str) -> dict:
        """Parse .csproj file"""
        deps = {}
        for match in re.finditer(r'<PackageReference\s+Include="([^"]+)"[^>]*Version="([^"]+)"', content):
            deps[match.group(1)] = match.group(2)
        return {'dependencies': deps}

    def _parse_go_mod(self, content: str) -> dict:
        """Parse go.mod"""
        deps = {}
        module_name = None
        go_version = None

        for line in content.split('\n'):
            if line.startswith('module '):
                module_name = line[7:].strip()
            elif line.startswith('go '):
                go_version = line[3:].strip()
            elif '\t' in line or line.startswith('require'):
                match = re.search(r'(\S+)\s+v?([\d.]+)', line)
                if match:
                    deps[match.group(1)] = match.group(2)

        return {'name': module_name, 'version': go_version, 'dependencies': deps}

    def _parse_go_sum(self, content: str) -> dict:
        """Parse go.sum"""
        deps = {}
        for line in content.split('\n')[:50]:
            parts = line.split()
            if len(parts) >= 2:
                deps[parts[0]] = parts[1]
        return {'dependencies': deps}

    def _parse_cargo_toml(self, content: str) -> dict:
        """Parse Cargo.toml"""
        deps = {}
        name = None
        version = None
        in_deps = False

        for line in content.split('\n'):
            if '[package]' in line:
                in_deps = False
            elif '[dependencies]' in line:
                in_deps = True
            elif 'name = ' in line and not in_deps:
                name = line.split('=')[1].strip().strip('"\'')
            elif 'version = ' in line and not in_deps:
                version = line.split('=')[1].strip().strip('"\'')
            elif in_deps and '=' in line:
                parts = line.split('=', 1)
                deps[parts[0].strip()] = parts[1].strip().strip('"\'')

        return {'name': name, 'version': version, 'dependencies': deps}

    def _check_sensitive_data(self, content: str, file_type: str) -> List[str]:
        """Check for sensitive data in content"""
        findings = []
        content_lower = content.lower()

        # Check for credentials/secrets
        sensitive_patterns = [
            (r'password\s*[=:]\s*["\'][^"\']+["\']', 'Password found'),
            (r'api[_-]?key\s*[=:]\s*["\'][^"\']+["\']', 'API Key found'),
            (r'secret\s*[=:]\s*["\'][^"\']+["\']', 'Secret found'),
            (r'token\s*[=:]\s*["\'][^"\']+["\']', 'Token found'),
            (r'private[_-]?key', 'Private key reference'),
            (r'aws[_-]?access', 'AWS credentials reference'),
            (r'database[_-]?url', 'Database URL found'),
            (r'mongodb://[^\s]+', 'MongoDB connection string'),
            (r'mysql://[^\s]+', 'MySQL connection string'),
            (r'postgres://[^\s]+', 'PostgreSQL connection string'),
        ]

        for pattern, desc in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(desc)

        # Docker-specific checks
        if file_type == 'docker':
            if 'SECRET' in content.upper() or '--password' in content:
                findings.append('Secrets in Docker commands')
            if re.search(r'ENV\s+\w*(?:KEY|SECRET|PASSWORD|TOKEN)', content, re.IGNORECASE):
                findings.append('Sensitive ENV variables')

        return findings

    def _generate_exploit_steps(self, url: str, file_info: dict, parsed_data: dict, sensitive_findings: List[str]) -> List[str]:
        """Generate exploitation steps"""
        steps = [
            f"STEP 1: DOWNLOAD THE FILE\n"
            f"─────────────────────────\n"
            f"curl -o {file_info['path'].lstrip('/')} '{url}'\n\n"
            f"This retrieves the {file_info['name']} file for offline analysis.",

            f"STEP 2: ANALYZE DEPENDENCIES\n"
            f"────────────────────────────\n"
            f"Review dependencies for known vulnerabilities:\n"
            f"• Check versions against CVE databases\n"
            f"• Look for outdated packages\n"
            f"• Identify internal/private packages\n\n"
            f"Tools:\n"
            f"• npm audit (for package.json)\n"
            f"• safety check (for requirements.txt)\n"
            f"• snyk test (multi-language)\n"
            f"• OWASP Dependency-Check",
        ]

        if sensitive_findings:
            steps.append(
                f"STEP 3: EXTRACT SENSITIVE DATA\n"
                f"──────────────────────────────\n"
                f"Sensitive data detected:\n" +
                '\n'.join(f"• {f}" for f in sensitive_findings) +
                f"\n\nSearch for credentials, API keys, and connection strings."
            )

        if parsed_data.get('repository'):
            steps.append(
                f"STEP 4: INVESTIGATE REPOSITORY\n"
                f"──────────────────────────────\n"
                f"Repository: {parsed_data['repository']}\n\n"
                f"• Check for exposed .git directory\n"
                f"• Look for commit history leaks\n"
                f"• Search for additional branches/tags"
            )

        if file_info['type'] == 'docker':
            steps.append(
                f"STEP 5: DOCKER EXPLOITATION\n"
                f"───────────────────────────\n"
                f"• Analyze base image for vulnerabilities\n"
                f"• Check exposed ports for services\n"
                f"• Review RUN commands for misconfigurations\n"
                f"• Look for hardcoded credentials in ENV"
            )

        return steps


def get_module(module_path: str, payload_limit: int = None):
    """Factory function to create module instance"""
    return PackageFilesScanner(module_path, payload_limit=payload_limit)

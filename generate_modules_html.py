#!/usr/bin/env python3
"""
Generate modules.html dashboard
Shows all scanner modules with statistics and metadata
"""

import os
import json
import datetime
from pathlib import Path
from typing import Dict, List, Any

def load_module_info(module_dir: str) -> Dict[str, Any]:
    """Load information about a module"""
    info = {
        'name': os.path.basename(module_dir),
        'enabled': False,
        'description': 'No description',
        'severity': 'Unknown',
        'payload_count': 0,
        'pattern_count': 0,
        'last_modified': None,
        'cwe': '',
        'owasp': '',
        'cvss': '',
    }

    # Load config.json
    config_path = os.path.join(module_dir, 'config.json')
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                info['enabled'] = config.get('enabled', False)
                info['description'] = config.get('description', 'No description')
                info['severity'] = config.get('severity', 'Unknown')
                info['cwe'] = config.get('cwe', '')
                info['owasp'] = config.get('owasp', '')
                info['cvss'] = config.get('cvss', '')

            # Get last modified time
            info['last_modified'] = datetime.datetime.fromtimestamp(
                os.path.getmtime(config_path)
            ).strftime('%Y-%m-%d %H:%M')
        except Exception as e:
            print(f"Error reading config for {module_dir}: {e}")

    # Count payloads
    payloads_path = os.path.join(module_dir, 'payloads.txt')
    if os.path.exists(payloads_path):
        try:
            with open(payloads_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                # Count non-empty, non-comment lines
                info['payload_count'] = len([
                    line for line in lines
                    if line.strip() and not line.strip().startswith('#')
                ])
        except Exception as e:
            print(f"Error reading payloads for {module_dir}: {e}")

    # Count patterns/detectors from module.py
    module_path = os.path.join(module_dir, 'module.py')
    if os.path.exists(module_path):
        try:
            with open(module_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                # Count regex patterns (simple heuristic)
                info['pattern_count'] = content.count('re.compile') + content.count('r\'') + content.count('r"')
                # More accurate: look for pattern dictionaries
                if 'PATTERNS' in content or 'patterns' in content:
                    # Try to count dictionary entries
                    import re
                    pattern_dicts = re.findall(r'\{[^}]*:[^}]*\}', content)
                    if pattern_dicts:
                        info['pattern_count'] = max(info['pattern_count'], len(pattern_dicts))
        except Exception as e:
            print(f"Error reading module.py for {module_dir}: {e}")

    return info

def generate_modules_html(modules_dir: str = 'modules', output_file: str = 'modules.html'):
    """Generate HTML dashboard for all modules"""

    # Scan modules directory
    modules = []
    if os.path.exists(modules_dir):
        for item in os.listdir(modules_dir):
            # Skip __pycache__ and other non-module directories
            if item.startswith('__') or item.startswith('.'):
                continue

            module_path = os.path.join(modules_dir, item)
            if os.path.isdir(module_path):
                # Only include if it has a config.json (valid module)
                config_path = os.path.join(module_path, 'config.json')
                if os.path.exists(config_path):
                    info = load_module_info(module_path)
                    # Only show enabled modules
                    if info['enabled']:
                        modules.append(info)

    # Sort by name
    modules.sort(key=lambda x: x['name'])

    # Calculate statistics
    total_modules = len(modules)
    enabled_modules = len([m for m in modules if m['enabled']])
    disabled_modules = total_modules - enabled_modules
    total_payloads = sum(m['payload_count'] for m in modules)
    total_patterns = sum(m['pattern_count'] for m in modules)

    severity_counts = {
        'Critical': len([m for m in modules if m['severity'] == 'Critical']),
        'High': len([m for m in modules if m['severity'] == 'High']),
        'Medium': len([m for m in modules if m['severity'] == 'Medium']),
        'Low': len([m for m in modules if m['severity'] == 'Low']),
        'Info': len([m for m in modules if m['severity'] == 'Info']),
    }

    # Generate HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dominator Scanner - Modules Dashboard</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}

        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}

        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        header .subtitle {{
            font-size: 1.1em;
            opacity: 0.9;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}

        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        }}

        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 5px;
        }}

        .stat-card .label {{
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .severity-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
            padding: 20px 30px;
            background: white;
        }}

        .severity-card {{
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            color: white;
            font-weight: bold;
        }}

        .severity-critical {{ background: #dc3545; }}
        .severity-high {{ background: #fd7e14; }}
        .severity-medium {{ background: #ffc107; color: #333; }}
        .severity-low {{ background: #28a745; }}
        .severity-info {{ background: #17a2b8; }}

        .filters {{
            padding: 20px 30px;
            background: #f8f9fa;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }}

        .filters label {{
            font-weight: 600;
            margin-right: 10px;
        }}

        .filters select, .filters input {{
            padding: 8px 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
        }}

        .modules-table {{
            width: 100%;
            border-collapse: collapse;
        }}

        .modules-table thead {{
            background: #667eea;
            color: white;
        }}

        .modules-table th {{
            padding: 15px;
            text-align: left;
            font-weight: 600;
            cursor: pointer;
            user-select: none;
        }}

        .modules-table th:hover {{
            background: #5568d3;
        }}

        .modules-table th::after {{
            content: ' ⇅';
            opacity: 0.5;
        }}

        .modules-table tbody tr {{
            border-bottom: 1px solid #eee;
            transition: background 0.2s;
        }}

        .modules-table tbody tr:hover {{
            background: #f8f9fa;
        }}

        .modules-table td {{
            padding: 15px;
        }}

        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
        }}

        .badge-enabled {{
            background: #d4edda;
            color: #155724;
        }}

        .badge-disabled {{
            background: #f8d7da;
            color: #721c24;
        }}

        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: #333; }}
        .badge-low {{ background: #28a745; color: white; }}
        .badge-info {{ background: #17a2b8; color: white; }}

        .footer {{
            padding: 20px 30px;
            background: #f8f9fa;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }}

        .updated {{
            font-style: italic;
            color: #999;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔱 Dominator Scanner</h1>
            <p class="subtitle">Vulnerability Detection Modules Dashboard</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="number">{total_modules}</div>
                <div class="label">Total Modules</div>
            </div>
            <div class="stat-card">
                <div class="number">{enabled_modules}</div>
                <div class="label">Enabled</div>
            </div>
            <div class="stat-card">
                <div class="number">{disabled_modules}</div>
                <div class="label">Disabled</div>
            </div>
            <div class="stat-card">
                <div class="number">{total_payloads:,}</div>
                <div class="label">Total Payloads</div>
            </div>
            <div class="stat-card">
                <div class="number">{total_patterns:,}</div>
                <div class="label">Total Patterns</div>
            </div>
        </div>

        <div class="severity-grid">
            <div class="severity-card severity-critical">
                <div style="font-size: 1.8em;">{severity_counts['Critical']}</div>
                <div>Critical</div>
            </div>
            <div class="severity-card severity-high">
                <div style="font-size: 1.8em;">{severity_counts['High']}</div>
                <div>High</div>
            </div>
            <div class="severity-card severity-medium">
                <div style="font-size: 1.8em;">{severity_counts['Medium']}</div>
                <div>Medium</div>
            </div>
            <div class="severity-card severity-low">
                <div style="font-size: 1.8em;">{severity_counts['Low']}</div>
                <div>Low</div>
            </div>
            <div class="severity-card severity-info">
                <div style="font-size: 1.8em;">{severity_counts['Info']}</div>
                <div>Info</div>
            </div>
        </div>

        <div class="filters">
            <label>Filter:</label>
            <select id="statusFilter" onchange="filterModules()">
                <option value="all">All Modules</option>
                <option value="enabled">Enabled Only</option>
                <option value="disabled">Disabled Only</option>
            </select>

            <select id="severityFilter" onchange="filterModules()">
                <option value="all">All Severities</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
                <option value="Info">Info</option>
            </select>

            <input type="text" id="searchInput" placeholder="Search modules..." onkeyup="filterModules()" style="flex: 1; min-width: 250px;">
        </div>

        <table class="modules-table">
            <thead>
                <tr>
                    <th onclick="sortTable(0)">Module Name</th>
                    <th onclick="sortTable(1)">Status</th>
                    <th onclick="sortTable(2)">Severity</th>
                    <th onclick="sortTable(3)">Description</th>
                    <th onclick="sortTable(4)">Payloads</th>
                    <th onclick="sortTable(5)">Patterns</th>
                    <th onclick="sortTable(6)">CWE</th>
                    <th onclick="sortTable(7)">OWASP</th>
                    <th onclick="sortTable(8)">CVSS</th>
                    <th onclick="sortTable(9)">Last Modified</th>
                </tr>
            </thead>
            <tbody id="modulesTable">
"""

    # Add module rows
    for module in modules:
        status_badge = 'badge-enabled' if module['enabled'] else 'badge-disabled'
        status_text = 'Enabled' if module['enabled'] else 'Disabled'
        severity_badge = f"badge-{module['severity'].lower()}"

        html += f"""                <tr data-status="{'enabled' if module['enabled'] else 'disabled'}" data-severity="{module['severity']}">
                    <td><strong>{module['name']}</strong></td>
                    <td><span class="badge {status_badge}">{status_text}</span></td>
                    <td><span class="badge {severity_badge}">{module['severity']}</span></td>
                    <td>{module['description'][:100]}{'...' if len(module['description']) > 100 else ''}</td>
                    <td style="text-align: center;">{module['payload_count']}</td>
                    <td style="text-align: center;">{module['pattern_count']}</td>
                    <td>{module['cwe']}</td>
                    <td>{module['owasp']}</td>
                    <td>{module['cvss']}</td>
                    <td class="updated">{module['last_modified'] or 'Unknown'}</td>
                </tr>
"""

    # Close HTML
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    html += f"""            </tbody>
        </table>

        <div class="footer">
            <p>Generated: {now}</p>
            <p>To update this dashboard, run: <code>python generate_modules_html.py</code></p>
        </div>
    </div>

    <script>
        function sortTable(columnIndex) {{
            const table = document.getElementById('modulesTable');
            const rows = Array.from(table.rows);
            const isNumeric = columnIndex === 4 || columnIndex === 5 || columnIndex === 8;

            rows.sort((a, b) => {{
                let aVal = a.cells[columnIndex].textContent.trim();
                let bVal = b.cells[columnIndex].textContent.trim();

                if (isNumeric) {{
                    aVal = parseFloat(aVal) || 0;
                    bVal = parseFloat(bVal) || 0;
                }}

                if (aVal < bVal) return -1;
                if (aVal > bVal) return 1;
                return 0;
            }});

            rows.forEach(row => table.appendChild(row));
        }}

        function filterModules() {{
            const statusFilter = document.getElementById('statusFilter').value;
            const severityFilter = document.getElementById('severityFilter').value;
            const searchText = document.getElementById('searchInput').value.toLowerCase();
            const rows = document.getElementById('modulesTable').rows;

            for (let row of rows) {{
                const status = row.dataset.status;
                const severity = row.dataset.severity;
                const text = row.textContent.toLowerCase();

                let show = true;

                if (statusFilter !== 'all' && status !== statusFilter) {{
                    show = false;
                }}

                if (severityFilter !== 'all' && severity !== severityFilter) {{
                    show = false;
                }}

                if (searchText && !text.includes(searchText)) {{
                    show = false;
                }}

                row.style.display = show ? '' : 'none';
            }}
        }}
    </script>
</body>
</html>
"""

    # Write HTML file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"[+] Generated {output_file}")
    print(f"  - Total modules: {total_modules}")
    print(f"  - Enabled: {enabled_modules}")
    print(f"  - Total payloads: {total_payloads:,}")
    print(f"  - Total patterns: {total_patterns:,}")
    return output_file

if __name__ == '__main__':
    generate_modules_html()

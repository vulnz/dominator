"""
Config Converter Utility
Converts module configs from JSON to TOML format and vice versa.
Supports reading both formats with TOML taking priority.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional

# For reading TOML (Python 3.11+)
try:
    import tomllib
except ImportError:
    tomllib = None

# For writing TOML
try:
    import tomli_w
    HAS_TOML_WRITE = True
except ImportError:
    HAS_TOML_WRITE = False


def load_config(module_path: str) -> Dict[str, Any]:
    """
    Load module config, preferring TOML over JSON.

    Args:
        module_path: Path to module directory

    Returns:
        Config dictionary
    """
    toml_path = os.path.join(module_path, "config.toml")
    json_path = os.path.join(module_path, "config.json")

    # Try TOML first
    if os.path.exists(toml_path) and tomllib:
        try:
            with open(toml_path, "rb") as f:
                return tomllib.load(f)
        except Exception as e:
            print(f"Error loading TOML config from {toml_path}: {e}")

    # Fall back to JSON
    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading JSON config from {json_path}: {e}")

    # Return empty config if nothing found
    return {}


def save_toml_config(config: Dict[str, Any], output_path: str) -> bool:
    """
    Save config as TOML file.

    Args:
        config: Configuration dictionary
        output_path: Path to save TOML file

    Returns:
        True if successful
    """
    if not HAS_TOML_WRITE:
        print("tomli_w not installed. Cannot write TOML files.")
        print("Install with: pip install tomli-w")
        return False

    try:
        with open(output_path, "wb") as f:
            tomli_w.dump(config, f)
        return True
    except Exception as e:
        print(f"Error saving TOML config to {output_path}: {e}")
        return False


def convert_json_to_toml_string(config: Dict[str, Any]) -> str:
    """
    Convert config dict to TOML string manually (no external deps).

    Args:
        config: Configuration dictionary

    Returns:
        TOML formatted string
    """
    lines = ["# Module Configuration (TOML format)", ""]

    for key, value in config.items():
        if isinstance(value, bool):
            lines.append(f'{key} = {str(value).lower()}')
        elif isinstance(value, str):
            # Escape special characters in strings
            escaped = value.replace('\\', '\\\\').replace('"', '\\"')
            lines.append(f'{key} = "{escaped}"')
        elif isinstance(value, (int, float)):
            lines.append(f'{key} = {value}')
        elif isinstance(value, list):
            if all(isinstance(item, str) for item in value):
                items = ', '.join(f'"{item}"' for item in value)
                lines.append(f'{key} = [{items}]')
            elif all(isinstance(item, (int, float)) for item in value):
                items = ', '.join(str(item) for item in value)
                lines.append(f'{key} = [{items}]')
            else:
                # Complex list - convert to JSON-like array
                lines.append(f'{key} = {json.dumps(value)}')
        elif isinstance(value, dict):
            # Nested table
            lines.append(f'\n[{key}]')
            for sub_key, sub_value in value.items():
                if isinstance(sub_value, bool):
                    lines.append(f'{sub_key} = {str(sub_value).lower()}')
                elif isinstance(sub_value, str):
                    escaped = sub_value.replace('\\', '\\\\').replace('"', '\\"')
                    lines.append(f'{sub_key} = "{escaped}"')
                elif isinstance(sub_value, (int, float)):
                    lines.append(f'{sub_key} = {sub_value}')
                else:
                    lines.append(f'{sub_key} = {json.dumps(sub_value)}')
        else:
            # Fallback to JSON representation
            lines.append(f'{key} = {json.dumps(value)}')

    return '\n'.join(lines) + '\n'


def convert_module_to_toml(module_path: str, remove_json: bool = False) -> bool:
    """
    Convert a module's config.json to config.toml.

    Args:
        module_path: Path to module directory
        remove_json: Whether to remove the JSON file after conversion

    Returns:
        True if successful
    """
    json_path = os.path.join(module_path, "config.json")
    toml_path = os.path.join(module_path, "config.toml")

    if not os.path.exists(json_path):
        print(f"No config.json found in {module_path}")
        return False

    # Load JSON
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except Exception as e:
        print(f"Error loading {json_path}: {e}")
        return False

    # Convert to TOML string
    toml_content = convert_json_to_toml_string(config)

    # Save TOML
    try:
        with open(toml_path, "w", encoding="utf-8") as f:
            f.write(toml_content)
        print(f"Created: {toml_path}")

        if remove_json:
            os.remove(json_path)
            print(f"Removed: {json_path}")

        return True
    except Exception as e:
        print(f"Error saving {toml_path}: {e}")
        return False


def convert_all_modules(modules_dir: str = "modules", remove_json: bool = False) -> Dict[str, bool]:
    """
    Convert all module configs from JSON to TOML.

    Args:
        modules_dir: Path to modules directory
        remove_json: Whether to remove JSON files after conversion

    Returns:
        Dict mapping module name to success status
    """
    results = {}

    if not os.path.exists(modules_dir):
        print(f"Modules directory not found: {modules_dir}")
        return results

    for item in os.listdir(modules_dir):
        module_path = os.path.join(modules_dir, item)

        if not os.path.isdir(module_path):
            continue

        if item.startswith('_') or item == '__pycache__':
            continue

        json_path = os.path.join(module_path, "config.json")
        if os.path.exists(json_path):
            results[item] = convert_module_to_toml(module_path, remove_json)

    # Summary
    success = sum(1 for v in results.values() if v)
    print(f"\nConversion complete: {success}/{len(results)} modules converted")

    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Convert module configs from JSON to TOML")
    parser.add_argument("--modules-dir", default="modules", help="Path to modules directory")
    parser.add_argument("--remove-json", action="store_true", help="Remove JSON files after conversion")
    parser.add_argument("--module", help="Convert single module by name")

    args = parser.parse_args()

    if args.module:
        module_path = os.path.join(args.modules_dir, args.module)
        convert_module_to_toml(module_path, args.remove_json)
    else:
        convert_all_modules(args.modules_dir, args.remove_json)

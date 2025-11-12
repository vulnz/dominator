"""
Dynamic module loader for vulnerability scanner
Loads modules from modules/ directory at runtime
"""

import os
import importlib.util
from typing import List, Dict, Any
from core.logger import get_logger

logger = get_logger(__name__)


class ModuleLoader:
    """Dynamically loads scanner modules"""

    def __init__(self, modules_dir: str = "modules"):
        """
        Initialize module loader

        Args:
            modules_dir: Path to modules directory
        """
        self.modules_dir = modules_dir
        self.available_modules = self._discover_modules()

        logger.info(f"Module loader initialized. Available modules: {len(self.available_modules)}")

    def _discover_modules(self) -> Dict[str, str]:
        """
        Discover all available modules

        Returns:
            Dictionary mapping module name to module path
        """
        available = {}

        if not os.path.exists(self.modules_dir):
            logger.warning(f"Modules directory not found: {self.modules_dir}")
            return available

        try:
            for item in os.listdir(self.modules_dir):
                module_path = os.path.join(self.modules_dir, item)

                # Check if it's a directory
                if not os.path.isdir(module_path):
                    continue

                # Check if module.py exists
                module_file = os.path.join(module_path, "module.py")
                if os.path.exists(module_file):
                    available[item] = module_path
                    logger.debug(f"Discovered module: {item} at {module_path}")

        except Exception as e:
            logger.error(f"Error discovering modules: {e}")

        return available

    def load_module(self, module_name: str) -> Any:
        """
        Load a single module dynamically

        Args:
            module_name: Name of module to load (e.g., 'xss', 'sqli')

        Returns:
            Module instance or None if failed
        """
        # Normalize module name
        module_name = module_name.lower().strip()

        if module_name not in self.available_modules:
            logger.warning(f"Module '{module_name}' not found in {self.modules_dir}/")
            return None

        module_path = self.available_modules[module_name]
        module_file = os.path.join(module_path, "module.py")

        try:
            # Dynamically import module.py
            spec = importlib.util.spec_from_file_location(
                f"modules.{module_name}",
                module_file
            )

            if spec is None or spec.loader is None:
                logger.error(f"Failed to load spec for module '{module_name}'")
                return None

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Get module instance
            if hasattr(module, 'get_module'):
                module_instance = module.get_module(module_path)
                logger.info(f"Successfully loaded module: {module_name}")
                return module_instance
            else:
                logger.error(f"Module '{module_name}' missing get_module() function")
                return None

        except Exception as e:
            logger.error(f"Error loading module '{module_name}': {e}")
            import traceback
            traceback.print_exc()
            return None

    def load_modules(self, module_names: List[str]) -> List[Any]:
        """
        Load multiple modules

        Args:
            module_names: List of module names to load

        Returns:
            List of loaded module instances
        """
        loaded_modules = []

        for name in module_names:
            module = self.load_module(name)
            if module:
                # Check if module is enabled
                if hasattr(module, 'is_enabled') and not module.is_enabled():
                    logger.warning(f"Module '{name}' is disabled in config")
                    continue

                loaded_modules.append(module)
            else:
                logger.warning(f"Failed to load module: {name}")

        logger.info(f"Loaded {len(loaded_modules)} out of {len(module_names)} requested modules")

        return loaded_modules

    def get_available_modules(self) -> List[str]:
        """Get list of available module names"""
        return list(self.available_modules.keys())

    def print_available_modules(self):
        """Print all available modules"""
        print("\nAvailable Modules:")
        print("=" * 80)

        if not self.available_modules:
            print("No modules found!")
            return

        for module_name in sorted(self.available_modules.keys()):
            module_path = self.available_modules[module_name]

            # Try to load config to get description
            try:
                import json
                config_path = os.path.join(module_path, "config.json")
                if os.path.exists(config_path):
                    with open(config_path, 'r', encoding='utf-8') as f:
                        config = json.load(f)
                        desc = config.get('description', 'No description')
                        enabled = config.get('enabled', True)
                        status = "✓" if enabled else "✗"
                else:
                    desc = "No description"
                    status = "?"
            except:
                desc = "No description"
                status = "?"

            print(f"  [{status}] {module_name:15s} - {desc}")

        print("=" * 80 + "\n")

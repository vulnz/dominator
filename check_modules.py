import os
import json

modules_dir = 'modules'
for item in os.listdir(modules_dir):
    module_path = os.path.join(modules_dir, item)
    if os.path.isdir(module_path) and item != '__pycache__':
        config_path = os.path.join(module_path, 'config.json')
        if os.path.exists(config_path):
            with open(config_path) as f:
                config = json.load(f)
                enabled = config.get('enabled', False)
                severity = config.get('severity', 'Unknown')
                print(f"{item:25} enabled={enabled:5} severity={severity}")

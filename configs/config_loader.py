import yaml
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_FILE_PATH = os.path.join(BASE_DIR, 'configs', 'config.yml')

def load_config():
    with open(CONFIG_FILE_PATH, 'r') as file:
        return yaml.safe_load(file)

def save_config(config):
    with open(CONFIG_FILE_PATH, 'w') as file:
        yaml.safe_dump(config, file, default_flow_style=False)

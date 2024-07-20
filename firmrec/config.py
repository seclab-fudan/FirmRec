# pylint: disable=missing-docstring
import os
import yaml


class Config:
    """Configurations of FirmRec"""

    def __init__(self, path):
        with open(path, "r", encoding="utf-8") as config_fp:
            _config = yaml.safe_load(config_fp)
        for key, val in _config.items():
            self.__setattr__(key, val)

    def get(self, key, default=None):
        """Get the value of the key"""
        if hasattr(self, key):
            return getattr(self, key)
        return default


gconfig = Config(os.path.join(os.path.dirname(__file__), "../config.yaml"))

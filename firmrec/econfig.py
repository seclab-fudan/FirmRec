import os
import json
import shutil

from .config import gconfig
from .consts import ConstPaths, ConstCmds, ConstValues


class ExperimentConfig:
    """Experiment configuration"""

    def __init__(self, raw_config):
        self.images = raw_config["images"]
        self.vulns = raw_config["vulns"]
        self.name = raw_config["name"]
        # read config from config path
        self.gconfig = gconfig
        self.db_name = gconfig.get("db_name")
        self.vuln_db_name = self.db_name + "_vuln"
        self.db_user = gconfig.get("db_user")
        self.db_user_passwd = gconfig.get("db_user_passwd")

    @classmethod
    def load(cls, config_path):
        """Load experiment config from file"""
        if not os.path.exists(config_path):
            return None
        with open(config_path, "r", encoding="utf-8") as config_fp:
            config = json.load(config_fp)

        return cls(config)

    @property
    def cmds(self):
        return ConstCmds

    @property
    def paths(self):
        return ConstPaths

    @property
    def values(self):
        return ConstValues

    @property
    def all_images(self):
        """All target images and vulnerable images"""
        return set(self.images).union(self.get_vuln_images().values())

    def get_vuln_images(self):
        """Get map from vulnerability to corresponding vulnerable images"""
        images = {}
        for vuln in self.vulns:
            vuln_info = self.get_vuln_info(vuln)
            image = vuln_info["firmware_filename"]
            found_image_path = os.path.join(os.path.dirname(self.get_vuln_info_path(vuln)), os.path.basename(image))
            assert os.path.exists(found_image_path), f"Image path {found_image_path} does not exist"

            # Ensure the image exists
            image_path = self.get_image_path(image)
            if not os.path.exists(image_path):
                shutil.copyfile(found_image_path, image_path)

            images[vuln] = image
        return images

    @classmethod
    def get_image_path(cls, image_filename):
        """Get image path"""
        return os.path.join(ConstPaths.IMAGE_DIR, image_filename)

    @classmethod
    def get_extracted_path(cls, image_filename):
        """Get extracted path"""
        return os.path.join(ConstPaths.EXTRACTED_DIR, image_filename + ".tar")

    @classmethod
    def get_unpacked_path(cls, image_filename):
        """Get unpacked path"""
        return os.path.join(ConstPaths.UNPACKED_DIR, image_filename)

    @classmethod
    def get_keyword_path(cls, image_filename):
        """Get keyword path"""
        return os.path.join(ConstPaths.KEYWORDS_DIR, image_filename + ".json")

    @classmethod
    def get_filtered_binary_path(cls, image_filename):
        """Get filtered binary path"""
        return os.path.join(ConstPaths.FILTERED_BINARY_DIR, image_filename + ".json")
    
    @classmethod
    def get_filtered_vuln_binary_path(cls, image_filename, vuln_name):
        """Get filtered binary path for a vulnerability"""
        vuln_name = os.path.basename(vuln_name)
        return os.path.join(ConstPaths.FILTERED_BINARY_DIR, f"{image_filename}_{vuln_name}.json")

    @classmethod
    def get_vuln_info_path(cls, vuln_name):
        """Get vulnerability information path"""
        vuln_info_path = os.path.join(ConstPaths.VULN_INFO_DIR, vuln_name, "meta.json")
        return vuln_info_path

    @classmethod
    def get_vuln_info(cls, vuln_name) -> dict:
        """Get vulnerability information"""
        vuln_info_path = cls.get_vuln_info_path(vuln_name)
        if not os.path.exists(vuln_info_path):
            return None
        with open(vuln_info_path, "r", encoding="utf-8") as vuln_info_fp:
            return json.load(vuln_info_fp)

    @classmethod
    def get_vuln_name(cls, vuln_name):
        """Get vulnerability name from a name that may include vendor name"""
        if "/" in vuln_name:
            vuln_name = vuln_name.split("/")[-1]
        return vuln_name

    @classmethod
    def get_vuln_ana_result_path(cls, vuln_name):
        """Get vulnerability analysis result path"""
        vuln_name = cls.get_vuln_name(vuln_name)
        return os.path.join(ConstPaths.SIG_DIR, vuln_name + ".json")

    @classmethod
    def get_sig_search_result_path(cls, vuln_name):
        vuln_name = cls.get_vuln_name(vuln_name)
        return os.path.join(ConstPaths.SIG_SIMEXP_INPUT_DIR, "", vuln_name + ".json")

    @classmethod
    def get_search_result_path(cls, vuln_name):
        """Get search result path"""
        return os.path.join(ConstPaths.SIMEXP_INPUT_DIR, vuln_name + ".json")
    
    @classmethod
    def get_sig_gen_search_result_path(cls, vuln_name):
        """Get search result path"""
        return os.path.join(ConstPaths.SIG_SIMEXP_INPUT_DIR, vuln_name + ".json")

    @classmethod
    def get_filter_input_path(cls, vendor, firmware_id, path):
        """Get path of the input filter file"""
        bin_entry = f"{vendor}@@{firmware_id}@@{path.replace('/', '@@')}"
        path = os.path.join(ConstPaths.FILTER_INPUT_DIR, bin_entry + ".json")
        return path


econfig = ExperimentConfig.load(ConstPaths.EXPERIMENT_CONFIG_PATH)
if not econfig:
    print(
        f"Failed to load experiment configuration at {ConstPaths.EXPERIMENT_CONFIG_PATH}"
    )
    exit(1)

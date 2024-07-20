"""
This module contain constant variables.
It assumes that the configuration defined by config.yaml must be properly set, 
otherwise exceptions will be raised.
"""

import os

from .config import gconfig


class ConstPaths:
    """
    Constant directories and paths
    """

    ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
    CONFIG_PATH = os.path.join(ROOT_DIR, "config.yaml")
    VULN_TEST_PATH = os.path.join(ROOT_DIR, "tests/vuln_test.py")

    # Extractor
    EXTRACTOR_DIR = os.path.join(ROOT_DIR, "extractor")
    EXTRACT_IMAGE_CMD = os.path.join(EXTRACTOR_DIR, "extract.sh")
    UNPACK_IMAGE_CMD = os.path.join(EXTRACTOR_DIR, "unpack.sh")

    # Firmware
    FIRMWARE_DIR = gconfig.get("firmware_dir")
    IMAGE_DIR = os.path.join(FIRMWARE_DIR, "images")
    EXTRACTED_DIR = os.path.join(FIRMWARE_DIR, "extracted")
    UNPACKED_DIR = os.path.join(FIRMWARE_DIR, "unpacked")

    # GroundTruth
    VULN_INFO_DIR = gconfig.get("vuln_info_dir")

    # Data layout
    OUTPUT_DIR = gconfig.get("firmrec_output_dir")
    GHIDRA_PROJECT_DIR = gconfig.get("project_path")
    EXPERIMENT_CONFIG_PATH = os.path.join(OUTPUT_DIR, "experiment.json")
    CMDS_DIR = os.path.join(OUTPUT_DIR, "cmds")

    KEYWORDS_DIR = os.path.join(OUTPUT_DIR, "keywords")
    FILTERED_BINARY_DIR = os.path.join(OUTPUT_DIR, "filtered_binaries")
    BIN_HASH_MAP_PATH = os.path.join(OUTPUT_DIR, "bin_hash_map.json")
    VULN_BIN_HASH_MAP_PATH = os.path.join(OUTPUT_DIR, "vuln_bin_hash_map.json")

    FUNC_MODEL_PATH = os.path.join(OUTPUT_DIR, "func_model/func_model.json")
    FUNC_MODEL_CHAIN_PATH = os.path.join(OUTPUT_DIR, "func_model/func_model.chain.json")
    VULN_FUNC_MODEL_PATH = os.path.join(OUTPUT_DIR, "func_model/vuln_func_model.json")
    VULN_FUNC_MODEL_CHAIN_PATH = os.path.join(OUTPUT_DIR, "func_model/vuln_func_model.chain.json")

    FIRMENTRY_DB_PATH = os.path.join(OUTPUT_DIR, "firmentry/firmentry.sql")
    FIRMENTRY_VULN_DB_PATH = os.path.join(OUTPUT_DIR, "firmentry/firmentry_vuln.sql")

    VULN_NAMED_INPUT_ENTRIES_PATH = os.path.join(OUTPUT_DIR, "firmentry/named_input_entries_vuln.json")
    VULN_UNNAMED_INPUT_ENTRIES_PATH = os.path.join(OUTPUT_DIR, "firmentry/unnamed_constants_vuln.json")

    NAMED_INPUT_ENTRIES_PATH = os.path.join(OUTPUT_DIR, "firmentry/named_input_entries.json")
    UNNAMED_INPUT_ENTRIES_PATH = os.path.join(OUTPUT_DIR, "firmentry/unnamed_constants.json")
    NAME_SIM_DICTIONARY_PATH = os.path.join(OUTPUT_DIR, "firmentry/name_sim_dictionary.csv")
    
    LLM_TMP_DIR = os.path.join(OUTPUT_DIR, "llm_tmp")

    SIG_SIMEXP_INPUT_DIR = os.path.join(OUTPUT_DIR, "sig_simexp_inputs")
    SIG_SIMEXP_RESULT_DIR = os.path.join(OUTPUT_DIR, "sig_simexp_results")
    EMU_RESULT_DIR = os.path.join(OUTPUT_DIR, "emu_results")
    SIG_DIR = os.path.join(OUTPUT_DIR, "signatures")
    FILTER_INPUT_DIR = os.path.join(OUTPUT_DIR, "filter_inputs")
    SIMEXP_INPUT_DIR = os.path.join(OUTPUT_DIR, "simexp_inputs")
    SIMEXP_RESULT_DIR = os.path.join(OUTPUT_DIR, "simexp_results")


class ConstCmds:
    """
    Constant commands
    """
    
    # Preprocessing: prepare binaries
    EXTRACT_IMAGE_CMD = ConstPaths.EXTRACT_IMAGE_CMD # Extract rootfs
    UNPACK_IMAGE_CMD = ConstPaths.UNPACK_IMAGE_CMD # Unpack extracted files
    FILTER_BINARY_CMD = "python -m firmrec.pipeline.filter_binary"

    # Extract potential keywords from binary, 
    EXTRACT_KEYWORDS_CMD = "python -m firmrec.pipeline.extract_keywords"

    SEARCH_CMD = "python -m firmrec.pipeline.search"
    SEARCH_PREPARE_CMD = "python -m firmrec.pipeline.search_prepare"
    CORRECT_MODEL_CMD = "python -m firmrec.pipeline.correct_model"
    ANA_VULN_CMD = "python -m firmrec.pipeline.analyze_vuln"
    LLM_SIM_DETECT_CMD = "python -m firmrec.llm"
    SIMEXP_CMD = "python -m firmrec.pipeline.simexp"
    
    EXTRACT_INPUT_CMD = f"java -jar {gconfig.get('firmrec_static_jar')}" # Perform static analysis to extract constants
    DIAG_CMD = "python -m firmrec.diag"



class ConstValues:
    """
    Constant values
    """

    INPUT_ANA_MEMLIM = 20  # GB
    SIMEMU_TIMEOUT = 600  # Timeout for vuln_test
    SIMEXP_TIMEOUT = 300  # Timeout for replay
    SIMEXP_MEMLIM = 10

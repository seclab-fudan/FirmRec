#!python
"""
This module provide pipeline commands generation and execution.
"""
import sys
import os
import json
import subprocess
import logging
import shlex
from abc import ABCMeta, abstractmethod
from multiprocessing import Pool
from subprocess import Popen, check_output, PIPE
from functools import cached_property

import psycopg2

from firmlib import calc_binary_hash, track
from ..econfig import ExperimentConfig, econfig
from ..iters import TargetFilterBuilder, iter_search_targets
from ..models.result import ResultItem
from ..diag import main as diag_main


PARALLEL = int(os.getenv("PARALLEL", "16"))

CREATE_TABLES_INS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data/schema"
)

# Configurable environment variables
ONLY_GEN = os.getenv("ONLY_GEN", "0") == "1"
NO_GEN = os.getenv("NO_GEN", "0") == "1"
FORCE = os.getenv("FORCE", "0") == "1"
FORCE_ALL = os.getenv("FORCE_ALL", "0") == "1"
CHECK = os.getenv("CHECK", "1") == "1"
ONLY_GT_VULN = os.getenv("ONLY_GT_VULN", "0") == "1"
ONLY_VULN = os.getenv("ONLY_VULN", "0") == "1"

PARALLEL = int(os.getenv("PARALLEL", "16"))

INPUT_ANA_MEMLIM = int(
    os.getenv("INPUT_ANA_MEMLIM", str(econfig.values.INPUT_ANA_MEMLIM))
)  # 10 GB
SIMEXP_TIMEOUT = int(
    os.getenv("SIMEXP_TIMEOUT", str(econfig.values.SIMEXP_TIMEOUT))
)  # 5 minutes
SIMEXP_MEMLIM = int(
    os.getenv("SIMEXP_MEMLIM", str(econfig.values.SIMEXP_MEMLIM))
)  # 10 GB


class Command(object, metaclass=ABCMeta):
    """Command"""

    name = "Command"
    seq = False
    cd_root = True
    is_commander = False

    def __init__(self, config: ExperimentConfig):
        self.config = config

    @property
    def cmd_path(self):
        """Path of executed commands"""
        return os.path.join(self.config.paths.CMDS_DIR, self.name)

    @property
    def cmd_log_path(self):
        """Path of execution of generated commands"""
        return self.cmd_path + ".log"

    @cached_property
    def log(self):
        """Log that output to stdout and cmd_log_path"""
        log = logging.getLogger(str(self.__class__.__name__))
        log.handlers.clear()
        # log.addHandler(logging.StreamHandler(stream=None))
        log.addHandler(logging.FileHandler(self.cmd_log_path, mode="a+"))
        log.setLevel(logging.DEBUG)
        return log

    def clear_log(self):
        """Clear log"""
        if os.path.exists(self.cmd_log_path):
            os.remove(self.cmd_log_path)

    @abstractmethod
    def gen_cmd(self, force=False):
        """Generate command

        :return: list of commands
        """
        raise NotImplementedError("gen_cmd not implemented")

    def check(self):
        """Check command execution status"""
        return

    def save(self, cmd_lines):
        """Save commands to file"""
        with open(self.cmd_path, "w", encoding="utf-8") as cmd_fp:
            cmd_fp.write("\n".join(cmd_lines))

    def execute(self, gen=True, gen_force=False, check=False, parallel=PARALLEL):
        """Execute commands

        :param gen: generate commands if True
        :param parallel: number of parallel processes
        """
        if self.cd_root:
            os.chdir(self.config.paths.ROOT_DIR)
        if gen:
            cmd_lines = self.gen_cmd(force=gen_force)
            self.save(cmd_lines)
        if not os.path.isfile(self.cmd_path):
            raise FileNotFoundError(f"Command file not generated: {self.cmd_path}")

        if not gen:
            with open(self.cmd_path, "r", encoding="utf-8") as cmd_fp:
                cmd_lines = cmd_fp.readlines()

        cmd_lines = [f"/usr/bin/time -v {cmd_line}" for cmd_line in cmd_lines]

        if self.seq:
            for cmd_line in track(
                cmd_lines, total=len(cmd_lines), description=self.name
            ):
                res = self._execute_one(cmd_line)
                self.log_handle_result(res)
        else:
            pool = Pool(parallel)
            for res in track(
                pool.imap_unordered(self._execute_one, cmd_lines),
                total=len(cmd_lines),
                description=self.name,
            ):
                self.log_handle_result(res)
        if check:
            self.check()

    @staticmethod
    def _execute_one(cmd_line):
        """Execute one command"""
        args = shlex.split(cmd_line)
        proc = Popen(args, shell=False, stdout=PIPE, stderr=PIPE)
        out, err = proc.communicate()
        # decode out and err
        out = out.decode("utf-8", errors="ignore")
        err = err.decode("utf-8", errors="ignore")
        return cmd_line, out, err

    def log_handle_result(self, res):
        """Write result to log"""
        cmd_line, out, err = res
        self.log.info("CMD: %s", cmd_line)
        if out:
            self.log.info("OUT: \n%s", out)
        if err:
            self.log.info("ERR: \n%s", err)
        self.log.info("====================================")

    def __str__(self):
        return self.name


class ExtractImageCommand(Command):
    """Extract command

    Required econfig attributes:
        images: list of image filenames
        get_image_path: function to get image path
        get_extracted_path: function to get extracted path
    """

    name = "1.1-EXTRACT-IMAGES"
    seq = False

    def gen_cmd(self, force=False):
        config = self.config
        image_filenames = config.all_images
        extract_cmds = []
        for image_filename in image_filenames:
            image_path = config.get_image_path(image_filename)
            extracted_path = config.get_extracted_path(image_filename)
            if force or not os.path.isfile(extracted_path):
                # generate extract command
                if not os.path.isfile(image_path):
                    raise FileNotFoundError(f"Image file not found: {image_path}")
                extract_cmd = f"{self.config.cmds.EXTRACT_IMAGE_CMD} {image_path} {os.path.dirname(extracted_path)}"
                extract_cmds.append(extract_cmd)
        return extract_cmds

    def check(self):
        config = self.config
        image_filenames = config.images
        for image_filename in image_filenames:
            extracted_path = config.get_extracted_path(image_filename)
            if not os.path.isfile(extracted_path):
                print(f"Extract failed: {extracted_path}")


class UnpackImageCommand(Command):
    """Unpack command

    Required econfig attributes:
        images: list of image filenames
        get_image_path: function to get image path
        get_extracted_path: function to get extracted path
        get_unpacked_path: function to get unpacked path
    """

    name = "1.2-UNPACK-IMAGES"
    seq = False

    def gen_cmd(self, force=False):
        config = self.config
        image_filenames = config.all_images
        unpack_cmds = []
        for image_filename in image_filenames:
            image_path = config.get_image_path(image_filename)
            extracted_path = config.get_extracted_path(image_filename)
            unpacked_path = config.get_unpacked_path(image_filename)
            if force or (
                not os.path.isdir(unpacked_path) or not os.listdir(unpacked_path)
            ):
                if not os.path.isfile(extracted_path):
                    raise FileNotFoundError(
                        f"Extracted archive not found: {image_path}"
                    )
                # generate unpack command
                unpack_cmd = f"{self.config.cmds.UNPACK_IMAGE_CMD} {extracted_path} {unpacked_path}"
                unpack_cmds.append(unpack_cmd)
        return unpack_cmds

    def check(self):
        config = self.config
        for image_filename in config.images:
            unpacked_path = config.get_unpacked_path(image_filename)
            if not os.path.isdir(unpacked_path) or not os.listdir(unpacked_path):
                print(f"Unpack failed: {unpacked_path}")


class ExtractKeywordsCommand(Command):
    """Extract keywords used for filtering binaries"""

    name = "1.3-EXTRACT-KEYWORDS"
    seq = False

    def gen_cmd(self, force=FORCE):
        config = self.config
        image_filenames = config.all_images
        extract_keywords_cmds = []
        for image_filename in image_filenames:
            unpacked_path = config.get_unpacked_path(image_filename)
            # assume unpacked directory exists and is not empty
            keyword_path = config.get_keyword_path(image_filename)
            if not force and os.path.exists(keyword_path):
                continue
            extract_keyword_cmd = f"{self.config.cmds.EXTRACT_KEYWORDS_CMD} {unpacked_path} {keyword_path}"
            extract_keywords_cmds.append(extract_keyword_cmd)
        return extract_keywords_cmds

    def check(self):
        config = self.config
        image_filenames = config.images
        if not os.path.exists(self.config.paths.KEYWORDS_DIR):
            print("Keywords not extracted")
            return
        find_res = check_output(
            f"find {self.config.paths.KEYWORDS_DIR} -name '*.json' -size -8c",
            shell=True,
            stderr=PIPE,
        )
        not_extract = 0
        n_keywords = 0
        for image_filename in image_filenames:
            keyword_path = config.get_keyword_path(image_filename)
            if not os.path.isfile(keyword_path):
                not_extract += 1
                continue
            with open(keyword_path, "r", encoding="utf-8") as keyword_fp:
                keywords = json.load(keyword_fp)
                n_keywords += len(keywords)
        if not_extract:
            print(f"{not_extract} image keywords not extracted")
        empty_lines = find_res.decode("utf-8").splitlines()
        if empty_lines:
            print(f"{len(empty_lines)} Empty keyword files found")
            for line in empty_lines:
                print(f"\t{line}")

        print(f"Total keywords: {n_keywords}")


class FilterVulnBinaryCommand(Command):
    """Filter binaries that may contain vulnerabilities"""

    name = "1.4-FILTER-VULN-BINARY"
    seq = False

    def gen_cmd(self, force=FORCE):
        config = self.config
        filter_binary_cmds = []
        for vuln, image_filename in config.get_vuln_images().items():
            unpacked_path = config.get_unpacked_path(image_filename)
            keywords_file = config.get_keyword_path(image_filename)
            output_path = config.get_filtered_vuln_binary_path(image_filename, vuln)
            vuln_info_path = config.get_vuln_info_path(vuln)

            if force or not os.path.isfile(output_path):
                filter_binary_cmd = f"{self.config.cmds.FILTER_BINARY_CMD} --vuln-info {vuln_info_path} {unpacked_path} {keywords_file} {output_path}"
                filter_binary_cmds.append(filter_binary_cmd)
        return filter_binary_cmds

    @staticmethod
    def check_filter_result(
        config, image_filenames, filter_result_paths, out_bin_hash_map
    ):
        total_bin_number = 0
        no_bin_number = 0
        bin_hash_map = {}
        for image_filename, filter_binary_path in zip(
            image_filenames, filter_result_paths
        ):
            if not os.path.isfile(filter_binary_path):
                print(f"Filter result not found: {filter_binary_path}")
            with open(filter_binary_path, "r", encoding="utf-8") as fb_fp:
                filter_result = json.load(fb_fp)
            if "target_paths" not in filter_result:
                no_bin_number += 1
                continue

            # collect binary hash
            if filter_result:
                total_bin_number += len(filter_result["target_paths"])
                for bin_rel_path in filter_result["target_paths"]:
                    binary_path = os.path.join(
                        config.get_unpacked_path(image_filename), bin_rel_path
                    )
                    if not os.path.isfile(binary_path):
                        print(f"Binary path not found: {image_filename} {binary_path}")
                        continue
                    bin_hash = calc_binary_hash(binary_path)
                    if bin_hash not in bin_hash_map:
                        bin_hash_map[bin_hash] = []
                    bin_key = " ".join((image_filename, bin_rel_path))
                    if bin_key not in bin_hash_map[bin_hash]:
                        bin_hash_map[bin_hash].append(bin_key)
                    else:
                        continue

        unique_binaries = sorted(bin_hash_map.values())
        with open(out_bin_hash_map, "w", encoding="utf-8") as bhm_fp:
            json.dump(bin_hash_map, bhm_fp, indent=2)

        print("Check bin numbers:", total_bin_number)
        print("Check no bin image numbers:", no_bin_number)
        print("Check unique bin numbers:", len(unique_binaries))

    def check(self):
        # The following code is used to check the vulnerable bins in the target
        config = self.config
        print("Checking vulnerable bins in target")
        for vuln_name in config.vulns:
            vuln_info = config.get_vuln_info(vuln_name)
            if not vuln_info:
                print(f"Vuln info not found for {vuln_name}")
            if "firmware_filename" not in vuln_info:
                print(f"firmware_filename not found for {vuln_name}")
            image_filename = vuln_info["firmware_filename"]
            if "bin_path" not in vuln_info["groundtruth"]:
                print(f"bin_path not found for {vuln_name}")
            bin_path = vuln_info["groundtruth"]["bin_path"]
            filter_binary_path = config.get_filtered_vuln_binary_path(
                image_filename, vuln_name
            )
            with open(filter_binary_path, "r", encoding="utf-8") as fb_fp:
                filter_result = json.load(fb_fp)
            if bin_path not in filter_result["paths"]:
                print(f"\t{bin_path} of {vuln_name} not in paths {filter_binary_path}")
            elif bin_path not in filter_result["target_paths"]:
                print(
                    f"\t{bin_path} of {vuln_name} not in target_paths {filter_binary_path}"
                )

        filter_binary_paths = []
        image_filenames = []
        for vuln, image_filename in config.get_vuln_images().items():
            filter_binary_path = config.get_filtered_vuln_binary_path(
                image_filename, vuln
            )
            filter_binary_paths.append(filter_binary_path)
            image_filenames.append(image_filename)

        self.check_filter_result(
            config,
            image_filenames,
            filter_binary_paths,
            config.paths.VULN_BIN_HASH_MAP_PATH,
        )


class FilterBinaryCommand(Command):
    """Filter binary command"""

    name = "1.5-FILTER-BINARY"
    seq = False

    def gen_cmd(self, force=FORCE):
        config = self.config
        image_filenames = config.images
        filter_binary_cmds = []
        for image_filename in image_filenames:
            unpacked_path = config.get_unpacked_path(image_filename)
            keywords_file = config.get_keyword_path(image_filename)
            output_path = config.get_filtered_binary_path(image_filename)
            if force or not os.path.isfile(output_path):
                filter_binary_cmd = f"{self.config.cmds.FILTER_BINARY_CMD} {unpacked_path} {keywords_file} {output_path}"
                filter_binary_cmds.append(filter_binary_cmd)
        return filter_binary_cmds

    def check(self):
        config = self.config
        filter_binary_paths = []
        image_filenames = []
        for image_filename in config.images:
            filter_binary_path = config.get_filtered_binary_path(image_filename)
            filter_binary_paths.append(filter_binary_path)
            image_filenames.append(image_filename)

        FilterVulnBinaryCommand.check_filter_result(
            config,
            image_filenames,
            filter_binary_paths,
            config.paths.BIN_HASH_MAP_PATH,
        )


class PrepareDatabaseCommand(Command):
    """Setup database for input entry recording"""

    name = "2.1-PREPARE-DATABASE"
    seq = True

    def gen_cmd(self, force=FORCE):
        db_name = self.config.db_name
        vuln_db_name = self.config.vuln_db_name
        cmds = []
        for db in (db_name, vuln_db_name):
            cmds.extend(
                [
                    f"psql -c 'DROP DATABASE {db}'",
                    f"psql -c 'CREATE DATABASE {db}'",
                    f"psql -d {db} -f {CREATE_TABLES_INS}",
                ]
            )
            if not force:
                proc = subprocess.run(
                    f"psql -lqt | cut -d \\| -f 1 | grep -qw {db}",
                    shell=True,
                    check=False,
                )
                if proc.returncode == 0:
                    cmds = [f"psql -d {db} -f {CREATE_TABLES_INS}"]

        if not force:
            if os.path.isfile(self.config.paths.FIRMENTRY_DB_PATH):
                cmds.append(
                    f"psql -d {db_name} -f {self.config.paths.FIRMENTRY_DB_PATH}"
                )
            if os.path.isfile(self.config.paths.FIRMENTRY_VULN_DB_PATH):
                cmds.append(
                    f"psql -d {vuln_db_name} -f {self.config.paths.FIRMENTRY_VULN_DB_PATH}"
                )
        return cmds


class ExtractInputCommand(Command):
    """Extract input command"""

    name = "2.2-EXTRACT-INPUT"
    seq = False

    def gen_cmd(self, force=FORCE, only_vuln=ONLY_GT_VULN):
        """Generate extract input commands"""
        config = self.config
        image_filenames = config.images

        os.makedirs(self.config.paths.GHIDRA_PROJECT_DIR, exist_ok=True)

        db_names = (config.vuln_db_name, config.db_name)
        if not force:
            conns = [
                psycopg2.connect(
                    database=db,
                    user=config.db_user,
                    password=config.db_user_passwd,
                    host="localhost",
                    port=5432,
                )
                for db in db_names
            ]
            cursors = [conn.cursor() for conn in conns]

        # Analyzing both target and vulnerable images
        target_images = []
        for vuln, image_filename in config.get_vuln_images().items():
            target_images.append((image_filename, vuln))
        for image_filename in image_filenames:
            target_images.append((image_filename, None))

        bin_hash_map = json.load(
            open(config.paths.BIN_HASH_MAP_PATH, "r", encoding="utf-8")
        )
        vuln_bin_hash_map = json.load(
            open(config.paths.VULN_BIN_HASH_MAP_PATH, "r", encoding="utf-8")
        )

        # Find duplicate binaries
        target_bin_keys = set()
        hash_visited = set()
        assert os.path.exists(
            self.config.paths.BIN_HASH_MAP_PATH
        ), "Bin hash map not found"
        assert os.path.exists(
            self.config.paths.VULN_BIN_HASH_MAP_PATH
        ), "Vuln bin hash map not found"

        # Add vulnerable binaries first to avoid overwriting binaries used for signature extraction
        for bin_hash, bin_keys in vuln_bin_hash_map.items():
            hash_visited.add(bin_hash)
            target_bin_keys.add(bin_keys[0])
        for bin_hash, bin_keys in bin_hash_map.items():
            if bin_hash in hash_visited:
                continue
            target_bin_keys.add(bin_keys[0])

        args = []
        for image_filename, vuln in target_images:
            if vuln:
                db = db_names[0]
                filtered_binary_lst_path = config.get_filtered_vuln_binary_path(
                    image_filename, vuln
                )
            else:
                db = db_names[1]
                filtered_binary_lst_path = config.get_filtered_binary_path(
                    image_filename
                )

            with open(
                filtered_binary_lst_path, "r", encoding="utf-8"
            ) as filtered_binaries_fp:
                filter_binary_result = json.load(filtered_binaries_fp)

            firmware_id = image_filename.split("/", 1)[-1]

            for bin_rel_path in filter_binary_result.get("target_paths", []):
                extra_args = ""
                if not force:
                    cursor = cursors[0] if vuln else cursors[1]
                    cursor.execute(
                        """
                        SELECT firmware_id, path, bin.hash AS bin_hash from bin
                        WHERE firmware_id = %s AND path = %s
                        """,
                        (firmware_id, bin_rel_path),
                    )
                    if cursor.fetchall():
                        continue
                keywords_file = config.get_keyword_path(image_filename)

                # Filter duplicate binaries to reduce analysis time
                bin_key = " ".join((image_filename, bin_rel_path))
                if bin_key not in target_bin_keys:
                    continue

                args.append(
                    (image_filename, bin_rel_path, keywords_file, db, extra_args)
                )

        if not force:
            for cursor in cursors:
                cursor.close()
            for conn in conns:
                conn.close()

        # Generating cmds
        extract_input_cmds = []
        for image_filename, bin_rel_path, keywords_file, db, extra_args in args:
            binary_path = os.path.join(
                config.get_unpacked_path(image_filename), bin_rel_path
            )

            jar_cmd = self.config.cmds.EXTRACT_INPUT_CMD.replace(
                "-jar", f"-Xmx{INPUT_ANA_MEMLIM}G -jar"
            )
            extract_input_cmd = (
                f"{jar_cmd} {self.config.paths.CONFIG_PATH} {binary_path} "
                f"{keywords_file} {db} {extra_args}"
            )
            extract_input_cmds.append(extract_input_cmd)

        return extract_input_cmds


class SaveDatabaseCommand(Command):
    """Save database"""

    name = "2.3-SAVE-DATABASE"
    seq = True

    def gen_cmd(self, force=FORCE):
        vuln_db_name = self.config.vuln_db_name
        db_name = self.config.db_name
        os.makedirs(os.path.dirname(self.config.paths.FIRMENTRY_DB_PATH), exist_ok=True)
        cmds = [
            f"pg_dump {vuln_db_name} -f {self.config.paths.FIRMENTRY_VULN_DB_PATH}",
            f"pg_dump {db_name} -f {self.config.paths.FIRMENTRY_DB_PATH}",
        ]
        return cmds


class AnalyzeInputCommand(Command):
    """Analyze the inputs and correct the function models"""

    name = "2.4-ANALYZE-INPUT"
    seq = True

    def gen_cmd(self, force=FORCE):
        config = self.config
        if not force and os.path.isfile(self.config.paths.FUNC_MODEL_PATH):
            return []
        return [
            (
                f"{self.config.cmds.CORRECT_MODEL_CMD} {self.config.paths.CONFIG_PATH}"
                f" {config.vuln_db_name} {self.config.paths.VULN_FUNC_MODEL_PATH}"
            ),
            (
                f"{self.config.cmds.CORRECT_MODEL_CMD} {self.config.paths.CONFIG_PATH}"
                f" {config.db_name} {self.config.paths.FUNC_MODEL_PATH}"
            ),
        ]


class SignatureExtractionSearchCommand(Command):
    """Search for potentially vulnerable input entries"""

    name = "3.1-SIGNATURE-EXTRACT-SEARCH"
    seq = False

    def gen_cmd(self, force=FORCE):
        config = self.config
        search_cmds = []

        for vuln in config.vulns:
            search_result_path = self.config.get_sig_gen_search_result_path(vuln)
            vuln_info_path = self.config.get_vuln_info_path(vuln)
            search_cmd = (
                f"{self.config.cmds.SEARCH_CMD} --sig-gen {vuln_info_path} "
                f"{self.config.paths.CONFIG_PATH} "
                f"{config.vuln_db_name} "
                f"{self.config.paths.VULN_FUNC_MODEL_PATH} "
                f"{self.config.paths.NAME_SIM_DICTIONARY_PATH} "  # this argument is not used
                f"{self.config.paths.VULN_NAMED_INPUT_ENTRIES_PATH} "
                f"{self.config.paths.VULN_UNNAMED_INPUT_ENTRIES_PATH} "
                f"{search_result_path} "
            )
            if force:
                search_cmd += " --force"
            search_cmds.append(search_cmd)
        return search_cmds

    def execute(self, *args, **kwargs):
        # Collect entries from database before searching
        prepare_cmd = (
            "/usr/bin/time -v "
            f"{self.config.cmds.SEARCH_PREPARE_CMD} "
            f"{self.config.paths.CONFIG_PATH} "
            f"{self.config.vuln_db_name} "
            f"{self.config.paths.VULN_FUNC_MODEL_PATH} "
            f"{self.config.paths.NAME_SIM_DICTIONARY_PATH} "
            f"{self.config.paths.VULN_NAMED_INPUT_ENTRIES_PATH} "
            f"{self.config.paths.VULN_UNNAMED_INPUT_ENTRIES_PATH} "
        )
        if FORCE:
            prepare_cmd += " --force"
        res = self._execute_one(prepare_cmd)
        self.log_handle_result(res)
        return super().execute(*args, **kwargs)


class SignatureExtractionSimEXPCommand(Command):
    """Extract simexp_results for signature extraction"""

    name = "3.2-SIGNATURE-EXTRACT-SIMEXP"
    seq = False

    def gen_cmd(self, force=False):
        cmd_lines = []
        for idx_info in iter_search_targets(
            self.config.paths.SIG_SIMEXP_INPUT_DIR, only_idx=True
        ):
            target_info, target_info_path, target_info_idx = idx_info

            cmd_line = (
                f"{self.config.cmds.SIMEXP_CMD} --force -o {self.config.paths.SIG_SIMEXP_RESULT_DIR}"
                f" --timeout {SIMEXP_TIMEOUT * 2} --memlim {SIMEXP_MEMLIM}"
                f" --stop-on-vuln --vuln-test {target_info_path} {target_info_idx}"
            )
            result_item = ResultItem(
                self.config.paths.SIG_SIMEXP_RESULT_DIR, target_info
            )
            if not force:
                if result_item.exists:
                    continue
            cmd_lines.append(cmd_line)

        return cmd_lines

    def check(self):
        vuln_simexp_results = {}
        for idx_info in iter_search_targets(
            self.config.paths.SIG_SIMEXP_INPUT_DIR, only_idx=True
        ):
            target_info, target_info_path, target_info_idx = idx_info
            result_item = ResultItem(
                self.config.paths.SIG_SIMEXP_RESULT_DIR, target_info
            )
            if not result_item.exists:
                continue
            result_item = result_item.load(save_space=True)
            if result_item.vuln:
                vuln_simexp_results.setdefault(result_item.vuln_name, []).append(
                    result_item
                )

        for vuln_name, results in vuln_simexp_results.items():
            full_vuln_name = results[0].vendor + "/" + vuln_name
            vuln_info = self.config.get_vuln_info(full_vuln_name)
            hit = False
            for result in results:
                if "groundtruth" in vuln_info:
                    gt = vuln_info["groundtruth"]
                    left = (
                        vuln_info["firmware_filename"],
                        gt["bin_path"],
                        int(gt["entry_addr"], 16),
                    )
                    right = (
                        result.vendor + "/" + result.firmware_id,
                        result.path,
                        result.entry_addr,
                    )
                    if left == right:
                        hit = True
                        break
            print(f"{vuln_name}: {len(results)} vulns. Hit: {hit}")


class AnalyzeVulnerabilityCommand(Command):
    """Analyze vulnerability command"""

    name = "3.3-ANALYZE-VULNERABILITY"
    seq = False

    def gen_cmd(self, force=FORCE):
        cmd_lines = []

        for vuln in self.config.vulns:
            ana_result_path = self.config.get_vuln_ana_result_path(vuln)
            if not force and os.path.isfile(ana_result_path):
                with open(ana_result_path, "r", encoding="utf-8") as ana_res_fp:
                    ana_result = json.load(ana_res_fp)
                if ana_result:
                    continue
            vuln_info_path = self.config.get_vuln_info_path(vuln)
            if not force and os.path.exists(ana_result_path):
                continue
            cmd_line = (
                f"{self.config.cmds.ANA_VULN_CMD} "
                f"{vuln} {self.config.paths.SIG_SIMEXP_RESULT_DIR} "
                f"{vuln_info_path} {ana_result_path}"
            )
            cmd_lines.append(cmd_line)
        return cmd_lines

    def check(self):
        for vuln in self.config.vulns:
            ana_result_path = self.config.get_vuln_ana_result_path(vuln)
            if not os.path.isfile(ana_result_path):
                print(f"Analyze result is missing for {vuln}")
            with open(ana_result_path, "r", encoding="utf-8") as ana_res_fp:
                ana_result = json.load(ana_res_fp)
            if not ana_result:
                print(f"Analyze vulnerability failed for {vuln}")


class LLMSimDetectionCommand(Command):
    """Use large language model to detect similar names"""

    name = "4.1-LLM-SIM-DETECT"
    seq = True

    def gen_cmd(self, force=FORCE):
        out_path = self.config.paths.NAME_SIM_DICTIONARY_PATH
        if not force and os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            return []
        return [
            (
                f"{self.config.cmds.LLM_SIM_DETECT_CMD} {self.config.paths.CONFIG_PATH} "
                f"{self.config.paths.SIG_DIR} {self.config.paths.NAMED_INPUT_ENTRIES_PATH} "
                f"{self.config.paths.LLM_TMP_DIR} {out_path} {'--force' if force else ''} "
            )
        ]


class SearchInputCommand(Command):
    """Search inputs command"""

    name = "4.2-SEARCH-INPUT"
    seq = False

    def __init__(self, config: ExperimentConfig, exact=False):
        super().__init__(config)
        self.exact = exact

    def gen_cmd(self, force=FORCE):
        config = self.config
        search_cmds = []

        for vuln in config.vulns:
            ana_result_path = self.config.get_vuln_ana_result_path(vuln)
            search_result_path = self.config.get_search_result_path(vuln)
            search_cmd = (
                f"{self.config.cmds.SEARCH_CMD} --detect {ana_result_path} "
                f"{self.config.paths.CONFIG_PATH} "
                f"{config.db_name} "
                f"{self.config.paths.FUNC_MODEL_PATH} "
                f"{self.config.paths.NAME_SIM_DICTIONARY_PATH} "
                f"{self.config.paths.NAMED_INPUT_ENTRIES_PATH} "
                f"{self.config.paths.UNNAMED_INPUT_ENTRIES_PATH} "
                f"{search_result_path} "
            )
            if force:
                search_cmd += " --force"
            if self.exact:
                search_cmd += " --exact"
            search_cmds.append(search_cmd)
        return search_cmds

    def execute(self, *args, **kwargs):
        # Collect entries from database before searching
        prepare_cmd = (
            "/usr/bin/time -v "
            f"{self.config.cmds.SEARCH_PREPARE_CMD} "
            f"{self.config.paths.CONFIG_PATH} "
            f"{self.config.db_name} "
            f"{self.config.paths.FUNC_MODEL_PATH} "
            f"{self.config.paths.NAME_SIM_DICTIONARY_PATH} "
            f"{self.config.paths.NAMED_INPUT_ENTRIES_PATH} "
            f"{self.config.paths.UNNAMED_INPUT_ENTRIES_PATH} "
        )
        if FORCE:
            prepare_cmd += " --force"
        res = self._execute_one(prepare_cmd)
        self.log_handle_result(res)
        return super().execute(*args, **kwargs)

    def check(self):
        config = self.config
        for vuln in config.vulns:
            search_result_path = config.get_search_result_path(vuln)
            if os.path.isfile(search_result_path):
                with open(search_result_path, "r", encoding="utf-8") as search_res_fp:
                    search_results = json.load(search_res_fp)
            else:
                search_results = None
            if not search_results:
                print(f"No search result for {vuln}")
                continue


class SimulateExploitCommand(Command):
    """Simulate Exploitation"""

    name = "4.3-SIMULATE-EXPLOIT"
    seq = False

    def gen_cmd(self, force=FORCE, only_gt_vuln=ONLY_GT_VULN, only_vuln=ONLY_VULN):
        cmd_lines = []
        output = self.config.paths.SIMEXP_RESULT_DIR
        target_filter = None
        if only_gt_vuln:
            config = self.config
            vulns = config.vulns
            tfb = TargetFilterBuilder(output=output)
            for vuln in vulns:
                vuln_name = config.get_vuln_name(vuln)
                vuln_info = config.get_vuln_info(vuln)
                bin_path = vuln_info["bin_path"]
                firmware_id = vuln_info["firmware_filename"].split("/")[-1]
                entry_addr = vuln_info["entry_addr"]
                tfb.add_filter(
                    vuln_name=vuln_name,
                    firmware_id=firmware_id,
                    path=bin_path,
                    entry_addr=entry_addr,
                    extra=None,
                )
            target_filter = tfb.build()

        if only_vuln:
            tfb = TargetFilterBuilder(output=output)
            tfb.add_option("only_vuln", True)
            target_filter = tfb.build()

        for idx_info in iter_search_targets(
            self.config.paths.SIMEXP_INPUT_DIR, only_idx=True
        ):
            target_info, target_info_path, target_info_idx = idx_info

            cmd_line = (
                f"{self.config.cmds.SIMEXP_CMD} --force -o {self.config.paths.SIMEXP_RESULT_DIR}"
                f" --timeout {SIMEXP_TIMEOUT} --memlim {SIMEXP_MEMLIM}"
                f" --stop-on-vuln {target_info_path} {target_info_idx}"
            )
            # cmd_line = (
            #    f"{self.config.cmds.SIMEXP_CMD} --force -o {self.config.paths.SIMEXP_RESULT_DIR}"
            #    f" --vuln-test --timeout {SIMEXP_TIMEOUT} --memlim {SIMEXP_MEMLIM}"
            #    f" --stop-on-vuln {target_info_path} {target_info_idx}"
            # )
            result_item = ResultItem(self.config.paths.SIMEXP_RESULT_DIR, target_info)
            if not force:
                if result_item.exists:
                    continue
            if target_filter:
                if not target_filter.match(result_item.key):
                    continue
            # if (
            #     target_info.vendor + "/" + target_info.firmware_id
            # ) not in econfig.images[:320]:
            #     continue
            cmd_lines.append(cmd_line)

        return cmd_lines


class ShowResultCommand(Command):
    """Show vulnerability detection results"""

    name = "4.4-SHOW-RESULT"
    seq = True
    is_commander = True

    def gen_cmd(self, force=FORCE):
        pass

    def execute(self, gen=True, gen_force=FORCE, check=CHECK, parallel=PARALLEL):
        diag_main(
            [
                "collect",
                "--only-vuln-filter",
                "--save-csv",
                "--input",
                self.config.paths.SIMEXP_INPUT_DIR,
                "--output",
                self.config.paths.SIMEXP_RESULT_DIR,
            ]
        )
        output_path = os.path.join(self.config.paths.SIMEXP_RESULT_DIR, "result.csv")
        with open(output_path, 'r', encoding='utf-8') as fp:
            print(fp.read())


class FirmRecCommand(Command):
    """Full Firmrec command"""

    name = "FIRMREC-ALL"
    seq = True
    is_commander = True

    def gen_cmd(self, *args, **kwargs):
        pass

    def save(self, _):
        pass

    def execute(self, gen=True, gen_force=FORCE, check=CHECK, parallel=PARALLEL):
        """Execute all FirmRec commands"""
        log = self.log
        config = self.config
        # Preparation
        extract_image_cmd = ExtractImageCommand(config)
        unpack_image_cmd = UnpackImageCommand(config)
        extract_keyword_cmd = ExtractKeywordsCommand(config)
        filter_vuln_binary_cmd = FilterVulnBinaryCommand(config)
        filter_binary_cmd = FilterBinaryCommand(config)

        # Input entry identification
        prepare_database_cmd = PrepareDatabaseCommand(config)
        extract_input_cmd = ExtractInputCommand(config)
        save_database_cmd = SaveDatabaseCommand(econfig)
        analyze_input_cmd = AnalyzeInputCommand(config)

        # Signature extraction
        signature_extraction_search_cmd = SignatureExtractionSearchCommand(config)
        signature_extraction_simexp_cmd = SignatureExtractionSimEXPCommand(config)
        analyze_vulnerability_cmd = AnalyzeVulnerabilityCommand(config)

        # Vulnerability detection
        llm_sim_detection_cmd = LLMSimDetectionCommand(config)
        search_input_cmd = SearchInputCommand(config)
        simulate_exploit_cmd = SimulateExploitCommand(config)

        log.info("Extracting images")
        extract_image_cmd.execute(
            gen=gen, gen_force=False, check=check, parallel=parallel
        )

        log.info("Unpacking images")
        unpack_image_cmd.execute(
            gen=gen, gen_force=False, check=check, parallel=parallel
        )

        log.info("Extracting keywords")
        extract_keyword_cmd.execute(
            gen=gen, gen_force=gen_force, check=check, parallel=parallel
        )

        log.info("Filtering vulnerable binaries")
        filter_vuln_binary_cmd.execute(
            gen=gen, gen_force=gen_force, check=True, parallel=parallel
        )

        log.info("Filtering binaries")
        filter_binary_cmd.execute(
            gen=gen, gen_force=gen_force, check=True, parallel=parallel
        )

        log.info("Preparing database")
        prepare_database_cmd.execute(
            gen=gen, gen_force=gen_force, check=check, parallel=parallel
        )

        log.info("Extracting input")
        extract_input_cmd.execute(
            gen=gen, gen_force=gen_force, check=check, parallel=parallel
        )

        log.info("Saving database")
        save_database_cmd.execute(
            gen=gen, gen_force=gen_force, check=check, parallel=parallel
        )

        log.info("Analyzing input")
        analyze_input_cmd.execute(
            gen=gen, gen_force=gen_force, check=check, parallel=parallel
        )

        log.info("Searching for signature generation")
        signature_extraction_search_cmd.execute(
            gen=gen, gen_force=gen_force, check=check, parallel=parallel
        )

        log.info("Simulate exploitation for signature generation")
        signature_extraction_simexp_cmd.execute(
            gen=gen, gen_force=gen_force, check=check, parallel=parallel
        )

        log.info("Generating signatures")
        analyze_vulnerability_cmd.execute(
            gen=gen, gen_force=gen_force, check=check, parallel=parallel
        )

        log.info("Detecting similar names")
        llm_sim_detection_cmd.execute(
            gen=gen, gen_force=gen_force, check=check, parallel=parallel
        )

        log.info("Searching input")
        search_input_cmd.execute(
            gen=gen, gen_force=gen_force, check=check, parallel=parallel
        )

        log.info("Simulating exploit")
        simulate_exploit_cmd.execute(
            gen=gen, gen_force=gen_force, check=check, parallel=parallel
        )

        log.info("Done")


def pipeline_main(cmds: dict):
    """Main"""
    if len(sys.argv) < 2:
        step_prompt = "\n\t".join([str(cmd) for idx, cmd in cmds.items()])
        choice = input(f"Choices:\n\t{step_prompt}\n> ")
        args = [choice]
    else:
        args = sys.argv[1:]
    idxes = list()
    for arg in args:
        try:
            if arg not in cmds:
                raise ValueError(f"Invalid choice '{arg}'")
        except ValueError:
            print(f"Invalid choice {arg}. Valid choices are {cmds.keys()}")
            sys.exit(1)
        idxes.append(arg)

    idxes.sort()

    for idx in idxes:
        print(f"Generating Commands For {cmds[idx]}")
        cmd = cmds[idx]
        os.makedirs(cmd.config.paths.CMDS_DIR, exist_ok=True)
        gen_kwargs = {}
        if FORCE_ALL:
            gen_kwargs["force"] = True
        clear_log = False
        if not cmd.is_commander and not NO_GEN:
            cmd_lines = cmd.gen_cmd(**gen_kwargs)
            cmd.save(cmd_lines)
            if cmd_lines and not ONLY_GEN:
                clear_log = True
        if not ONLY_GEN:
            gen = False
            gen_force = False
            if cmd.is_commander:
                gen = True
                gen_force = FORCE
            if clear_log:
                cmd.clear_log()
            cmd.execute(gen=gen, gen_force=gen_force)
        if CHECK:
            cmd.check()


def firmrec_main():
    """FirmRec main"""
    pipeline_main(
        {
            "all": FirmRecCommand(econfig),
            # Prepare
            "1.1": ExtractImageCommand(econfig),
            "1.2": UnpackImageCommand(econfig),
            "1.3": ExtractKeywordsCommand(econfig),
            "1.4": FilterVulnBinaryCommand(econfig),
            "1.5": FilterBinaryCommand(econfig),
            # Input Identification
            "2.1": PrepareDatabaseCommand(econfig),
            "2.2": ExtractInputCommand(econfig),
            "2.3": SaveDatabaseCommand(econfig),
            "2.4": AnalyzeInputCommand(econfig),
            # Signature Extraction
            "3.1": SignatureExtractionSearchCommand(econfig),
            "3.2": SignatureExtractionSimEXPCommand(econfig),
            "3.3": AnalyzeVulnerabilityCommand(econfig),
            # Vulnerability Detection
            "4.1": LLMSimDetectionCommand(econfig),
            "4.2": SearchInputCommand(econfig),
            "4.3": SimulateExploitCommand(econfig),
            "4.4": ShowResultCommand(econfig),
        }
    )


if __name__ == "__main__":
    firmrec_main()

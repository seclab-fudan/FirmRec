"""
This module provide view of vulnerable result
"""

from __future__ import annotations
from typing import TYPE_CHECKING
import os
import json

from ..taint_analysis.enums import ERStatus
from ..models.result import ResultSet
from ..models.target_info import TargetInfo
from ..econfig import econfig
from ..consts import ConstPaths

if TYPE_CHECKING:
    from ..models.result import ResultItem


class VulnResultItemView:
    """View of vulnerable result"""

    chain_info = None  # chain information to identify front end source
    filter_info = {}

    def __init__(self, result_item: ResultItem) -> None:
        if not result_item.vuln:
            raise ValueError("Result item is not vulnerable")
        self._item = result_item

    @property
    def item(self) -> ResultItem:
        """Result Item"""
        return self._item

    @property
    def source(self) -> str | None:
        """Source function of vulnerability"""
        knowledge = self._item.target_info.extra_info.get("knowledge")
        if not knowledge:
            return None
        return knowledge.get("source_func_name", None)

    @property
    def sink(self) -> str | None:
        """Sink function of vulnerability"""
        for record in reversed(self.item.vuln_path.records):
            if record.status == ERStatus.ENTER or record.status == ERStatus.LEAVE:
                return record.func_name
        return None

    @property
    def vuln_reason(self) -> str | None:
        """Vulnerability reason"""
        vuln_record = self.item.vuln_record
        if not vuln_record:
            return None
        return vuln_record.data.get("reason", None)

    @property
    def keyword(self) -> str | None:
        """Keyword of vulnerability"""
        knowledge = self._item.target_info.extra_info.get("knowledge")
        if not knowledge:
            return None
        return knowledge.get("found_keyword", None)

    @property
    def keyword_filtered(self):
        """Check more precisely whether the result is vulnerable"""
        if self.filter_info is None:
            return False
        key = econfig.get_filter_input_path(
            self._item.vendor, self._item.firmware_id, self._item.path
        )
        if key in self.filter_info and self.keyword in self.filter_info[key]:
            return True
        return False

    @property
    def keyword_match(self):
        """Check whether the exploited keyword match to target or no keyword is found"""
        if self.keyword is None:
            return True
        expect_keyword = self.item.target_info.extra_info["knowledge"].get(
            "found_keyword"
        )
        if expect_keyword is None:
            return True
        if expect_keyword == self.keyword:
            return True
        return False

    @property
    def front_source_chain(self):
        """Front-end source chain"""
        assert self.chain_info is not None, "Chain info is not loaded"
        return SourceChainUtils.find_source_chains_rec(
            self._item, self.chain_info, only_front=True
        )

    @property
    def source_chains(self):
        """All source chains"""
        assert self.chain_info is not None, "Chain info is not loaded"
        return SourceChainUtils.find_source_chains_rec(
            self._item, self.chain_info, only_front=False
        )

    @classmethod
    def load_chain_info(cls, chain_info_path):
        """
        Load source chain information from file
        """
        if cls.chain_info:
            return
        if not os.path.isfile(chain_info_path):
            return 
        with open(chain_info_path, "r", encoding="utf-8") as chain_fp:
            chain_info = json.load(chain_fp)
        cls.chain_info = chain_info

    @classmethod
    def load_filter_info(cls, filter_info_dir):
        """
        Load input filter information from file
        """
        if cls.filter_info:
            return
        filter_info = {}
        if not os.path.isdir(filter_info_dir):
            return
        for res_file in os.listdir(filter_info_dir):
            res_path = os.path.join(filter_info_dir, res_file)
            with open(res_path, "r", encoding="utf-8") as filter_fp:
                raw = json.load(filter_fp)
                filter_info[res_path] = set(raw["results"])
        cls.filter_info = filter_info


class SourceChainUtils:
    """Utils for source chain inferring"""

    @classmethod
    def _is_front_source_api(cls, source_chain):
        """Check is the source api is front end source api"""
        api_name = source_chain["source_api"]
        if "web" in api_name.lower():
            return True
        # source_bin_path = source_chain["path"]
        # if source_bin_path.endswith("d"):
        #     return True
        return False

    @classmethod
    def find_source_chains_non_rec(
        cls, keyword, source_addr, firmware_chains, visited=()
    ):
        """Find get set chain non-recursively"""
        chains = []
        if keyword not in firmware_chains:
            if not source_addr:
                return chains
            for chain in firmware_chains.get("", []):
                if source_addr == chain["source_api_addr"]:
                    chains.append(chain)
        else:
            chains = firmware_chains[keyword][0]
        for chain in chains:
            source_api = chain["source_api_id"]
            if source_api in visited:
                continue
            visited.add(source_api)
            yield chain

    @classmethod
    def find_source_chains_rec(cls, vuln_result, chain_info, only_front=True):
        """Find get set chain recursively"""
        if vuln_result.firmware_id not in chain_info:
            return None
        firmware_chains = chain_info[vuln_result.firmware_id]
        visited = set()
        if vuln_result.target_info.source_info:
            source_addr = vuln_result.target_info.source_info[0].addr
        else:
            source_addr = None
        keyword = vuln_result.target_info.extra_info["knowledge"]["found_keyword"]
        stack = [(keyword, source_addr, [])]
        if not only_front:
            results = []
        else:
            results = None
        while stack:
            keyword, source_addr, chains = stack.pop()
            for chain in cls.find_source_chains_non_rec(
                keyword, source_addr, firmware_chains, visited
            ):
                if only_front:
                    new_chains = [chain] + chains
                    if cls._is_front_source_api(chain):
                        return new_chains
                    new_keyword = chain["source_keyword"]
                    new_source_addr = chain["source_api_addr"]
                    stack.append((new_keyword, new_source_addr, new_chains))
                else:
                    results.append(chain)
        return results


class VulnFilter:
    """Filter false positives of vuln results"""

    def filter_results(self, resset: ResultSet) -> ResultSet:
        """Filter results"""
        _visited_id = set()
        vuln_resset = ResultSet("VulnReports")
        for result_item in resset.vuln_results:
            if not result_item.prepared:
                result_item = result_item.load()
            ref_id = TargetInfo.refer_id(result_item)
            if ref_id in _visited_id:
                continue
            _visited_id.add(ref_id)
            if self.is_vulnerable(result_item):
                vuln_resset.add(result_item)
        return vuln_resset

    def is_vulnerable(self, result_item: ResultItem) -> bool:
        """Check if the result item is vulnerable"""
        if not result_item.vuln:
            return False

        if not result_item.vuln_record:
            return False

        vuln_view = VulnResultItemView(result_item)
        VulnResultItemView.load_chain_info(ConstPaths.FUNC_MODEL_CHAIN_PATH)
        VulnResultItemView.load_filter_info(ConstPaths.FILTER_INPUT_DIR)

        # filter by vuln reason
        vuln_reason = vuln_view.vuln_reason
        if not vuln_reason or vuln_reason == "Control-flow Hijacked":
            return False

        if vuln_view.keyword_filtered:
            return False

        # filter by source blacklist
        source = vuln_view.source
        black_words = [
            "add",
            "pend",
            "concat",
            "insert",
            "push",
            "put",
            "copy",
            "join",
            "move",
            "replace",
            "revert",
            "pop",
            "splice",
            "unshift",
            "unset",
            "write",
            "update",
            "out",
            "log",
            "tag",
            "mark",
            "contain",
            "generate",
        ]
        for blakc_word in black_words:
            if blakc_word in source.lower():
                return False

        # Finally, got a vulnerable report
        return True

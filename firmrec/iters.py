import os
import json
import traceback

from firmlib import find_binaries

from .models.result import ResultItem, ResultKey
from .models.target_info import TargetInfo


class TargetFilterBuilder:
    """Builder of TargetFilter"""

    def __init__(self, output=None):
        self.output = output
        self._f = []
        self._o = {}

    def add_filter(self, **kwargs):
        """Add a filter rule"""
        filter_rule = dict(**kwargs)
        self._f.append(ResultKey.from_dict(filter_rule))
        return self

    def add_option(self, option_name, option_value):
        """Add an option"""
        self._o[option_name] = option_value
        return self

    def build(self):
        """Build the filter"""
        target_filter = TargetFilter(output=self.output)
        # pylint: disable=protected-access
        target_filter._f = self._f
        target_filter._o = self._o
        return target_filter


class TargetFilter:
    """
    Filter of replay target
    """

    def __init__(self, output=None):
        self.output = output
        self._f = []
        self._o = {}
        self._ref_resset = None
        
    def add_option(self, option_name, option_value):
        """Add an option"""
        self._o[option_name] = option_value
        return self

    def match(self, key: ResultKey):
        """Check if the key matches the filter"""
        if self._f:
            for f_key in self._f:
                if f_key.match(key):
                    break
            else:
                return False
        if self._o.get("only_exist", False):
            r = ResultItem(self.output, key)
            if not r.exists:
                return False
        if self._o.get("only_timeout", False):
            r = ResultItem(self.output, key)
            if not r.exists:
                return False
            r = r.load(save_space=True)
            if not r.timeout:
                return False
        if self._o.get("only_vuln", False):
            r = ResultItem(self.output, key)
            if not r.exists:
                return False
            r = r.load(save_space=True)
            if not r.vuln:
                return False
            vuln_reason = self._o.get("only_vuln_reason", None)
            if vuln_reason:
                r = r.load(save_space=False)
                record = r.vuln_record
                if not record:
                    return False
                reason = record.data.get("reason", None)
                if not reason or reason != vuln_reason:
                    return False
        return True

    @classmethod
    def load(cls, filter_path, output=None):
        """Load filter from file"""
        with open(filter_path, "r", encoding="utf-8") as fp:
            raw_filters = json.load(fp)
        filters = []
        for raw in raw_filters["filters"]:
            enabled = raw.pop("enabled", True)
            if not enabled:
                continue
            filters.append(ResultKey.from_dict(raw))

        options = raw_filters.get("options", {})

        # may replace reference ouput directory
        ref_output = raw_filters.get("ref_output", None)
        if ref_output:
            output = ref_output

        rf = TargetFilter(output=output)
        rf._f = filters
        rf._o = options
        return rf

    def save(self, filter_path):
        """Save filter to file"""
        filters = [key.to_dict() for key in self._f]
        data = dict(filters=filters, options=self._o)
        with open(filter_path, "w+", encoding="utf-8") as fp:
            json.dump(data, fp)


def iter_targets(target_info_dir, target_filter=None):
    """Legacy function to iterate targets"""
    if target_filter:
        rf = TargetFilter.load(target_filter)
    target_file_names = (
        os.popen(f"find {target_info_dir} -name '*.json'")
        .read()
        .strip()
        .splitlines(keepends=False)
    )
    for target_info_path in target_file_names:
        target_infos: list[TargetInfo] = []
        try:
            for target_info in TargetInfo.load_from_file(target_info_path):
                if target_filter and not rf.match(target_info.key):
                    continue
                target_infos.append(target_info)
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            print(f"Warning: fail to load {target_info_path}")
            traceback.print_exc()
        yield target_info_path, target_infos


def iter_search_targets(target_info_dir, target_filter=None, only_idx=False):
    """
    Iterate targets for search

    :param target_info_dir: directory of target info
    :param target_filter: filter of target
    :param only_idx: only return index of target info
    :return: (target_info, target_info_path, idx) if only_idx is True else target_info
    """
    if isinstance(target_filter, str):
        rf = TargetFilter.load(target_filter)
    else:
        rf = target_filter
    target_file_names = (
        os.popen(f"find {target_info_dir} -name '*.json'")
        .read()
        .strip()
        .splitlines(keepends=False)
    )

    target_infos = []
    target_dup_infos = {}
    for target_info_path in target_file_names:
        try:
            with open(target_info_path, "r", encoding="utf-8") as fp:
                search_results = json.load(fp)
            for idx, search_result in enumerate(search_results):
                target_info = TargetInfo.load_from_search_result(search_result)
                if not target_info:
                    continue
                if target_filter and not rf.match(target_info.key):
                    continue
                uniq_id = TargetInfo.refer_id(target_info)
                if uniq_id not in target_dup_infos:
                    target_dup_infos[uniq_id] = []
                target_dup_infos[uniq_id].append((target_info, target_info_path, idx))
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            print(f"Warning: fail to load {target_info_path}")
            traceback.print_exc()

    total = 0
    for _, lst in target_dup_infos.items():
        total += len(lst)
        for target_info, target_info_path, idx in lst:
            target_info.set_extra(idx)
            if only_idx:
                target_infos.append((target_info, target_info_path, idx))
            else:
                target_infos.append(target_info)
            break
    return target_infos


def index_target_info(target_info_path, idx):
    """Index target info from search result
    :param target_info_path: path of target info
    :param idx: index of search result
    :return TargetInfo: target info
    """
    with open(target_info_path, "r", encoding="utf-8") as fp:
        search_results = json.load(fp)
    search_result = search_results[idx]
    target_info = TargetInfo.load_from_search_result(search_result)
    target_info.set_extra(idx)
    return target_info


def iter_fws(firmware_dir):
    """
    Iterate all firmwares
    """
    for vendor in os.listdir(firmware_dir):
        vendor_path = os.path.join(firmware_dir, vendor)
        for fw in os.listdir(vendor_path):
            fw_path = os.path.join(vendor_path, fw)
            yield fw_path


def iter_bins(firmware_dir):
    """
    Iterate all binaries
    """
    for fw_path in iter_fws(firmware_dir):
        for binary in find_binaries(fw_path):
            yield binary




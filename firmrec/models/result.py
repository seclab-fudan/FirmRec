"""
This module defines the result of FirmRec
"""
from __future__ import annotations
import os
import logging
import pickle
from dataclasses import dataclass, field, fields
from functools import cached_property

from ..taint_analysis.pathinfo import PathInfo
from ..consts import ConstValues


@dataclass
class ResultKey:
    """
    Key of result
    """

    vuln_name: str = field(default_factory=lambda: None)
    vendor: str = field(default_factory=lambda: None)
    firmware_id: str = field(default_factory=lambda: None)
    path: str = field(default_factory=lambda: None)
    entry_addr: int = field(default_factory=lambda: None)
    extra: int = field(default_factory=lambda: None)

    @classmethod
    def parse(cls, key_str: str) -> ResultKey:
        """
        Parse FirmRecResultKey from string

        :param key_str: the exact string to be parsed
        :return (FirmRecResultKey) key: parsed key
        """
        splits = key_str.split("@@", 4)
        if len(splits) != 5:
            raise ValueError("Invalid key_str", key_str)

        try:
            entry_addr = int(splits[2], 16)
        except (TypeError, ValueError):
            entry_addr = splits[2]

        vuln_name = splits[1]
        if vuln_name == "*":
            vuln_name = None

        last_splits = splits[4].split("@Ex", 1)
        if len(last_splits) > 1:
            splits[4] = last_splits[0]
            extra = int(last_splits[1])
        else:
            extra = 0

        key = cls(
            vuln_name=vuln_name,
            vendor=splits[0],
            firmware_id=splits[3],
            path=splits[4].replace("@@", "/"),
            entry_addr=entry_addr,
            extra=extra,
        )
        return key

    def match(self, key=None, **kwargs) -> bool:
        """
        Match with target key val

        :param kwargs: key and value to match
        """
        if key:
            kvs = key.to_dict()
        else:
            kvs = kwargs
        for key, val in kvs.items():
            self_val = getattr(self, key, None)
            if self_val is None or val is None:
                continue
            if self_val != val:
                return False
        return True

    @classmethod
    def from_dict(cls, dict_obj):
        """Load ResultKey from dict"""
        n_field = 0
        r = cls()
        for obj_field in fields(r):
            key = obj_field.name
            val = dict_obj.get(key, None)
            if val is None:
                continue
            if key == "entry_addr" and isinstance(val, str):
                try:
                    val = int(val, 16)
                except ValueError:
                    pass
            n_field += 1
            setattr(r, key, val)
        # assert len(dict_obj) == n_field
        return r

    def to_dict(self):
        """Convert ResultKey to dict"""
        dict_obj = {}
        for obj_field in fields(self):
            key = obj_field.name
            val = getattr(self, key)
            if val is None:
                continue
            dict_obj[key] = val
        return dict_obj

    def __str__(self) -> str:
        vuln_name = "*" if self.vuln_name is None else self.vuln_name
        try:
            entry_addr = hex(self.entry_addr)
        except TypeError:
            entry_addr = self.entry_addr
        if self.extra:
            extra = self.extra
        else:
            extra = 0
        return f"{self.vendor}@@{vuln_name}@@{entry_addr}@@{self.firmware_id}@@{self.path.replace('/', '@@')}@Ex{extra}"

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, ResultKey):
            return False
        return str(self) == str(__value)

    def __hash__(self) -> int:
        return hash(
            (
                self.vuln_name,
                self.vendor,
                self.firmware_id,
                self.path,
                self.entry_addr,
            )
        )


class ResultItem:
    """
    Result of FirmRec
    """

    def __init__(self, out_path, target_or_key):
        self.out_path = out_path

        if isinstance(target_or_key, ResultKey):
            key = target_or_key
        elif hasattr(target_or_key, "key"):
            key = target_or_key.key
        else:
            raise ValueError(
                "Invalid type to construct ResultItem", str(type(target_or_key))
            )
        self.key = ResultKey.from_dict(key.to_dict())  # copy

        self.paths = None
        self.path_counts = {}
        self.run_time = None
        self.timeout = None
        self.taint_applied = None

        self._logger = None
        self.target_info = None
        self.poc_info = None

        self._dup = None

    def prepare_result(self, ct, target_info=None, poc_info=None):
        """
        Prepare result to be saved

        :param ct: CoreTaint object that has finished run
        """
        if self.dup:
            return
        self.paths = ct.paths
        self.target_info = target_info
        self.poc_info = poc_info
        self.path_counts = {stash: len(self.paths[stash]) for stash in self.paths}
        self.run_time = ct.run_time
        self.timeout = ct.timeout_triggered or self.run_time < 0
        self.taint_applied = ct.taint_applied

    @property
    def dup(self):
        if not hasattr(self, "_dup"):
            return None
        return self._dup

    @property
    def n_paths(self):
        """Number of all paths"""
        if self.dup:
            return self.dup.n_paths
        return sum([self.path_counts[stash] for stash in self.paths])

    def get_n_paths(self, stash=None):
        """Get number of paths of specified stash
        :param stash: stash name
        :return (int) n_paths: number of paths of specified stash
            or total number of paths if stash is None
        """
        if not stash:
            return self.n_paths
        return self.path_counts.get(stash, 0)

    @property
    def prepared(self) -> bool:
        """Check if result is prepared"""
        return self.paths is not None

    @property
    def logger(self) -> logging.Logger:
        """Get logger"""
        if self._logger:
            return self._logger
        log = logging.Logger("FirmRec", logging.INFO)
        os.makedirs(self.log_dir, exist_ok=True)
        log.addHandler(logging.FileHandler(self.log_path, "w+", delay=True))
        log.setLevel(logging.DEBUG)
        self._logger = log
        return log

    @property
    def key_str(self) -> str:
        """Key string"""
        return str(self.key)

    @property
    def vuln(self) -> bool:
        """Check if it is a vulnerable target"""
        return self.get_n_paths("sanitized") > 0

    @property
    def vuln_path(self) -> PathInfo:
        """Get vulnerable path if exists"""
        if not self.vuln:
            return None
        return self.paths["sanitized"][0]

    @property
    def vuln_record(self):
        """Get vulnerable record if exists"""
        path = self.vuln_path
        if not path:
            return None
        return path.vuln_record

    @property
    def vendor(self):
        """Vendor name"""
        return self.key.vendor

    @property
    def firmware_id(self):
        """Firmware identifier"""
        return self.key.firmware_id

    @property
    def path(self):
        """Relative path from firmware to binary"""
        return self.key.path

    @property
    def entry_addr(self):
        """Entry address of target"""
        return self.key.entry_addr

    @property
    def vuln_name(self):
        """Vulnerability name"""
        return self.key.vuln_name

    @property
    def result_dir(self):
        """Path to result directory"""
        return os.path.join(self.out_path, "results")

    @property
    def feature_dir(self):
        """Path to path feature directory"""
        return os.path.join(self.out_path, "features")

    @property
    def result_path(self):
        """Path to summarized result file"""
        return os.path.join(self.result_dir, self.key_str + ".pkl")

    @property
    def feature_path(self):
        """Path to path feature file"""
        return os.path.join(self.feature_dir, self.key_str + ".pkl")

    @property
    def log_dir(self):
        """Path to log directory"""
        return os.path.join(self.out_path, "logs")

    @property
    def log_path(self):
        """Path to log file"""
        return os.path.join(self.log_dir, self.key_str + ".log")

    @property
    def exists(self):
        """Check if result exists and is valid"""
        try:
            self.load(save_space=True)
        except:  # pylint: disable=bare-except
            return False
        return True

    def copy_dup(self, vendor, firmware_id, path):
        """
        copy the result to a new result with different vendor, firmware_id and path
        """
        key = ResultKey(
            vuln_name=self.vuln_name,
            vendor=vendor,
            firmware_id=firmware_id,
            path=path,
            entry_addr=self.entry_addr,
        )
        item = ResultItem(None, key)
        item._dup = self
        item.paths = self.paths
        item.target_info = self.target_info
        item.poc_info = self.poc_info
        item.path_counts = self.path_counts
        item.run_time = self.run_time
        item.timeout = self.timeout
        item.taint_applied = self.taint_applied
        return item

    def load_log(self):
        """Load log content from file"""
        with open(self.log_path, "r", encoding="utf-8") as fp:
            return fp.read()

    def save(self):
        """Save result to file"""
        assert self.prepared
        os.makedirs(self.result_dir, exist_ok=True)
        os.makedirs(self.feature_dir, exist_ok=True)
        with open(self.result_path, "wb+") as fp:
            paths = self.paths
            log = self._logger
            self.paths = None
            self._logger = None
            pickle.dump(self, fp)
            self.paths = paths
            self._logger = log

        with open(self.feature_path, "wb+") as fp:
            pickle.dump(self.paths, fp)

    def load(self, save_space=False) -> ResultItem:
        """
        Load ResultItem from file
        :param save_space: If True, do not load paths to save space
        """
        feature_path = self.feature_path if not save_space else None
        return self.load_from_file(self.result_path, feature_path)

    @classmethod
    def load_from_file(cls, result_path, feature_path=None, output=None) -> ResultItem:
        """
        Load
        """
        key_str = os.path.basename(result_path).rsplit(".", 1)[0]
        key = ResultKey.parse(key_str)
        with open(result_path, "rb") as fp:
            res = pickle.load(fp)
        if output:
            res.output = output
        res.key = key  # Override key

        if feature_path:
            with open(feature_path, "rb") as fp:
                paths = pickle.load(fp)
            res.paths = paths
        return res


@dataclass
class ResultSet(object):
    """Set of FirmRecResult"""

    name: str
    result_dict: dict[ResultKey, ResultItem] = field(default_factory=dict)

    @property
    def results(self):
        for result in self.values():
            yield result

    @property
    def vuln_results(self):
        for result in self.values():
            if result.vuln:
                yield result
                
    @cached_property
    def field_indexes(self):
        """
        Get field indexes of this key
        """
        indexes = {}
        for key in fields(ResultKey):
            indexes[key.name] = index = {}
            for result in self.results:
                key_value = getattr(result.key, key.name)
                if key_value not in index:
                    index[key_value] = set()
                index[key_value].add(result)
        return indexes

    @property
    def run_time(self):
        return sum(map(lambda r: r.run_time if r.run_time > 0 else ConstValues.SIMEXP_TIMEOUT, self.results))

    def keys(self):
        return self.result_dict.keys()

    def values(self):
        return self.result_dict.values()

    def items(self):
        return self.result_dict.items()

    def update(self, another):
        if not isinstance(another, ResultSet):
            raise ValueError(repr(another), "Is not instanece of FirmRecResultSet")
        self.result_dict.update(another.result_dict)

    def update_if(self, another, condition, replace=None):
        for tr in another.results:
            r = self.get(tr.key)
            if condition(r, tr):
                if replace:
                    replace(r, tr)
                self.add(tr)

    def add(self, result: ResultItem):
        """
        Add a result to set

        :param result: result to add
        :return old: return old result of the same key if it exists
        """

        old = self.get(result.key, None)
        self[result.key] = result
        return old

    def get(self, key: ResultKey, default=None):
        if key in self:
            return self[key]
        return default
    
    def find_resset(self, name, **kwargs):
        """
        Find results in result set with give field filter.
        :param name: name of the new result set
        :param load: if True, load result from file
        :param kwargs: key and value to match
        :return: a new result set with found results that matching field filters,
        """
        load = kwargs.pop("load", False)
        resset = ResultSet(name)
        for result in self.find_results(**kwargs):
            if load and not result.prepared:
                result = result.load()
            resset.add(result)
        return resset

    def find_results(self, **kwargs):
        """Find results in result set with give field filter.

        :param kwargs: key and value to match
            :field filter: function to filter result
        :return: a generator of found results that matching field filters,
            if no filter is give, all results will be returned
        """
        filter = kwargs.pop("filter", None)
        indexed_result_sets = []
        for key, value in kwargs.items():
            if key in self.field_indexes:
                index = self.field_indexes[key]
                if value in index:
                    indexed_result_sets.append(index[value])
                else:
                    return
        if indexed_result_sets:
            results = set.intersection(*indexed_result_sets)
        else:
            results = self.results

        for result in results:
            if not result.key.match(**kwargs):
                continue
            if filter and not filter(result):
                continue
            yield result

    def diff(self, another):
        """Diff with another result set

        :param another: resultset to diff
        :param diff_func: function to distinguish different result
        :return: (resset_l, resset_r, resset_vl, resset_vr)
        """
        if not isinstance(another, ResultSet):
            raise ValueError(f"Can't sub {type(another)} from {type(self)}")
        resset_l = ResultSet(f"{self.name} - {another.name}")
        resset_r = ResultSet(f"{another.name} - {self.name}")
        resset_vl = ResultSet(f"Vuln {self.name} - {another.name}")
        resset_vr = ResultSet(f"diff [{self.name}, {another.name}]")
        keys = set(self.keys()).union(another.keys())
        for k in keys:
            r = self.result_dict.get(k, None)
            r_c = another.result_dict.get(k, None)
            if not r:
                resset_r.add(r_c)
            elif not r_c:
                resset_l.add(r)
            else:
                if r.vuln and not r_c.vuln:
                    resset_vl.add(r)
                elif not r.vuln and r_c.vuln:
                    resset_vr.add(r_c)

        return resset_l, resset_r, resset_vl, resset_vr

    @classmethod
    def load(
        cls,
        name,
        output=None,
        target_infos=None,
        show_progress=True,
        save_space=False,
        target_filter=None,
    ):
        """
        Load from output

        :param name: name of the result set
        :param output: directory of output, the results from output will overwrite those loaded from target_infos
        :param target_infos: iterator of target_info, can be regarded as the full set
        :param show_progress: show progress bar
        :param save_space: if enabled, the paths will become unavaiable and thus save RAM space
        :param filter: filter to filter results
        :return: loaded set
        """
        resset = cls(name=name)

        if show_progress:
            from rich.progress import track

            traverse = track
        else:
            traverse = lambda x, **kwargs: x

        if target_infos:
            for target_info in traverse(
                target_infos, description="load all targets", total=len(target_infos)
            ):
                res = ResultItem(None, target_info)
                resset.add(res)

        if output:
            result_dir = os.path.join(output, "results")
            if os.path.isdir(result_dir):
                file_names = os.listdir(result_dir)
            else:
                file_names = []
            for file_name in traverse(
                file_names, description="load simexp results", total=len(file_names)
            ):
                if target_filter:
                    key = ResultKey.parse(file_name.rsplit(".", 1)[0])
                    if not target_filter.match(key):
                        continue
                file_path = os.path.join(result_dir, file_name)
                feature_path = os.path.join(output, "features", file_name)
                if save_space:
                    feature_path = None
                try:
                    res = ResultItem.load_from_file(
                        file_path, feature_path, output=output
                    )
                except EOFError:
                    os.remove(file_path)
                resset.add(res)

        return resset

    def __sub__(self, another: ResultSet):
        if not isinstance(another, ResultSet):
            raise ValueError(f"{another} is not an instance of ResultSet")
        result_dict = {}
        for k in self:
            if k not in another:
                result_dict[k] = self.result_dict[k]
        sub_resset = ResultSet(f"({self}-{another})", result_dict)
        return sub_resset

    def __len__(self):
        return len(self.result_dict)

    def __contains__(self, key):
        return key in self.result_dict

    def __getitem__(self, key):
        return self.result_dict[key]

    def __setitem__(self, key, result):
        self.result_dict[key] = result

    def __iter__(self):
        return self.result_dict.__iter__()

    def __repr__(self) -> str:
        return f"<ResultSet(name={repr(self.name)})>"

    def __str__(self) -> str:
        return self.__repr__()

from __future__ import annotations
from typing import List
import os
import json

from .poc_info import PoCInfo
from .result import ResultKey, ResultItem


class SourceFunctionInfo:
    """
    Information of source function

    :ivar sf: if not None, this summarized function will be used
    :ivar addr: the addr can also be a symbol name
    """

    def __init__(self, protocol, addr, key_arg, val_arg, name="", sf=None, **kwargs):
        self.protocol = protocol
        self.addr = addr
        try:
            self.addr = int(addr, 16)
        except ValueError:
            pass
        except TypeError:
            pass
        self.key_arg = key_arg
        if isinstance(val_arg, int) and val_arg < 0:
            val_arg = None
        self.val_arg = val_arg
        self.sf = sf
        self.name = name
        self.kwargs = dict(kwargs)

    def to_dict(self):
        return {
            "protocol": self.protocol,
            "addr": self.addr,
            "key_arg": self.key_arg,
            "val_arg": self.val_arg,
            "name": self.name,
        }

    def __eq__(self, __o: object) -> bool:
        if not isinstance(__o, SourceFunctionInfo):
            return False
        return (
            self.addr == __o.addr
            and self.protocol == __o.protocol
            and self.key_arg == __o.key_arg
            and self.val_arg == __o.val_arg
        )

    def __hash__(self) -> int:
        return hash(self.addr)

    def __str__(self) -> str:
        if self.protocol == "kv":
            extra_args = f", key_arg={self.key_arg}, val_arg={self.val_arg}"
        else:
            extra_args = ""
        return (
            f"SourceFunctionInfo(addr={self.addr}, proto={self.protocol}{extra_args})"
        )

    def __repr__(self) -> str:
        return str(self)


class TargetInfo:
    """
    Information of Proof-of-concept

    :ivar bin_path: path of target binary
    :ivar entry_addr: entry function address
    :ivar arch: architecture of target binary
    :ivar source_info: information of source functions
    """

    SUPPORTED_PROTOCOLS = ["kw", "raw"]
    REFER_ID_FIELD_FIRMWARE_ID = 0
    REFER_ID_FIELD_VENDOR = 1
    REFER_ID_FIELD_PATH = 2
    REFER_ID_FIELD_ENTRY_ADDR = 3
    REFER_ID_FIELD_SOURCE_INFO = 4
    REFER_ID_FIELD_KEYWORD = 5
    REFER_ID_FIELD_VULN_TYPE = 6
    REFER_ID_LENGTH = 7

    def __init__(
        self,
        firmware_id,
        vuln_name,
        vendor,
        path,
        bin_path,
        base_addr,
        entry_addr,
        arch=None,
        lib_paths=None,
        source_info: List[SourceFunctionInfo] = None,
        extra_info=None,
        extra=None,
    ):
        self.vuln_name = vuln_name
        self.firmware_id = firmware_id
        self.vendor = vendor
        self.path = path
        self.bin_path = bin_path
        self.base_addr = base_addr
        self.entry_addr = entry_addr
        self.arch = arch
        self.lib_paths = lib_paths
        self.source_info = source_info
        self.extra_info = extra_info
        self.extra = extra

    @property
    def key(self):
        return ResultKey(
            vuln_name=self.vuln_name,
            vendor=self.vendor,
            firmware_id=self.firmware_id,
            path=self.path,
            entry_addr=self.entry_addr,
            extra=self.extra,
        )

    @property
    def poc_info(self):
        """Get PoC information"""
        return PoCInfo.load_from_searched_target(self)

    def set_extra(self, extra=0):
        """Set extra id for unique identification"""
        self.extra = extra

    def to_dict(self):
        """Convert all field to dict"""
        res = {
            "vuln_name": self.vuln_name,
            "firmware_id": self.firmware_id,
            "vendor": self.vendor,
            "path": self.path,
            "entry_addr": self.entry_addr,
            "extra": self.extra,
            "source_info": [si.to_dict() for si in self.source_info],
            "extra_info": self.extra_info,
        }
        return res

    @classmethod
    def load_from_file(cls, file_path) -> List[TargetInfo]:
        with open(file_path, "r", encoding="utf-8") as fp:
            data = json.load(fp)
        firmware_id, vuln_name = (
            os.path.basename(file_path).replace(".json", "").split("-", 1)
        )

        results = []

        bin_path = data["Path"]
        base_addr = data["Base Address"]

        vendor_path = os.path.dirname(bin_path[: bin_path.rfind(firmware_id)])
        vendor = os.path.basename(vendor_path)
        rel_bin_path = os.path.relpath(bin_path, vendor_path)
        path = rel_bin_path.split(os.path.sep, 1)[1]

        source_infos = set()
        for raw_result in data["Results"]:
            # parse source function information
            for source_info in raw_result["Sources"]:
                func_name = source_info["Function"]
                if func_name.startswith("FUN_"):
                    addr = int(func_name[4:], 16)
                else:
                    addr = source_info["Address"]

                # TODO: not hard code this
                kwargs = {}
                if "tenda" in file_path:
                    key_arg = 1
                    val_arg = None
                elif "netgear" in file_path:
                    key_arg = 1
                    val_arg = 2
                    kwargs["conservative"] = False
                elif "tp-link" in file_path:
                    key_arg = 1
                    val_arg = None
                    kwargs["taint_web_obj"] = True
                    # kwargs['lib_paths'] = []
                elif "dlink" in file_path:
                    key_arg = 1
                    val_arg = None
                else:
                    raise ValueError(f"Input not model for {file_path}")
                source_function_info = SourceFunctionInfo(
                    "kv", addr, key_arg, val_arg, **kwargs
                )
                source_infos.add(source_function_info)

        for raw_result in data["Results"]:
            # Arch sepecific register
            extra_info = {"conc_regs": {}}
            if "t9" in raw_result:
                extra_info["conc_regs"]["t9"] = raw_result["t9"]
            if "gp" in raw_result:
                extra_info["conc_regs"]["gp"] = raw_result["gp"]

            entry_addr = raw_result["Address"]
            target_info = TargetInfo(
                firmware_id,
                vuln_name,
                vendor,
                path,
                bin_path,
                base_addr,
                entry_addr,
                arch=None,
                source_info=source_infos,
                extra_info=extra_info,
            )
            results.append(target_info)

        return results

    @classmethod
    def load_from_search_result(cls, search_result):
        """Load target info from search result"""
        if "source_info" not in search_result:
            # TODO handle raw bytes reading function
            return None
        raw_source_info = search_result["source_info"]
        source_info = [
            SourceFunctionInfo(
                raw["type"],
                raw["addr"],
                raw["key_arg"],
                raw["out_arg"],
                name=raw.get("name", ""),
            )
            for raw in raw_source_info
        ]
        target_info = TargetInfo(
            search_result["firmware_id"],
            search_result["vuln_name"],
            search_result["vendor"],
            search_result["path"],
            search_result["bin_path"],
            search_result["base_addr"],
            search_result["entry_addr"],
            arch=None,
            lib_paths=search_result["lib_paths"],
            source_info=source_info,
            extra_info=search_result["extra_info"],
        )
        return target_info

    @classmethod
    def refer_eq(cls, obj_a, obj_b):
        """
        Check whether two object may refer to the same target
        :param obj_a: TargetInfo or ResultItem or ResultKey
        :param obj_b: TargetInfo or ResultItem or ResultKey
        :return: True if two object may refer to the same target
        """
        refer_id_a = cls.refer_id(obj_a)
        refer_id_b = cls.refer_id(obj_b)
        if not refer_id_a or not refer_id_b:
            return False
        for idx, ele_a in enumerate(refer_id_a):
            ele_b = refer_id_b[idx]
            if not ele_a or not ele_b:
                continue
            if ele_a != ele_b:
                return False
        return True

    @classmethod
    def refer_id(cls, obj):
        """
        Get the identifier of the target
        :param obj: TargetInfo or ResultItem or ResultKey
        :return: identifier of the target
        """
        key, target = cls._get_key_target_info(obj)
        if not key:
            return None
        key_id = cls._get_id_from_key(key)
        if not target:
            return key_id + (None, None, None)
        target_id = cls._get_id_from_target(target)
        return key_id + target_id

    @classmethod
    def _get_key_target_info(cls, obj):
        if isinstance(obj, TargetInfo):
            key, target_info = obj.key, obj
        elif isinstance(obj, ResultItem):
            key, target_info = obj.key, obj.target_info
        elif isinstance(obj, ResultKey):
            key, target_info = obj, None
        else:
            key, target_info = None, None
        return key, target_info

    @classmethod
    def _get_id_from_key(cls, key: ResultKey):
        return (
            key.firmware_id,
            key.vendor,
            key.path,
            key.entry_addr,
        )

    @classmethod
    def _get_id_from_target(cls, target_info: TargetInfo):
        # source_info = tuple(sorted(str(source) for source in target_info.source_info))
        knowledge = target_info.extra_info.get("knowledge")
        if not knowledge:
            source = None
        else:
            source = knowledge.get("source_func_name", None)
        if "knowledge" not in target_info.extra_info:
            uniq_id = tuple([source, None, None])
            return uniq_id
        keyword = target_info.extra_info["knowledge"].get("found_keyword", None)
        val = (
            target_info.extra_info["poc_info"]
            .get("input", {})
            .get("kv", {})
            .get(keyword)
        )
        if not val:
            vuln_type = 0
        elif len(val) > 0x40:
            vuln_type = 1
        else:
            vuln_type = 2
        uniq_id = (source, keyword, vuln_type)
        return uniq_id

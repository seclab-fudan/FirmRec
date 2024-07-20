"""
This file is used to analyze vulnerability with emulation and analyze the results
"""

#!python
# -*- coding: utf-8 -*-
import sys
import os
import json
from argparse import ArgumentParser

from firmlib import is_func_name

from ..models.result import ResultSet
from ..views.vuln_result import VulnFilter, VulnResultItemView
from ..iters import TargetFilterBuilder
from ..taint_analysis.enums import ERStatus


def get_vuln_name(vuln: str):
    if "/" in vuln:
        return vuln.split("/", 1)[1]
    return vuln


def get_vuln_vendor(vuln):
    if "/" in vuln:
        return vuln.split("/", 1)[0]
    return ""


def ana_white_call_signatures(record):
    return record.data.get("sig") if record.data else None


def ana_simexp_result(full_vuln_name, vuln_info_path, simexp_result_dir):
    """
    Analyze emulation results
    """
    vuln_name = get_vuln_name(full_vuln_name)
    resset = ResultSet.load(
        "result",
        output=simexp_result_dir,
        save_space=False,
        target_filter=TargetFilterBuilder().add_filter(vuln_name=vuln_name).build(),
    )

    result = {}

    # Extract input keywords from poc info
    with open(vuln_info_path, "r", encoding="utf-8") as fp:
        vuln_info = json.load(fp)
    inputs = vuln_info["input"]

    # Extract key keywords from analyze result
    firmware_id = os.path.basename(vuln_info["firmware_filename"])

    vf = VulnFilter()
    ana_results = list(
        resset.find_results(
            vuln_name=vuln_name,
            firmware_id=firmware_id,
            filter=vf.is_vulnerable,
        )
    )

    if not ana_results:
        print(f"Cannot find any result for {vuln_name}")
        return {}

    # Select the result that uses the most depicted keywords
    ana_result = max(ana_results, key=lambda x: len(x.vuln_path.get_keywords()))

    vuln_path = ana_result.vuln_path
    if not vuln_path:
        print(f"Cannot find vuln path for {full_vuln_name}")
        return {}

    entry_info = {}
    key_vars = vuln_path.key_vars
    entry_info["key_vars"] = key_vars
    key_consts = vuln_path.key_consts
    entry_info["key_consts"] = key_consts

    if not key_vars and not key_consts:
        return {}

    if "kv" in inputs:
        if not key_vars:
            print(f"Cannot find key vars for {full_vuln_name}")
            return {}
        for key_var in key_vars:
            if key_var not in inputs["kv"]:
                print(
                    f"Cannot find key var {key_var} value in input for {full_vuln_name}"
                )

    if "kv" not in inputs and "raw" not in inputs:
        print(f"Input protocol is not supported for {full_vuln_name}")
        return {}

    # Extract vuln_info
    with open(vuln_info_path, "r", encoding="utf-8") as fp:
        vuln_info = json.load(fp)

    result["vuln_name"] = vuln_name
    result["vuln_vendor"] = get_vuln_vendor(full_vuln_name)
    result["target_info"] = ana_result.target_info.to_dict()

    # Infer source function names and type signatures
    name_map = {}
    type_sigs = set()
    for record in ana_result.vuln_path.records:
        if record.status == ERStatus.ENTER:
            if is_func_name(record.name):
                name_map[record.addr] = record.name
            type_sig = ana_white_call_signatures(record)
            if type_sig:
                type_sigs.add(type_sig)

    for source_info in result["target_info"]["source_info"]:
        addr = source_info["addr"]
        source_info["name"] = name_map.get(addr, "")

    result["entry_info"] = entry_info

    white_calls = list(name_map.values()) + list(type_sigs)
    result["white_calls"] = white_calls

    # library paths
    result["lib_paths"] = vuln_info.get("libs", [])

    return result


def main():
    """Main"""
    parser = ArgumentParser(description="Analyze vulnerability with emulation")
    parser.add_argument("vuln", help="Vulnerability name")
    parser.add_argument(
        "simexp_result_dir", help="Simulation and exploitation result directory"
    )
    parser.add_argument("vuln_info_path", help="Vulnerability information path")
    parser.add_argument("ana_result_path", help="Output path")
    args = parser.parse_args()

    vuln = args.vuln
    simexp_result_dir = args.simexp_result_dir
    vuln_info_path = args.vuln_info_path
    ana_result_path = args.ana_result_path

    result = ana_simexp_result(vuln, vuln_info_path, simexp_result_dir)

    os.makedirs(os.path.dirname(ana_result_path), exist_ok=True)
    with open(ana_result_path, "w+", encoding="utf-8") as fp:
        json.dump(result, fp, indent=4)


if __name__ == "__main__":
    main()

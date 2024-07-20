#!python
# -*- coding: utf-8 -*-
"""
This is a script mainly for analysis purpose now
"""
import sys
import os
import json
import argparse
import shutil
from multiprocessing import Pool
import faulthandler
import traceback
from itertools import groupby

from IPython import embed
import csv

from firmlib import track
from firmrec.config import gconfig
from firmrec.models.result import ResultSet, ResultKey
from firmrec.views.result import ResultSetXlsxView, ResultSetCSVView, CSVResultSet
from firmrec.views.firmdb import FirmwareStatistic
from firmrec.views.compare import ComparisonXlsxView

# pylint: disable=unused-import
from firmrec.taint_analysis.enums import ERStatus
from firmrec.views.vuln_result import VulnResultItemView as VV, VulnFilter

# from bbf.border_binaries_finder import BorderBinariesFinder
from firmrec.views.binstat import BinAnalyzer
from firmrec.iters import iter_targets, iter_search_targets, TargetFilter
from firmrec.firmrec import FirmRec
from firmrec.consts import ConstPaths


class CSVView:
    """CSVView to a table"""

    def __init__(self, csv_file_path) -> None:
        header, data = self.load_csv(csv_file_path)
        self._header = header
        self._data = data

    @property
    def items(self):
        """Non-empty csv item entries"""
        _items = []
        for line in self._data:
            if line and line[0]:
                _items.append(line)
        return _items

    def get_cells(self, item, *fields):
        """Get all cells of a field"""
        cells = []
        for field in fields:
            cell = self.get_cell(item, field)
            cells.append(cell)
        return tuple(cells)

    def get_cell(self, item, field):
        """Get item by index"""
        if field not in self._header:
            return None
        return item[self._header.index(field)]

    @classmethod
    def load_csv(cls, csv_file_path):
        """Load csv header and data"""
        rows = []
        with open(csv_file_path, "r", encoding="utf-8") as csv_file:
            reader = csv.reader(csv_file)
            for row in reader:
                rows.append(row)
        header = rows[0]
        data = rows[1:]
        return header, data


def do_replay_task(task_args):
    """
    Function for replaying exploiting procedure on a single target
    """
    try:
        target_info, output, timeout, memlim, stop_on_vuln, force = task_args

        firmrec = FirmRec(gconfig, output, skip_exist=not force)
        firmrec.run(
            target_info,
            timeout=timeout,
            memlim=memlim,
            stop_on_vuln=stop_on_vuln,
        )
    except:  # pylint: disable=bare-except
        traceback.print_exc()


def cmd_replay(args):
    """
    Cmd for replaying exploiting procedure on all (filtered) targets
    """
    tasks = []
    all_target_infos = {}
    target_info_lst = []
    # Note that: when we specify input, we use the search results
    use_search_result = bool(args.input)

    if use_search_result:
        for target_info in iter_search_targets(args.input, target_filter=args.filter):
            target_info_lst.append(target_info)
    else:
        for _, target_infos in iter_targets(
            gconfig.get("target_info_dir"), target_filter=args.filter
        ):
            if not target_infos:
                continue

            for target_info in target_infos:
                key = target_info.key
                if target_info.key not in all_target_infos:
                    all_target_infos[key] = []
                all_target_infos[key].append(target_info)

        # remove duplicate tasks
        for key, target_info_lst_by_key in all_target_infos.items():
            # choose by their extra infos
            target_info = max(
                target_info_lst_by_key,
                key=lambda target_info: len(target_info.extra_info),
            )
            target_info_lst.append(target_info)

    for target_info in target_info_lst:
        task = (
            target_info,
            args.output,
            args.timeout,
            args.memlim,
            args.stop_on_vuln,
            args.force,
        )
        tasks.append(task)

    print(f"{len(tasks)} tasks to run")

    len_tasks = len(tasks)
    if not tasks:
        return

    if args.parallel == 1:
        for task in tasks:
            print(str(task[1].key))
            do_replay_task(task)
    else:
        pool = Pool(min(args.parallel, len_tasks))
        imap_iters = pool.imap_unordered(do_replay_task, tasks)
        pool.close()
        for _ in track(imap_iters, total=len_tasks):
            pass


def _rerun_filter(result, targets):
    """
    Filter for rerun
    """
    for r in targets:
        if (
            r.firmware_id == result.firmware_id
            and r.path == result.path
            and r.vendor == result.vendor
            and int(r.entry_addr) == result.entry_addr
        ):
            return True
    # result = result.load()
    # if VV(result).sink != 'snprintf':
    #     return False
    return False


def _rerun_one(args):
    """
    Rerun one result
    """
    r, output, timeout, memlim = args
    firmrec = FirmRec(gconfig, output, skip_exist=False)
    firmrec.rerun(r, timeout=timeout, memlim=memlim)


def cmd_rerun(args):
    """
    Cmd for rerun results
    """
    resset = ResultSet.load("result", output=args.output, save_space=True)

    # rerun_resset = resset.find_resset("rerun", filter=_rerun_filter)
    rerun_resset = resset
    pool = Pool(min(args.parallel, len(rerun_resset)))
    tasks = []
    for result in rerun_resset.results:
        task = (result, args.output, args.timeout, args.memlim)
        tasks.append(task)

    map_iters = pool.imap_unordered(_rerun_one, tasks)
    pool.close()
    for _ in track(map_iters, total=len(tasks), description="rerun"):
        pass


def cmd_collect(args):
    """
    Cmd for collecting and showing results
    """
    rf = TargetFilter.load(args.filter, output=args.output) if args.filter else None
    if args.only_vuln_filter or args.only_vuln:
        if not rf:
            rf = TargetFilter(output=args.output)
        rf.add_option("only_vuln", True)
    resset = ResultSet.load(
        "result", output=args.output, save_space=args.save_space, target_filter=rf
    )

    if args.bin_hash:
        with open(args.bin_hash, "r", encoding="utf-8") as bin_hash_fp:
            hash_map = json.load(bin_hash_fp)
        bin_map = {}
        for bin_paths in hash_map.values():
            if len(bin_paths) < 2:
                continue
            for idx, bin_path in enumerate(bin_paths):
                bin_map[bin_path] = bin_paths[: idx - 1] + bin_paths[idx + 1 :]
        for result in list(resset.vuln_results):
            bin_path_entry = f"{result.vendor}/{result.firmware_id} {result.path}"
            if bin_path_entry not in bin_map:
                continue
            for bin in bin_map[bin_path_entry]:
                # parse bin like bin_path_entry
                image_name, path = bin.split(" ", 1)
                vendor, firmware_id = image_name.split("/", 1)
                r = result.copy_dup(vendor, firmware_id, path)
                resset.add(r)

    if args.only_vuln_filter:
        assert (
            not args.save_space
        ), "Cannot use save_space and only_vuln_filter together"
        vuln_filter = VulnFilter()
        resset = vuln_filter.filter_results(resset)

    if args.save_xlsx:
        xlsx_path = os.path.join(args.output, "result.xlsx")
        xlsx_view = ResultSetXlsxView(resset, migrate_from=args.migrate)
        # if args.groundtruth:
        #     gt = GroundTruth.load(args.groundtruth)
        #     view.mark_ground_truth(gt)
        xlsx_view.save(xlsx_path)

    if args.save_csv:
        csv_path = os.path.join(args.output, "result.csv")
        csv_view = ResultSetCSVView(resset)
        csv_view.save(csv_path)

    if args.collect_vuln_bins:
        collect_vuln_bins(args, resset)

    if args.db:
        firm_statics = FirmwareStatistic()
        st = firm_statics.statistic(gconfig.get("firmware_dir"), resset)
        title = " Firmware Statistics "
        print(f"{title:=^80s}")
        json.dump(st, sys.stdout, indent=2)
        print(f"{'=':=^80s}\n")

    if args.impact:
        bin_analyzer = BinAnalyzer()
        bin_analyzer.statistic(args.output)

    if args.compare:
        resset_c = ResultSet.load(
            "result_c",
            output=args.compare,
            save_space=args.save_space,
            target_filter=rf,
        )
        cmp_l, cmp_r, cmp_vl, cmp_vr = resset.diff(resset_c)
        print("#Left  Unique:", len(cmp_l))
        print("#Right Unique:", len(cmp_r))
        print("#Left  Unique Vuln:", len(cmp_vl))
        print("#Right Unique Vuln:", len(cmp_vr))
        print("#Left  Unique Vuln in Common Set:", len(cmp_vl - cmp_l))
        print("#Right Unique Vuln in Common Set:", len(cmp_vr - cmp_r))

    if args.gt:
        diag_res = regression_compare(resset, args.gt)

    if args.migrate_res:
        assert args.input, "input must be specified"
        migrate_resset(resset, args.input)

    if args.diagnose:
        VV.load_chain_info(ConstPaths.FUNC_MODEL_CHAIN_PATH)
        embed()


def regression_compare(resset: ResultSet, gt_path: str):
    gt_view = CSVView(gt_path)
    diag_res = dict(no_target=[], no_detect=[])
    for item in gt_view.items:
        (
            vendor,
            firmware_id,
            path,
            entry_addr,
            ref_vuln_name,
            keyword,
            vuln_reason,
            run_time,
        ) = item
        if isinstance(entry_addr, str):
            try:
                entry_addr = int(entry_addr, 16)
            except ValueError:
                entry_addr = int(entry_addr, 10)
        key = ResultKey(
            vuln_name=ref_vuln_name,
            vendor=vendor,
            firmware_id=firmware_id,
            path=path,
            entry_addr=entry_addr,
        )
        check_dict = dict(
            vuln_name=ref_vuln_name,
            vendor=vendor,
            firmware_id=firmware_id,
            path=path,
            entry_addr=entry_addr,
        )
        if not any(resset.find_results(**check_dict)):
            ConstPaths.FILTERED_BINARY_DIR
            diag_res["no_target"].append(item)
            print(f"{key} No Target")
        elif not any(
            resset.find_results(filter=lambda result: result.vuln, **check_dict)
        ):
            diag_res["no_detect"].append(item)
            print(f"{key} Not Detected")

    print(f"{'=':=^80s}")
    print(f"Total GT: {len(gt_view.items)}")
    print(f"No Target: {len(diag_res['no_target'])}")
    print(f"Not Detected: {len(diag_res['no_detect'])}")
    print(f"{'=':=^80s}")
    return diag_res


def migrate_resset(resset, target_info_dir):
    item_map = []
    keys = iter_search_targets(target_info_dir, only_idx=True)
    for result in resset.results:
        for target_info, target_path, target_idx in keys:
            res_info = result.target_info.to_dict()
            tgt_info = target_info.to_dict()
            res_info["extra"] = tgt_info["extra"] = 0
            if res_info == tgt_info:
                item_map.append((result, (target_info, target_path, target_idx)))
                break
    for item in item_map:
        result, key = item
        _, _, idx = key
        old_result_path = result.result_path
        old_log_path = result.log_path
        old_feauture_path = result.feature_path
        result.key.extra = idx
        new_result_path = result.result_path
        new_log_path = result.log_path
        new_feature_path = result.feature_path
        shutil.move(old_result_path, new_result_path)
        shutil.move(old_feauture_path, new_feature_path)
        shutil.move(old_log_path, new_log_path)


def append_dict_to_json_file(file_path, data):
    """
    Appends a dictionary object to a JSON file, creating the file if it doesn't exist.
    """
    try:
        # Try to open the file in read mode to check if it's loadable
        with open(file_path, "r") as f:
            existing_data = json.load(f)
    except FileNotFoundError:
        # If the file doesn't exist, create it and write the dictionary object as the only item in a list
        existing_data = []

    except json.JSONDecodeError:
        # If the file is not loadable, raise an error
        raise ValueError(
            f"Error: The file '{file_path}' is not loadable as a JSON file."
        )

    # Append the new dictionary object to the existing list of data
    if data not in existing_data:
        existing_data.append(data)

    # Write the updated list of data to the file
    with open(file_path, "w") as f:
        json.dump(existing_data, f)


def collect_vuln_bins(args, resset: ResultSet):
    """
    This function collect vulnerable binaries
    """
    # iterate vulnerable results and keep their keys
    vuln_bin_paths = {}
    for result in resset.vuln_results:
        bin_path = result.target_info.bin_path
        vendor = result.key.vendor
        if vendor not in vuln_bin_paths:
            vuln_bin_paths[vendor] = []
        vuln_bin_paths[vendor].append((bin_path, result.key))

    # collect binaries
    for vendor, pairs in vuln_bin_paths.items():
        vendor_dir = os.path.join(args.output, "vuln_bins", vendor)
        os.makedirs(vendor_dir, exist_ok=True)
        for bin_path, key in pairs:
            name = f"{key.firmware_id}@@{key.path.replace('/', '@@')}"
            dest = os.path.join(vendor_dir, name)
            desc_dest = dest + ".json"
            append_dict_to_json_file(desc_dest, key.to_dict())
            if os.path.exists(dest):
                continue
            shutil.copy2(bin_path, dest)

    print(
        f"Collected binaries of {sum(len(bin_paths) for bin_paths in vuln_bin_paths.values())} vulnerable targets in {len(vuln_bin_paths)} vendors."
    )


def ana_firmrec_csv():
    view = CSVView("/tmp/firmrec_res.csv")
    report_t = set()
    report_f = set()
    report_a = set()
    func_t = set()
    func_f = set()
    func_a = set()

    for item in view.items:
        verify = view.get_cell(item, "Verify")
        func = view.get_cells(
            item, "厂家", "Firmware", "路径", "入口地址", "Source", "漏洞原因"
        )
        report = func + view.get_cells(item, "Keyword")
        if report in report_a:
            print(report)
        report_a.add(report)
        func_a.add(func)
        if verify == "True":
            report_dst = report_t
            func_dst = func_t
        elif verify == "False":
            report_dst = report_f
            func_dst = func_f
        else:
            continue
        report_dst.add(report)
        func_dst.add(func)

    func_f = func_f - func_t
    vendor_res = {}
    field_dicts = {
        "RA": report_a,
        "RT": report_t,
        "RF": report_f,
        "FA": func_a,
        "FT": func_t,
        "FF": func_f,
    }

    for name, data_set in field_dicts.items():
        for vendor, lst in groupby(
            sorted(data_set, key=lambda x: x[0]), key=lambda x: x[0]
        ):
            count = len(list(lst))
            if vendor not in vendor_res:
                vendor_res[vendor] = {field: 0 for field in field_dicts}
            vendor_res[vendor][name] = count
    for vendor, res in vendor_res.items():
        res["RPrecision"] = f"{res['RT'] / (res['RT'] + res['RF']):.3}"
        res["FPrecision"] = f"{res['FT'] / (res['FT'] + res['FF']):.3}"
    print(json.dumps(vendor_res, indent=2))


def parse_args(arg_lst):
    """Parse arguments"""
    parser = argparse.ArgumentParser(description=FirmRec.__doc__)
    parser.set_defaults(func=lambda _: parser.print_help())
    subparsers = parser.add_subparsers(help="Commands")

    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        "--output",
        "-o",
        default=ConstPaths.SIMEXP_RESULT_DIR,
        help="output directory",
    )
    parent_parser.add_argument(
        "--input",
        "-i",
        default=ConstPaths.SIMEXP_INPUT_DIR,
        help="input directory of target infos",
    )
    parent_parser.add_argument("--filter", help="filter file of target")
    parent_parser.add_argument(
        "--parallel", "-j", type=int, default=32, help="number of parallel"
    )

    # findil_parser = subparsers.add_parser(
    #     "findil", parents=[parent_parser], help="Find input locations"
    # )
    # findil_parser.set_defaults(func=cmd_findil)

    # Deprecated
    replay_parser = subparsers.add_parser(
        "replay", parents=[parent_parser], help="Replay PoCs"
    )
    replay_parser.add_argument("--timeout", type=int, default=60 * 10)
    replay_parser.add_argument("--memlim", type=int, default=10, help="GB")
    replay_parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="force replay target even when the result exists",
    )
    replay_parser.add_argument(
        "--stop-on-vuln",
        action="store_true",
        help="stop when one vulnerable path detected",
    )
    replay_parser.set_defaults(func=cmd_replay)

    rerun_parser = subparsers.add_parser(
        "rerun", parents=[parent_parser], help="Rerun Results"
    )
    rerun_parser.add_argument("--timeout", type=int, default=60 * 5)
    rerun_parser.add_argument("--memlim", type=int, default=10, help="GB")
    rerun_parser.set_defaults(func=cmd_rerun)

    collect_parser = subparsers.add_parser(
        "collect", parents=[parent_parser], help="Collect and show results"
    )
    collect_parser.add_argument(
        "--bin-hash", "-b", help="bin hash map file to extend the vulnerable results"
    )
    collect_parser.add_argument("--compare", "-c", help="output directory to compare")
    collect_parser.add_argument("--gt", help="csv path to ground truth")
    collect_parser.add_argument(
        "--diagnose",
        "-d",
        action="store_true",
        help="interact with IPython for diagnosis",
    )
    collect_parser.add_argument(
        "--db", action="store_true", help="Show firmware statistics"
    )
    collect_parser.add_argument(
        "--impact", action="store_true", help="Show affected products and versions"
    )
    # collect_parser.add_argument("--groundtruth", "-g", help="path of ground truth")
    collect_parser.add_argument(
        "--save-xlsx", action="store_true", help="save results as xlsx"
    )
    collect_parser.add_argument(
        "--save-csv", action="store_true", help="save results as csv"
    )
    collect_parser.add_argument("--migrate", help="migrate existing data when save")
    collect_parser.add_argument(
        "--migrate-res", action="store_true", help="migrate existing result set"
    )
    collect_parser.add_argument("--save-space", action="store_true", help="save space")
    collect_parser.add_argument(
        "--only-vuln", action="store_true", help="load only vuln target"
    )
    collect_parser.add_argument(
        "--only-vuln-filter",
        action="store_true",
        help="load only vuln target with filter",
    )
    collect_parser.add_argument(
        "--collect-vuln-bins",
        action="store_true",
        help="collect vulnerable binaries for analysis",
    )
    collect_parser.set_defaults(func=cmd_collect)

    return parser.parse_args(arg_lst)


def main(arg_lst):
    """Setup and run"""
    sys.setrecursionlimit(0x100000)
    faulthandler.enable()
    args = parse_args(arg_lst)
    args.func(args)


if __name__ == "__main__":
    main(sys.argv[1:])

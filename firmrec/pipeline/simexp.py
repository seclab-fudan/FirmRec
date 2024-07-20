#!python
# -*- coding:utf-8 -*-
import argparse
import logging

from ..firmrec import FirmRec
from ..models.poc_info import PoCInfo
from ..iters import index_target_info
from ..config import gconfig


def parse():
    """Parse arguments"""
    parser = argparse.ArgumentParser("simexp")
    parser.add_argument("--timeout", type=int, default=60 * 10)
    parser.add_argument("--memlim", type=int, default=10, help="GB")
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="force run firmrec on target even when the result exists",
    )
    parser.add_argument(
        "--input",
        "-i",
        default="",
        help="input directory of target infos",
    )
    parser.add_argument(
        "--output",
        "-o",
        required=True,
        help="output directory",
    )
    parser.add_argument(
        "--stop-on-vuln",
        action="store_true",
        help="stop when one vulnerable path detected",
    )
    parser.add_argument(
        "--vuln-test",
        action="store_true",
        help="signature extraction mode",
    )
    parser.add_argument("target_info_path", help="Path to target info file")
    parser.add_argument(
        "target_info_idx", type=int, help="Index of target info in target info file"
    )
    return parser.parse_args()


def simexp():
    """Exploit one target"""
    args = parse()
    target_info_path = args.target_info_path
    target_info_idx = args.target_info_idx
    target_info = index_target_info(target_info_path, target_info_idx)
    poc_info = target_info.poc_info
    output = args.output
    timeout = args.timeout
    memlim = args.memlim
    stop_on_vuln = args.stop_on_vuln
    force = args.force
    try:
        firmrec = FirmRec(gconfig, output, skip_exist=not force)
        firmrec.run(
            target_info,
            timeout=timeout,
            memlim=memlim,
            stop_on_vuln=stop_on_vuln,
            vuln_test=args.vuln_test,
        )
    except KeyboardInterrupt:
        print("Interrupted")
    except Exception as ex:  # pylint: disable=broad-except
        logging.exception(ex)


if __name__ == "__main__":
    simexp()

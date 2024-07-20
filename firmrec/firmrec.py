#!python
import sys
import os
import resource
import logging
import traceback
import json
import resource

import angr

from .models.target_info import TargetInfo
from .models.result import ResultItem

from .taint_analysis.coretaint import CoreTaint
from .taint_analysis import summary_functions as sf
from .config import gconfig as gconfig


class FirmRec:
    """
    FirmRec: detecting recurring bug in firmware with PoC

    :ivar output: directory of output
    """

    OPT_LOOP_LIMIT = 3
    OPT_MAX_RET_STOP = 10

    def __init__(self, config, output: str, skip_exist=True):
        self.config = config
        self.output = output
        self.skip_exist = skip_exist
        self._glob_setting_done = False

    def rerun(
        self,
        result: ResultItem,
        memlim=0,
        timeout=0,
        stop_on_vuln=True,
        hook_before_run=None,
        vuln_test=False
    ):
        """
        Rerun a result, refer to replay
        """
        target_info = result.target_info
        return self.run(
            target_info,
            log=result.logger,
            memlim=memlim,
            timeout=timeout,
            stop_on_vuln=stop_on_vuln,
            hook_before_run=hook_before_run,
            vuln_test=vuln_test,
        )

    def run(
        self,
        target_info: TargetInfo,
        log=None,
        memlim=0,
        timeout=0,
        stop_on_vuln=True,
        hook_before_run=None,
        vuln_test=False,
    ):
        """
        Run FirmRec on target

        :param output: directory of output
        :param target_info: information of target
        :param log: log object
        :param memlim: memory limit in GB
        :param timeout: timeout
        :param stop_on_vuln: stop execution when vulnerabiliti is sanitized
        :param hook_before_run: hook to setup ct and state before running
        """
        self.glob_setting()
        res = ResultItem(self.output, target_info)
        if self.skip_exist and res.exists:
            res = res.load()
            if res.vuln:
                return res, None

        # setup log
        if not log:
            if not self.output:
                log = logging.getLogger("firmrec")
            else:
                log = res.logger
            log.setLevel(logging.DEBUG)

        # load bin_name and load options
        main_opts = dict()
        main_opts["base_addr"] = target_info.base_addr
        if target_info.arch:
            # TODO: set backend and arch
            # backend: main_opts['backend'] = backend
            main_opts["arch"] = target_info.arch

        # white_calls are function addresses that we must follow
        white_calls = target_info.extra_info.get("white_calls", [])

        # Heuristic: raw byte processing is complex, the call stack may be deeper
        poc_info = target_info.poc_info
        smart_call = True
        if "raw" in poc_info.protocols:
            interfunction_level = 8
        else:
            interfunction_level = 6

        force_load_libs = target_info.lib_paths

        p = angr.Project(
            target_info.bin_path,
            auto_load_libs=False,
            main_opts=main_opts,
            force_load_libs=force_load_libs,
        )

        ct = CoreTaint(
            p,
            interfunction_level=interfunction_level,
            smart_call=smart_call,
            follow_unsat=True,
            black_calls=[],
            white_calls=white_calls,
            try_thumb=True,
            shuffle_sat=True,
            exit_on_decode_error=True,
            force_paths=True,
            taint_returns_unfollowed_calls=True,
            allow_untaint=False,
            taint_dyn_infer=False,
            stop_on_vuln=stop_on_vuln,
            logger_obj=log,
            path_limit=100,
            fine_taint_check=True,
            sym_global=True,
            opt_ret_merge=True,
            opt_loop_limit=self.OPT_LOOP_LIMIT,
            opt_max_ret_stop=self.OPT_MAX_RET_STOP,
            opt_taint_exit_guard=True,
            fine_recording=vuln_test,
            pending_explore=vuln_test,
        )

        state = ct.get_initial_state(target_info.entry_addr)
        # Set some registers to concrete values. This is usually
        # neccessary for mips architecture to identify .got call
        if "conc_regs" in target_info.extra_info:
            for reg, val in target_info.extra_info["conc_regs"].items():
                setattr(state.regs, reg, val)

        # load input paradigms and values
        payloads = []
        for protocol in poc_info.protocols:
            payload = poc_info.get_payload(protocol)
            if protocol == "kv":
                for key, val in payload.items():
                    ct.add_var(key, val)
                    if (
                        hasattr(poc_info, "key_keywords")
                        and key in poc_info.key_keywords
                    ):
                        ct.add_var(key, val, essential=True)
            elif protocol == "raw":
                payloads.extend(payload)
            else:
                pass
        state.info.payloads = payloads

        # setup input summarized functions
        for source_info in target_info.source_info:
            protocol = source_info.protocol
            func_name = source_info.name
            if source_info.sf:
                sum_f = source_info.sf  # replace default summarized function
            elif func_name and func_name in sf.SUM_FS:
                sum_f = sf.SUM_FS[func_name]
            elif protocol == "kv":
                sum_f = sf.get_env(
                    key_arg=source_info.key_arg,
                    out_arg=source_info.val_arg,
                    **source_info.kwargs,
                )
            elif protocol == "raw":
                sum_f = sf.recv(val_arg=source_info.val_arg)
            else:
                raise ValueError(f"Unknown SourceFunction protocol {protocol}")

            ct.add_sum_f(source_info.addr, sum_f)

        def _check_sink(current_path, *_, ct: CoreTaint = None, **__):
            # We don't sanitize vulnerabilities in this function,
            # but implementing general sanitizers in critical summarized APIs or
            # ret instructions
            pass

        # hook summarized functions by names
        ct.prepare_summarized_functions()

        # may add extra logic
        if hook_before_run:
            hook_before_run(ct, state)

        try:
            if memlim:
                _, hard = resource.getrlimit(resource.RLIMIT_AS)
                resource.setrlimit(
                    resource.RLIMIT_AS, (memlim * 1024 * 1024 * 1024, hard)
                )

            if timeout:
                ct.set_alarm(timeout, n_tries=3)

            msg = f"{target_info.bin_path} {target_info.vuln_name} {target_info.entry_addr:#x}"
            log.critical(msg)
            log.critical(json.dumps(target_info.to_dict(), indent=2))

            ct.run(
                state,
                (),
                (),
                summarized_f={},
                force_thumb=False,
                check_func=_check_sink,
                init_bss=False,
                use_smart_concretization=False,
            )

            ct.log_summary()
        except KeyboardInterrupt:
            log.warning("Keyboard interruptted")
            sys.exit(0)
        except MemoryError:
            assert memlim
            _, hard = resource.getrlimit(resource.RLIMIT_AS)
            # enlarge memory limit for error handling
            resource.setrlimit(
                resource.RLIMIT_AS, (2 * memlim * 1024 * 1024 * 1024, hard)
            )
            ct.paths.clear()
            log.warning("Memory error")
        except Exception:
            log.warning(traceback.format_exc())

        # the result need to be saved explicitly
        res.prepare_result(ct, target_info, poc_info)
        if self.output:
            res.save()

        return ct, res

    # def findil(self, fw_path, pool=None):
    #     """
    #     Find input locations from firmware
    #     """
    #     self.glob_setting()

    #     log = logging.getLogger("firmrec")
    #     log.setLevel(logging.DEBUG)

    #     bbf = BorderBinariesFinder(fw_path=fw_path, logger_obj=log)

    #     pickle_dir = os.path.join(self.output, "border_binaries")
    #     bbs = bbf.run(pickle_dir=pickle_dir, bins=None, process_pool=pool)
    #     print(fw_path, "bbs:", bbs)

    def glob_setting(self):
        """
        Setup some resource limitations and log settings for
        replay execution
        """
        if self._glob_setting_done:
            return
        sys.setrecursionlimit(0x100000)
        sys.set_int_max_str_digits(10000)

        # disable angr logging
        logging.getLogger("angr").setLevel(logging.CRITICAL)
        logging.getLogger("cle").setLevel(logging.CRITICAL)
        logging.getLogger("pyvex").setLevel(logging.CRITICAL)
        logging.getLogger("pyvex.lifting.libvex").setLevel(logging.CRITICAL)
        # angr.loggers.disable_root_logger()
        # angr.logging.disable(logging.ERROR)

        self._glob_setting_done = True

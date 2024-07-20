import os

import claripy
import logging
import random
import signal
import traceback
import time
import itertools
import string
from random import shuffle
from functools import cached_property, reduce
from collections import deque

import pyvex
import angr
from angr import BP, SimValueError
from angr.state_plugins.heap.heap_base import DEFAULT_HEAP_LOCATION
from cle import SymbolType

from .utils import set_ret_target, arg_reg_name, ret_reg_name, arg_reg_num
from .stateinfo import SimStateInfo
from .summary_functions import skip, stub, simp, ENV_VAR_MARK
from .varmodel import VAR_MODELS
from .pathinfo import PathInfo
from .enums import PointerType, PointerValueType, ERStatus
from .datadep import DataDepUtils
from . import summary_functions as sf

logging.basicConfig()
log = logging.getLogger("CoreTaint")
log.setLevel("DEBUG")

GLOB_TAINT_DEP_KEY = "taint_deps"
UNTAINT_DATA = "untainted_data"
UNTAINTED_VARS = "untainted_vars"
SEEN_MASTERS = "seen_masters"


class MyFileHandler(object):
    def __init__(self, filename, handler_factory, **kw):
        kw["filename"] = filename
        self._handler = handler_factory(**kw)

    def __getattr__(self, n):
        if hasattr(self._handler, n):
            return getattr(self._handler, n)
        raise AttributeError(n)


class TimeOutException(Exception):
    def __init__(self, message):
        super(TimeOutException, self).__init__(message)


class UnSATException(Exception):
    def __init__(self, message):
        super(UnSATException, self).__init__(message)


class CoreTaint:
    """
    Perform a symbolic-execution-based taint analysis on a given binary to find whether
    it exists a tainted path between a source and a sink.
    """

    def __init__(
        self,
        p,
        interfunction_level=0,
        exploration_strategy=None,
        smart_call=True,
        follow_unsat=False,
        try_thumb=False,
        white_calls=tuple(),
        black_calls=tuple(),
        not_follow_any_calls=False,
        default_log=True,
        exit_on_decode_error=True,
        concretization_strategy=None,
        force_paths=False,
        reverse_sat=False,
        only_tracker=False,
        shuffle_sat=False,
        taint_returns_unfollowed_calls=False,
        taint_arguments_unfollowed_calls=False,
        allow_untaint=True,
        taint_dyn_infer=False,
        stop_on_vuln=False,
        logger_obj=None,
        path_limit=None,
        san_heap=True,
        sym_global=True,
        fine_taint_check=True,
        opt_ret_merge=True,
        opt_loop_limit=0,
        opt_max_ret_stop=0,
        opt_first_taint=True,
        opt_taint_solve=True,
        opt_taint_exit_guard=True,
        fine_recording=False,
        pending_explore=False,
    ):
        """
        Initialialization function

        :param p: angr project
        :param interfunction_level: interfunction level
        :param log_path:  path where the analysis' log is created
        :param smart_call: if True a call is followed only if at least one of its parameters is tainted
        :param follow_unsat: if true unsat successors are also considered during path exploration. In this case
                             the collected constraints up to that point will be dropped.
        :param try_thumb: try to force thumb mode if some decoding error occurred
        :param white_calls: calls to follow in any case
        :param default_log: log info by default
        :param exit_on_decode_error: terminate the analysis in case of error
        :param concretization_strategy: concretization strategy callback
        :param force_paths: force a path to be followed even when some decode errors were found
        :param allow_untaint: allow to untaint variables.
        :param fine_taint_check: check taint variable more carefully
        :param taint_dyn_infer: [DEPRECATED] allow infer dynamic linked function summaries
        :param stop_on_vuln: stop when vulnerability is sanitized
        :param logger_obj: logger object
        :param path_limit: path limitation, currently not used

        :param san_heap: sanitize heap overflow

        :param opt_ret_merge: collect all returning paths and merge
        :param opt_loop_limit: limit the number of looping
        :param opt_max_ret_stop: limit the max return stop points
        :param opt_first_taint: only reserve the first tainting path
        :param opt_taint_solve: make solve taint variable more efficient

        :param fine_recording: enable fine-grained recording
        :param pending_explore: enable pending some states for strategy exploration
        """

        self._old_signal_handler = None
        self._old_timer = 0
        self._count_var = 0
        self._use_smart_concretization = False
        self._back_jumps = {}
        self._N = 1
        self._keep_run = True
        self._timeout_triggered = False
        self._timer = 30
        self._force_exit_after = -1
        self._p = p
        self._taint_buf = "taint_buf"
        self._taint_applied = False
        self._taint_buf_size = 4096
        self._bogus_return = 0x41414141
        self._bogus_callee = 0x51515151
        self._fully_taint_guard = []
        self._white_calls = set(white_calls)
        self._black_calls = set(black_calls)
        self._taint_returns_unfollowed_calls = taint_returns_unfollowed_calls
        self._taint_arguments_unfollowed_calls = taint_arguments_unfollowed_calls
        self._allow_untaint = allow_untaint
        self._fine_taint_check = fine_taint_check
        self._taint_dyn_infer = taint_dyn_infer
        self._stop_on_vuln = stop_on_vuln
        self._not_follow_any_calls = not_follow_any_calls
        self._reverse_sat = reverse_sat
        self._shuffle_sat = shuffle_sat
        self._exploration_strategy = (
            self._base_exploration_strategy
            if exploration_strategy is None
            else exploration_strategy
        )
        self._only_tracker = only_tracker
        self._try_to_avoid_z3 = 3

        self._fine_recording = fine_recording
        self._pending_explore = pending_explore

        self._san_heap = san_heap
        self._sym_global = sym_global

        self._taint_vars = {}

        self._opt_ret_merge = opt_ret_merge  # collect all returning paths and merge
        self._opt_loop_limit = opt_loop_limit  # limit the number of looping
        self._opt_max_ret_stop = opt_max_ret_stop  # limit the max return stop points
        self._opt_first_taint = opt_first_taint
        self._opt_taint_exit_guard = opt_taint_exit_guard
        
        self._force_stop = False

        # if exploration_strategy is not None and (shuffle_sat or reverse_sat):
        #     self.log.warning("Exploration strategy takes precedence over state shuffling/reversing")

        self._deref_taint_address = False
        self._deref_instruction = None
        self._deref_addr_expr = None
        self._deref = (None, None)
        self._old_deref = self._deref
        self._old_deref_taint_address = self._deref_taint_address
        self._old_deref_addr_expr = self._deref_addr_expr

        self._interfunction_level = interfunction_level
        self._smart_call = smart_call
        self._follow_unsat = follow_unsat
        self._followed_calls = set()
        self._prev_follow_set_regs = []

        self._concretizations = {}
        self._summarized_f = {}
        self._init_summarized_f = {}
        self._taint_cache = []

        # env_var
        self._env_var = {}
        self._env_var_tainted = {}
        self._init_env_var = {}
        self._init_env_var_tainted = {}
        self._essential_vars = set()

        self._interesing_path = {"sink": [], "deref": [], "loop": []}
        self._try_thumb = try_thumb
        self._force_paths = force_paths

        self._default_log = default_log

        self._exit_on_decode_error = exit_on_decode_error
        self._concretization_strategy = (
            self._default_concretization_strategy
            if concretization_strategy is None
            else concretization_strategy
        )

        self._hooked_addrs = []

        self.add_sum_f(self._bogus_callee, skip())

        # monkey patch to optimize taint solve
        if opt_taint_solve:
            old_concrete_value = angr.state_plugins.solver._concrete_value

            def my_concrete_value(e):
                v = old_concrete_value(e)
                if v is None:
                    return self.extract_taint_var(e)

            angr.state_plugins.solver._concrete_value = my_concrete_value

        # stats
        self._run_start_time = 0
        self._run_end_time = 0

        self._invalid_path = False  # indicate whether current path is invalid, can be modified by summarized functions
        self._sanitized_path = False  # indicate whether vulnerability is sanitized, can be modified by summarized functions
        self._new_path = True
        self._paths = None
        self._path_limit = path_limit

        self._bp_disabled = False

        if logger_obj:
            self.log = logger_obj

        self.STACK_BASE = 0x7FFFFFF0

        # if type(log) == logging.Logger:
        #     formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        #     fileh = MyFileHandler(log_path + '._log', logging.FileHandler)
        #     fileh.setFormatter(formatter)
        #     self.log.addHandler(fileh)

    def get_initial_state(self, addr):
        """
        Sets and returns the initial state of the analysis
        :param p: the angr project
        :param ct: the coretaint object
        :param addr: entry point
        :return: the state
        """

        s = self.p.factory.blank_state(remove_options={angr.options.LAZY_SOLVES})

        if "info" not in s.plugins:
            s.plugins["info"] = info_plugin = SimStateInfo(
                white_calls=self._white_calls, black_calls=self._black_calls
            )

        # set arguments
        p = self.p
        reg_num = arg_reg_num(p)
        for arg_idx in range(reg_num):
            reg = arg_reg_name(p, arg_idx)
            val = self.get_sym_val(f"arg{arg_idx}", p.arch.bits, taint=False)
            setattr(s.regs, reg, val)

        # set a bogus return at the end of this function and in the link register (if applicable)
        s.callstack.ret_addr = self.bogus_return
        if hasattr(s.regs, "lr"):
            setattr(s.regs, "lr", self.bogus_return)
        set_ret_target(s, self.bogus_return)
        s.ip = addr
        self.STACK_BASE = s.reg_concrete("sp")
        return s

    def add_var(
        self, keyword: bytes, val: bytes, tainted=True, init=True, essential=False
    ):
        """
        Add keyword variable

        :param keyword: keyword to be added
        :param val: value to be added
        :param tainted: whether keyword and value are tainted
        """
        # for initialization
        if init:
            self._init_env_var[keyword] = val
            self._init_env_var_tainted[keyword] = tainted
        # for runtime
        self._env_var[keyword] = val
        self._env_var_tainted[keyword] = tainted

        if essential:
            self._essential_vars.add(keyword)

    def get_var(self, keyword: bytes):
        env_var = self._env_var
        key_absent = keyword not in env_var
        # it was set before
        if not key_absent:
            val = env_var[keyword]
            if isinstance(val, (str, bytes)):
                return claripy.BVV(val, len(val) * 8).concat(claripy.BVV(0, 8))
            else:
                assert isinstance(val, claripy.Bits)
                return val
        else:
            return None

    def is_var_tainted(self, keyword: bytes):
        return self._env_var_tainted.get(keyword, False)

    def init_sum_f(self):
        self._summarized_f = dict(self._init_summarized_f)

    def add_sum_f(self, addr, f, init=True):
        """
        Add summarized function
        :param addr: address of target addr or the function name
        :param f: summarized function
        :return: original hooked function
        """
        p = self.p

        mo = p.loader.main_object
        try:
            # pylint:disable=bare-except
            if (
                not isinstance(addr, str)
                and addr != self._bogus_callee
                and addr >= mo.min_addr
                and addr < mo.max_addr
            ):
                # If hook at call instruction, change to hook callee
                blk = p.factory.block(addr)
                # mips jump block has 2 instructions
                is_mips = p.arch.name.startswith("MIPS")
                if blk.instructions == 1 or is_mips and blk.instructions == 2:
                    if blk.vex.direct_next:
                        # plt jumps
                        addr = blk.vex.next.con.value
        except:
            pass

        orig_f = self._summarized_f.get(addr)
        self._summarized_f[addr] = f
        if init:
            self._init_summarized_f[addr] = f
        return orig_f

    def del_sum_f(self, addr, init=False):
        """Delete summarized function"""
        if addr in self._summarized_f:
            del self._summarized_f[addr]
        if init:
            if addr in self._init_summarized_f:
                del self._init_summarized_f[addr]

    def handler(self, _, frame):
        """
        Timeout handler

        :param _: signal number
        :param frame:  frame
        :return:
        """
        self.log.info(f"Timeout triggered, {str(self._force_exit_after)} left....")

        self.stop_run()
        self._timeout_triggered = True
        self._force_exit_after -= 1
        signal.alarm(self._timer)

        if self._force_exit_after <= 0 and not self.is_running:
            # raising an exception while the execution is in z3 might crash the program
            if not self._timeout_triggered and "z3" in frame.f_code.co_filename:
                self.log.info(
                    "Hard Timeout triggered, but we are in z3, trying again in 30 seconds"
                )
                signal.alarm(30)
            else:
                self.log.info(
                    f"Hard Timeout triggered, {str(self._force_exit_after)} left...."
                )
                raise TimeOutException("Hard timeout triggered")

    def _get_bb(self, addr):
        """
        Get a basic block of an address

        :param addr: address
        :return:  the basic block
        """
        # pylint: disable=bare-except
        try:
            blk = self._p.factory.block(addr)
        except:
            blk = None

        if blk is None or blk.vex.jumpkind == "Ijk_NoDecode":
            try:
                blk = self._p.factory.block(addr, thumb=True)
            except:
                blk = None

        return blk

    def _save_taint_flag(self):
        """
        Save the tainting related flags

        :return:
        """

        self._old_deref = self._deref
        self._old_deref_taint_address = self._deref_taint_address
        self._old_deref_addr_expr = self._deref_addr_expr

    def _restore_taint_flags(self):
        """
        Restiore the tainting related flags

        :return:
        """

        self._deref = self._old_deref
        self._deref_taint_address = self._old_deref_taint_address
        self._deref_addr_expr = self._old_deref_addr_expr

    def _disable_breakpoints(self):
        """
        Disable usage of breakpoints
        """
        self._bp_disabled = True

    def _enable_breakpoints(self):
        """
        Enable usage of breakpoints
        """
        self._bp_disabled = False

    @property
    def run_time(self):
        return self._run_end_time - self._run_start_time

    @property
    def n_paths(self):
        return sum([len(self._paths[stash]) for stash in self._paths])

    def get_n_paths(self, stash=None):
        if not stash:
            return self.n_paths
        return len(self._paths.get(stash, []))

    @property
    def paths(self):
        return self._paths

    @property
    def bogus_return(self):
        return self._bogus_return

    @property
    def taint_buf(self):
        return self._taint_buf

    @property
    def taint_buf_size(self):
        return self._taint_buf_size

    @property
    def taint_applied(self):
        return self._taint_applied

    @property
    def timeout_triggered(self):
        return self._timeout_triggered

    @property
    def p(self):
        return self._p

    @property
    def vuln_record(self):
        if self.get_n_paths("sanitized") > 0:
            vuln_path = self.paths["sanitized"][0]
            return vuln_path.vuln_record
        return None

    @cached_property
    def _imports_by_addr(self):
        res = {}
        for obj in self.p.loader.all_elf_objects:
            for sym, reloc in obj.imports.items():
                if reloc.resolved and reloc.symbol.type == SymbolType.TYPE_FUNCTION:
                    res[reloc.rebased_addr] = sym
            for sym in obj.symbols:
                addr = sym.rebased_addr
                if sym.type != SymbolType.TYPE_FUNCTION:
                    continue
                if (
                    sym.is_import or sym.is_extern
                ):  # we only record non-concrete functions
                    res[addr] = sym.name
            for sym, jmprel in obj.jmprel.items():
                if jmprel.resolved and jmprel.symbol.type == SymbolType.TYPE_FUNCTION:
                    res[jmprel.value] = sym
        return res

    @cached_property
    def _imports_var_by_addr(self):
        res = {}
        for obj in self.p.loader.all_elf_objects:
            for sym, reloc in obj.imports.items():
                if reloc.resolved and reloc.symbol.type == SymbolType.TYPE_OBJECT:
                    res[reloc.rebased_addr] = sym
            for sym in obj.symbols:
                addr = sym.rebased_addr
                if sym.type != SymbolType.TYPE_OBJECT:
                    continue
                res[addr] = sym.name
            for sym, jmprel in obj.jmprel.items():
                if jmprel.resolved and jmprel.symbol.type == SymbolType.TYPE_OBJECT:
                    res[jmprel.value] = sym
        return res

    def get_func_name_by_addr(self, addr):
        """Get the function name by address"""
        if addr in self._imports_by_addr:
            name = self._imports_by_addr[addr]
        else:
            sym = self.p.loader.find_symbol(addr)
            if sym:
                name = sym.name
            else:
                name = f"FUN_{addr:x}"
        return name

    def prepare_summarized_functions(self):
        """Add summarized functions to the state"""
        # pylint: disable=bare-except
        for addr, sym in self._imports_by_addr.items():
            if sym in sf.SUM_FS:
                f = sf.SUM_FS[sym]
                self.add_sum_f(addr, f)

    def disable_summarized_functions(self, *sfs):
        for addr, sym in self._imports_by_addr.items():
            if addr in sfs or sym in sfs:
                self.del_sum_f(addr, init=True)
        for addr in list(self._summarized_f):
            if addr in sfs:
                self.del_sum_f(addr, init=True)

    def resolve_val(self, state, val, keep_sym=False):
        if isinstance(val, claripy.Bits):
            conc = state.solver.eval(val)
        elif isinstance(val, int):
            sym = None
            conc = val
        else:
            assert False
        if keep_sym:
            return conc, sym
        return conc

    def estimate_mem_buf_size(self, state, addr, max_size=None):
        """
        Estimate the size allocated in a buffer
        :param state: the current state
        :param addr: addr of the buffer
        :param max_size: the maximum size to load
        :return: the estimated allocated size

        """
        if not max_size:
            max_size = self.taint_buf_size
        try:
            addr_conc = self.resolve_val(state, addr)
            str_length = state.info.get_strlen(addr_conc)
            if str_length is not None:
                return str_length * 8
            # estimate the size of the buffer by looking at the buffer contents in memory
            temp_load = state.memory.load(addr, max_size)
            if self._taint_buf in str(temp_load.args[0]):
                # when there is only one thing to load
                if isinstance(temp_load.args[0], str):
                    return temp_load.length
                # tainted
                size = 0
                for arg in temp_load.args:
                    if self._taint_buf in str(arg):
                        size += arg.length
                    else:
                        break
            else:
                # not tainted
                if isinstance(temp_load.args[0], (str, int)):
                    return temp_load.length
                size = temp_load.args[0].length
                if not size:
                    # TODO solve when there is a conditional in the data
                    self.log.error(
                        "Should debug. Encountered something in estimate buffer size that should not happen"
                    )
                    size = temp_load.length
            return size
        except Exception as e:
            # The size may be too long and collide with the heap. Try a smaller size. Stop when size smaller than 1
            # This is a bug in angr that may be fixed at a later time, since there are not enough stack pages allocated
            new_max_size = int(max_size / 2)
            if new_max_size > 1:
                return self.estimate_mem_buf_size(state, addr, new_max_size)
            return 1

    def safe_concretize_str(self, path, addr, max_size=0x1000, exact=None):
        """
        Backup symbolic string at addr, and replace it with concrete value

        :param path: path
        :param addr:  address
        :param max_size: maximum size of string
        :param exact: length of the returned string if specified
        :return: the symbolic string
        """
        str_bytes, sym = self.safe_load_str(path, addr, max_size, exact, symbolic=True)
        if exact is None:
            str_bytes += b"\x00"

        state = path.active[0]
        state.memory.store(addr, str_bytes)

        return sym

    def safe_unconcretize_str(self, path, addr, sym):
        """
        Restore symbolic string

        :param path: path
        :param addr:  address
        :param sym: symbolic string to restore
        """
        state = path.active[0]
        state.memory.store(addr, sym)

    def safe_begin(self):
        """Begin of safe operation,"""
        self._save_taint_flag()
        self._disable_breakpoints()

    def safe_end(self):
        """End of safe operation,"""
        self._enable_breakpoints()
        self._restore_taint_flags()

    def safe_load_num(self, path, addr, n_byte=None, idx=0):
        """
        Load number

        :param path: path
        :param addr: address
        :param n_byte: number of bytes to load, default to pointer size
        :param idx: treat the addr as an array, load the idx element from it
        :return: loaded address
        """
        self.safe_begin()

        state = path.active[0]
        p = self.p
        if not n_byte:
            n_byte = p.arch.bits >> 3
        endness = p.arch.memory_endness
        res = state.memory.load(addr + idx * n_byte, size=n_byte, endness=endness)

        self.safe_end()

        return res

    def safe_store_num(self, path, addr, val, n_byte=None, idx=0):
        """
        Store number

        :param path: path
        :param addr: address
        :param val: value to store
        :param idx: treat the addr as an array, store the idx element to it
        :return: loaded address
        """
        self.safe_begin()

        state = path.active[0]
        p = self.p
        if not n_byte:
            n_byte = p.arch.bits >> 3
        endness = p.arch.memory_endness
        state.memory.store(addr + idx * n_byte, val, size=n_byte, endness=endness)

        self.safe_end()

    def safe_load_str(self, path, addr, max_size=None, exact=None, symbolic=False):
        """
        Loads string from memory, saving and restoring taint info

        :param path: path
        :param addr:  address
        :param max_size: maximum size of string
        :param exact: length of the returned string if specified.
        :param symbolic: whether return symbolic value
        :return: the byte string. Tailing \x00 will be stripped if exact is not specified
            if symbolic is True, the symbolic value will be returned, and tailing \x00 will
            not be stripped
        """

        self.safe_begin()

        state = path.active[0]

        if max_size is None:
            max_size = 0x1000

        addr_conc = self.resolve_val(state, addr)
        if exact is None:
            exact = state.info.get_strlen(addr_conc)

        if exact is not None:
            exact = self.resolve_val(state, exact)
            exact = min(exact, max_size)
            val = state.memory.load(addr, exact)
        else:
            val = state.memory.load(addr, max_size)

        if exact:
            conc = self.resolve_val(state, val)
            str_bytes = int.to_bytes(conc, exact, byteorder="big")
            term_idx = str_bytes.find(b"\x00")
            if term_idx >= 0x18:
                str_bytes = str_bytes[:term_idx]
            while str_bytes.endswith(b"\x00"):
                str_bytes = str_bytes[:-1]
        else:
            bv_bytes = val.chop(8)
            str_bytes = []
            for bv_byte in bv_bytes:
                conc_byte = self.resolve_val(state, bv_byte)
                if conc_byte == 0:
                    break
                str_bytes.append(conc_byte)

        if len(str_bytes) > max_size:
            str_bytes = str_bytes[:max_size]

        self.safe_end()

        if symbolic:
            if str_bytes:
                sym = val.get_bytes(0, len(str_bytes))
            else:
                sym = claripy.BVV(0, 0)
            return bytes(str_bytes), sym

        return bytes(str_bytes)

    def safe_load(
        self, path, addr, size=None, unconstrained=False, estimate_size=False
    ):
        """
        Loads bytes from memory, saving and restoring taint info

        :param path: path
        :param addr:  address
        :param size: size of the returned bytes
        :return: the content in memory at address addr
        """

        self.safe_begin()

        state = path.active[0] if not unconstrained else path.unconstrained[0]
        if not size and not estimate_size:
            size = self._p.arch.bytes
        elif not size and estimate_size:
            size = self.estimate_mem_buf_size(state, addr) >> 3
        # convert to int to prevent errors, since it requires an int not float
        size = int(size)
        mem_cnt = state.memory.load(addr, size)

        self.safe_end()
        return mem_cnt

    def safe_store(self, path, addr, thing):
        """
        Stores bytes in memory, saving and restoring taint info

        :param path: path
        :param addr: address
        :param thing: thing to store
        :return:
        """

        self.safe_begin()
        path.active[0].memory.store(addr, thing)
        self.safe_end()

    def _set_deref_bounds(self, ast_node):
        """
        Check an ast node and if  contains a dereferenced address, it sets
        its bounds

        :param ast_node: ast node
        :return: None
        """

        lb = self._deref[0]
        ub = self._deref[1]

        if (
            hasattr(ast_node, "op")
            and ast_node.op == "Extract"
            and self.is_tainted(ast_node.args[2])
        ):
            m = min(ast_node.args[0], ast_node.args[1])
            lb = m if lb is None or m < lb else lb
            m = max(ast_node.args[0], ast_node.args[1])
            ub = m if ub is None or m > ub else ub
            self._deref = (lb, ub)
        elif hasattr(ast_node, "args"):
            for a in ast_node.args:
                self._set_deref_bounds(a)
        elif self.is_tainted(ast_node):
            self._deref = (0, 0)

    def _addr_concrete_before(self, state):
        """
        Hook for address concretization

        We need to disable SimConcretizationStrategyRange, which may add extra constraints
        """
        if self._bp_disabled:
            return
        s = state.inspect.address_concretization_strategy
        if isinstance(
            s, angr.concretization_strategies.range.SimConcretizationStrategyRange
        ):
            state.inspect.address_concretization_strategy = None
        state.inspect.address_concretization_add_constraints = False

    def _addr_concrete_after(self, state):
        """
        Hook for address concretization

        :param state: Program state
        """
        if self._bp_disabled:
            return

        addr_expr = state.inspect.address_concretization_expr

        if self._use_smart_concretization:
            state.inspect.address_concretization_result = [
                self._get_target_concretization(addr_expr, state)
            ]
        else:
            if state.inspect.address_concretization_result is None:
                # current angr strategy didn't give result, trying next one
                return None

        # a tainted buffer's location is used as address
        if self.is_tainted(addr_expr, state=state):
            self._set_deref_bounds(addr_expr)
            self._deref_taint_address = True
            self._deref_addr_expr = addr_expr
            self._deref_instruction = state.ip.args[0]

            if state.inspect.address_concretization_action == "load":
                # new fresh var
                name = f"cnt_pt_by({self._taint_buf}[{str(self._deref[0])}, {str(self._deref[1])}])"
                for conc_addr in state.inspect.address_concretization_result:
                    old_val = state.memory.load(conc_addr, self._p.arch.bytes)
                    # we do not apply any extra constraints if there is already taint at this location
                    if self.is_tainted(old_val):
                        continue
                    if self._only_tracker:
                        try:
                            state.solver.eval_atleast(old_val, 2)
                        except SimValueError:
                            # TODO: find real bitsize
                            var = self.get_sym_val(name=name, bits=self._p.arch.bits)
                            state.memory.store(
                                conc_addr, var, endness=self.p.arch.memory_endness
                            )
                            val = self.resolve_val(state, old_val)
                            state.add_constraints(var == val)

    def _mem_read_after(self, state):
        """
        Hook for memory read. Borrow from PDIFF

        :param state: Program state
        """
        if self._bp_disabled:
            return

        a = state.inspect.mem_read_address
        l = state.inspect.mem_read_length
        e = state.inspect.mem_read_expr
        if not state.solver.single_valued(a) or not state.solver.single_valued(l):
            return
        try:
            l = self.resolve_val(state, l)
            a = self.resolve_val(state, a)
            e_conc = self.resolve_val(state, e)
        except angr.SimUnsatError:
            return

        # HACK for external call and global variable access
        if l == 4 or l == 8:
            if a in self._summarized_f:
                state.inspect.mem_read_expr = state.inspect.mem_read_address
            elif a in self._imports_by_addr:
                summarized, sum_f = self._auto_add_summarized_import_func(a, a)
                if summarized:
                    replace_expr = state.inspect.mem_read_address
                    if isinstance(sum_f, stub):
                        replace_expr = claripy.BVV(sum_f.target_addr, l << 3)
                    state.inspect.mem_read_expr = replace_expr
            elif a in self._imports_var_by_addr:
                for model in VAR_MODELS:
                    ptr = model.match(state, self._imports_var_by_addr[a], a, e_conc)
                    if ptr is not None:
                        state.inspect.mem_read_expr = ptr
                        break

            if self._sym_global and not self.taint_applied:
                mo = self.p.loader.main_object
                # heuristically symbolize global variable that may be initialized during run-time
                if e.concrete and a >= mo.min_addr and a < mo.max_addr:
                    # uninitialized global variables or imported variables
                    if e_conc == 0 or e_conc in self._imports_var_by_addr:
                        section = mo.find_section_containing(a)
                        if section and ".got" not in section.name:
                            state.inspect.mem_read_expr = self.get_sym_val(
                                name=f"glob_{a:08x}_", bits=l << 3
                            )

        # Fine-grained recording
        if self._fine_recording:
            ptr_type = self.get_pointer_type(a)

            if ptr_type == PointerType.NONE:
                return

            state.info.rec_mem_read(state, a, l, e, ptr_type)

    def _mem_write_after(self, state):
        """
        Hook for memory write. Currently we use this hook for fine-grained recording

        :param state: Program state
        """
        if self._bp_disabled:
            return

        if not self._fine_recording:
            return

        a = state.inspect.mem_write_address
        l = state.inspect.mem_write_length

        if a is None or l is None:
            return
        if not state.solver.single_valued(a) or not state.solver.single_valued(l):
            return
        l = self.resolve_val(state, l)
        a = self.resolve_val(state, a)

        ptr_type = self.get_pointer_type(a)

        if ptr_type == PointerType.NONE:
            return

        e = state.inspect.mem_write_expr
        state.info.rec_mem_write(state, a, l, e, ptr_type)

    def _exit_before(self, state):
        """
        Hook for exit

        :param state: Program state
        """
        # We always need to record function exit, so we don't disable this breakpoint
        # if self._bp_disabled: return

        exit_target = state.inspect.exit_target
        exit_guard = state.inspect.exit_guard
        state.inspect.exit_guard = exit_guard = claripy.simplify(exit_guard)

        state.info.rec_cons(state)
        if not isinstance(exit_target, int) and exit_target.symbolic:
            self.log.warning(f"Symbolic exit_target {exit_target} at {hex(state.addr)}")
            # HACK: stop run
            if self.is_tainted(exit_target, state=state):
                self.mark_path(
                    vuln=True,
                    state=state,
                    data={"reason": "Control-flow Hijacked", "vars": [exit_target]},
                )
            return

        if state.inspect.exit_jumpkind == "Ijk_Ret":
            if exit_target.concrete:
                exit_target_addr = exit_target.args[0]
                self.log.debug(f"Return to {hex(exit_target_addr)}")
                state.info.rec_leave(state)
        elif self._opt_taint_exit_guard:
            # optimize taint exit_guard
            if self.is_tainted(exit_guard, state=state):
                new_guard = self._optimize_taint_constraint(exit_guard)
                state.inspect.exit_guard = new_guard

    def _optimize_taint_constraint(self, constraint):
        """optimize exit guard to avoid solving constraints"""
        replacements = {}
        variable_set = set()
        for ast in constraint.recursive_children_asts:
            val = self.extract_taint_var(ast, bv=True)
            if val is not None:
                replacements[ast.cache_key] = val
                variable_set.update(ast.variables)
        new_constraint = constraint.replace_dict(
            replacements, variable_set=variable_set
        )
        simp_exit_guard = claripy.simplify(new_constraint)
        return simp_exit_guard

    def _expr_after(self, state):
        """
        Hook for expr

        :param state: Program state
        """
        expr = state.inspect.expr
        expr_result = state.inspect.expr_result

        if expr_result.concrete or expr_result.uninitialized:
            return

        # handle absent var
        taint_related = self.is_tainted(expr_result)
        if taint_related:
            state.info.taint_related = True

        if taint_related or ENV_VAR_MARK in str(expr_result):
            # print(expr.__class__)
            # print(expr_result)
            # stmts = state.block().vex.statements
            # stmt_idx = state.scratch.stmt_idx
            # if stmts and stmt_idx < len(stmts):
            #     stmt = stmts[state.scratch.stmt_idx]
            #     print(stmt)
            exprs = state.info.exprs
            expr_id = expr_result._hash
            if expr_id not in exprs:
                exprs[expr_id] = expr_result

    def _default_concretization_strategy(self, state, cnt):
        """
        Default concretization strategy

        :param state: angr state
        :param cnt: variable to concretize
        :return: concretization value for the variable
        """
        extra_constraints = state.inspect.added_constraints

        if not extra_constraints:
            extra_constraints = tuple()
        concs = state.solver.eval_upto(cnt, 50, extra_constraints=extra_constraints)
        return random.choice(concs)

    def _get_target_concretization(self, var, state):
        """
        Concretization must be done carefully in order to perform
        a precise taint analysis. We concretize according the following
        strategy:
        * every symbolic leaf of an ast node is concretized to unique value, according on its name.

        In this way we obtain the following advantages:
        a = get_pts();
        b = a

        c = a + 2
        d = b + 1 + 1

        d = get_pts()

        conc(a) = conc(b)
        conc(c) = conc(d)
        conc(d) != any other concretizations

        :param var: ast node
        :param state: current state
        :return: concretization value
        """

        def get_key_cnt(x):
            # angr by default create a unique id for every new symbolic variable.
            # as in karonte we often have to copy the state, step and check some
            # quantities before step() with the current state, two identical variables might assume
            # two different names. Therefore, we should not consider the unique _id_ added to symbolic variables
            # created by angr
            ret = str(x)
            if "_" in str(x) and not self.is_tainted(x):
                splits = str(x).split("_")
                idx = splits[-2]

                if not idx.isdigit():
                    self.log.error(
                        f"get_key_cnt: Symbolic ID parsing failed, using the whole id: {ret}"
                    )
                    return ret

                ret = "_".join(splits[:-2]) + "_"
                ret += "_".join(splits[-1:])
            return ret

        # chek if unconstrained
        state_cp = state.copy()
        se = state_cp.solver
        leafs = [l for l in var.recursive_leaf_asts]

        if not leafs:
            conc = self._concretization_strategy(state_cp, var)

            if not se.solution(var, conc):
                conc = se.eval(var)

            key_cnt = get_key_cnt(var)
            self._concretizations[key_cnt] = conc
            return conc

        # todo why is this constraining a copied state?
        for cnt in leafs:
            key_cnt = get_key_cnt(cnt)
            # concretize all unconstrained children
            if cnt.symbolic:
                # first check whether the value is already constrained
                if key_cnt in self._concretizations.keys():
                    conc = self._concretizations[key_cnt]
                    if state_cp.solver.solution(cnt, conc):
                        state_cp.add_constraints(cnt == conc)
                        continue

                conc = self._concretization_strategy(state_cp, cnt)
                self._concretizations[key_cnt] = conc
                state_cp.add_constraints(cnt == conc)

        val = state_cp.solver.eval(var)
        return val

    def mark_path(self, vuln=False, invalid=False, state=None, **kwargs):
        """
        Mark status of current path
        """
        if vuln:
            self._sanitized_path = True
            if state:
                data = kwargs.pop("data", None)
                state.info.rec_vuln(state, data=data)
            else:
                # TODO: Tool Error
                pass
        if invalid:
            self._invalid_path = True

    def is_tainted(self, var, path=None, state=None, unconstrained=False):
        """
        Checks if a variable is tainted

        :param var: variable
        :param path: angr path
        :param state: state
        :param unconstrained: check unconstrained states
        :return:
        """

        def is_untaint_constraint_present(v, un_vars):
            for u in un_vars:
                # get argument name
                if v.args[0] in u:
                    # variable is untainted
                    return True
            # no untaint found, var is tainted!
            return False

        # Nothing is tainted
        if self._taint_buf not in str(var):
            return False

        #
        # something is tainted
        #

        if (
            not self._fine_taint_check
            and not self._allow_untaint
            or not path
            and not state
        ):
            return True

        taint_leafs = set()
        seen = set()
        ast_queue = deque([var])
        while ast_queue:
            ast = ast_queue.pop()
            if isinstance(ast, claripy.ast.Base) and id(ast.cache_key) not in seen:
                seen.add(id(ast.cache_key))

                if ast.depth == 1 and self._taint_buf in str(ast):
                    taint_leafs.add(ast)
                    continue

                # carefully process if
                if self._fine_taint_check and ast.op == "If":
                    ast_queue.extend(ast.args[1:])
                else:
                    ast_queue.extend(ast.args)
                continue

        default = bool(taint_leafs)

        if self._allow_untaint:
            # get contraints
            if path:
                state = path.active[0] if not unconstrained else path.unconstrained[0]
            untaint_var_strs = state.globals[UNTAINT_DATA][UNTAINTED_VARS]
            if not untaint_var_strs:
                return default
            taints = set()

            for l in taint_leafs:
                if l in taints:
                    continue
                # search an untaint constraint for this taint variable
                if not is_untaint_constraint_present(l, untaint_var_strs):
                    return default
                taints.add(l)
            return False
        else:
            return default

    def add_taint_glob_dep(self, master, slave, path):
        """
        Add a taint dependency: if master gets untainted, slave should be untainted
        :param master: master expression
        :param slave: slave expression
        :param path: path
        :return:
        """

        if not self.is_tainted(master):
            return
        leafs = list(set([l for l in master.recursive_leaf_asts if self.is_tainted(l)]))
        key = tuple(map(str, leafs))
        if key not in self.get_state(path).globals[GLOB_TAINT_DEP_KEY]:
            self.get_state(path).globals[GLOB_TAINT_DEP_KEY][key] = []
        self.get_state(path).globals[GLOB_TAINT_DEP_KEY][key].append(slave)

    def _do_recursive_untaint_core(self, dst, path):
        """
        Given an expression to untaint, we untaint every single tainted variable in it.
        E.g., given (taint_x + taint_y) to untaint, both variables gets untainted as
        they cannot assume no longer arbitrary values down this path.

        :param dst: expression to untaint
        :param path: angr path
        :return:
        """

        if not self._allow_untaint:
            return

        state = self.get_state(path)
        leafs = list(set([l for l in dst.recursive_leaf_asts if self.is_tainted(l)]))

        # then we use the collected untainted variables
        # and check whether we should untaint some other variables
        state.globals[UNTAINT_DATA][UNTAINTED_VARS] += map(str, leafs)
        deps = dict(state.globals[GLOB_TAINT_DEP_KEY])
        for master, slave in deps.items():
            # if not already untainted, let's consider it
            if master not in state.globals[UNTAINT_DATA][SEEN_MASTERS]:
                untainted_vars = set(state.globals[UNTAINT_DATA][UNTAINTED_VARS])
                set_master = set(master)

                # we can not untaint it
                if set_master.intersection(untainted_vars) == set_master:
                    state.globals[UNTAINT_DATA][SEEN_MASTERS].append(master)
                    for entry in deps[master]:
                        self._do_recursive_untaint_core(entry, path)
                    # restart!
                    continue

    def do_recursive_untaint(self, dst, path):
        """
        Perform the untaint operation (see do_recursive_untaint_core)

        :param dst: variable to untaint
        :param path: angr path
        :return:
        """

        return self._do_recursive_untaint_core(dst, path)

    def add_taint_var(self, sym, val):
        """
        Adds a taint to a variable

        :param var: variable to taint
        :param taint_id: taint identification
        :return:
        """
        if isinstance(val, bytes):
            val = claripy.BVV(val)
        if sym.op == "Reverse":
            sym = sym.reversed
            val = val.reversed
        name = str(sym)
        self._taint_vars[name] = val

    def extract_taint_var(self, sym, bv=False):
        """
        Extracts value from a tainted variable

        :param var: sym to extract
        :return: concrete value of sym or None if fail to extract
        """
        if not hasattr(sym, "op"):
            return None
        if sym.op != "Extract":
            return None
        lb_idx, rb_idx, var = sym.args
        name = str(var)
        if name not in self._taint_vars:
            return None

        data = self._taint_vars[name]
        ev = data[lb_idx:rb_idx]
        if bv:
            return ev
        return ev.args[0]

    def apply_taint_to_reg(self, current_path, reg, taint_id, add_constraint=True):
        """
        Applies the taint to a register

        :param current_path: angr current path
        :param addr: address to taint
        :param taint_id: taint identification
        :param keep_constraint: if True, val == var will be automatically added as a constraint if val is concrete
        :return: tainted variable
        """

        self._save_taint_flag()
        if isinstance(current_path, angr.sim_state.SimState):
            state = current_path
        else:
            state = self.get_state(current_path)

        val = getattr(state.regs, reg)

        t = self.get_sym_val(name=taint_id, bits=val.length, taint=True)
        if self.p.arch.memory_endness == "Iend_LE":
            t = t.reversed
        setattr(state.regs, reg, t)

        if add_constraint:
            if val.concrete:
                state.add_constraints(val == t)

        self._restore_taint_flags()
        self._taint_applied = True
        return t

    def apply_taint(
        self,
        current_path,
        addr,
        taint_id,
        bit_size=None,
        add_constraint=True,
        explicit=False,
    ):
        """
        Applies the taint to an address addr

        :param current_path: angr current path
        :param addr: address to taint
        :param taint_id: taint identification
        :param bit_size: number of bites
        :param keep_constraint: if True, val == var will be automatically added as a constraint if val is concrete
        :return: tainted variable
        """

        self._save_taint_flag()
        state = self.get_state(current_path)
        bit_size = bit_size if bit_size else self.estimate_mem_buf_size(state, addr)

        if add_constraint:
            val = state.memory.load(addr, bit_size >> 3)

        # todo check endianness, since now it is always LE
        t = self.get_sym_val(
            name=taint_id, bits=bit_size, taint=True, explicit=explicit
        )
        if self.p.arch.memory_endness == "Iend_LE":
            t = t.reversed
        state.memory.store(addr, t)

        if add_constraint:
            if val.concrete:
                state.add_constraints(val == t)

        self._restore_taint_flags()
        self._taint_applied = True
        return t

    def get_sym_val(self, name="x_", bits=None, inc=True, explicit=False, taint=False):
        """
        Creates a fresh symbolic variable

        :param name: variable name
        :param bits: number of bits
        :param inc: increment the global counter
        :param explicit: name should be exactly as reported (True, False)
        :return: a symbolic variable
        """

        if bits is None:
            bits = self._p.arch.bits

        if taint:
            name = self._taint_buf + "_" + name + "_"
            self._taint_applied = True

        if explicit:
            var = claripy.BVS(name=name, size=bits, explicit_name=True)
        else:
            var = claripy.BVS(
                name=(name + "_" + str(self._count_var) + "_" + str(self._p.arch.bits)),
                size=bits,
                explicit_name=True,
            )
            if inc:
                self._count_var += 1
        return var

    def get_addr(self, path):
        """
        Gets the path current address

        :param path: angr path
        :return: path current address
        """

        return path.active[0].ip.args[0]

    def get_state(self, path):
        """
        Gets the state from a path

        :param path: path
        :return: angr state
        """

        return path.active[0]

    def get_any_state(self, path):
        """
        Gets the state from a path, even it is not active

        :param path: path
        :return: angr state
        """
        for _, stash in path.stashes.items():
            for state in stash:
                return state
        return None

    def get_loader_object(self, addr):
        """
        Get loaded binary object at specific address
        """
        return self.p.loader.find_object_containing(addr)

    def get_call_sigs(self, path, args):
        arg_sigs = []
        state = self.get_state(path)
        for arg in args:
            arg_addr = self.resolve_val(state, arg)
            arg_ptr_type = self.get_pointer_type(arg_addr)
            if arg_ptr_type == PointerType.NONE:
                arg_val_type = PointerValueType.NONE
            else:
                arg_val_type = self.get_ptr_value_type(path, arg)
            arg_sigs.append((arg_val_type, arg_val_type))
        arg_sigs = tuple(arg_sigs)
        return str(arg_sigs)

    def get_ptr_value_type(self, path, ptr):
        """
        Get pointer value type

        :param state: Program state
        :param ptr(int): the pointer to analysis
        :ret: pointer type or None if it is not a pointer
        """
        s = self.safe_load_str(path, ptr, exact=3)
        if not s:
            return PointerValueType.SYM
        elif chr(s[0]) in string.printable and chr(s[1]) in string.printable:
            return PointerValueType.CONST_STR
        else:
            return PointerValueType.CONST

    def get_pointer_type(self, ptr: int):
        """
        Get pointer type

        :param state: Program state
        :param ptr(int): the pointer to analysis
        :ret: pointer type or None if it is not a pointer
        """
        if ptr > DEFAULT_HEAP_LOCATION and ptr - DEFAULT_HEAP_LOCATION < 0x100000:
            return PointerType.HEAP

        STACK_BASE = self.STACK_BASE
        if ptr <= STACK_BASE + 0x1000 and STACK_BASE - ptr < 0x100000:
            return PointerType.STACK

        for obj in self.p.loader.all_elf_objects:
            if obj.contains_addr(ptr):
                break
        else:
            return PointerType.NONE

        for segment in obj.segments:
            if segment.contains_addr(ptr):
                break
        else:
            # Don raise exception
            return PointerType.NONE

        if segment.is_executable:
            return PointerType.GLOB_CODE
        else:
            return PointerType.GLOB_DATA

    def is_uninitialized(self, x):
        if not isinstance(x, claripy.Bits):
            return False
        return any(l.uninitialized for l in x.recursive_leaf_asts)

    def is_or_points_to_tainted_data(self, x, path, unconstrained=False):
        """
        Checks if a symbolic variable is or points to tainted data
        :param x: variable
        :param path: angr current path
        :param unconstrained: consider unconstrained data
        :return:
        """
        if x.uninitialized:
            return False
        return self.is_tainted(
            x, path=path, unconstrained=unconstrained
        ) or self.is_tainted(
            self.safe_load(path, x, unconstrained=unconstrained),
            path=path,
            unconstrained=unconstrained,
        )

    def _get_dyn_call_from_stub(self, state):
        """
        Checks if a call is a stub call to dynamic jmprel (e.g. plt call)

        :param state: call state of stub function
        :return: the jmprel address of called dyn function; return None is not dyn_call

        ARM IRSB {
        t0:Ity_I32 t1:Ity_I64 t2:Ity_I64 t3:Ity_I64

        00 | ------ IMark(0x419e20, 6, 0) ------
        01 | t2 = LDle:I64(0x000000000066e0b8)
        NEXT: PUT(rip) = t2; Ijk_Boring
        }
        """
        try:
            block = state.block().vex
        except:
            return None
        if block.jumpkind != "Ijk_Boring":
            return None

        # stub function is usually small
        if block.size > 20:
            return None

        if not isinstance(block.next, pyvex.IRExpr.RdTmp):
            return None
        tmp = block.next.tmp

        # backward dataflow to find the address load address
        for stmt in reversed(block.statements):
            if isinstance(stmt, pyvex.IRStmt.WrTmp) and stmt.tmp == tmp:
                break
        else:
            # unlikely
            return None

        load_expr = stmt.data
        if not isinstance(load_expr, pyvex.IRExpr.Load):
            return None
        if not isinstance(load_expr.addr, pyvex.IRExpr.Const):
            return None
        return load_expr.addr.con.value

    def _auto_add_summarized_import_func(self, addr, hooked_addr):
        """Automatically add summarized function according to import entries
        :param addr: address to search in imports
        :param hooked_addr: address to hook for target summarized function
        :return(status, sumf): status is True if a summarized function is added
        """
        if addr in self._imports_by_addr:
            sym = self._imports_by_addr[addr]
            for lib in ["libc", "glibc", "posix", "uclibc", "libstdcpp"]:
                sim_procedure_cls = angr.SIM_PROCEDURES[lib].get(sym, None)
                if sim_procedure_cls:
                    break
            if sym in sf.FORCE_SKIP_FUNCS:
                sim_procedure_cls = None
            # summarized function by name
            if sym in self._summarized_f:
                f = self._summarized_f[sym]
                self._summarized_f[hooked_addr] = f
            elif sim_procedure_cls:
                sim_procedure = sim_procedure_cls()
                f = simp(lib, sym, sim_procedure)
                self._summarized_f[hooked_addr] = f
                return True, f
            else:
                # Because judging with symbol table is too excessive, we
                # need to furthur check if the target function is followable (not imported)
                obj = self.get_loader_object(addr)
                if not obj:
                    return False, None
                sym_entry = obj.get_symbol(sym)
                if sym_entry and (sym_entry.is_import or sym_entry.is_extern):
                    for sym in self.p.loader.find_all_symbols(sym_entry.name):
                        if not (sym.is_import or sym.is_extern):
                            # Call libraries
                            stub_f = stub(sym.rebased_addr, name=sym.name)
                            self._summarized_f[hooked_addr] = stub_f
                            return True, stub_f
                    skip_f = skip(name=sym.name, reason="External")
                    self._summarized_f[hooked_addr] = skip_f
                    return True, skip_f
        return False, None

    def _safe_call_if_summarized_dyn(self, prev_path, succ_path):
        try:
            summarized = self._call_if_summarized_dyn(prev_path, succ_path)
        except: # pylint: disable=bare-except
            self.log.warning("Call summarized exception not caught")
            self.log.warning(traceback.format_exc())
            summarized = True

        return summarized

    def _call_if_summarized_dyn(self, prev_path, succ_path, *_):
        """
        Infer and check if function is summarized, and execute it if so.

        :param prev_path: previous path
        :param suc_path: successor path
        :return: True if summarized function is called
        """

        # first check if function is summarized
        addr = self.get_addr(succ_path)

        if self._summarized_f:
            sum_f = None
            if (
                addr not in self._not_summarized_f
                and addr not in self._summarized_f
                and addr not in self._hooked_addrs
            ):
                # HACK: just search accessive address table
                hooked = False
                if addr in self._imports_by_addr:
                    hooked, _ = self._auto_add_summarized_import_func(addr, addr)

                if not hooked:
                    # recognize dyn call to summarized functions
                    dyn_addr = self._get_dyn_call_from_stub(self.get_state(succ_path))

                    if dyn_addr is not None:
                        if dyn_addr in self._summarized_f:
                            # use summarized function
                            self._summarized_f[addr] = self._summarized_f[dyn_addr]
                        else:
                            # try use SimProcedure
                            if dyn_addr in self._imports_by_addr:
                                self._auto_add_summarized_import_func(dyn_addr, addr)
                            else:
                                # Skip the plt function
                                skip_f = skip(name=self.get_func_name_by_addr(dyn_addr))
                                self._summarized_f[addr] = skip_f
                                # self._not_summarized_f.add(addr)
                    else:
                        self._not_summarized_f.add(addr)

            return self._call_if_summarized(prev_path, succ_path)
        return False

    def _call_if_summarized(self, prev_path, succ_path, *_):
        """
        Check if function is summarized, and execute it if so.

        :param prev_path: previous path
        :param suc_path: successor path
        :return: True if summarized function is called
        """
        addr = self.get_addr(succ_path)
        if addr in self._summarized_f.keys():
            func = self._summarized_f[addr]
            func(self, prev_path, succ_path)
            if isinstance(func, stub):
                # We only redirect the function
                return False
            return True
        else:
            # Hack: call site is hooked
            prev_block = self.get_state(prev_path).block()
            for call_site_addr in prev_block.instruction_addrs[-2:]:
                if call_site_addr in self._summarized_f:
                    func = self._summarized_f[call_site_addr]
                    func(self, prev_path, succ_path)
                    self.add_sum_f(addr, func, init=False)
                    return True

        return False

    def _is_reg_or_mem_taint_quick(self, state, reg):
        """
        Quickly identify whether register content or pointed memory are tainted
        :param state: program state
        :r: register name
        """
        if not self.taint_applied:
            return False
        reg_cnt = getattr(state.regs, reg)

        if reg_cnt.uninitialized:
            # We may set an explicit mark for an uninitialized object
            if self.is_tainted(state.memory.load(reg_cnt, 1)):
                return True
            return False
        if self.is_tainted(reg_cnt):
            return True
        # check if it is pointing to a tainted location
        try:
            # estimate the size first, so we are not loading to much data. limit it at the taint_buf_size
            size = min(
                self.estimate_mem_buf_size(state, reg_cnt) >> 3, self.taint_buf_size
            )
            mem_cnt = state.memory.load(reg_cnt, size)
        except KeyError as e:
            # state is unconstrained
            self.log.warning("Tried to dereference a non pointer!")
            return False

        # we might have dereferenced wrongly a tainted variable during the tests before
        if self.is_tainted(mem_cnt):
            return True
        return False

    def _safe_load_arg(self, state, arg_id, concrete=False):
        reg_val = getattr(state.regs, arg_reg_name(self.p, arg_id))
        if concrete:
            return self.resolve_val(state, reg_val)
        return reg_val

    def _dyn_infer_getenv_and_call_summarized(self, prev_path, suc_path):
        """
        DEPRECATED
        Dynamically infer callee function, generate corresponding summarized function, and call it

        :param prev_path: previous path
        :param suc_path: successive path
        :return: True if summarized function is generated and called
        """
        state = self.get_state(suc_path)
        f_addr = state.addr

        if f_addr in self._inferred_summarized_f:
            if not self._inferred_summarized_f[f_addr]:
                return False
            else:
                assert False, "Summarized function is not called"

        # whether args contain address
        possible_addr_args = []
        possible_addr_arg_vals = []
        ARG_RANGE = 3
        for arg_idx in range(ARG_RANGE):
            arg_val = self._safe_load_arg(state, arg_idx, concrete=True)
            if arg_val > 0x10000:
                possible_addr_args.append(arg_idx)
                possible_addr_arg_vals.append(arg_val)

        if not possible_addr_args:
            self._inferred_summarized_f[f_addr] = None
            return False

        # find key arg
        key_arg = -1
        for idx, arg_idx in enumerate(possible_addr_args):
            arg_val = possible_addr_arg_vals[idx]
            keyword = self.safe_load_str(suc_path, arg_val)
            if keyword in self._env_var:
                key_arg = arg_idx
                break

        if key_arg < 0:
            self._inferred_summarized_f[f_addr] = None
            return False

        if key_arg + 1 in possible_addr_args:
            out_arg = key_arg + 1
        else:
            out_arg = None

        self._inferred_summarized_f[f_addr] = self._summarized_f[f_addr] = sf.get_env(
            key_arg=key_arg, out_arg=out_arg, conservative=False
        )
        return self._safe_call_if_summarized_dyn(prev_path, suc_path)

    def _infer_calling_convention(self, calling_state):
        """
        Infer calling convention of a function
        :param calling_state: state of the calling function (before entering the function)
        :return: calling convention represented by a list of parameter registers
        """
        state = calling_state
        def bl_is_bare_jmp(blk):
            return (
                self._p.arch.name == "MIPS32"
                and blk.vex.jumpkind == "Ijk_Boring"
                and blk.instructions <= 2
            )

        puts = []
        history = state.history
        current_addr = history.addr
        block_addrs = [current_addr]

        # HACK: consider at leasttwo block
        if history.parent:
            pp_addr = history.parent.addr
            pp_bl = self._get_bb(pp_addr)
            if pp_bl and pp_bl.vex.jumpkind == "Ijk_Boring":
                block_addrs.append(pp_addr)
                current_addr = pp_addr
                history = history.parent

        while True:
            blk = self._get_bb(current_addr)
            if not blk:
                break
            if blk.vex.jumpkind != "Ijk_Boring":
                break
            if not bl_is_bare_jmp(blk):
                break
            history = history.parent
            if not history:
                break
            current_addr = history.addr
            block_addrs.append(current_addr)

        for addr in reversed(block_addrs):
            blk = self._get_bb(addr)
            if not blk:
                continue
            puts.extend([s for s in blk.vex.statements if s.tag == "Ist_Put"])

        expected = 0
        index = 0
        set_regs = []

        # type of regs we are looking for
        if self._p.arch.name == "MIPS32":
            reg_ty = "a"
        else:
            reg_ty = "r" if self._p.arch.bits == 32 else "x"

        while True:
            if index >= len(puts):
                break

            put = puts[index]

            if self._p.arch.register_names[put.offset] == reg_ty + str(expected):
                set_regs.append(reg_ty + str(expected))
                expected += 1
                index = 0
                continue

            index += 1

        # Some callee may directly derive callers parameters, we recognize them heuristically
        if not set_regs and current_addr in self._followed_calls:
            set_regs = self._prev_follow_set_regs
        self._prev_follow_set_regs = set_regs
        
        return set_regs

    def _follow_call(self, prev_path, suc_path, args=None):
        """
        Checks if a call should be followed or not: if any of its parameters is tainted
        and the current depth of transitive closure allows it yes, otherwise no.

        :param prev_path: previous path
        :param suc_path: successive path
        :return: True if call should be followed, false otherwise
        """

        if self._not_follow_any_calls:
            return False

        addr = self.get_addr(suc_path)
        suc_state = self.get_state(suc_path)

        if suc_state.info.is_black_call(addr):
            return False

        if suc_state.info.is_white_call(addr):
            return True

        # check if call falls within bound binary
        # TODO: consider their may be multiple binaries
        if addr > self._p.loader.max_addr or addr < self._p.loader.min_addr:
            return False

        # Surpress call depth
        cur_depth = self.get_state(prev_path).info.call_depth
        if self._interfunction_level > 0:
            max_depth = self._interfunction_level
        else:
            max_depth = 0xFFFFFFFF

        if cur_depth >= max_depth:
            return False

        if not self._smart_call:
            return True

        # if not self._taint_applied:
        #     return False

        calling_regs = self._infer_calling_convention(suc_state)

        self._save_taint_flag()

        if isinstance(args, list):
            for reg in calling_regs:
                reg_content = getattr(suc_state.regs, reg)
                args.append(reg_content)

        for reg in calling_regs:
            if self._is_reg_or_mem_taint_quick(suc_state, reg):
                self._restore_taint_flags()
                return True

        if args and len(args) >= 2 and self._white_calls:
            # Check white call
            call_sigs = self.get_call_sigs(suc_path, args)
            if str(call_sigs) in self._white_calls:
                return True

        self._restore_taint_flags()
        return False

    def _follow_back_jump(self, current_path, next_path, guards_info):
        """
        Check if a back jump (probably a loop) should be followed.

        :param current_path:  current path
        :param next_path: next path
        :param guards_info:  guards information
        :return:  True if should back jump, False otherwise
        """

        key = hash("".join(sorted(list(set([x[0] for x in guards_info])))))
        bj = (key, self.get_addr(next_path), self.get_addr(current_path))
        if bj not in self._back_jumps.keys():
            self._back_jumps[bj] = 1
        elif self._back_jumps[bj] > self._N:
            # we do not want to follow the same back jump infinite times
            return False
        else:
            self._back_jumps[bj] += 1
        return True

    @staticmethod
    def _check_sat_state(current_path):
        """
        Check whether the state is SAT

        :param current_path: angr current path
        :return: True is the state is SAT, False otherwise
        """
        return current_path.active[0].solver.satisfiable()

    def _trim_state_space(self, path):
        """
        Drop all the constraints within the symbolic engine

        :param path: angr current path
        :return:  None
        """
        for _, stash in path.stashes.items():
            for state in stash:
                state.release_plugin("solver")
                state.downsize()
                state.history.trim()
                state.info.clean()

    # FIXME: change offset according arch.
    def _next_inst(self, bl):
        """
        Get next instruction (sometimes angr messes up)

        :param bl: basic block
        :return:
        """

        return bl.instruction_addrs[-1] + 4

    def _base_exploration_strategy(self, _, next_states):
        """
        Base exploration strategy

        :param current_path: angr current path
        :param next_states: next states
        :return:
        """

        if self._reverse_sat:
            next_states.reverse()
        elif self._shuffle_sat:
            shuffle(next_states)
        return next_states

    def _create_path(self, state):
        if "info" not in state.plugins:
            state.plugins["info"] = SimStateInfo()
        return self._p.factory.simgr(state, save_unconstrained=True, save_unsat=True)

    def _reset_new_path_stat(self):
        self._new_path = True
        self._invalid_path = False
        self._sanitized_path = False

    def _collect_paths(self):
        """
        Prepare the paths after exploration
        """
        pass

    def _check_and_record_path_end(self, state, path):
        """
        Internal check on path execution status. if path end, it will be recorded

        :param state: state of the path (before following call)
        :param path: path to check
        :return: return true if path end
        """

        # An error occurs in summarized_function that disable keep running
        # for example, the return value is written with symbolic data

        if self._sanitized_path:
            self.log.info(f"vulnerability detected")
            self._reset_new_path_stat()
            new_path_record = PathInfo(state)
            self._trim_state_space(path)
            self._paths["sanitized"].append(new_path_record)
            if self._stop_on_vuln:
                self.stop_run()
            return True

        # the successor leads out of the function, we do not want to follow it
        if path.active and self.get_addr(path) == self._bogus_return:
            self.log.info("hit a return")
            self._reset_new_path_stat()
            # HACK: Assume the PoC must trigger a "sanitizer", and will not return
            new_path_record = PathInfo(state)
            self._trim_state_space(path)
            self._paths["invalid"].append(new_path_record)
            return True

        # mark a new path as invalid. _invalid_path can be set by a summarized function
        if self._invalid_path:
            self.log.info(
                f"ignore invalid path at {hex(path.active[0].addr if path.active else state.addr)}"
            )
            self._reset_new_path_stat()
            new_path_record = PathInfo(state)
            self._trim_state_space(path)
            self._paths["invalid"].append(new_path_record)
            return True

        if not state.info.func:
            self.log.info(
                f"Path end at {hex(path.active[0].addr if path.active else state.addr)}"
            )
            self._reset_new_path_stat()
            new_path_record = PathInfo(state)
            self._trim_state_space(path)
            self._paths["invalid"].append(new_path_record)
            return True

        return False

    def _flat_explore(
        self,
        current_path,
        check_path_fun,
        stop_points,
        stop_point_records,
        pending_records,
        no_stop_points=False,
        **kwargs,
    ):
        """
        Performs the symbolic-based exploration

        :param current_path: current path
        :param check_path_fun: function to call for every block in the path
        :param stop_points: addresses of block to stop
        :param stop_point_records: records of each stop point
        :param kwargs: additional arguments to pass to check_path_fun
        :return: not continued path states
        """
        # pylint:disable=bare-except

        current_path_addr = self.get_addr(current_path)

        self.log.debug(
            f"{os.path.basename(self._p.filename)}: Analyzing block {hex(current_path_addr)}"
        )

        if not CoreTaint._check_sat_state(current_path) and not self._timeout_triggered:
            self.log.error("State got messed up!")
            raise UnSATException("State became UNSAT")

        # check whether we reached a sink
        # todo add back in
        try:
            if check_path_fun:
                check_path_fun(current_path, ct=self, **kwargs)
        except:
            self.log.error(
                f"'Function check path errored out: \n{traceback.format_exc()}"
            )

        current_state = self.get_state(current_path)
        # self._loop_optimizer.run(current_state)

        tainted_before = self.taint_applied

        try:
            succ_path = current_path.copy().step()
        except:
            self.log.error(f"ERROR during copy step:\n{traceback.format_exc()}")
            return dict(error=[current_state])

        # try thumb
        if (
            succ_path
            and succ_path.errored
            and self._try_thumb
            and not self._force_paths
        ):
            succ_path = current_path.copy().step(thumb=True)

        if (
            succ_path
            and succ_path.errored
            and self._try_thumb
            and not self._force_paths
        ):
            if self._exit_on_decode_error:
                self.stop_run()
            return dict(error=[current_state])

        succ_states_unsat = succ_path.unsat if self._follow_unsat else []
        succ_states_sat = succ_path.active

        if succ_path.deadended and not succ_states_sat and not succ_states_unsat:
            self.log.debug("Backtracking from dead path")
            return dict(dead=[current_state])

        if not succ_states_sat:
            # check if it was un unconstrained call.
            # sometimes angr fucks it up
            bl = self._get_bb(current_path_addr)
            if not bl:
                return dict(uncons=[current_state])  # HACK: consider unconstrained
            if bl.vex.jumpkind == "Ijk_Call":
                # create a fake successors
                # which should have been created
                # before.
                if not succ_path.unconstrained:
                    return dict(uncons=[current_state])

                # We just skip the unconstrained call and log a warning
                self.log.warn(f"Skip unconstrained call at {hex(current_path_addr)}")
                unconstrained_state = succ_path.unconstrained[0]
                # _bogus_callee is hooked with ReturnUnconstrained
                unconstrained_state.regs.pc = self._bogus_callee
                succ_path = self._create_path(unconstrained_state)
                succ_path.step()
                succ_states_unsat = succ_path.unsat if self._follow_unsat else []
                succ_states_sat = succ_path.active

        # register sat and unsat information so that later we can drop the constraints
        for s in succ_states_sat:
            s.sat = True
        for s in succ_states_unsat:
            s.sat = False

        # collect and prepare the successors to be analyzed
        succ_states_sat = self._exploration_strategy(current_path, succ_states_sat)
        # succ_states = succ_states_sat + succ_states_unsat
        succ_states = succ_states_sat

        if len(succ_states) > 1:
            self.log.debug(f"Branching at {hex(current_path_addr)}")

        remain_states = dict(unfinished=[], uncons=[], error=[], dead=[], loop=[])
        for next_state in succ_states:
            if not self.is_running or self._force_stop:
                remain_states["unfinished"].append(current_state)
                continue
            if self._new_path:
                self._new_path = False

            if hasattr(next_state.ip, "symbolic") and next_state.ip.symbolic:
                if next_state.sat:
                    self.log.error("Next state UNSAT")
                self.log.warning(
                    "Got a symbolic IP, perhaps a non-handled switch statement? FIX ME... "
                )
                remain_states["uncons"].append(next_state)
                continue

            # create a new path state with only the next state to continue from
            origin_next_state = next_state
            next_path = self._create_path(origin_next_state.copy())
            next_state = self.get_state(next_path)

            if (
                self._p.is_hooked(next_state.addr)
                and next_state.addr in self._hooked_addrs
            ):
                self._p.unhook(next_state.addr)
                self._hooked_addrs.remove(next_state.addr)

            if not next_state.solver.satisfiable():
                # unsat successors, drop the constraints and continue with other states
                self._trim_state_space(next_path)
                continue

            next_is_call = False
            summarized = False
            followed = False

            # First, let's see if we can follow the calls
            try:
                jumpkind = next_state.history.jumpkind
                # Call or tailing call
                if (
                    jumpkind == "Ijk_Call"
                    or jumpkind == "Ijk_Boring"
                    and self._get_dyn_call_from_stub(next_state)
                ):
                    next_is_call = True

                    # Call summarized function
                    summarized = self._safe_call_if_summarized_dyn(current_path, next_path)

                    # Try dynamic summarizing
                    if not summarized and self._taint_dyn_infer:
                        summarized = self._dyn_infer_getenv_and_call_summarized(
                            current_path, next_path
                        )

                    # Get address after summarized, because call to stub may have changed the state
                    next_addr = self.get_addr(next_path)

                    # Try follow call
                    if not summarized:
                        args = []
                        followed = self._follow_call(current_path, next_path, args=args)
                        if followed:
                            self.log.debug(
                                f"Following function call to {hex(next_addr)}"
                            )
                            self._followed_calls.add(next_addr)
                            # the state has been updated
                            next_state = self.get_state(next_path)
                            func_name = self.get_func_name_by_addr(next_addr)
                            rec_call_data = dict(args=args)
                            if self._fine_recording:
                                rec_call_data['sig'] = self.get_call_sigs(next_path, args)
                            next_state.info.rec_enter(
                                next_state, func_name=func_name, data=rec_call_data, 
                            )
                        else:
                            # Add pending call for later exploration
                            if self._pending_explore:
                                state = self.get_state(next_path)
                                stop_points = self._get_stop_points(
                                    state, addr=next_addr
                                )
                                record = {
                                    "state": state,
                                    "type": "follow",
                                    "stop_points": stop_points,
                                }
                                pending_records.append(record)
                                op_str = "Pend"
                            else:
                                op_str = "Skip"

                            self.log.debug(
                                f"{op_str} function call to {hex(next_addr)} at {hex(current_state.addr)}"
                            )
                            # we add a hook with the return unconstrained on the call
                            skip_name = self.get_func_name_by_addr(next_addr)
                            self.add_sum_f(
                                next_state.addr,
                                skip(name=skip_name, n_arg=len(args)),
                                init=False,
                            )
                            # quick skip
                            self._call_if_summarized(current_path, next_path)
                            self.del_sum_f(next_state.addr, init=False)
            # pylint:disable=broad-except
            except Exception:
                self.log.error(f"Call coretaint: {traceback.format_exc()}")
                self._trim_state_space(next_path)
                remain_states["error"].append(current_state)
                continue

            tmp_next_state = self.get_any_state(next_path)
            if tmp_next_state is not None:
                next_state = tmp_next_state

            path_end = self._check_and_record_path_end(next_state, next_path)
            if path_end:
                continue

            next_state.info.rec_step(next_state)

            # Detect loop and prune it
            is_loop = False
            if self._opt_loop_limit:
                hit_count = next_state.info.get_hit_count(next_state)
                is_loop = self._opt_loop_limit <= hit_count
                if is_loop:
                    jump_guard = next_state.history.jump_guard
                    if jump_guard.singlevalued or self.is_tainted(
                        jump_guard, state=next_state
                    ):
                        single_valued = True
                    else:
                        single_valued = False
                    # prune only unconstrained loop
                    if not single_valued:
                        self.log.debug(
                            f"Loop: Prune at {hex(next_state.addr)} (hit {hit_count})"
                        )
                        remain_states["loop"].append(next_state)

                        self._prune_force_uncons_ret(next_state, stop_point_records)

                        # skip this path
                        continue
                    else:
                        self.log.debug(
                            f"Loop: Continue at {hex(next_state.addr)} (hit {hit_count})"
                        )

            # save the info about the guards of this path
            # new_guards_info = list(guards_info)
            # current_guards = [g for g in self.get_state(next_path).history.jump_guards]
            # if current_guards and len(new_guards_info) < len(current_guards):
            #     new_guards_info.append([hex(self.get_addr(current_path)), current_guards[-1]])
            # new_guards_info = guards_info

            # stop at stop points and record the stopping state
            # note that, we exclude callee node whose indegree may also > 1
            next_addr = next_state.addr
            is_ret = self._is_state_ret(next_state)

            should_stop = (
                is_ret
                or stop_points
                and not no_stop_points
                and not next_is_call
                and next_addr in stop_points
                and not is_loop
            )  # we try not to stop at stop_points inside loop

            first_taint = (
                self._opt_first_taint and self.taint_applied and not tainted_before
            )
            if first_taint:
                last_rec = next_state.info.records[-1]
                if (
                    not self._essential_vars
                    or last_rec.status != ERStatus.LEAVE
                    or last_rec.data["rt_info"]["keyword"] in self._essential_vars
                ):
                    first_taint = should_stop = True
                else:
                    first_taint = False

            if should_stop:
                # decide stop point type
                if first_taint:
                    record_type = "first_taint"
                elif is_ret:
                    record_type = "ret"
                elif followed:
                    # when following a call we need to update stop_points information
                    # in schedule_run
                    record_type = "follow"
                else:
                    record_type = "merge"

                record = {
                    "state": next_state,
                    "type": record_type,
                    "stop_points": stop_points,
                }

                if first_taint:
                    self._force_stop = True
                elif is_ret:
                    # Is it ok to make stop_point and state.addr different?
                    ret_succs = next_path.copy().step()
                    if ret_succs.active:
                        ret_state = ret_succs.active[0]
                        if ret_state.info.func:
                            func_addr = ret_state.info.func[-1][0]
                            record["stop_points"] = self._get_stop_points(
                                ret_state, addr=func_addr
                            )
                        else:
                            record["stop_points"] = []
                        record["state"] = ret_state
                    else:
                        self.log.warning(
                            f"Fail to return at return stop point {next_addr}"
                        )
                        # HACK: directly skip the return stop point
                        self._prune_force_uncons_ret(next_state=next_state, stop_point_records=stop_point_records)
                        continue
                elif followed:
                    record["stop_points"] = self._get_stop_points(next_state)

                if next_addr not in stop_point_records:
                    stop_point_records[next_addr] = []
                stop_point_records[next_addr].append(record)

                # heursitic: force stop exploring if returning count exceed a limit
                if self._opt_max_ret_stop:
                    n_records = 0
                    for records in stop_point_records.values():
                        n_records += len(records)
                        if any((map(lambda r: r["type"] != "ret", records))):
                            break
                    else:
                        if n_records >= self._opt_max_ret_stop:
                            self._force_stop = True

                # continue other exploring
                continue

            # next step!
            sub_remain_states = self._flat_explore(
                next_path,
                check_path_fun,
                stop_points,
                stop_point_records,
                pending_records,
                **kwargs,
            )
            for stash in sub_remain_states:
                states = sub_remain_states[stash]
                if states:
                    remain_states[stash] += states
            self.log.debug(f"Back to block {hex(self.get_addr(current_path))}")
            self._new_path = True

        # information about this state is not needed anymore. Drop constraints to free up lots of memory
        # self._trim_state_space(current_path)
        self.log.debug("Backtracking")
        return remain_states

    def _prune_force_uncons_ret(self, next_state, stop_point_records):
        """
        Heuristic: mark return value as unconstrained for the returning function
        """
        ret_found = False
        for record_lst in stop_point_records.values():
            for record in record_lst:
                if record["type"] != "ret":
                    continue
                tmp_state = record["state"]
                if len(next_state.info.func) <= 1 or not tmp_state.info.func:
                    continue
                ret_func = tmp_state.info.func[-1]
                par_func = next_state.info.func[-2]
                if ret_func != par_func:
                    continue
                reg = ret_reg_name(self.p)
                val = tmp_state.solver.Unconstrained(
                    f"unconstrained_ret_{ret_func[1]}",
                    self.p.arch.bits,
                    explicit_name=True,
                )
                setattr(tmp_state.regs, reg, val)
                ret_found = True
        # We need to create a unconstrained ret state
        if not ret_found:
            parent_state = next_state.info.func_states[-1]
            # Don't create a unconstrained ret state for the entry function
            if parent_state.addr == self._entry_addr:
                return

            ret_path = self._create_path(parent_state.copy())
            self.log.debug(f"Add a return state from {hex(next_state.addr)}")
            skip_f = skip(name=self.get_func_name_by_addr(parent_state.addr))
            skip_f(self, None, ret_path)

            ret_state = self.get_state(ret_path)
            ret_func_addr = ret_state.info.func[-1][0]
            record = {
                "state": ret_state,
                "type": "ret",
                "stop_points": self._get_stop_points(ret_state, addr=ret_func_addr),
            }

            next_addr = ret_state.addr
            if next_addr not in stop_point_records:
                stop_point_records[next_addr] = []
            stop_point_records[next_addr].append(record)

    def set_project(self, p):
        """
        Set the project

        :param p: angr project
        :return:
        """

        self._p = p

    def stop_run(self):
        """
        Stop the taint analysis

        :return: None
        """

        self._keep_run = False

    @property
    def is_running(self):
        return self._keep_run

    def flat_explore(
        self, state, check_path_fun, force_thumb, stop_points, pending_records, **kwargs
    ):
        """
        Run a symbolic-based exploration

        :param state: state
        :param check_path_fun: function to call for each visited basic block
        :param force_thumb: start with thumb mode ON
        :param stop_points: addresses of block to stop
        :param kwargs: kwargs
        :return: stop_point_records
        """

        initial_path = self._create_path(state)

        self._force_stop = False

        if force_thumb:
            # set thumb mode
            initial_path = initial_path.step(thumb=True)[0]
        if state.addr in self._summarized_f:
            init_call = self._summarized_f[state.addr]
            init_call(self, None, initial_path)
        try:
            stop_point_records = {}
            remain_states = self._flat_explore(
                initial_path,
                check_path_fun,
                stop_points,
                stop_point_records,
                pending_records,
                **kwargs,
            )
            for stash, stash_states in remain_states.items():
                stash_paths = [PathInfo(state) for state in stash_states]
                if stash in self._paths:
                    self._paths[stash] += stash_paths
                else:
                    self._paths[stash] = stash_paths
            return stop_point_records
        except Exception as e:
            raise e

    def _init_bss(self, state):
        """
        Initialize the bss section with symboli data (might be slow!).
        :param state: angr state
        :return:
        """

        bss = [s for s in self._p.loader.main_object.sections if s.name == ".bss"]
        if not bss:
            return

        bss = bss[0]
        min_addr = bss.min_addr
        max_addr = bss.max_addr

        for a in range(min_addr, max_addr + 1):
            var = self.get_sym_val(name="bss_", bits=8)
            state.memory.store(a, var)

    def set_alarm(self, timer, n_tries=0):
        """
        Set the alarm to interrupt the analysis

        :param timer: timer
        :param n_tries: number of tries to stop the analysis gracefully
        :return: Non
        """
        if self._old_signal_handler is None:
            handler = signal.getsignal(signal.SIGALRM)
            assert (
                handler != signal.SIG_IGN
            ), "The coretaint alarm handler should never be SIG_IGN"
            self._old_signal_handler = handler

        # TODO save the time left by the previous analysis
        # and restore it
        signal.signal(signal.SIGALRM, self.handler)
        self._old_timer = signal.alarm(timer)

        self._force_exit_after = n_tries
        self._timer = timer

    def unset_alarm(self):
        signal.alarm(0)

    def restore_signal_handler(self):
        """
        Restore the signal handler

        :return: None
        """

        if self._old_signal_handler is not None:
            signal.signal(signal.SIGALRM, self._old_signal_handler)
        if self._old_timer != 0:
            # someone else was looking at this time
            # let's restore it
            signal.alarm(self._old_timer)

    def run(
        self,
        state,
        sinks_info,
        sources_info,
        summarized_f=None,
        init_bss=True,
        check_func=None,
        force_thumb=False,
        use_smart_concretization=True,
    ):
        """
        Run the static taint engine

        :param state: initial state
        :param sinks_info: sinks info
        :param sources_info: sources info
        :param summarized_f: function summaries
        :param init_bss: initializ bss flag
        :param check_func: function to execute for each explored basic block
        :param force_thumb: start analysis in thumb mode
        :param use_smart_concretization: use smart concretization attempts to decrease imprecision due to spurious
                                         pointer aliasing.
        :return: None
        """

        def null_fun(*_, **__):
            return None

        if summarized_f is None:
            summarized_f = {}
        summarized_f.update(self._init_summarized_f)

        self._use_smart_concretization = use_smart_concretization
        state.memory.write_strategies = state.memory.read_strategies
        state.inspect.add_breakpoint(
            "address_concretization",
            BP(when=angr.BP_BEFORE, action=self._addr_concrete_before),
        )
        state.inspect.add_breakpoint(
            "address_concretization",
            BP(when=angr.BP_AFTER, action=self._addr_concrete_after),
        )
        state.inspect.add_breakpoint(
            "mem_read", BP(when=angr.BP_AFTER, action=self._mem_read_after)
        )

        if self._fine_recording:
            state.inspect.add_breakpoint(
                "mem_write", BP(when=angr.BP_AFTER, action=self._mem_write_after)
            )

        state.inspect.add_breakpoint(
            "exit", BP(when=angr.BP_BEFORE, action=self._exit_before)
        )

        # state.inspect.add_breakpoint(
        #     'expr',
        #     BP(when=angr.BP_AFTER, action=self._expr_after)
        # )

        state.globals[GLOB_TAINT_DEP_KEY] = {}
        state.globals[UNTAINT_DATA] = {UNTAINTED_VARS: [], SEEN_MASTERS: []}

        self._count_var = 0
        self._new_path = True
        self._invalid_path = False
        self._sanitized_path = False
        self._back_jumps = {}
        self._keep_run = True
        self._bp_disabled = False
        self._taint_applied = False
        self._fully_taint_guard = []
        self._deref_taint_address = False
        self._deref_addr_expr = None
        self._deref = (None, None)
        self._old_deref = self._deref
        self._old_deref_taint_address = self._deref_taint_address
        self._old_deref_addr_expr = self._deref_addr_expr
        self._concretizations = {}
        self._summarized_f = summarized_f
        self._inferred_summarized_f = {}
        self._not_summarized_f = set()
        self._timeout_triggered = False
        
        self._entry_addr = state.addr

        func_name = self.get_func_name_by_addr(state.addr)
        state.info.rec_enter(
            state, func_name=func_name
        )  # for buffer_overflow_sanitizer

        # env_var
        self._env_var = dict(self._init_env_var)
        self._env_var_tainted = dict(self._init_env_var_tainted)

        self._paths = dict(invalid=[], sanitized=[])

        check_func = null_fun if check_func is None else check_func

        if init_bss:
            self.log.info("init .bss")
            self._init_bss(state)

        try:
            self._run_start_time = time.time()
            self.schedule_run(
                state,
                check_func,
                force_thumb=force_thumb,
                sinks_info=sinks_info,
                sources_info=sources_info,
            )
            self._run_end_time = time.time()
        except TimeOutException:
            self.log.warning("Hard timeout triggered")
        except:
            self.log.error(f"Unhandled ERROR:\n{traceback.format_exc()}")
        finally:
            self._collect_paths()

        if self.timeout_triggered:
            self.log.debug("Timeout triggered")

    def _get_cfg_by_addr(self, start_addr, initial_state=None):
        """Get angr CFG by entry address"""
        if not hasattr(self, "_cached_cfg"):
            self._cached_cfg = {}
        if start_addr in self._cached_cfg:
            return self._cached_cfg[start_addr]

        # disable all plugins and breakpoints
        if initial_state:
            initial_state = initial_state.copy()
            for event_type, l in initial_state.inspect._breakpoints.items():
                for bp in l:
                    initial_state.inspect.remove_breakpoint(event_type, bp=bp)
        cfg = self.p.analyses.CFGEmulated(
            context_sensitivity_level=0,
            call_depth=0,
            starts=[start_addr],
            max_steps=100,
            fail_fast=True,
            initial_state=initial_state,
        )
        return cfg

    def _is_taint_related(self, state):
        """Identify whether state path is taint related"""
        return state.info.taint_related

    def _get_stop_points(self, start_state, addr=None):
        """
        Retrieve merge_points, which are nodes whose indegree > 1
        """
        if not hasattr(self, "_cached_stop_points"):
            self._cached_stop_points = {}
        if addr is not None:
            start_addr = addr
        else:
            start_addr = start_state.addr

        # use cache
        if start_addr in self._cached_stop_points:
            return self._cached_stop_points[start_addr]

        stop_points = set()

        cfg = self._get_cfg_by_addr(start_addr, initial_state=start_state)
        start_node = cfg.get_any_node(start_addr)
        func_name = start_node.name
        back_edges = []
        for edge in cfg.graph.edges():
            node_u, node_v = edge
            if node_u.name is None or node_v.name is None:
                continue
            if "+" not in node_u.name or "+" not in node_v.name:
                continue
            if node_u.name.split("+")[0] != node_v.name.split("+")[0]:
                continue
            if node_u.addr > node_v.addr:
                back_edges.append(edge)
        for node, indegree in cfg.graph.in_degree:
            node_name = node.name
            if (
                func_name
                and node_name
                and ("+" not in node_name or node_name.split("+")[0] != func_name)
            ):
                continue
            if indegree > 1:
                addr = node.addr
                # ignore node in back edge, may be a loop
                for back_edge in back_edges:
                    node_u, node_v = back_edge
                    addr0, addr1 = node_u.addr, node_v.addr
                    if addr >= addr1 and addr < addr0:
                        break
                else:
                    stop_points.add(addr)

        self._cached_stop_points[start_addr] = stop_points
        return stop_points

    def _merge_ret_records(self, collected_ret_records):
        res_records = []
        # group by address
        grouped_ret_records = {}
        for _, state_group in itertools.groupby(
            collected_ret_records.keys(), key=lambda s: s.addr
        ):
            # find common parent
            state_group = list(state_group)
            parents_lst = [list(s.history.parents)[::-1] for s in state_group]
            j = 1
            for j in range(1, len(parents_lst[0])):
                parent_history = parents_lst[0][-j]
                if parent_history.addr is None:
                    continue
                if all(
                    parent_history in reversed(parents_lst[i])
                    for i in range(len(state_group))
                ):
                    break
            else:
                for state in state_group:
                    grouped_ret_records[state.history] = collected_ret_records[state]
                continue

            # use common parent
            records = []
            for state in state_group:
                records.extend(collected_ret_records[state])
            if parent_history in grouped_ret_records:
                grouped_ret_records[parent_history].extend(records)
            else:
                grouped_ret_records[parent_history] = records

        for parent_state_history, records in grouped_ret_records.items():
            # HACK: group by return values
            ret_reg = ret_reg_name(self.p)
            get_ret_val = lambda r: getattr(r["state"].regs, ret_reg)
            get_ret_addr = lambda r: r["state"].addr

            group_iter = itertools.groupby(
                records, key=lambda r: (get_ret_addr(r), get_ret_val(r)._hash)
            )
            for _, group in group_iter:
                group_records = list(group)
                merged_record = self._merge_records(parent_state_history, group_records)
                res_records.append(merged_record)
        return res_records

    def _merge_records(self, parent_state_history, records):
        """merge stop point records"""
        assert records
        added_constraint_bins = {}

        # collect paths to merge
        parent_path = list(parent_state_history.bbl_addrs)
        merge_point = len(parent_path)
        merged_paths = [list(record["state"].history.bbl_addrs) for record in records]
        while True:
            addrs = {
                path[merge_point] if merge_point < len(path) else None
                for path in merged_paths
            }
            if len(addrs) != 1 or None in addrs:
                break
            merge_point += 1
        merged_paths = [merge_path[merge_point:] for merge_path in merged_paths]

        # collect constraints by their hash
        for record in records:
            state = record["state"]
            added_constraints = state.history.constraints_since(parent_state_history)
            for cons in added_constraints:
                cons_hash = cons.ast._hash
                if cons_hash not in added_constraint_bins:
                    added_constraint_bins[cons_hash] = []
                added_constraint_bins[cons_hash].append(cons.ast)

        new_state = records[0]["state"].copy()

        # HACK: simply remove non-common constraints by hash
        constraints_to_reserve = [
            cons
            for cons in new_state.solver.constraints
            if cons._hash not in added_constraint_bins
            or len(added_constraint_bins[cons._hash]) == len(records)
        ]
        new_state.solver._solver.constraints = [cons for cons in constraints_to_reserve]
        new_state.solver.reload_solver()
        new_state.info.path_merge_info[merge_point] = merged_paths

        new_record = {
            "state": new_state,
            "type": "merged",
            "stop_points": records[0]["stop_points"],
        }
        return new_record

    def _is_state_ret(self, state):
        mo = state.project.loader.main_object
        if state.addr < mo.min_addr or state.addr >= mo.max_addr:
            return False
        return state.block().vex.jumpkind == "Ijk_Ret"

    def _filter_pending_records(self, pending_records):
        """Prune and sort pending records"""
        new_pending_records = []
        visited_addrs = set()
        relevant_node_addrs = set()
        pending_states = [pending_record["state"] for pending_record in pending_records]
        ddg = DataDepUtils.from_states(self, pending_states)
        relevant_nodes = DataDepUtils.get_relevant_var_nodes(ddg)
        relevant_node_addrs = {node.addr for node in relevant_nodes}

        for pending_record in pending_records:
            # self._evaluate_pending_record(pending_record)
            pending_state = pending_record["state"]
            addr = pending_state.addr
            if addr not in relevant_node_addrs:
                continue
            if addr in visited_addrs:
                continue
            visited_addrs.add(addr)
            new_pending_records.append(pending_record)
        return new_pending_records

    def _evaluate_pending_record(self, pending_record):
        """Evaluate importance of the pended record"""
        state = pending_record["state"]
        start_idx = len(state.info.records)

        self.log.debug(f"Evaluating pending record from {state.addr:#x}")
        tmp_pending_records = []
        stop_point_records = self.flat_explore(
            state,
            None,
            force_thumb=False,
            stop_points=None,
            pending_records=tmp_pending_records,
            no_stop_points=True,
        )

        for stop_point, records in stop_point_records.items():
            for record in records:
                end_state = record["state"]
                records = end_state.info.records[start_idx:]
                len(records)

    def schedule_run(
        self, start_state, check_func, force_thumb, sinks_info, sources_info
    ):
        """This is the path scheduling algorithm"""
        current_records = [
            {
                "state": start_state,
                "type": "start",
                "stop_points": self._get_stop_points(start_state),
            }
        ]

        collected_ret_records = {}
        pending_records = []
        taint_records = []

        # type list: [ret, follow, merge, merged, start]
        def get_typed_records(records, *record_types, rev=False):
            return [
                record
                for record in records
                if (
                    (record["type"] not in record_types)
                    if rev
                    else (record["type"] in record_types)
                )
            ]

        while current_records or collected_ret_records or pending_records:
            if self._opt_ret_merge and not current_records and collected_ret_records:
                # Merge return records
                current_records = self._merge_ret_records(collected_ret_records)
                n_ret_records = sum(map(len, collected_ret_records.values()))
                ret_addrs = set()
                for records in collected_ret_records.values():
                    for record in records:
                        ret_addrs.add(record["state"].addr)
                self.log.debug(
                    f"Schedule Merged {n_ret_records} returning paths to "
                    f"{[hex(x) for x in ret_addrs]} -> {len(current_records)} paths"
                )
                collected_ret_records = {}

            # if not current_records and pending_records:
            #     pending_records = self._filter_pending_records(pending_records)

            if not current_records and pending_records:
                # Use pending records
                chosen_record = pending_records[0]
                chosen_state = chosen_record["state"]
                for record in pending_records:
                    state = record["state"]
                    chosen_state.info.add_white_call(state.addr)
                self.init_sum_f()  # remove skip functions

                current_records, pending_records = [chosen_record], []
                # current_records, pending_records = pending_records, []
                self.init_sum_f()  # remove skip functions
                for record in current_records:
                    state = record["state"]
                    state.info.add_white_call(state.addr)
                self.log.debug(f"Schedule Using {len(current_records)} pending states")

            new_records = []
            for record in current_records:
                state = record["state"]
                stop_points = record["stop_points"]

                self.log.debug(f"Exploring from {state.addr:#x}")
                stop_point_records = self.flat_explore(
                    state,
                    check_func,
                    force_thumb=force_thumb,
                    sinks_info=sinks_info,
                    sources_info=sources_info,
                    stop_points=stop_points,
                    pending_records=pending_records,
                )
                if not stop_point_records:
                    continue
                if not self.is_running:
                    continue

                for stop_point, records in stop_point_records.items():
                    if self._opt_ret_merge:
                        # Take ret records from the exploring list for merging
                        ret_records = get_typed_records(records, "ret")
                        if ret_records:
                            if state not in collected_ret_records:
                                collected_ret_records[state] = []
                            collected_ret_records[state].extend(ret_records)
                        records = get_typed_records(records, "ret", rev=True)

                    if self._opt_first_taint:
                        # Reserve the first taint path
                        taint_records = get_typed_records(records, "first_taint")
                        if taint_records:
                            self.log.debug(
                                f"Schedule Reserve only first tainted path at {taint_records[0]['state'].addr:#x}"
                            )
                            break

                    if not records:
                        continue

                    # Distinguish taint (un)related states
                    tr_records = ntr_records = []
                    for res, group in itertools.groupby(
                        records,
                        key=lambda record: self._is_taint_related(record["state"]),
                    ):
                        if res:
                            tr_records = list(group)
                        else:
                            ntr_records = list(group)

                    if len(records) == 1:
                        # trivial go through
                        new_records.extend(records)
                        self.log.debug(f"Schedule Pass {stop_point:#x}")
                    elif len(ntr_records) != len(records):
                        # prune states
                        self.log.debug(
                            f"Schedule Prune {len(ntr_records)} paths at {stop_point:#x}"
                        )
                        new_records.extend(tr_records)
                    else:
                        # merge states
                        self.log.debug(
                            f"Schedule Merging {len(ntr_records)} paths from {state.addr:#x} to {stop_point:#x}"
                        )
                        merged_record = self._merge_records(state.history, ntr_records)
                        new_records.append(merged_record)

                if taint_records:
                    # keep only one record
                    collected_ret_records = {}
                    new_records = taint_records
                    break
            # mark taint unrelated
            for record in new_records:
                record["state"].info.taint_related = False
            current_records = new_records

    def log_summary(self, interact=False):
        summary = f"""
        Summary
          Time Elapsed      : {self.run_time:.1f}s
          #Total Paths      : {self.n_paths}
          #Invalid Paths    : {self.get_n_paths("invalid")}
          #Unfinished Paths : {self.get_n_paths("unfinished")}
          #Uncons Paths     : {self.get_n_paths("uncons")}
          #Dead Paths       : {self.get_n_paths("dead")}
          #Error Paths      : {self.get_n_paths("error")}
          #Loop Paths       : {self.get_n_paths("loop")}
          #Vuln Paths       : {self.get_n_paths("sanitized")}
          Taint Applied     : {self.taint_applied}
          Timeout           : {self.timeout_triggered}
        """

        if self.get_n_paths("sanitized") > 0:
            vuln_path = self.paths["sanitized"][0]
            self.log.info(vuln_path.dump())

        self.log.info(summary)

        if interact:
            from IPython import embed

            embed()

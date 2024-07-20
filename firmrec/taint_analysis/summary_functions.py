"""
Though karonte relies on angr's sim procedures, sometimes these add in the current state some constraints to make the
used analysis faster. For example, if a malloc has an unconstrained size, angr add the constraint
size == angr-defined.MAX_SIZE. Though this makes the analysis faster, it makes impossible to reason about the maximum
buffer sizes (as needed by karonte).

In this module we wrap sim procedures to avoid them to add such constraints.

Note however, that the semantic of an expression might get lost.
Eg. strlen(taint_x) = taint_y, taint_y is an unconstrained variable
"""

import abc
import re
import functools
import math
import traceback
import bisect

import archinfo
import angr
from angr.procedures.stubs.ReturnUnconstrained import ReturnUnconstrained
import claripy

from .utils import (
    arg_reg_name,
    arg_reg_num,
    ret_reg_name,
    get_ret_target,
    set_ret_target,
    arg_stack_off,
    get_arg_val,
    set_arg_val,
    get_ret_val,
    set_ret_val,
)
from .monkey import my_sprintf, my_snprintf, my_vsprintf, my_vsnprintf


# pylint:disable=invalid-name


class SimCallException(Exception):
    """Exception raised when a call fails."""

    def __init__(self, sim_name, *args):
        self.sim_name = sim_name
        self.args = args


class SummarizedFunction(abc.ABC):
    """Summarized function."""

    def __init__(self, *args, **kwargs):
        self._core = None
        self._prev_path = None
        self._succ_path = None
        self.name = self.__class__.__name__
        self.n_arg = kwargs.pop("n_arg", None)
        self._rt_info = None

    def _reset_rt_info(self):
        self._rt_info = {"sum_f": self.name}

    def __call__(self, core, prev_path, succ_path, **kwargs):
        """
        Call procedure

        :param core: core taint engine
        :param prev_path: path of call site
        :param succ_path: path to the called function
        :return: None
        """
        self._reset_rt_info()  # run-time information
        self._core = core
        self._prev_path = prev_path
        self._succ_path = succ_path

        if self.n_arg is not None:
            args = []
            for i in range(self.n_arg):
                args.append(self.get_arg_val(i))
        elif prev_path:
            # infer calling convention
            calling_regs = self._core._infer_calling_convention(self.prev_state)
            args = []
            for reg in calling_regs:
                reg_content = getattr(self.succ_state.regs, reg)
                args.append(reg_content)
            self.n_arg = len(args)
        else:
            args = None

        self.succ_state.info.rec_enter(
            self.succ_state, func_name=self.func_name, data=dict(args=args)
        )
        addr = self.succ_state.addr
        call_log_msg = (
            f"Call summarized function {self.name} of {hex(addr)} {self.func_name}"
        )
        try:
            self.run(**kwargs)
            self.log.debug(f"{call_log_msg} {self._rt_info}")
            self.succ_state.info.records[-1].data["rt_info"] = self._rt_info
        except:  # pylint: disable=bare-except
            self.log.debug(call_log_msg)
            self.log.warning("Call summarize exception, regard as invalid")
            # self.log.warning(traceback.format_exc())
            self.core.mark_path(invalid=True)
        if not self._succ_path.active:
            # if self._succ_path.unconstrained:
            #     core._sanitized_path = True
            # else:
            core._invalid_path = True

    def run(self, **kwargs):
        """
        Run procedure
        """
        raise NotImplementedError()

    @property
    def func_name(self):
        """Function name"""
        return self.core.get_func_name_by_addr(self.succ_state.addr)

    @property
    def core(self):
        return self._core

    @property
    def succ_path(self):
        return self._succ_path

    @property
    def prev_path(self):
        return self._prev_path

    @property
    def succ_state(self):
        return self._core.get_state(self._succ_path)

    @property
    def prev_state(self):
        return self._core.get_state(self._prev_path)

    @property
    def log(self):
        return self._core.log

    def call_sim(self, sim_procedure):
        core = self.core
        plt_path = self._succ_path

        # this call can continue with an empty sim procedure since it does nothing
        next_addr = self.succ_state.addr
        core.p.hook(next_addr, sim_procedure)

        self.core.safe_begin()
        try:
            sim_call_error = False
            plt_path.step()
            if not plt_path.active:
                sim_call_error = True
        except:  # pylint: disable=bare-except
            sim_call_error = True
            traceback.print_exc()
        finally:
            self.core.safe_end()
            core.p.unhook(next_addr)

        if sim_call_error:
            raise SimCallException(self.name)

    def ret(self, ret_val=None):
        core = self.core
        p = core.p
        # this call can continue with an empty sim procedure since it does nothing
        next_addr = self.succ_state.addr
        # disable simprocedure
        if core.p.is_hooked(next_addr):
            core.p.unhook(next_addr)
        if ret_val is None:
            ret_val = core.get_sym_val(name=f"ret_{self.func_name}", bits=p.arch.bits)
        core.p.hook(next_addr, ReturnUnconstrained(return_val=ret_val))
        self.succ_path.step()
        core.p.unhook(next_addr)

    def plt_ret(self):
        """
        Return from procedure
        """
        path = self.succ_path
        state = self.succ_state
        path.step()
        assert self._core.p.is_hooked(state.addr), (
            f"{self.name} ({hex(state.addr)}):"
            " Summary function relies on angr's sim procedure"
            ", add option use_sim_procedures to the loader"
        )
        path.step()
        assert (
            path.active
        ), "size of function has no active successors, not walking this path..."

    def get_arg_val(self, arg_idx):
        """Wrapper of get_arg_val"""
        return get_arg_val(self.succ_state, arg_idx)

    def set_arg_val(self, arg_idx, val):
        """Wrapper of set_arg_val"""
        return set_arg_val(self.succ_state, arg_idx, val)

    def get_ret_val(self):
        """Wrapper of get_ret_val"""
        return get_ret_val(self.succ_state)

    def set_ret_val(self, val):
        """Wrapper of set_ret_val"""
        return set_ret_val(self.succ_state, val)

    def sanitize_stack_overflow(self, mark_as_vuln=True):
        state = self.succ_state
        info = state.info
        # stack overflow
        for sp_value, orig_ret_target in zip(info.func_sp, info.ret_target):
            ret_target = get_ret_target(state, sp_value)
            tainted = self.core.is_tainted(ret_target, self.succ_path)
            if tainted:
                # ret_target.singlevalued and orig_ret_target.singlevalued \
                # and state.solver.eval(orig_ret_target) != state.solver.eval(ret_target):
                if mark_as_vuln:
                    self.core.mark_path(
                        vuln=True,
                        state=state,
                        data={"reason": "Stack Overflow", "vars": [ret_target]},
                    )
                else:
                    self.core.mark_path(
                        invalid=True,
                    )
                return True
        return False

    def sanitize_heap_overflow(self, write_start, write_size):
        write_start = self.resolve_val(write_start)
        write_size = self.resolve_val(write_size)
        state = self.succ_state
        heap = state.info.heap
        if not heap or write_start >= heap[-1] or write_start < heap[0]:
            # We sanitize data segment overflow here
            mo = self.core.p.loader.main_object
            if mo.find_section_containing(write_start) != mo.find_section_containing(
                write_start + write_size
            ) or mo.find_segment_containing(write_start) != mo.find_segment_containing(
                write_start + write_size
            ):
                sym = self.core.safe_load(self.succ_path, write_start, write_size)
                self.core.mark_path(
                    vuln=True,
                    state=state,
                    data={"reason": "Data Overflow", "vars": [sym]},
                )
                return True
            return False
        start_pos = bisect.bisect_left(heap, write_start + 1)
        last_addr = write_start + max(write_size - 1, 0)
        end_pos = bisect.bisect_left(heap, last_addr, lo=start_pos)
        # cnt = self.core.safe_load(self.succ_path, last_addr-1, 1)
        if start_pos != end_pos:
            sym = self.core.safe_load(self.succ_path, write_start, write_size)
            self.core.mark_path(
                vuln=True,
                state=state,
                data={"reason": "Heap Overflow", "vars": [sym]},
            )
            return True
        return False

    def allocate(self, size):
        addr = self.succ_state.heap.allocate(size)
        size_conc = self.resolve_val(size)
        addr_conc, addr_sym = self.resolve_val(addr, keep_sym=True)
        heap = self.succ_state.info.heap
        if not heap:
            heap.append(addr_conc)
        heap.append(addr_conc + size_conc)
        if addr_sym is None:
            addr_sym = claripy.BVV(addr, self.core.p.arch.bits)
        return addr_sym

    def resolve_val(self, val, keep_sym=False):
        return self.core.resolve_val(self.succ_state, val, keep_sym)


class skip(SummarizedFunction):
    """Skip the function call and return unconstrained value"""

    def __init__(self, name=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if name:
            self.name = f"skip_{name}"

    def run(self, **kwargs):
        self.ret()


class stub(SummarizedFunction):
    """Jmp to target function"""

    def __init__(self, target_addr, name=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if name:
            self.name = f"stub_{name}"
        self.target_addr = target_addr

    def run(self, **kwargs):
        self.succ_state.ip = self.target_addr
        self._rt_info["target"] = self.target_addr

        # Explictly mark leave to balance the call stack
        self.succ_state.info.rec_leave(self.succ_state)


class wrap(SummarizedFunction):
    def __init__(self, name, func, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = f"wrap_{name}"
        self.func = func

    def run(self, **kwargs):
        self.func(self, **kwargs)


class simp(SummarizedFunction):
    """Wrapper for SimProcedure"""

    def __init__(self, lib, func_name, sim_procedure=None, **kwargs):
        super().__init__(**kwargs)
        self.name = f"{lib}__{func_name}"
        self._lib = lib
        self._func_name = func_name
        if sim_procedure is None:
            sim_procedure = angr.SIM_PROCEDURES[self._lib].get(self._func_name, None)()
        self._sim_procedure = sim_procedure

        self.skip = self._should_skip()

    def run(self, **kwargs):
        if self.skip:
            self.ret()
            return
        self._succ_path, bak_path = self.succ_path.copy(), self._succ_path
        self.core.safe_begin()
        try:
            # HACK: avoid SimCallException
            self.call_sim(self._sim_procedure)
            self._succ_path = bak_path
            self.call_sim(self._sim_procedure)
        except SimCallException:
            self.log.warning(f"SimCallException in {self.name}. Falling back to skip.")
            self._succ_path = bak_path
            self.ret()
        finally:
            self.core.safe_end()

    def _should_skip(self):
        if self._func_name in FORCE_SKIP_FUNCS:
            return True
        return False


class memcmp(SummarizedFunction):
    def __init__(self, sized=False, case=False, force_str=False, **kwargs):
        super().__init__(**kwargs)
        self.sized = sized
        self.case = case
        self.force_str = force_str

    """memcmp-like unsized (e.g., strlen) function summary"""

    def run(self, **kwargs):
        core = self.core
        path = self.succ_path
        p = core.p

        op1_reg_val = self.get_arg_val(0)
        op2_reg_val = self.get_arg_val(1)
        self._rt_info["s1"] = op1_reg_val
        self._rt_info["s2"] = op2_reg_val

        if op1_reg_val.uninitialized or op2_reg_val.uninitialized:
            return_value = core.get_sym_val(name="memcmp", bits=p.arch.bits)
            self.ret(return_value)
            self._rt_info["ret"] = return_value
            return

        if self.sized:
            n = self.get_arg_val(2)
            n_val = self.core.resolve_val(self.succ_state, n)
            if not n_val:
                return_value = core.get_sym_val(name="memcmp", bits=p.arch.bits)
                self.ret(return_value)  # unconstrained
                self._rt_info["ret"] = return_value
                return
            self._rt_info["size"] = n_val
        else:
            n_val = None

        # load part of string to avoid stucking at long string
        NEEDLE_SIZE = min(10, n_val or 10)
        s1 = core.safe_load_str(path, op1_reg_val, max_size=NEEDLE_SIZE, exact=n_val)
        s2 = core.safe_load_str(path, op2_reg_val, max_size=NEEDLE_SIZE, exact=n_val)
        if self.case:
            s1 = s1.lower()
            s2 = s2.lower()
        cnt1 = core.safe_load(path, op1_reg_val, NEEDLE_SIZE)
        cnt2 = core.safe_load(path, op2_reg_val, NEEDLE_SIZE)

        tainted = self._core.is_tainted(cnt1, self._succ_path) or self._core.is_tainted(
            cnt2, self._succ_path
        )

        # if not _core.is_tainted(b1, plt_path):
        #     b1 = None
        # if not _core.is_tainted(b2, plt_path):
        #     b2 = None

        # if either of the two is not tainted, we untaint the other
        # if b1 is not None and b2 is None:
        #     _core.do_recursive_untaint(b1, plt_path)
        # elif b2 is not None and b1 is None:
        #     _core.do_recursive_untaint(b2, plt_path)

        if s1 and s2 or cnt1.concrete and cnt2.concrete:
            if s1 == s2:
                if self.sized or len(s1) == NEEDLE_SIZE or len(s2) == NEEDLE_SIZE:
                    # compare full string
                    s1 = core.safe_load_str(path, op1_reg_val, exact=n_val)
                    s2 = core.safe_load_str(path, op2_reg_val, exact=n_val)
                    if self.case:
                        s1 = s1.lower()
                        s2 = s2.lower()
                    if s1 == s2:
                        return_value = 0
                    elif s1 > s2:
                        return_value = 1
                    else:
                        return_value = -1
                else:
                    return_value = 0
            elif s1 > s2:
                return_value = 1
            else:
                return_value = -1
            self.ret(return_value)
        elif s1 or s2 or cnt1.concrete or cnt2.concrete:
            if s1 or cnt1.concrete:
                con_s = core.safe_load_str(path, op1_reg_val, exact=n_val)
                sym_s = core.safe_load(path, op2_reg_val, len(con_s))
                cmp_res = -(sym_s - con_s)
            else:
                con_s = core.safe_load_str(path, op2_reg_val, exact=n_val)
                sym_s = core.safe_load(path, op1_reg_val, len(con_s))
                cmp_res = sym_s - con_s
            bits = p.arch.bits
            return_value = claripy.If(
                cmp_res == 0,
                claripy.BVV(0, bits),
                claripy.If(
                    cmp_res > 0, claripy.BVV(1, bits), claripy.BVV(0xFFFFFFFF, bits)
                ),
            )
            self.ret(return_value)
        else:
            # Situation 3: both are symbolic
            if tainted:
                return_value = core.get_sym_val(
                    name=core.taint_buf + "_memcmp", bits=p.arch.bits
                )
            else:
                return_value = core.get_sym_val(name="memcmp", bits=p.arch.bits)
            self.ret(return_value)
            # sim_procedure = angr.SIM_PROCEDURES['libc'].get("strcmp", None)()
            # self.call_sim(sim_procedure)
        self._rt_info["ret"] = return_value
        self._rt_info["*s1"] = s1
        self._rt_info["*s2"] = s2


class memcpy(SummarizedFunction):
    """memcpy-like unsize (e.g., strcpy) function summary"""

    def __init__(self, sized, force_str, **kwargs):
        super().__init__(**kwargs)
        self.sized = sized
        self.force_str = force_str

    def run(self, **kwargs):
        core = self.core
        path = self.succ_path
        state = self.succ_state

        dst = self.get_arg_val(0)
        src = self.get_arg_val(1)
        self._rt_info["src"] = src
        self._rt_info["dst"] = dst

        if self.sized:
            n = self.get_arg_val(2)
            # if core.is_tainted(n, path):
            #     core._sanitized_path = True
            #     self.ret(dst)
            #     self._rt_info['size'] = n
            #     return
            n_val = self.resolve_val(n)
            self._rt_info["size"] = n_val
            # avoid false positive
            if n_val > 0x10000:
                self.ret()
                return
        else:
            n_val = None

        # skip uninitialized address to avoid sim_procedure error
        if core.is_uninitialized(src) or core.is_uninitialized(dst):
            self.ret(dst)
            return

        if self.force_str:
            src_conc, src_loaded = core.safe_load_str(
                path, src, max_size=n_val, symbolic=True
            )
        else:
            src_conc, src_loaded = core.safe_load_str(
                path, src, exact=n_val, symbolic=True
            )
        self._rt_info["res"] = src_conc
        state.memory.store(dst, src_loaded)
        if self.force_str:
            strlen = src_loaded.length >> 3
            if not self.sized:
                pad_zero_nbyte = 1
            else:
                # strncpy
                pad_zero_nbyte = n_val - strlen
            if pad_zero_nbyte > 0:
                state.memory.store(dst + strlen, claripy.BVV(0, pad_zero_nbyte << 3))

        self.ret(dst)
        if self.force_str:
            state.info.mark_strlen(dst, strlen)

        # HACK: fast sanitize
        self.sanitize_stack_overflow()
        self.sanitize_heap_overflow(dst, len(src_conc))


class sizeof(SummarizedFunction):
    """sizeof-like (e.g., strlen) function summary"""

    def run(self, **kwargs):
        core = self.core
        path = self.succ_path
        state = self.succ_state
        p = core.p

        addr = self.get_arg_val(0)

        if addr.uninitialized:
            return_value = core.get_sym_val(name="__size__", bits=p.arch.bits).reversed
            self.ret(return_value)
            return

        cnt = core.safe_load(path, addr, core.taint_buf_size // 8)

        addr_conc = self.core.resolve_val(state, addr)
        str_length = state.info.get_strlen(addr_conc)

        if str_length is not None:
            # use cached length
            return_value = str_length
        else:
            s = core.safe_load_str(path, addr)

            if s or cnt.concrete:
                return_value = len(s)
            else:
                return_value = None

        # TODO: check if the constraints set by angr sim procedure are correct
        # if there is a tainted buffer in one of the registers then also taint this variable
        if core.is_tainted(cnt, path=path) or core.is_tainted(addr, path=path):
            t = core.get_sym_val(
                name=(core.taint_buf + "__size__"), bits=p.arch.bits, taint=True
            ).reversed
            # constrain output of this variable equal to the output of sizeof and add it to the return register
            if return_value is not None:
                self.succ_state.add_constraints(return_value == t)
        elif return_value is None:
            t = core.get_sym_val(name="__size__", bits=p.arch.bits).reversed
            return_value = t

        self.ret(return_value)


class str_search(SummarizedFunction):
    """Summarized function for memchr, strchr"""

    def __init__(self, name, **kwargs):
        super().__init__(**kwargs)
        self.name = name
        self.big_arg = 0
        self.case = False

        if name in ("strchr", "strrchr", "memchr"):
            self.needle = "c"  # character
        elif name in ("strpbrk", "strspn", "strcspn"):
            self.needle = "cs"  # character set
        else:  # ('strstr', 'strcasestr', 'strnstr', 'memmem')
            self.needle = "s"  # string

        if name in ("memmem",):
            self.little_arg = 2
        else:
            self.little_arg = 1

        self.big_len_arg = None
        self.little_len_arg = None  # little length
        if name in ("strnstr", "memchr"):
            self.big_len_arg = 2
        elif name in ("memmem",):
            self.big_len_arg = 1
            self.little_len_arg = 3
        # else ('strstr', 'strcasestr', 'strchr', 'strrchr')

        self.reverse = False
        if name in ("strrchr",):
            self.reverse = True

        self.ret_spn = False
        self.ret_cspn = False
        if name == "strspn":
            self.ret_spn = True
        if name == "strcspn":
            self.ret_cspn = True

        self.force_str = name.startswith("str")

    def run(self, **kwargs):
        core = self.core
        path = self.succ_path
        p = core.p
        state = self.succ_state

        big = self.get_arg_val(self.big_arg)
        little = self.get_arg_val(self.little_arg)
        self._rt_info["big"] = big
        self._rt_info["little"] = little

        # load big len
        if self.big_len_arg is not None:
            big_len = self.get_arg_val(self.big_len_arg)
            big_len = core.resolve_val(state, big_len)
            self._rt_info["big_len"] = big_len
        else:
            big_len = None

        # load little len
        if self.little_len_arg is not None:
            little_len = self.get_arg_val(self.little_len_arg)
            little_len = core.resolve_val(state, little_len)
            self._rt_info["little_len"] = little_len
        else:
            little_len = None

        # load strings
        if self.force_str:
            big_str, big_sym = core.safe_load_str(
                path, big, max_size=big_len, symbolic=True
            )
        else:
            big_str, big_sym = core.safe_load_str(
                path, big, exact=big_len, symbolic=True
            )
        if self.needle == "c":
            little_sym = little & 0xFF
            little_conc = core.resolve_val(state, little_sym)
            little_str = bytes([little_conc & 0xFF])
        else:
            if self.force_str:
                little_str, little_sym = core.safe_load_str(
                    path, little, max_size=little_len, symbolic=True
                )
            else:
                little_str, little_sym = core.safe_load_str(
                    path, little, exact=little_len, symbolic=True
                )

        if self.case:
            big_str = big_str.lower()
            little_str = little_str.lower()

        self._rt_info["big_str"] = big_str
        self._rt_info["little_str"] = little_str

        # search string
        if (big_str or big_sym.length > 0 and big_sym.concrete) and (
            little_str or little_sym.length > 0 and little_sym.concrete
        ):
            if self.needle == "cs":
                needles = [little_str[i : i + 1] for i in range(len(little_str))]
            else:
                needles = [little_str]

            if self.ret_spn:
                # strspn
                return_value = len(big_str) - len(big_str.lstrip(little_str))
            elif self.ret_cspn:
                # strcspn
                return_value = 0
                for c in big_str:
                    if c not in little_str:
                        return_value += 1
            else:
                # others
                idxes = []
                for needle in needles:
                    if self.reverse:
                        idx = big_str.rfind(needle)
                    else:
                        idx = big_str.find(needle)
                    if idx >= 0:
                        idxes.append(idx)
                if not idxes:
                    return_value = 0
                else:
                    return_value = big + min(idxes)
        else:
            return_value = core.get_sym_val(name=self.name, bits=p.arch.bits)
            if big_len is not None:
                cons = claripy.Or(
                    return_value == 0,
                    claripy.And(return_value >= big_len, return_value < big + big_len),
                )
            else:
                cons = claripy.Or(return_value == 0, return_value >= big)
            state.add_constraints(cons)

        self._rt_info["ret"] = return_value

        self.ret(return_value)


class strcat(SummarizedFunction):
    """Summarized function for strcat, strncat"""

    def __init__(self, sized=False, **kwargs):
        super().__init__(**kwargs)
        self.dst_arg = 0
        self.src_arg = 1
        self.sized = sized

    def run(self, **kwargs):
        core = self.core
        path = self.succ_path
        state = self.succ_state

        dst = self.get_arg_val(self.dst_arg)
        src = self.get_arg_val(self.src_arg)

        if self.sized:
            n = self.get_arg_val(2)
            if core.is_tainted(n, path):
                # core._sanitized_path = True
                self.ret(dst)
                return
            n_val = self.resolve_val(n)
        else:
            n_val = None

        self._rt_info["src"] = src
        self._rt_info["dst"] = dst
        self._rt_info["n"] = n_val

        # skip uninitialized address to avoid sim_procedure error
        if core.is_uninitialized(dst) or core.is_uninitialized(dst):
            self.ret(dst)
            return

        dst_conc, dst_loaded = core.safe_load_str(path, dst, symbolic=True)

        src_conc, src_loaded = core.safe_load_str(
            path, src, max_size=n_val, symbolic=True
        )

        res_loaded = dst_loaded.concat(src_loaded)
        res_conc = dst_conc + src_conc
        self._rt_info["res"] = res_conc

        state.memory.store(dst, res_loaded)
        if n_val is not None:
            # strncat
            if len(src_conc) < n_val:
                padding = claripy.BVV(0, (n_val - (src_loaded.length >> 3)) << 3)
            else:
                padding = None
        else:
            padding = claripy.BVV(0, 8)
        if padding is not None:
            state.memory.store(dst + (res_loaded.length >> 3), padding)

        # assert (
        #     self.core.safe_load_str(path, dst, max_size=len(res_conc)) == res_conc
        # ), f"{self.core.safe_load_str(path, dst)} != {res_conc}"
        state.info.mark_strlen(dst, len(res_conc))

        self.ret(dst)

        # HACK: fast sanitize
        self.sanitize_stack_overflow()
        self.sanitize_heap_overflow(dst, len(src_conc))


#
# Heap functions
#
class heap_alloc(SummarizedFunction):
    def __init__(self, *args, sz_idxs=(0,), **kwargs):
        """
        :param sz_idx: argument index of size
        """
        super().__init__(*args, **kwargs)
        self.sz_idxs = sz_idxs
        if len(sz_idxs) == 1:
            self.get_sz = lambda: self.get_arg_val(sz_idxs[0])
        else:
            self.get_sz = lambda: functools.reduce(
                lambda x, y: x * y, self.get_arg_val(sz_idxs), 1
            )

    """Heap allocation function stub"""

    def run(self, **kwargs):
        core = self.core
        p = core.p

        sim_size = self.get_sz()

        state = self.succ_state

        # when the size is symbolic, choose the maximum size possible
        if state.solver.symbolic(sim_size):
            size = state.solver.max(sim_size)
            if size > state.libc.max_variable_size:
                size = state.libc.max_variable_size
        else:
            size = sim_size

        chunk = self.allocate(((size + 7) >> 3) << 3)  # 8 byte align
        # use the sim procedure
        self.ret(chunk)

        self._rt_info["size"] = sim_size
        self._rt_info["addr"] = chunk

        # if sim_size is not None:
        #     taint_args = [l for l in sim_size.recursive_leaf_asts if _core.is_tainted(l, call_site_path)]
        #     if taint_args and len(set(taint_args)) == 1:
        #         arg = taint_args[0]
        #         if '__size__' in str(arg): # is_size_tainted
        #             _core.do_recursive_untaint(arg, plt_path)


class fmt_string(SummarizedFunction):
    def __init__(self, buf_arg=0, fmt_arg=1, size_arg=None, name=None, **kwargs):
        super().__init__(**kwargs)
        self.buf_arg = buf_arg
        self.fmt_arg = fmt_arg
        self.size_arg = size_arg
        if name:
            self.name = name

    def run(self, **kwargs):
        core = self.core
        p = core.p
        state = self.succ_state
        path = self.succ_path

        dest_addr = self.get_arg_val(self.buf_arg)
        fmt_addr = self.get_arg_val(self.fmt_arg)
        if self.size_arg:
            n = self.get_arg_val(self.size_arg)
            self._rt_info["size"] = n

        fmt_str = core.safe_load_str(path, fmt_addr)

        tainted = False
        pattern = rb"(?:\x25\x25)|^\x25(?:([1-9]\d*)\$|\(([^\)]+)\))?(\+)?(0|'[^$])?(-)?(\d+)?(?:\.(\d+))?([b-fiosuxX])"
        va_arg_count = 0
        for match in re.finditer(pattern, fmt_str):
            if match.group(0) == "%%":
                continue

            va_arg_count += 1
            va_arg_idx = self.fmt_arg + va_arg_count
            va_reg_name = arg_reg_name(p, va_arg_idx)
            va_arg_val = self.get_arg_val(va_arg_idx)
            # TODO: fine-grained taint
            if core._is_reg_or_mem_taint_quick(self.succ_state, va_reg_name):
                tainted = True

        if self.name == "sprintf":
            sim_procedure = my_sprintf(self)
        elif self.name == "snprintf":
            sim_procedure = my_snprintf(self)
        elif self.name == "vsprintf":
            sim_procedure = my_vsprintf(self)
        elif self.name == "vsnprintf":
            sim_procedure = my_vsnprintf(self)
        elif not self.size_arg:
            sim_procedure = my_sprintf(self)
        else:
            sim_procedure = my_snprintf(self)
        self.call_sim(sim_procedure)

        self.sanitize_stack_overflow()

        self._rt_info["fmt"] = fmt_str
        self._rt_info["dst_addr"] = dest_addr

        try:
            length = self.core.resolve_val(self.succ_state, self.get_ret_val())
            self._rt_info["length"] = length
            addr = self.core.resolve_val(state, dest_addr)
            self.succ_state.info.mark_strlen(addr, length)
            res_str, res_sym = core.safe_load_str(
                path, dest_addr, length, symbolic=True
            )
        except:
            return

        self._rt_info["res_sym"] = res_sym
        self._rt_info["res_str"] = res_str
        self._rt_info["ret"] = length

        if tainted:
            core.apply_taint(path, dest_addr, "fmt", length * 8)


#
# RCE function
#
class system(SummarizedFunction):
    """
    summary of system/doSystemCmd-like functions

    :ivar cmd_arg: the argument index of cmd string
    """

    def __init__(self, cmd_arg=0, argv_arg=1, inspect_argv=False, **kwargs):
        super().__init__(**kwargs)
        self.cmd_arg = cmd_arg
        self.argv_arg = argv_arg
        self.inspect_argv = inspect_argv

    def run(self, **kwargs):
        core = self.core
        p = core.p
        path = self.succ_path
        state = self.succ_state

        cmd_addr = self.get_arg_val(self.cmd_arg)
        self._rt_info["cmd_addr"] = cmd_addr

        vuln = False

        if core.is_tainted(cmd_addr, path=path):
            vuln = True
            vuln_var = cmd_addr
        else:
            conc_str, cont = core.safe_load_str(path, cmd_addr, symbolic=True)
            # This model format-like system function
            for arg_idx in self._get_format_str_idxes(
                conc_str, start_arg_idx=self.cmd_arg + 1
            ):
                if arg_idx - self.cmd_arg > 3:
                    break
                arg = self.get_arg_val(arg_idx)
                _, arg_cont = core.safe_load_str(path, arg, symbolic=True)
                if core.is_tainted(arg_cont, path=path):
                    vuln = True
                    vuln_var = arg_cont
                    break
            if core.is_tainted(cont, path=path):
                vuln = True
                vuln_var = cont
            elif self.inspect_argv and conc_str in [b"sh", b"bash"]:  # consider bashing
                # inspect argv for shell script
                argv = self.get_arg_val(self.argv_arg)

                argv_conc = []
                self._rt_info["argv_conc"] = argv_conc

                max_argv = 5
                for i in range(max_argv):
                    arg = self.core.safe_load_num(self.succ_path, argv, idx=i)
                    if self.core.resolve_val(state, arg) == 0:
                        break
                    conc_arg, sym_arg = core.safe_load_str(path, arg, symbolic=True)
                    argv_conc.append(conc_arg)
                    if core.is_tainted(sym_arg, path=path):
                        vuln_var = sym_arg
                        vuln = True

            self._rt_info["cmd_conc"] = conc_str
            self._rt_info["cmd"] = cont

        if vuln:
            core.mark_path(
                vuln=True,
                state=self.succ_state,
                data={"reason": "Command Injection", "vars": [vuln_var]},
            )

        # Just skip the function
        self.ret()

    @classmethod
    def _get_format_str_idxes(cls, s, start_arg_idx=1):
        for idx, ch in enumerate(s):
            if ch == ord(b"%"):
                if idx < len(s) - 1:
                    next_ch = s[idx + 1]
                    if next_ch == ord(b"s"):
                        yield start_arg_idx
                    elif next_ch not in b"d":
                        continue
                    start_arg_idx += 1


#
# Env function
#
ENV_VAR_MARK = "env_var"


class set_env(SummarizedFunction):
    """
    setenv function summary

    :ivar key_arg: the key argument position
    :ivar val_arg: the val argument position
    """

    def __init__(self, key_arg=0, val_arg=1, **kwargs):
        super().__init__(**kwargs)
        self.key_arg = key_arg
        self.val_arg = val_arg

    def run(self, **kwargs):
        core = self.core
        p = core.p
        path = self.succ_path

        state = self.succ_state

        # add the environment variable to the list of env_variables with this key
        key_reg = arg_reg_name(p, self.key_arg)
        val_reg = arg_reg_name(p, self.val_arg)
        key_addr = getattr(self.succ_state.regs, key_reg)
        val_addr = getattr(self.succ_state.regs, val_reg)
        key = core.safe_load_str(path, key_addr)
        val = core.safe_load_str(path, val_addr)
        tainted = core._is_reg_or_mem_taint_quick(
            state, key_reg
        ) or core._is_reg_or_mem_taint_quick(state, val_reg)
        core.add_var(key, val, tainted)

        self.ret()


class get_env(SummarizedFunction):
    """
    getenv function summary

    :ivar key_arg: the key argument position
    :ivar out_arg: the output address argument position. If none, output with returned argument
    :ivar ret_type: what the function returns
        ptr: return the pointer of out_arg
        zero: return 0 if success
        non-zero: return 0 if fail
    :ivar conservative: if True, absent value will be symbolic; otherwise, it will be set to \x00
    :ivar taint_web_obj: if True, the first parameter of function will be tainted
    :ivar ret_none_if_absent: if True, return zero when key is absent.
        otherwhise pointer to empty string will be returned when key is absent.
    """

    def __init__(self, key_arg=0, out_arg=None, ret_type="ptr", **kwargs):
        super().__init__(**kwargs)
        self.key_arg = key_arg
        self.out_arg = out_arg
        self.ret_type = ret_type
        self.conservative = kwargs.get("conservative", True)
        self.taint_web_obj = kwargs.get("taint_web_obj", False)
        self.ret_none_if_absent = kwargs.get("ret_none_if_absent", False)

    def _guess_arg_position(self):
        """Guess the argument position of key and output"""
        raise NotImplementedError("_guess_arg_position")

    def run(self, **kwargs):
        core = self.core
        p = core.p
        path = self._succ_path

        state = self.succ_state

        reg = self.get_arg_val(self.key_arg)
        key_str = core.safe_load_str(path, reg)

        to_store = core.get_var(key_str)
        need_taint = core.is_var_tainted(key_str)

        key_absent = to_store is None

        if key_absent:
            to_store = claripy.BVV(0, p.arch.bits)

            cnt_mem = core.safe_load(path, reg)
            # this info is passed by some user controllable source
            env_var_size = 0x40 * 8  # Be conservative
            if core.is_tainted(reg, path=path) or core.is_tainted(cnt_mem, path=path):
                if self.conservative:
                    to_store = core.get_sym_val(name=core.taint_buf, bits=env_var_size)
                need_taint = True
            # fresh symbolic var
            else:
                if self.conservative and not self.ret_none_if_absent:
                    to_store = core.get_sym_val(name=ENV_VAR_MARK, bits=env_var_size)
        else:
            env_var_size = math.ceil((8 + to_store.length) / 64) * 64

        if to_store is not None:
            # core.add_var(key_str, to_store, need_taint, init=False)

            # get output address
            if self.out_arg is None:
                addr = self.allocate(env_var_size >> 3)
            else:
                addr = self.get_arg_val(self.out_arg)

                # HACK: infer out_arg
                # if not (state.solver.eval(addr) or core.safe_load_str(path, addr)):
                #     self.out_arg = None
                #     addr = self.allocate(env_var_size // 8)

            # store the symbolic buffer at the memory address
            state.memory.store(addr, to_store)

        # mark string
        if not key_absent:
            if self.sanitize_stack_overflow(mark_as_vuln=False):
                self.ret()
                return
            addr_conc = self.core.resolve_val(state, addr)
            self.succ_state.info.mark_strlen(addr_conc, (to_store.length - 8) >> 3)

        if need_taint:
            # taint web handle to automatically follow
            # here we assume opt_first_taint is True
            if self.taint_web_obj and not self.core.taint_applied:
                web_obj = self.get_arg_val(0)
                if web_obj.uninitialized:
                    web_obj_conc = self.allocate(0x100)
                    state.add_constraints(web_obj == web_obj_conc)
                web_obj_mark = core.get_sym_val(name="web_obj", bits=8, taint=True)
                state.memory.store(web_obj, web_obj_mark)
            taint_id = ENV_VAR_MARK + f"_{key_str.decode('utf-8')}"
            taint_var = core.apply_taint(
                path, addr, taint_id, to_store.size(), explicit=True
            )
            core.add_taint_var(taint_var, to_store)
            state.info.rec_input(
                state, data={"type": "kv", "keywords": [key_str.decode("utf-8", "ignore")]}
            )

        # set return value
        if self.ret_none_if_absent and key_absent:
            ret_val = 0
        elif self.ret_type == "ptr" or self.out_arg is None:
            ret_val = addr
        elif self.ret_type == "zero":
            ret_val = -1 if key_absent else 0
        elif self.ret_type == "non-zero":
            ret_val = 0 if key_absent else 1
        else:
            raise ValueError("Invalid ret_type", self.ret_type)

        self.ret(ret_val)
        self._rt_info["keyword"] = key_str
        self._rt_info["absent"] = key_absent
        if to_store is not None:
            self._rt_info["dst_addr"] = addr
        self._rt_info["ret_val"] = ret_val


class cJSON_GetObjectItem(get_env):
    def __init__(self, **kwargs):
        super().__init__(key_arg=1, out_arg=None, ret_type="ptr", **kwargs)
        self.name = "cJSON_GetObjectItem"

    def run(self, **kwargs):
        super().run(**kwargs)

        bits = self.core.p.arch.bits
        if bits == 32:
            obj_size = 36
            off_value_str = 16
            off_value_int = off_value_str + 4
        else:
            obj_size = 64
            off_value_str = 32
            off_value_int = off_value_str + 8

        val_str = self.get_ret_val()

        obj = self.allocate(obj_size)

        # HACK: we just use keyword but don't follow the json structure
        self.core.safe_store_num(self.succ_path, obj + off_value_str, val_str)
        try:
            val_str_conc = self.core.safe_load_str(self.succ_path, val_str)
            value_int = int(val_str_conc)
            self.core.safe_store_num(
                self.succ_path, obj + off_value_int, value_int, n_byte=bits >> 3
            )
        except:
            pass

        self.set_ret_val(obj)
        self._rt_info["ret_val"] = obj


#
# Numerical
#
class atoi(SummarizedFunction):
    def __init__(self, val_size=32, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.val_size = val_size

    def run(self, **kwargs):
        core = self.core
        p = core.p
        path = self.succ_path

        addr = self.get_arg_val(0)
        # tainted = core.is_or_points_to_tainted_data(addr, path)
        # if tainted:
        #     addr = self.succ_state.memory.load(addr, p.arch.bytes)
        #     _core.do_recursive_untaint(addr, plt_path)

        if addr.uninitialized:
            astr = None
        else:
            astr = core.safe_load_str(path, addr)
        try:
            val = int(astr)
            val = claripy.BVV(val, self.val_size)
        except:
            val = claripy.BVS("atoi_ret", self.val_size)

        # Don't taint
        # if tainted:
        #     core.apply_taint_to_reg(path, ret_reg_name(p), "atoi")
        self.ret(val)


#
# Network function
#
class store_payload(SummarizedFunction):
    @property
    def payloads(self):
        return self.succ_state.info.payloads

    def run(self, **kwargs):
        core = self.core
        path = self.succ_path
        state = self.succ_state

        if not self.payloads:
            # core.mark_path(invalid=True)
            return 0
        else:
            payload = self.payloads[-1]

        addr = self.get_addr()  # must called before pop payload
        size = self.get_size()
        payload = self.payloads.pop()
        if len(payload) > size:
            payload, remain = payload[:size], payload[size:]
            self.payloads.append(remain)

        state.memory.store(addr, payload)
        t = core.apply_taint(path, addr, "recv", 8 * len(payload))
        core.add_taint_var(t, payload)

        state.info.rec_input(state, data={"type": "raw"})
        return len(payload)

    def get_addr(self):
        raise NotImplementedError("get_addr")

    def get_size(self):
        raise NotImplementedError("get_size")


class recv(store_payload):
    """Summarize recv function"""

    def __init__(self, val_arg=1, size_arg=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.val_arg = val_arg
        self.size_arg = size_arg

    def get_addr(self):
        state = self.succ_state
        addr = self.get_arg_val(self.val_arg)
        # if addr.uninitialized:
        #     addr = self.allocate(len(self.payloads[-1]) + 1)
        #     self.set_arg_val(self.val_arg, addr)
        return addr

    def get_size(self):
        if self.size_arg is None:
            return 0xFFFFFFFF
        size = self.get_arg_val(self.size_arg)
        return self.core.resolve_val(self.succ_state, size)

    def run(self, **kwargs):
        ret_val = super().run(**kwargs)
        self.ret(ret_val)


class recvfrom(recv):
    """Summarize recvfrom function"""

    def run(self, **kwargs):
        address_addr = self.get_arg_val(4)
        address_len_addr = self.get_arg_val(5)
        self.succ_state.memory.store(
            address_addr, self.core.get_sym_val(name="sockaddr", bits=16 << 3)
        )
        self.core.safe_store_num(self.succ_path, address_len_addr, claripy.BVV(16, 32))
        super().run(**kwargs)


class read(recv):
    """Summarize read function"""

    pass


class accept(SummarizedFunction):
    """Summarize accept"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run(self, **kwargs):
        core = self.core
        path = self.succ_path

        ret_val = 7
        self.ret(ret_val)
        core.apply_taint_to_reg(path, ret_reg_name(core.p), "accept")


class select(SummarizedFunction):
    """Summarize select"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run(self, **kwargs):
        state = self.succ_state
        # we make sure the fd is ready
        nfds = self.get_arg_val(0)
        readfds_ptr = self.get_arg_val(1)
        readfds_ptr_conc = self.core.resolve_val(state, readfds_ptr)
        if readfds_ptr_conc:
            val = claripy.BVV(-1, self.core.p.arch.bits)
            self.core.safe_store_num(self.succ_path, readfds_ptr, val)
        self.ret(1)


class ntohs(SummarizedFunction):
    def run(self, **kwargs):
        core = self.core
        p = core.p

        h = self.get_arg_val(0)

        n_byte = p.arch.bits >> 3
        if p.arch.register_endness == archinfo.Endness.BE:
            ret_val = h
        else:
            ret_val = (h.get_byte(n_byte - 1).zero_extend(8) << 8) | h.get_byte(
                n_byte - 2
            ).zero_extend(8)
            ret_val = ret_val.zero_extend((n_byte - 2) << 3)

        self.ret(ret_val)


class ntohl(SummarizedFunction):
    def run(self, **kwargs):
        core = self.core
        p = core.p

        h = self.get_arg_val(0)

        n_byte = p.arch.bits >> 3
        if p.arch.register_endness == archinfo.Endness.BE:
            ret_val = h
        else:
            ret_val = (
                (h.get_byte(n_byte - 1).zero_extend(24) << 24)
                | (h.get_byte(n_byte - 2).zero_extend(24) << 16)
                | (h.get_byte(n_byte - 3).zero_extend(24) << 8)
                | h.get_byte(n_byte - 4).zero_extend(24)
            )
            ret_val = ret_val.zero_extend((n_byte - 4) << 3)

        self.ret(ret_val)


class htons(ntohs):
    pass


class htonl(ntohl):
    pass


SUM_FS = {
    # memcpy like
    "strcpy": memcpy(sized=False, force_str=True, n_arg=2),
    "strncpy": memcpy(sized=True, force_str=True, n_arg=3),
    "memcpy": memcpy(sized=True, force_str=False, n_arg=3),
    "memmove": memcpy(sized=True, force_str=False, n_arg=3),
    # memcmp like
    "strcmp": memcmp(sized=False, case=False, force_str=True, n_arg=2),
    "strcasecmp": memcmp(sized=False, case=True, force_str=True, n_arg=2),
    "strncasecmp": memcmp(sized=True, case=True, force_str=True, n_arg=3),
    "strncmp": memcmp(sized=True, case=False, force_str=True, n_arg=3),
    "memcmp": memcmp(sized=True, case=False, force_str=False, n_arg=3),
    # format
    "sprintf": fmt_string(fmt_arg=1, size_arg=None, name="sprintf", n_arg=3),
    "snprintf": fmt_string(fmt_arg=2, size_arg=1, name="snprintf", n_arg=4),
    "vsprintf": fmt_string(fmt_arg=1, size_arg=None, name="vsprintf", n_arg=3),
    "vsnprintf": fmt_string(fmt_arg=2, size_arg=1, name="vsnprintf", n_arg=4),
    # string search
    "strstr": str_search(name="strstr", n_arg=2),
    "strcasestr": str_search(name="strcasestr", n_arg=2),
    "strnstr": str_search(name="strnstr", n_arg=3),
    "memmem": str_search(name="memmem", n_arg=3),
    "strchr": str_search(name="strchr", n_arg=2),
    "strrchr": str_search(name="strrchr", n_arg=2),
    "memchr": str_search(name="memchr", n_arg=3),
    "strpbrk": str_search(name="strpbrk", n_arg=2),
    "strspn": str_search(name="strspn", n_arg=2),
    # heap allocate
    "malloc": heap_alloc(sz_idxs=(0,), n_arg=1),
    "realloc": heap_alloc(sz_idxs=(1,), n_arg=2),
    "calloc": heap_alloc(sz_idxs=(0, 1), n_arg=2),
    # sizeof like
    "strlen": sizeof(n_arg=1),
    "sizeof": sizeof(n_arg=1),
    # Env
    "getenv": get_env(0, None, n_arg=3),
    "setenv": set_env(0, 1, n_arg=3),
    "nvram_get": get_env(0, None, n_arg=3),
    "nvram_set": get_env(0, 1, n_arg=3),
    "GetValue": get_env(0, None, n_arg=3),
    "SetValue": set_env(0, 1, n_arg=3),
    "cJSON_GetObjectItem": cJSON_GetObjectItem(n_arg=3),
    # recv
    "recv": recv(n_arg=4),
    "recvfrom": recvfrom(n_arg=4),
    "read": read(n_arg=3),
    # accept
    "accept": accept(n_arg=3),
    # select
    "select": select(n_arg=4),
    # strcat like
    "strcat": strcat(sized=False, n_arg=2),
    "strncat": strcat(sized=True, n_arg=3),
    # ntoh hton
    "ntohs": ntohs(n_arg=1),
    "ntohl": ntohl(n_arg=1),
    "htons": htons(n_arg=1),
    "htonl": htonl(n_arg=1),
    # atoi like
    "atoi": atoi(val_size=32, n_arg=1),
    "atol": atoi(val_size=32, n_arg=1),
    "atoll": atoi(val_size=64, n_arg=1),
    # system like
    "system": system(n_arg=1),
    "_system": system(n_arg=2),
    "__system": system(n_arg=1),
    "doSystem": system(n_arg=1),
    "doSystemCmd": system(n_arg=1),
    "popen": system(n_arg=1),
    "execl": system(inspect_argv=True, n_arg=2),
    "execlp": system(inspect_argv=True, n_arg=2),
    "execle": system(inspect_argv=True, n_arg=2),
    "execv": system(inspect_argv=True, n_arg=2),
    "execvp": system(inspect_argv=True, n_arg=2),
    "execvpe": system(inspect_argv=True, n_arg=2),
}

FORCE_SKIP_FUNCS = [
    "fscanf",
    "scanf",
    "fread",
    "inet_ntoa",
    "printf",
    "puts",
    "fprintf",
    "fputs",
    "fgets",
    "open",
    "openat",
    "fopen",
    "close",
    "fclose",
    "unlink",
]

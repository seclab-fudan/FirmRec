# import angr
import claripy
from angr.procedures.libc.sprintf import sprintf
from angr.procedures.libc.snprintf import snprintf
from angr.procedures.stubs.format_parser import FormatString, SimProcedureError

# from angr.procedures.libc.strlen import strlen
# from angr.procedures.libc.strcmp import strcmp
# from angr.procedures.libc.strncmp import strncmp
# from angr.procedures.libc.memcmp import memcmp


class my_FormatString(FormatString):
    def __init__(self, sf, parser, components):
        super().__init__(parser, components)
        self.sf = sf

    @classmethod
    def copy_from(cls, sf, fmt_str):
        return cls(sf, fmt_str.parser, fmt_str.components)

    def _get_str_at(self, str_addr, max_length=None):
        _, sym = self.sf._core.safe_load_str(
            self.sf._succ_path, str_addr, exact=max_length, symbolic=True
        )
        return sym


class my_sprintf(sprintf):
    def __init__(
        self,
        sf,
        project=None,
        cc=None,
        prototype=None,
        symbolic_return=None,
        returns=None,
        is_syscall=False,
        is_stub=False,
        num_args=None,
        display_name=None,
        library_name=None,
        is_function=None,
        **kwargs
    ):
        self.sf = sf
        super().__init__(
            project,
            cc,
            prototype,
            symbolic_return,
            returns,
            is_syscall,
            is_stub,
            num_args,
            display_name,
            library_name,
            is_function,
            **kwargs
        )

    def run(self, dst_ptr, fmt):
        res = super().run(dst_ptr, fmt)
        return res

    def _parse(self, fmtstr_ptr):
        fmt_str = super()._parse(fmtstr_ptr)
        return my_FormatString.copy_from(self.sf, fmt_str)
    
    def _sim_strlen(self, str_addr):
        length = super()._sim_strlen(str_addr)
        # supress error
        if self.state.solver.symbolic(length):
            return claripy.BVV(0, 32)
        return length


class my_snprintf(snprintf):
    def __init__(
        self,
        sf,
        project=None,
        cc=None,
        prototype=None,
        symbolic_return=None,
        returns=None,
        is_syscall=False,
        is_stub=False,
        num_args=None,
        display_name=None,
        library_name=None,
        is_function=None,
        **kwargs
    ):
        self.sf = sf
        super().__init__(
            project,
            cc,
            prototype,
            symbolic_return,
            returns,
            is_syscall,
            is_stub,
            num_args,
            display_name,
            library_name,
            is_function,
            **kwargs
        )

    def run(self, dst_ptr, size, fmt):  # pylint:disable=arguments-differ,unused-argument
        if self.state.solver.eval(size) == 0:
            return size
        conc_size = self.state.solver.eval(size)

        fmt_str = self._parse(fmt)
        out_str = fmt_str.replace(self.va_arg)

        n_byte = out_str.size() // self.arch.byte_width
        if n_byte > conc_size - 1:
            n_byte = conc_size - 1
            # cut string
            # to_store = out_str[out_str.size() - 1: n_byte * self.arch.byte_width]
            to_store = out_str[0: n_byte * self.arch.byte_width]
        else:
            to_store = out_str
            # place the terminating null byte
        self.state.memory.store(dst_ptr + n_byte, self.state.solver.BVV(0, 8))
        self.state.memory.store(dst_ptr, to_store)

        return out_str.size() // self.arch.byte_width

    def _parse(self, fmtstr_ptr):
        fmt_str = super()._parse(fmtstr_ptr)
        return my_FormatString.copy_from(self.sf, fmt_str)


MAX_ARG_LIST = 3


def simulate_va_args(sf, arg_start):
    va_list = sf.get_arg_val(arg_start)
    n_byte = sf.core.p.arch.bits >> 3
    endness = sf.core.p.arch.memory_endness
    for i in range(MAX_ARG_LIST):
        arg = sf.succ_state.memory.load(va_list + n_byte * i, n_byte, endness=endness)
        sf.set_arg_val(arg_start + i, arg)


class my_vsnprintf(snprintf):
    def __init__(
        self,
        sf,
        project=None,
        cc=None,
        prototype=None,
        symbolic_return=None,
        returns=None,
        is_syscall=False,
        is_stub=False,
        num_args=None,
        display_name=None,
        library_name=None,
        is_function=None,
        **kwargs
    ):
        self.sf = sf
        # this is designed to initialize then call
        simulate_va_args(sf, 3)
        super().__init__(
            project,
            cc,
            prototype,
            symbolic_return,
            returns,
            is_syscall,
            is_stub,
            num_args,
            display_name,
            library_name,
            is_function,
            **kwargs
        )


class my_vsprintf(sprintf):
    def __init__(
        self,
        sf,
        project=None,
        cc=None,
        prototype=None,
        symbolic_return=None,
        returns=None,
        is_syscall=False,
        is_stub=False,
        num_args=None,
        display_name=None,
        library_name=None,
        is_function=None,
        **kwargs
    ):
        self.sf = sf
        # this is designed to initialize then call
        simulate_va_args(sf, 2)
        super().__init__(
            project,
            cc,
            prototype,
            symbolic_return,
            returns,
            is_syscall,
            is_stub,
            num_args,
            display_name,
            library_name,
            is_function,
            **kwargs
        )

    def run(self, dst_ptr, fmt):
        res = super().run(dst_ptr, fmt)
        return res

    def _parse(self, fmtstr_ptr):
        fmt_str = super()._parse(fmtstr_ptr)
        return my_FormatString.copy_from(self.sf, fmt_str)

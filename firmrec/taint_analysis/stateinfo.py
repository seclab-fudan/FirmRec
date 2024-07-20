import enum
import claripy
from dataclasses import dataclass

from angr.state_plugins.plugin import SimStatePlugin

from .utils import get_ret_target, get_concrete_sp, get_ret_val
from .enums import ERStatus


@dataclass
class ER:
    """
    Execution Record
    """

    status: ERStatus
    addr: int
    name: str
    func_addr: int
    func_name: str
    data: dict


class SimStateInfo(SimStatePlugin):
    def __init__(
        self,
        func=[],
        func_sp=[],
        ret_target=[],
        records=[],
        func_bb_counts=[],
        constraints=[],
        heap=[],
        path_merge_info={},
        payloads=[],
        str_lengths={},
        func_states=[],
        taint_related=False,
        in_loop=False,
        white_calls=(),
        black_calls=(),
    ):
        super().__init__()
        self.func = func
        self.func_sp = func_sp
        self.ret_target = ret_target
        self.records = records
        self.func_bb_counts = func_bb_counts
        self.constraints = constraints
        self.heap = heap
        # self.mem = mem
        # self.symbolize_record = symbolize_record
        # self.call_regs = call_regs
        # self.call_list = call_list
        # self.globals = g
        # self.return_value = rv
        # self.exprs = exprs
        self.taint_related = taint_related
        self.path_merge_info = path_merge_info
        self.payloads = payloads
        self.str_lengths = str_lengths

        self.func_states = func_states  # recording calling state
        self.in_loop = in_loop

        self._white_calls = set(white_calls)
        self._black_calls = set(black_calls)

    # def set_state(self, state):
    #     super().set_state(state)

    def clean(self):
        self.func = None
        self.func_sp = None
        self.ret_target = None
        self.records = None
        self.func_bb_counts = None
        self.constraints = None
        self.heap = None
        # self.mem = None
        # self.symbolize_record = None
        # self.call_regs = None
        # self.call_list = None
        # self.globals = None
        # self.return_value = None
        # self.exprs = None
        self.taint_related = None
        self.path_merge_info = None
        self.payloads = None
        self._white_calls = None
        self._black_calls = None

    def get_hit_count(self, state):
        return self.bb_counts.get(state.addr, 0)

    @SimStatePlugin.memo
    def copy(self, memo):  # pylint: disable=unused-argument
        return SimStateInfo(
            func=self.func,  # copy on write
            func_states=self.func_states,  # copy on write
            func_sp=self.func_sp,  # copy on write
            ret_target=self.ret_target,  # copy on write
            records=self.records,  # copy on write
            func_bb_counts=list(dict(x) for x in self.func_bb_counts),
            constraints=self.constraints,  # copy on write
            heap=list(self.heap),
            # mem=dict(self.mem),
            # symbolize_record=dict(self.symbolize_record),
            # call_regs=self.call_regs,
            # call_list=list(self.call_list),
            # g=dict(self.globals),
            # rv=self.return_value,
            # exprs=dict(self.exprs),
            taint_related=self.taint_related,
            in_loop=self.in_loop,
            path_merge_info=dict(self.path_merge_info),
            payloads=list(self.payloads),
            str_lengths=self.str_lengths,  # copy on write
            white_calls=self._white_calls,  # copy on write
            black_calls=self._black_calls,  # copy on write
        )

    @property
    def bb_counts(self):
        """Number of times each basic block is executed"""
        return self.func_bb_counts[-1]

    @property
    def call_depth(self):
        """Depth of call stack"""
        return len(self.func) - 1

    def rec_step(self, state):
        """
        Check and issue a CONSTRAINT execution record
        """
        func_addr, func_name = self.func[-1]
        addr = state.addr
        new_count = self.bb_counts.get(addr, 0) + 1
        self.bb_counts[addr] = new_count
        if self.constraints:
            er = ER(
                ERStatus.CONSTRAINT,
                addr=state.addr,
                name=hex(state.addr),
                func_addr=func_addr,
                func_name=func_name,
                data=dict(constraints=self.constraints),
            )
            self.constraints = []
            self.add_execution_record(er)

    def rec_cons(self, state):
        """
        Record exit constraint for step()
        """
        func_addr, func_name = self.func[-1]

        constraint = state.inspect.exit_guard
        if not constraint.singlevalued:
            self.constraints = self.constraints + [constraint]
        else:
            # Judge whether the constraint is ommited because runtime value is concrete
            look_n = 3
            dep_records = []
            for record in state.info.records[-look_n:]:
                if (
                    record.status == ERStatus.MEM_READ
                    and record.addr >= state.history.addr
                    and record.addr < state.addr
                ):
                    dep_records.append(record)
            if dep_records:
                er = ER(
                    ERStatus.CONS_DEP,
                    addr=state.addr,
                    name=hex(state.addr),
                    func_addr=func_addr,
                    func_name=func_name,
                    data=dict(deps=dep_records),
                )
                self.add_execution_record(er)

    def rec_vuln(self, state, data: dict = None):
        """
        Issue a VULN execution record
        """
        func_addr, func_name = self.func[-1]
        addr = state.history.addr
        name = hex(addr)
        if not data:
            data = dict()
        er = ER(
            status=ERStatus.VULN,
            addr=addr,
            name=name,
            func_addr=func_addr,
            func_name=func_name,
            data=data,
        )
        self.add_execution_record(er)

    def rec_enter(self, state, func_name=None, data=None):
        """
        Issue a funtion ENTER execution record
        """
        if not data:
            data = dict(args=None)
        func_addr = state.addr
        if not func_name:
            func_name = f"FUN_{func_addr:x}"
        self.func = self.func + [(state.addr, func_name)]
        self.func_states = self.func_states + [state]

        sp_value = get_concrete_sp(state)
        if hasattr(state.regs, "lr"):
            ret_target = state.regs.lr
        else:
            ret_target = get_ret_target(state, sp_value)
        self.func_sp = self.func_sp + [sp_value]
        self.ret_target = self.ret_target + [ret_target]

        self.func_bb_counts.append(dict())

        addr = state.history.addr
        if not addr:
            addr = state.addr
            name = "Entry"
        else:
            name = hex(addr)
        er = ER(
            status=ERStatus.ENTER,
            addr=addr,
            name=name,
            func_addr=func_addr,
            func_name=func_name,
            data=data,
        )
        self.add_execution_record(er)

    def rec_leave(self, state):
        """
        Issue a funtion LEAVE execution record
        """
        assert self.func, "Miss match enter and leave"
        func_addr, func_name = self.func[-1]
        addr, name = state.addr, hex(state.addr)
        self.func = self.func[:-1]
        self.func_states = self.func_states[:-1]

        self.func_sp = self.func_sp[:-1]
        self.ret_target = self.ret_target[:-1]
        self.func_bb_counts.pop()
        ret_val = get_ret_val(state)
        er = ER(
            ERStatus.LEAVE,
            addr=addr,
            name=name,
            func_addr=func_addr,
            func_name=func_name,
            data=dict(ret=ret_val),
        )
        self.add_execution_record(er)

    def rec_mem_read(self, state, mem_addr, length, expr, ptr_type):
        """
        Issue a MEM_READ execution record
        """
        func_addr, func_name = self.func[-1]
        addr, name = state.addr, hex(state.addr)
        data = dict(mem_addr=mem_addr, length=length, expr=expr, ptr_type=ptr_type)
        er = ER(
            status=ERStatus.MEM_READ,
            addr=addr,
            name=name,
            func_addr=func_addr,
            func_name=func_name,
            data=data
        )
        self.add_execution_record(er)

    def rec_mem_write(self, state, mem_addr, length, expr, ptr_type):
        """
        Issue a MEM_WRITE execution record
        """
        func_addr, func_name = self.func[-1]
        addr, name = state.addr, hex(state.addr)
        data = dict(mem_addr=mem_addr, length=length, expr=expr, ptr_type=ptr_type)
        er = ER(
            status=ERStatus.MEM_WRITE,
            addr=addr,
            name=name,
            func_addr=func_addr,
            func_name=func_name,
            data=data
        )
        self.add_execution_record(er)

    def rec_input(self, state, data=None):
        """
        Issue a INPUT execution record
        """
        func_addr, func_name = self.func[-1]
        addr, name = state.addr, hex(state.addr)
        if not data:
            data = dict()
        er = ER(
            status=ERStatus.INPUT,
            addr=addr,
            name=name,
            func_addr=func_addr,
            func_name=func_name,
            data=data
        )
        self.add_execution_record(er)

    def add_execution_record(self, er):
        """Add execution record"""
        self.records = self.records + [er]

    def mark_strlen(self, addr, length):
        """Mark a string with length"""
        self.str_lengths = dict(self.str_lengths)
        self.str_lengths[addr] = length

    def unmark_strlen(self, addr):
        """Unmark a string"""
        self.str_lengths = dict(self.str_lengths)
        self.str_lengths.pop(addr, None)

    def get_strlen(self, addr):
        """Get recorded string length"""
        return self.str_lengths.get(addr, None)

    def is_white_call(self, key):
        """Check if address is a white call"""
        return key in self._white_calls

    def is_black_call(self, key):
        """Check if address is a black call"""
        return key in self._black_calls

    def add_white_call(self, key):
        """Add white call address"""
        self._white_calls = set(self._white_calls)
        self._white_calls.add(key)

    def del_white_call(self, key):
        """Delete white call address"""
        if key in self._white_calls:
            self._white_calls = set(self._white_calls)
            self._white_calls.remove(key)

    def add_black_call(self, key):
        """Add black call"""
        self._black_calls = set(self._black_calls)
        self._black_calls.add(key)

    def del_black_call(self, key):
        """Delete black call"""
        if key in self._black_calls:
            self._black_calls = set(self._black_calls)
            self._black_calls.remove(key)

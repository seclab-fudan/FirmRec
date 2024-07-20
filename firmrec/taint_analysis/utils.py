import angr
import claripy
import archinfo

_ordered_argument_regs_names = {
    "ARMEL": [
        "r0",
        "r1",
        "r2",
        "r3",
        "r4",
        "r5",
        "r6",
        "r7",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
    ],
    "AARCH64": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
    "MIPS32": ["a0", "a1", "a2", "a3"],
    "MIPS64": ["a0", "a1", "a2", "a3"],
}

_convention_arg_stack_offset = {
    "ARMEL": 0,
    "AARCH64": 0,
    "MIPS32": 16,
    "MIPS64": 16,
}

_archinfo_by_string = {
    "ARMEL": archinfo.ArchARMEL,
    "AARCH64": archinfo.ArchAArch64,
    "MIPS32": archinfo.ArchMIPS32,
    "MIPS64": archinfo.ArchMIPS64,
}


def arg_reg_num(p):
    return len(_ordered_argument_regs_names[p.arch.name])


def arg_reg_name(p, idx):
    """
    Gets a register name by the argument register index
    :param p: the project
    :param idx: the index of the argument register
    :return: the name of the register
    """
    return _ordered_argument_regs_names[p.arch.name][idx]


def arg_reg_names(p, n=-1):
    """
    Gets the first n argument register names. If n=-1, it will return all argument registers
    :param p: the project
    :param n: the number of elements to retrieve
    :return: the name of the register
    """
    if n < 0:
        return _ordered_argument_regs_names[p.arch.name]
    return _ordered_argument_regs_names[p.arch.name][:n]


def arg_stack_off(p):
    """
    Gets a stack offset for the stack variable of given idx
    :param p: the project
    :param idx: the index of the stack argument
    :return: the offset to sp
    """
    return _convention_arg_stack_offset[p.arch.name]


def arg_reg_off(p, idx):
    """
    Gets a register offset by the argument register index
    :param p: the project
    :param idx: the index of the argument register
    :return: the offset in vex
    """
    return next(
        x.vex_offset for x in p.arch.register_list if x.name == arg_reg_name(p, idx)
    )


def arg_reg_id(p, name):
    """
    Gets an argument register index by the argument register name
    :param p: the project
    :param name: the name of the register
    :return: the index of the register
    """
    return _ordered_argument_regs_names[p.arch.name].index(name)


def arg_reg_id_by_off(p, off):
    """
    Gets an argument register index by the argument register offset
    :param p: the project
    :param off: the offset of the register
    :return: the index of the register
    """
    return arg_reg_id(p, p.arch.register_names[off])


def ret_reg_name(p):
    """
    Returns the name of the return register
    :param p: the project
    :return: the name of the return register
    """
    return p.arch.register_names[p.arch.ret_offset]


def get_arguments_call_with_instruction_address(p, b_addr):
    """
    Retrieves the list of instructions setting arguments for a function call with the corresponding function address.
    It checks the arguments in order so to infer the arity of the function:
    Example: if the first argument (e.g., r0 in ARM) is not set, it assumes the arity's function is 0.
    :param p: angr project
    :param b_addr: basic block address
    :return: a list of (instruction_address and the arguments of a function call)
    """
    set_params = []
    b = p.factory.block(b_addr)
    for reg_name in arg_reg_names(p):
        put_stmts = [
            s
            for s in b.vex.statements
            if s.tag == "Ist_Put" and p.arch.register_names[s.offset] == reg_name
        ]
        if not put_stmts:
            break

        # if more than a write, only consider the last one
        # eg r0 = 5
        # ....
        # r0 = 10
        # BL foo
        put_stmt = put_stmts[-1]
        # find the address of this instruction
        stmt_idx = b.vex.statements.index(put_stmt)
        inst_addr = [x.addr for x in b.vex.statements[:stmt_idx] if hasattr(x, "addr")][
            -1
        ]

        set_params.append((inst_addr, put_stmt))

    return set_params


def get_ord_arguments_call(p, b_addr):
    """
    Retrieves the list of instructions setting arguments for a function call. It checks the arguments in order
    so to infer the arity of the function:
    Example: if the first argument (e.g., r0 in ARM) is not set, it assumes the arity's function is 0.
    :param p: angr project
    :param b_addr: basic block address
    :return: the arguments of a function call
    """
    set_params = []
    b = p.factory.block(b_addr)
    for reg_name in arg_reg_names(p):
        put_stmts = [
            s
            for s in b.vex.statements
            if s.tag == "Ist_Put" and p.arch.register_names[s.offset] == reg_name
        ]
        if not put_stmts:
            break

        # if more than a write, only consider the last one
        # eg r0 = 5
        # ....
        # r0 = 10
        # BL foo
        put_stmt = put_stmts[-1]
        set_params.append(put_stmt)

    return set_params


def get_any_arguments_call(p, b_addr):
    """
    Retrieves the list of instructions setting arguments for a function call.
    :param p: angr project
    :param b_addr: basic block address
    :return: instructions setting arguments
    """
    set_params = []
    b = p.factory.block(b_addr)
    # fix for newer version of angr to only include argument registers
    argument_registers_offset = [
        x.vex_offset for x in p.arch.register_list if x.argument
    ]
    put_stmts = [s for s in b.vex.statements if s.tag == "Ist_Put"]
    for stmt in put_stmts:
        if stmt.offset in argument_registers_offset:
            set_params.append(stmt)
    return set_params


def get_arity(p, b_addr):
    """
    Retrieves the arity by inspecting a funciton call
    :param p: angr project
    :param b_addr: basic block address
    :return: arity of the function
    """
    return len(get_ord_arguments_call(p, b_addr))


def get_ret_target(state, sp_value):
    """Get the return target of a function call."""
    addr_n_byte = state.project.arch.bits >> 3
    ret_target = state.memory.load(
        sp_value - addr_n_byte, addr_n_byte, endness=state.project.arch.memory_endness
    )
    return ret_target


def set_ret_target(state, ret_target):
    """Set the return target of a function call."""
    addr_n_byte = state.project.arch.bits >> 3
    sp_value = get_concrete_sp(state)
    if isinstance(ret_target, claripy.ast.Base):
        ret_target_val = ret_target
    else:
        ret_target_val = state.solver.BVV(ret_target, state.project.arch.bits)
    state.memory.store(
        sp_value - addr_n_byte,
        ret_target_val,
        endness=state.project.arch.memory_endness,
    )


def get_concrete_sp(state):
    """Get the concrete value of the stack pointer."""
    arch = state.project.arch
    sp_reg_name = arch.register_names[arch.sp_offset]
    sp_value = state.reg_concrete(sp_reg_name)
    return sp_value


def get_arg_val(state, arg_idx):
    """Get the value of an argument."""
    p = state.project
    reg_num = arg_reg_num(p)
    if arg_idx < reg_num:
        reg = arg_reg_name(p, arg_idx)
        return getattr(state.regs, reg)
    else:
        stack_reg_idx = arg_idx - reg_num
        sp = state.info.func_sp[-1]
        sp_off = arg_stack_off(p)

        n_byte = p.arch.bits >> 3
        endness = p.arch.memory_endness
        res = state.memory.load(sp + sp_off + stack_reg_idx * n_byte, size=n_byte, endness=endness)
        return res

def set_arg_val(state, arg_idx, val):
    """Set the value of an argument."""
    p = state.project
    reg_num = arg_reg_num(p)
    if arg_idx < reg_num:
        reg = arg_reg_name(p, arg_idx)
        return setattr(state.regs, reg, val)
    else:
        # TODO handle stack arguments
        return False
        # stack_reg_idx = arg_idx - reg_num
        # sp = state.info.func_sp[-1]
        # sp_off = arg_stack_off(p)
        # self.core.safe_store_num(
        #     self.succ_path, sp + sp_off, val, idx=stack_reg_idx
        # )
        # return True

def get_ret_val(state):
    """Get the return value of a function call."""
    p = state.project
    reg = ret_reg_name(p)
    return getattr(state.regs, reg)

def set_ret_val(state, val):
    """Set the return value of a function call."""
    p = state.project
    reg = ret_reg_name(p)
    setattr(state.regs, reg, val)

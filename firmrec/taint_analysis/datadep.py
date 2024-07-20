"""
Infer data dependency graph from execution records.
"""
from __future__ import annotations
import typing

import networkx as nx
import claripy

from .enums import ERStatus, DataDepNodeType, PointerType


if typing.TYPE_CHECKING:
    from .stateinfo import SimStateInfo
    from .coretaint import CoreTaint


class DataDepVar:
    """
    Data dependency node.
    :ivar addr: The address of the function.
    :ivar name: The name of the function.
    :ivar var: The value of the variable.
    """

    def __init__(self, addr, name, var):
        self.addr = addr
        self.name = name
        self.var = var
        self.type = DataDepNodeType.NONE

    @property
    def var_id(self):
        """Identifier of the variable."""
        if self.var.op == "BVS":
            name = self.var.args[0]
            splits = name.rsplit('_', 2)
            for postfix in splits[1:]:
                try:
                    int(postfix)
                except ValueError:
                    return name
            return splits[0]
        return self.var._hash

    @property
    def var_node_id(self):
        """Identifier of the variable."""
        return (self.addr, self.name, self.var_id, self.type)

    def __hash__(self) -> int:
        return hash(self.var_node_id)

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, DataDepVar):
            return False
        return self.var_node_id == __value.var_node_id

    def __str__(self) -> str:
        return f"({self.type.name}({self.addr:#x}, {self.name}, {self.var})"

    def __repr__(self) -> str:
        return str(self)


class DataDepArgVar(DataDepVar):
    """
    Data dependency node for function arguments or return values.
    :ivar arg_idx: The index of the argument. or -1 for return value.
    """

    def __init__(self, addr, name, var, arg_idx):
        super().__init__(addr, name, var)
        self.arg_idx = arg_idx
        if arg_idx >= 0:
            self.type = DataDepNodeType.ARG
        else:
            self.type = DataDepNodeType.RET

    @property
    def var_node_id(self):
        return super().var_node_id + (self.arg_idx,)

    def __str__(self) -> str:
        return f"({self.type.name}({self.addr:#x}, {self.name}, {self.arg_idx}, {self.var})"


class DataDepConsVar(DataDepVar):
    """
    Data dependency node for constraints.
    :ivar constraint: The constraint.
    """

    def __init__(self, addr, name, var, constraint):
        super().__init__(addr, name, var)
        self.type = DataDepNodeType.CONSTRAINT
        self.constraint = constraint

    @property
    def var_node_id(self):
        return super().var_node_id + (self.constraint._hash,)


class DataDepReadVar(DataDepVar):
    """
    Data dependency node for memory read.
    """

    def __init__(self, addr, name, var):
        super().__init__(addr, name, var)
        self.type = DataDepNodeType.READ


class DataDepWriteVar(DataDepVar):
    """
    Data dependency node for memory write.
    """

    def __init__(self, addr, name, var):
        super().__init__(addr, name, var)
        self.type = DataDepNodeType.WRITE


class DataDepUtils:
    """Builder of data dependency graph."""
    
    @classmethod
    def from_states(cls, core: CoreTaint, states: list) -> nx.DiGraph:
        """Analyse the state_info and construct a data dependency graph."""
        ddg = nx.DiGraph()
        for state in states:
            tmp_ddg = cls.from_state(core, state)
            ddg.add_nodes_from(tmp_ddg.nodes)
            ddg.add_edges_from(tmp_ddg.edges)
        return ddg

    @classmethod
    def from_state(cls, core: CoreTaint, state) -> nx.DiGraph:
        """Analyse the state_info and construct a data dependency graph."""
        ddg = nx.DiGraph()
        var_id_map = dict()
        func_args_map = []
        state_info: SimStateInfo = state.info

        def should_add_var(var):
            if not hasattr(var, "symbolic"):
                return False
            if var.symbolic:
                return True
            conc_var = core.resolve_val(state, var)
            return core.get_pointer_type(conc_var) != PointerType.NONE

        def add_var(var_node, check=True, mode="rw"):
            if check and not should_add_var(var_node.var):
                return False
            ddg.add_node(var_node)
            if "r" in mode and var_node.var_id in var_id_map:
                # depend on previous write
                ddg.add_edge(var_id_map[var_node.var_id], var_node)
            if "w" in mode:
                var_id_map[var_node.var_id] = var_node
            return True

        def connect_var_nodes(from_nodes, to_nodes):
            for from_node in from_nodes:
                for to_node in to_nodes:
                    ddg.add_edge(from_node, to_node)

        bits = core.p.arch.bits

        for record_idx, record in enumerate(state_info.records):
            status = record.status
            next_status = state_info.records[record_idx + 1].status if record_idx + 1 < len(state_info.records) else None
            prev_status = state_info.records[record_idx - 1].status if record_idx > 0 else None
            
            if status == ERStatus.ENTER:
                func_args_map.append(set())
                args = record.data.get("args", [])
                if not args:
                    continue
                for arg_idx, arg in enumerate(args):
                    for var in arg.recursive_leaf_asts:
                        var_node = DataDepArgVar(record.addr, record.func_name, var, arg_idx)
                        if add_var(var_node, mode="rw"):
                            func_args_map[-1].add(var_node)
                            break # HACK
                if next_status == ERStatus.LEAVE:
                    # Only connect if we don't follow the function call
                    connect_var_nodes(func_args_map[-1], func_args_map[-1])
            elif status == ERStatus.LEAVE:
                ret = record.data.get("ret", None)
                if ret is None:
                    continue
                for var in ret.recursive_leaf_asts:
                    var_node = DataDepArgVar(record.addr, record.func_name, var, -1)
                    add_var(var_node, mode="w")
                    if prev_status == ERStatus.ENTER:
                        # Only connect if we don't follow the function call
                        connect_var_nodes(func_args_map[-1], [var_node])
                func_args_map.pop()
            elif status == ERStatus.CONSTRAINT:
                for constraint in record.data["constraints"]:
                    for var in constraint.recursive_leaf_asts:
                        var_node = DataDepConsVar(
                            record.addr, record.func_name, var, constraint
                        )
                        add_var(var_node, mode="r")
            elif status == ERStatus.CONS_DEP:
                cons_var_node = DataDepConsVar(
                    record.addr, record.func_name, claripy.true, claripy.true
                )
                add_var(cons_var_node, check=False, mode="r")
                for dep_record in record.data["deps"]:
                    mem_addr = dep_record.data["mem_addr"]
                    var = claripy.BVV(mem_addr, bits)
                    var_node = DataDepReadVar(dep_record.addr, dep_record.func_name, var)
                    add_var(var_node, check=False, mode="r")
                    ddg.add_edge(var_node, cons_var_node)
            elif status == ERStatus.MEM_READ or status == ERStatus.MEM_WRITE:
                mem_addr = record.data["mem_addr"]
                var = claripy.BVV(mem_addr, bits)
                if status == ERStatus.MEM_READ:
                    var_node = DataDepReadVar(record.addr, record.func_name, var)
                    add_var(var_node, check=False, mode="r")
                else:
                    var_node = DataDepWriteVar(record.addr, record.func_name, var)
                    add_var(var_node, check=False, mode="w")
            else:
                continue

        # Only keep components that have edges
        nodes_to_remove = set()
        for component in nx.weakly_connected_components(ddg):
            if len(component) == 1 or not any(
                node.type
                in [
                    DataDepNodeType.RET,
                    DataDepNodeType.ARG,
                ]
                for node in component
            ):
                nodes_to_remove.update(component)
        for node in nodes_to_remove:
            ddg.remove_node(node)
        return ddg

    @classmethod
    def get_relevant_var_nodes(cls, ddg: nx.DiGraph) -> set[DataDepVar]:
        """Get the set of relevant var nodes in the ddg."""
        def update_dep_nodes(node):
            white_list = [DataDepNodeType.ARG, DataDepNodeType.RET]
            relevant_nodes.update(
                [
                    node
                    for node in nx.shortest_path(ddg, target=node)
                    if node.type in white_list
                ]
            )

        relevant_nodes = set()

        leaves = [
            node
            for node in ddg.nodes()
            if node.type == DataDepNodeType.CONSTRAINT
        ]
        for leave in leaves:
            update_dep_nodes(leave)
        # relevant_funcs = {node.name for node in relevant_nodes}
        # dep_nodes = [
        #     node
        #     for node in ddg.nodes()
        #     if node.type in [DataDepNodeType.ARG, DataDepNodeType.RET]
        #     and node.name in relevant_funcs
        # ]
        # for dep_node in dep_nodes:
        #     update_dep_nodes(dep_node)
        return relevant_nodes

    @classmethod
    def save_graph(cls, ddg: nx.DiGraph, path: str):
        """Save the ddg to a file."""
        agraph = nx.nx_agraph.to_agraph(ddg)
        agraph.write(path)

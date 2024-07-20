import re

from claripy.ast.base import Base

from .enums import ERStatus


class PathCallTree:
    """Tree of calling records"""

    def __init__(self) -> None:
        self._enter_record = None
        self._leave_record = None
        self._children = []
        self._vuln_record = None
        self._records = []

    @property
    def records(self):
        """Records"""
        return self._records

    @property
    def rt_info(self):
        """Runtime info"""
        if self._leave_record:
            return self._leave_record.data.get("rt_info", {})
        return {}

    @property
    def children(self):
        """Children"""
        return self._children

    def prety(self) -> str:
        """Pretty print"""
        return str(self)

    def prety_record(self) -> str:
        """Pretty print record"""
        record = self._enter_record
        args = []
        for key, value in self.rt_info.items():
            value_str = str(value)
            if len(value_str) > 20:
                value_str = value_str[:20] + "..."
            args.append(f"{key}={value_str}")
            args.append(", ")
        if args:
            args.pop()
        res = f"{record.func_name}@{record.addr:#x}({''.join(args)})"
        if self._vuln_record:
            res += f" -> {self._vuln_record.data.get('reason', 'Unknown Vuln')}"
        return res

    def __str__(self, level=0):
        ret = "\t" * level + self.prety_record() + "\n"
        for child in self._children:
            ret += child.__str__(level + 1)
        return ret

    @classmethod
    def from_path(cls, path_info):
        """Build call tree from path info"""
        # pylint: disable=protected-access
        node_stack = []
        node = None
        root_node = None
        records = []
        for record in path_info.records:
            if record.status == ERStatus.ENTER:
                node = cls()
                node._enter_record = record
                parent_node = node_stack[-1] if node_stack else None
                if not parent_node:
                    root_node = node
                    root_node._records = records # keep relevant records at root node
                else:
                    parent_node._children.append(node)
                node_stack.append(node)
            elif record.status == ERStatus.LEAVE:
                node = node_stack.pop()
                node._leave_record = record
            elif record.status == ERStatus.VULN:
                node._vuln_record = record
            else:
                continue
            records.append(record)
        return root_node


class PathInfo:
    """
    Information of an executed path
    """

    def __init__(self, state):
        info = state.info
        self.path = list(state.history.bbl_addrs)
        self.path_merge_info = dict(info.path_merge_info)
        self.records = list(info.records)

    def dump(self):
        """
        Dump string of this path
        """
        path_line = f"Path: {[hex(x) for x in self.path]}"
        record_header = "Records:"

        lines = [path_line, record_header]
        for record in self.records:
            lines.append(f"\t{record}")

        return "\n".join(lines)

    @property
    def call_tree(self):
        """
        Get the call tree of this path
        """
        return PathCallTree.from_path(self)

    @property
    def vuln_record(self):
        """
        Get the record of vulnerability
        """
        for record in reversed(self.records):
            if record.status == ERStatus.VULN:
                return record
        return None

    @property
    def key_vars(self):
        """
        Get the key variables that triggering vulnerability
        """
        record = self.vuln_record
        if record is None:
            return None
        vars = record.data["vars"]
        results = []
        for var in vars:
            var_names = self.extract_taint_var_names(var)
            results.extend(var_names)
        return results
    
    @property
    def key_consts(self):
        """
        Get the key constants that mark input entries nearby entries
        """
        results = []
        input_read = False
        for record in self.records:
            if record.status == ERStatus.INPUT:
                input_read = True
                continue
            if not input_read:
                continue
            if record.status != ERStatus.CONSTRAINT:
                continue
            # Extract constants from constraint
            for constraint in record.data['constraints']:
                if constraint.op == '__eq__':
                    for const_idx, taint_idx in ((0, 1), (1, 0)):
                        bv_const = constraint.args[const_idx]
                        bv_taint = constraint.args[taint_idx]
                        if bv_const.op != 'BVV':
                            continue
                        taint_var_names = self.extract_taint_var_names(bv_taint)
                        if not taint_var_names:
                            continue
                        const_val = bv_const.args[0]
                        if self._is_representative_const(const_val):
                            results.append(const_val)
        return results
    
    def get_keywords(self):
        """
        Get all keywords from this path
        """
        results = set()
        for record in self.records:
            if record.status == ERStatus.INPUT:
                results.update(record.data.get("keywords", []))
        return results
                

    @classmethod
    def extract_taint_var_names(cls, bv_var):
        """
        Extract taint variable from binary ninja variable
        """
        var_names = []
        if not isinstance(bv_var, Base):
            return var_names
        needles = ["taint_buf_env_var_", "taint_buf_recv_"]
        for needle in needles:
            for var_name in bv_var.variables:
                if var_name.startswith(needle):
                    name = var_name[len(needle) : -1]
                    if re.match(r"^_\d+_\d+$", name): # ignore suffix like _1_1
                        continue
                    var_names.append(name)
        return var_names

    @classmethod
    def _is_representative_const(cls, const_val: int):
        """
        Whether the constant is representativ
        """
        bit_count = lambda x: bin(x)[2:].count("1")
        if (abs(const_val) <= 0x1000 or bit_count(const_val) < 5 or bit_count(const_val + 1) < 5 or const_val % 100 == 0):
            return False
        return True

# from operations import *
import claripy
import claripy.operations as operations

LITE_REPR = 0
MID_REPR = 1
FULL_REPR = 2


def my_shallow_repr(BV_expr, max_depth=8, explicit_length=False, details=LITE_REPR):
    """
    Returns a string representation of this AST, but with a maximum depth to
    prevent floods of text being printed.
    :param max_depth:           The maximum depth to print.
    :param explicit_length:     Print lengths of BVV arguments.
    :param details:             An integer value specifying how detailed the output should be:
                                    LITE_REPR - print short repr for both operations and BVs,
                                    MID_REPR  - print full repr for operations and short for BVs,
                                    FULL_REPR - print full repr of both operations and BVs.
    :return:                    A string representing the AST
    """
    ast_queue = [(0, iter([BV_expr]))]
    arg_queue = []
    op_queue = []
    while ast_queue:
        try:
            depth, args_iter = ast_queue[-1]
            arg = next(args_iter)
            if not isinstance(arg, claripy.ast.Base):
                arg_queue.append(arg)
                continue
            if max_depth is not None:
                if depth >= max_depth:
                    arg_queue.append("<...>")
                    continue
            if arg.op in operations.reversed_ops:
                op_queue.append(
                    (
                        depth + 1,
                        operations.reversed_ops[arg.op],
                        len(arg.args),
                        arg.length,
                    )
                )
                ast_queue.append((depth + 1, reversed(arg.args)))
            else:
                op_queue.append((depth + 1, arg.op, len(arg.args), arg.length))
                ast_queue.append((depth + 1, iter(arg.args)))
        except StopIteration:
            ast_queue.pop()
            if op_queue:
                depth, op, num_args, length = op_queue.pop()
                args_repr = arg_queue[-num_args:]
                del arg_queue[-num_args:]
                length = length if explicit_length else None
                inner_repr = _op_repr(op, args_repr, depth > 1, length, details)
                arg_queue.append(inner_repr)
    assert len(op_queue) == 0, "op_queue is not empty"
    assert len(ast_queue) == 0, "arg_queue is not empty"
    assert len(arg_queue) == 1, ("repr_queue has unexpected length", len(arg_queue))
    return "{}".format(arg_queue.pop())


def _op_repr(op, args, inner, length, details):
    if details < FULL_REPR:
        if op == "BVS":
            base_without_pad = "_".join(args[0].split("_")[:-2])
            return base_without_pad
        elif op == "BoolV":
            return str(args[0])
        elif op == "BVV":
            if args[0] is None:
                value = "!"
            elif args[1] < 10:
                value = format(args[0], "")
            else:
                value = format(args[0], "#x")
            return value + "#%d" % length if length is not None else value
    if details < MID_REPR:
        if op == "If":
            value = "if {} then {} else {}".format(args[0], args[1], args[2])
            return "({})".format(value) if inner else value
        elif op == "Not":
            return "!{}".format(args[0])
        elif op == "Extract":
            return "{}[{}:{}]".format(args[2], args[0], args[1])
        elif op == "ZeroExt":
            value = "0#{} .. {}".format(args[0], args[1])
            return "({})".format(value) if inner else value
        elif op == "Concat":
            return " .. ".join(map(str, args))
        elif len(args) == 2 and op in operations.infix:
            value = "{} {} {}".format(args[0], operations.infix[op], args[1])
            return "({})".format(value) if inner else value
    return "{}({})".format(op, ", ".join(map(str, args)))

from enum import Enum, auto


class ERStatus(Enum):
    """
    Execution Record status
    """

    ENTER = auto()
    LEAVE = auto()
    CONSTRAINT = auto()
    VULN = auto()
    MEM_READ = auto()
    MEM_WRITE = auto()
    CONS_DEP = auto() # constraint dependency
    INPUT = auto()


class PointerType(Enum):
    """
    Type of pointer
    """

    NONE = auto()  # not a pointer
    HEAP = auto()
    STACK = auto()
    GLOB_DATA = auto()  # data segment
    GLOB_CODE = auto()  # code segment


class PointerValueType(Enum):
    """
    Type of pointer value
    """
    NONE = auto()
    SYM = auto()
    CONST = auto()
    CONST_STR = auto()


class DataDepNodeType(Enum):
    """
    Type of data dependency node
    """
    CONSTRAINT = auto()
    ARG = auto()
    RET = auto()
    READ = auto()
    WRITE = auto()
    NONE = auto()



# __all__ = ["track", "is_func_name", "calc_binary_hash", "get_strings_from_bin", "get_all_files", "is_elf", "is_elf_exe", "is_elf_lib"]

from typing import (
    Callable,
    Iterable,
    List,
    Optional,
    Sequence,
    Union,
)
import os
import stat
import hashlib
from subprocess import check_output, Popen, PIPE

from elftools.elf.elffile import ELFFile, ELFError

from rich.progress import (
    Progress,
    MofNCompleteColumn,
    SpinnerColumn,
    TimeElapsedColumn,
    ProgressType,
    StyleType,
    Console,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
    ProgressColumn,
)


def track(
    sequence: Union[Sequence[ProgressType], Iterable[ProgressType]],
    description: str = "Working...",
    total: Optional[float] = None,
    auto_refresh: bool = True,
    console: Optional[Console] = None,
    transient: bool = False,
    get_time: Optional[Callable[[], float]] = None,
    refresh_per_second: float = 10,
    style: StyleType = "bar.back",
    complete_style: StyleType = "bar.complete",
    finished_style: StyleType = "bar.finished",
    pulse_style: StyleType = "bar.pulse",
    update_period: float = 0.1,
    disable: bool = False,
    show_speed: bool = True,
    extra_columns: Optional[Sequence[ProgressColumn]] = None,
) -> Iterable[ProgressType]:
    """Track progress by iterating over a sequence.

    Args:
        sequence (Iterable[ProgressType]): A sequence (must support "len") you wish to iterate over.
        description (str, optional): Description of task show next to progress bar. Defaults to "Working".
        total: (float, optional): Total number of steps. Default is len(sequence).
        auto_refresh (bool, optional): Automatic refresh, disable to force a refresh after each iteration. Default is True.
        transient: (bool, optional): Clear the progress on exit. Defaults to False.
        console (Console, optional): Console to write to. Default creates internal Console instance.
        refresh_per_second (float): Number of times per second to refresh the progress information. Defaults to 10.
        style (StyleType, optional): Style for the bar background. Defaults to "bar.back".
        complete_style (StyleType, optional): Style for the completed bar. Defaults to "bar.complete".
        finished_style (StyleType, optional): Style for a finished bar. Defaults to "bar.finished".
        pulse_style (StyleType, optional): Style for pulsing bars. Defaults to "bar.pulse".
        update_period (float, optional): Minimum time (in seconds) between calls to update(). Defaults to 0.1.
        disable (bool, optional): Disable display of progress.
        show_speed (bool, optional): Show speed if total isn't known. Defaults to True.
    Returns:
        Iterable[ProgressType]: An iterable of the values in the sequence.

    """

    columns: List["ProgressColumn"] = (
        [SpinnerColumn()] +
        [TextColumn("[progress.description]{task.description}")] if description else []
    )
    columns.extend(
        (
            BarColumn(
                style=style,
                complete_style=complete_style,
                finished_style=finished_style,
                pulse_style=pulse_style,
            ),
            MofNCompleteColumn(),
            TaskProgressColumn(show_speed=show_speed),
            TimeElapsedColumn(),
            TimeRemainingColumn(elapsed_when_finished=True),
        )
    )
    if extra_columns:
        columns.extend(extra_columns)

    progress = Progress(
        *columns,
        auto_refresh=auto_refresh,
        console=console,
        transient=transient,
        get_time=get_time,
        refresh_per_second=refresh_per_second or 10,
        disable=disable,
    )

    with progress:
        yield from progress.track(
            sequence, total=total, description=description, update_period=update_period
        )


def is_func_name(name) -> bool:
    """Check if name is a true function name."""
    return (
        name
        and isinstance(name, str)
        and not name.startswith("FUN_")
        and not name.startswith("thunk_")
        and not name.startswith("sub_")
    )


def calc_binary_hash(binary_path, alg="sha256"):
    """
    Calculate the hash of a binary file.
    :param binary_path: path to the binary file
    :return: hex string hash of the binary file
    """
    buf_size = 65536  # read files in 64kb chunks
    hashalg = hashlib.new(alg)
    with open(binary_path, "rb") as f:
        while True:
            data = f.read(buf_size)
            if not data:
                break
            hashalg.update(data)
    return hashalg.hexdigest()


def get_strings_from_bin(bin_path, min_len=0, allow_space=True):
    """
    Get all strings from binary
    
    :param bin_path: path to binary
    :param min_len: minimum length of string
    :param allow_space: allow space in string
    :return: list of strings
    """
    delim = "======@@======"
    if min_len <= 1:
        len_arg = ""
    else:
        len_arg = f"-n {min_len}"
    strings_res = check_output(
        f"strings -a {len_arg} -w -s '{delim}' '{bin_path}'", shell=True
    )
    strings_res = strings_res.decode("utf-8", errors="ignore")
    all_strings = strings_res.split(delim)
    if allow_space:
        return all_strings
    return [s.strip() for s in all_strings if s.count(" ") == 0]


def find_binaries(fw_path):
    """
    Yields possible binaries within a firmware sample one by one.
    The list might contain false positives, angr will ignore them.

    :param fw_path:  firmware path
    :return: a generator yielding binaries
    """

    cmd = (
        f"find '{fw_path}' -executable -type f -exec file {{}} \; | "
        f"grep -iv image | grep -iv text | awk -F':' '{{print $1}}'"
    )
    p = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)

    for line in p.stdout:
        binary_path = line.strip().decode()
        if binary_path:
            yield binary_path

    p.communicate()


def get_all_files(p):
    """Get all files in a directory recursively
    :param p: path to directory
    :return: list of all regular files' absolute paths
    """
    if os.path.isdir(p):
        results = []
        all_files = os.listdir(p)
        for f in all_files:
            f_path = os.path.join(p, f)
            if os.path.isdir(f_path):
                results += get_all_files(f_path)
            else:
                st_mode = os.stat(f_path).st_mode
                if stat.S_ISREG(st_mode):
                    results.append(f_path)
        return results
    return [p]


def is_elf(bin_path):
    """
    Check if a binary is ELF
    """
    res = False
    try:
        st_mode = os.stat(bin_path).st_mode
        if not stat.S_ISREG(st_mode):
            return False
        with open(bin_path, "rb") as f:
            magic = f.read(4)
            if magic == b"\x7fELF":
                res = True
    except Exception as _: # pylint: disable=broad-except
        res = False
    return res


def is_elf_exe(bin_path):
    """
    Check if a binary is executable ELF
    """
    with open(bin_path, "rb") as binfp:
        try:
            elf = ELFFile(binfp)
            return elf.header['e_type'] == 'ET_EXEC'
        except ELFError:
            return False


def is_elf_lib(bin_path)        :
    """
    Check if a binary is ELF library
    """
    with open(bin_path, "rb") as binfp:
        try:
            elf = ELFFile(binfp)
            return elf.header['e_type'] == 'ET_DYN'
        except ELFError:
            return False

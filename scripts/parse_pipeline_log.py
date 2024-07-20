#!python
import os
import argparse
import re
from dataclasses import dataclass

import yaml


class ParseStatus:
    CMD = 1
    OUT = 2
    ERR = 3
    OTHER = 4


class TimeVerbose(object):
    def __init__(self):
        self._dict = None
        self.signal = 0
        self.modified = False

    @classmethod
    def from_lines(cls, lines):
        tv = cls()
        idx = 0
        for idx, line in enumerate(lines):
            line = line.strip()
            if line.startswith("Command being timed"):
                break
        else:
            return None
        raw = '\n'.join([line.strip() for line in lines[idx:]])
        try:
            tv._dict = yaml.load(raw, yaml.BaseLoader)
        except Exception:
            return None
        return tv

    def _get_value(self, key, parser):
        return parser(self._dict[key])

    def _set_value(self, key, value, formatter=lambda x: x):
        self._dict[key] = formatter(value)

    @property
    def user_time(self):
        return self._get_value("User time (seconds)", float)

    @user_time.setter
    def user_time(self, value):
        self._set_value("User time (seconds)", value)

    @property
    def system_time(self):
        return self._get_value("System time (seconds)", float)

    @system_time.setter
    def system_time(self, value):
        self._set_value("System time (seconds)", value)

    @property
    def cpu_usage(self):
        return self._get_value(
            "Percent of CPU this job got", lambda s: float(s.replace("%", "")) / 100
        )

    @cpu_usage.setter
    def cpu_usage(self, value):
        self._set_value("Percent of CPU this job got", value, lambda v: f"{v*100}%")

    @property
    def real_time(self):
        return self.user_time + self.system_time

    @property
    def time(self):
        return self.real_time * self.cpu_usage  # 误差很小

    @property
    def max_mem(self):
        return self._get_value("Maximum resident set size (kbytes)", int)

    @max_mem.setter
    def max_mem(self, value):
        self._set_value("Maximum resident set size (kbytes)", value)

    def __str__(self) -> str:
        return f"<TimeVerbose> time:{self.time:.1}s mem:{self.max_mem/1024:.1}MB>"

    def __repr__(self) -> str:
        return self.__str__()


@dataclass
class LogEntry:
    start_idx: int
    end_idx: int
    cmd_lines: list
    out_lines: list
    err_lines: list

    @property
    def cmd(self):
        """Command string"""
        return re.sub(r"\s+", " ", " ".join(self.cmd_lines)).strip()

    def __str__(self) -> str:
        return self.cmd

    def __repr__(self) -> str:
        return f"<LogEntry {self.cmd}>"


class LogEntryUtil:
    """Utilities to analyze log entries"""

    @staticmethod
    def is_input_extract_done(entry):
        """If a input extraction is done"""
        line = None
        for line in reversed(entry.out_lines):
            line = line.strip()
            if not line:
                continue
            break
        if line == "Done!":
            return True
        return False

    @staticmethod
    def get_time_tv(entry):
        """Get time from entry"""
        return TimeVerbose.from_lines(entry.err_lines)


class LogParser:
    FINI = "===================================="
    CMD = "CMD: "
    OUT = "OUT: "
    ERR = "ERR: "

    def __init__(self, log_path) -> None:
        self.log_path = log_path
        self.lines = None

        self.cmds = []

        self.prev_idx = -1
        self.curr_idx = 0
        self.succ_idx = 1

        self._status = ParseStatus.OTHER
        self._cmd_lines = []
        self._out_lines = []
        self._err_lines = []
        self._start_idx = 0

        self._entries = []

    @property
    def entries(self):
        return self._entries

    def parse(self):
        """
        Enter main parse loop
        """
        self._load()
        while True:
            if self.curr_idx >= len(self.lines):
                return
            line = self.lines[self.curr_idx]
            if line.startswith(self.FINI):
                self._finish()
                self._status = ParseStatus.OTHER
                continue

            # Detect status
            if line.startswith(self.CMD):
                self._status = ParseStatus.CMD
            elif line.startswith(self.OUT):
                self._status = ParseStatus.OUT
                self._move(self.curr_idx + 1)
                continue
            elif line.startswith(self.ERR):
                self._status = ParseStatus.ERR
                self._move(self.curr_idx + 1)
                continue

            # Parse line
            if self._status == ParseStatus.CMD:
                self._parse_cmd()
            elif self._status == ParseStatus.OUT:
                self._parse_out()
            elif self._status == ParseStatus.ERR:
                self._parse_err()
            else:
                self._move(self.curr_idx + 1)

    def _parse_cmd(self):
        line = self.lines[self.curr_idx]
        if line.startswith(self.CMD):
            line = line[len(self.CMD) :]
        self._cmd_lines.append(line)
        self._move(self.curr_idx + 1)

    def _parse_out(self):
        line = self.lines[self.curr_idx]
        self._out_lines.append(line)
        self._move(self.curr_idx + 1)

    def _parse_err(self):
        line = self.lines[self.curr_idx]
        self._err_lines.append(line)
        self._move(self.curr_idx + 1)

    def _finish(self):
        start_idx = self._start_idx
        end_idx = self.curr_idx
        log_entry = LogEntry(
            start_idx=start_idx,
            end_idx=end_idx,
            cmd_lines=self._cmd_lines,
            out_lines=self._out_lines,
            err_lines=self._err_lines,
        )
        self._entries.append(log_entry)

        self._move(self.curr_idx + 1)

        self._start_idx = self.curr_idx
        self._cmd_lines = []
        self._out_lines = []
        self._err_lines = []

    def _load(self):
        with open(self.log_path, "r", encoding="utf-8") as f:
            self.lines = f.readlines()
        self.prev_idx = -1
        self.curr_idx = 0
        self.succ_idx = 1

    def _move(self, idx, succ_idx=None):
        self.prev_idx = self.curr_idx
        self.curr_idx = idx
        if succ_idx is not None:
            self.succ_idx = succ_idx
        else:
            self.succ_idx = idx + 1
        self.succ_idx = succ_idx


def parse_arg():
    parser = argparse.ArgumentParser()
    parser.add_argument("log", help="Path to the log")
    return parser.parse_args()


def main():
    args = parse_arg()
    log_path = args.log
    log_parser = LogParser(log_path)
    log_parser.parse()
    from IPython import embed

    embed()


if __name__ == "__main__":
    main()

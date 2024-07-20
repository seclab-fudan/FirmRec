#!python
import json
import re
import os
import stat
import sys
from subprocess import check_output, PIPE
import string
import chardet


class KeywordExtractor(object):
    """Base Keyword Extractor"""

    def extract(self, file_path):
        """
        Extract keywords from a file
        """
        assert os.path.isdir(file_path)

        strings = []
        contents = []
        for file_content in self._find_target_content(file_path):
            contents.append(file_content)
            strings.extend(self.extract_from_content(file_content))
        return "\n\n\n".join(contents), strings

    @classmethod
    def extract_from_content(cls, content):
        all_strings = []

        for mat in re.finditer(r"(name|id)=[\"\'](?P<keyword>.+?)[\"\']", content):
            all_strings.append(mat.group("keyword"))

        # content_lines = content.split("\n")

        # for line in content_lines:
        #     all_strings.extend(line.split())
        #     if "name=" in lower_line or "id=" in lower_line:
        #     for mat in re.finditer(r"(name|id)=\s*[\"\'](?P<keyword>.+?)[\"\']", line):
        #         all_strings.append(mat.group("keyword"))
        #     for mat in re.finditer(r"<.*?\{(?P<keyword>[\w\-\.]+?)\}.*?>", line):
        #         all_strings.append(mat.group("keyword"))
        #     for mat in re.finditer(r"(?P<keyword>[\w\-\.]+)=[\'\"]", line):
        #         all_strings.append(mat.group("keyword"))
        #     all_strings.extend(line.split())

        all_strings = list(set(all_strings))

        final_strings = []
        for s in all_strings:
            keyword_s = cls._get_keyword(s)
            if keyword_s and len(keyword_s) > 1:
                final_strings.append(keyword_s)
        return list(set(final_strings))

    @classmethod
    def _find_target_content(cls, dir_path):
        for root, _, files in os.walk(dir_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                st_mode = os.stat(file_path).st_mode
                if not stat.S_ISREG(st_mode):
                    continue
                # Check with suffix will introduce lots of False Negatives
                suffix = file_name.rsplit(".", 1)[-1]
                if suffix in ["js", "xml", "php", "asp", "html", "htm"]:
                    yield cls._read_content(file_path)
                if suffix in ["png", "jpg", "jpeg", "gif", "ico"]:
                    continue
                else:
                    with open(file_path, "rb") as text_fp:
                        print(file_path)
                        content = text_fp.read(200)
                    # skip empty file
                    if not content:
                        continue

                    # judge whether it is a binary file
                    printable_content = [
                        c
                        for c in content
                        if c in string.printable.encode(encoding="utf-8")
                    ]
                    is_binary = len(printable_content) / len(content) < 0.9
                    if is_binary:
                        # try extract from binary
                        front_content = cls._extract_front_content_from_binary(
                            file_path
                        )
                        if front_content:
                            yield front_content
                        continue

                    needles = [b"html>", b"div>", b"script>"]
                    with open(file_path, "rb") as text_fp:
                        full_content = text_fp.read()
                    if any(needle in full_content for needle in needles):
                        yield cls._read_content(file_path)

    @classmethod
    def _extract_front_content_from_binary(cls, bin_path):
        """
        Some front end content may be embedded in binary files.
        We extract then from file
        """
        DELIM = "=============================================="
        strings_res = check_output(
            f"strings -a -n 40 -w -s '{DELIM}' '{bin_path}'", shell=True
        )
        strings_res = strings_res.decode("utf-8", errors="ignore")
        string_lst = []
        for string_candidate in strings_res.split(DELIM):
            stripped = string_candidate.strip()
            if stripped.startswith("<") and stripped.endswith(">"):
                string_lst.append(string_candidate)
        return "\n\n".join(string_lst)

    @classmethod
    def _read_content(cls, file_path):
        with open(file_path, "rb") as js_fp:
            encoding = chardet.detect(js_fp.read())["encoding"]
        with open(file_path, "r", encoding=encoding, errors="ignore") as fp:
            content = fp.read()
        return content

    @classmethod
    def _get_keyword(cls, s):
        char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."
        while len(s) > 0:
            if s[0] not in char_set:
                s = s[1:]
            else:
                break

        while len(s) > 0:
            if s[-1] not in char_set:
                s = s[:-1]
            else:
                break

        for c in s:
            if c not in char_set:
                return ""

        # No letters
        if all([c in "0123456789_-." for c in s]):
            return ""

        try:
            int(s)
            return ""
        except ValueError:
            pass

        return s


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python extract_keywords.py <file_path> <out_path>")
        sys.exit(1)
    file_path = sys.argv[1]
    if len(sys.argv) < 3:
        out_path = ""
    else:
        out_path = sys.argv[2]
    extractor = KeywordExtractor()

    raw_path = out_path + ".raw"
    if out_path and os.path.exists(raw_path):
        with open(raw_path, "r", encoding="utf-8") as raw_file:
            raw = raw_file.read()

        keywords = KeywordExtractor.extract_from_content(raw)

        with open(out_path, "w+", encoding="utf-8") as out_file:
            json.dump(keywords, out_file)
    else:
        raw, keywords = extractor.extract(file_path)
        if out_path:
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            raw_path = out_path + ".raw"

            with open(out_path, "w+", encoding="utf-8") as out_file:
                json.dump(keywords, out_file)

            with open(raw_path, "w+", encoding="utf-8") as out_file:
                out_file.write(raw)
        else:
            json.dump(keywords, sys.stdout)

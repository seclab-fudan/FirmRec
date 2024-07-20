import os

from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection, DynamicSegment
from elftools.elf.sections import SymbolTableSection
from elftools.elf.gnuversions import GNUVerSymSection, GNUVerDefSection, GNUVerNeedSection


class FileFilter:
    def __init__(self, files):
        self.files = files

    def filter(self):
        results = []
        for f in self.files:
            if not os.path.exists(f):
                continue
            if self.file_check(f):
                results.append(f)
        return results

    def file_check(self, f):
        if os.path.isdir(f):
            return False
        return True


class ELFFilter(FileFilter):

    def file_check(self, f):
        fd = os.open(f, os.O_RDONLY)
        info = os.fstat(fd)
        if info.st_size == 0:
            os.close(fd)
            return False
        os.close(fd)

        result = False
        try:
            with open(f, "rb") as f_stream:
                f_content = f_stream.read()
                if f_content.startswith(b"\x7fELF"):
                    result = True
        except OSError as e:
            result = False
        return result


class JNIFilter(FileFilter):

    def __init__(self, files):
        self.files = files
        self.elf_file = None
        self.version_info = None

    def is_executable(self):
        if self.elf_file is None:
            return False
        header = self.elf_file.header
        elf_type = header["e_type"]
        if elf_type == "ET_EXEC":
            return True

        if elf_type == "ET_DYN":
            dynamic = self.elf_file.get_section_by_name('.dynamic')
            if dynamic is None:
                return False
            for t in dynamic.iter_tags('DT_FLAGS_1'):
                if t.entry.d_val & 0x8000000:
                    return True
        return False

    def get_version_info(self):
        version_info = {'versym': None, 'verdef': None,
                             'verneed': None, 'type': None}

        for section in self.elf_file.iter_sections():
            if isinstance(section, GNUVerSymSection):
                version_info['versym'] = section
            elif isinstance(section, GNUVerDefSection):
                version_info['verdef'] = section
            elif isinstance(section, GNUVerNeedSection):
                version_info['verneed'] = section
            elif isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    if tag['d_tag'] == 'DT_VERSYM':
                        version_info['type'] = 'GNU'
                        break
        if not version_info['type'] and (
                version_info['verneed'] or version_info['verdef']):
            version_info['type'] = 'Solaris'

        return version_info

    def symbol_version(self, nsym):
        symbol_version = dict.fromkeys(('index', 'name', 'filename', 'hidden'))

        if (not self.version_info['versym'] or
                nsym >= self.version_info['versym'].num_symbols()):
            return None

        symbol = self.version_info['versym'].get_symbol(nsym)
        index = symbol.entry['ndx']
        if not index in ('VER_NDX_LOCAL', 'VER_NDX_GLOBAL'):
            index = int(index)

            if self.version_info['type'] == 'GNU':
                # In GNU versioning mode, the highest bit is used to
                # store whether the symbol is hidden or not
                if index & 0x8000:
                    index &= ~0x8000
                    symbol_version['hidden'] = True

            if (self.version_info['verdef'] and
                    index <= self.version_info['verdef'].num_versions()):
                _, verdaux_iter = \
                        self.version_info['verdef'].get_version(index)
                symbol_version['name'] = next(verdaux_iter).name
            else:
                verneed, vernaux = \
                        self.version_info['verneed'].get_version(index)
                symbol_version['name'] = vernaux.name
                symbol_version['filename'] = verneed.name

        symbol_version['index'] = index
        return symbol_version

    def get_export_symbols(self):
        if self.elf_file is None:
            return []

        results = []
        self.version_info = self.get_version_info()

        symbol_tables = [(idx, s) for idx, s in enumerate(self.elf_file.iter_sections())
                         if isinstance(s, SymbolTableSection)]

        for section_idx, section in symbol_tables:
            if not isinstance(section, SymbolTableSection):
                continue

            if section["sh_entsize"] == 0:
                continue

            for nsym, symbol in enumerate(section.iter_symbols()):
                symbol_name = symbol.name
                if (symbol['st_info']['type'] == 'STT_SECTION'
                        and symbol['st_shndx'] < self.elf_file.num_sections()
                        and symbol['st_name'] == 0):
                    symbol_name = self.elf_file.get_section(symbol['st_shndx']).name
                results.append(symbol_name)
        return results

    def file_check(self, f):
        with open(f, "rb") as f_stream:
            self.elf_file = ELFFile(f_stream)
            if self.is_executable():
                result = False
            else:
                export_symbols = self.get_export_symbols()
                if ("JNI_OnLoad" in export_symbols or
                        "JNI_OnUnload" in export_symbols):
                    result = True
                else:
                    result = False
                    for tmp_symbol in export_symbols:
                        if (tmp_symbol.startswith("Java_") or
                                tmp_symbol.startswith("JNI_OnLoad_") or
                                tmp_symbol.startswith("JNI_OnUnload_")):
                            result = True
                            break
        return result

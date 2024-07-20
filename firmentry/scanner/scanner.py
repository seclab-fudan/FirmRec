import os
import argparse

from filter import *

black_list = ["ANioNavigation.apk.cache", ".DS_Store"]


def get_files_in(directory):
    results = []
    current_files = os.listdir(directory)
    for tmp_file in current_files:
        if tmp_file in black_list:
            continue
        total_path = os.path.join(directory, tmp_file)
        if os.path.isdir(total_path):
            results += get_files_in(total_path)
        else:
            results.append(total_path)
    return results


def get_path_in(file_name, file_paths):
    for file_path in file_paths:
        if file_path.endswith(file_name):
            return file_path
    return file_name


def scan(directory, detail=True):
    all_files = get_files_in(directory)

    elf_filter = ELFFilter(all_files)
    all_elfs = elf_filter.filter()

    jni_filter = JNIFilter(all_elfs)
    all_jni_libs = jni_filter.filter()

    lib_linkage = {}
    if detail:
        for jni_path in all_jni_libs:
            linkage = get_linkage_libraries(jni_path)
            linkage_paths = [get_path_in(file_name, all_elfs) for file_name in linkage]
            lib_linkage[jni_path] = linkage_paths
    return all_jni_libs, lib_linkage


def get_linkage_libraries(lib):
    dt_needed = []

    with open(lib, "rb") as f:
        elf_file = ELFFile(f)
        for section in elf_file.iter_sections():
            if not isinstance(section, DynamicSection):
                continue

            for tag in section.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    dt_needed.append(tag.needed)

    return dt_needed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    parser.add_argument("--detail", action="store_true")

    args = parser.parse_args()
    scan_directory = args.directory
    if not os.path.exists(scan_directory):
        print(f"The directory {scan_directory} is not exists!")
        return

    # Output the results
    all_jni_libraries, lib_linkage = scan(scan_directory, args.detail)
    for jni_library in all_jni_libraries:
        print(jni_library)
        if jni_library in lib_linkage:
            for linkage_path in lib_linkage[jni_library]:
                print("\t" + linkage_path)


if __name__ == "__main__":
    main()

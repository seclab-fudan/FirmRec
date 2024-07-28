"""
Collect input entries from database and save them to json files.
"""

import os
import json, csv, yaml
import string
import argparse

import psycopg2


FETCH_NAMED_ENTRIES_CMD = """
SELECT
    bin.id AS bin_id,
    bin.hash AS bin_hash,
    bin.vendor AS vendor,
    bin.firmware_id as firmware_id,
    bin.path AS path,
    bin.base_addr AS base_addr,
    input.id AS input_id,
    input.keyword AS keyword,
    to_hex(input.address) AS addr,
    source_func.id AS source_func_id,
    source_func.name AS source_func_name,
    to_hex(source_func.address) AS source_func_addr,
    input.model AS source_func_model,
    caller_func.name AS caller_func_name,
    to_hex(caller_func.address) AS caller_func_addr
FROM input 
    JOIN bin ON input.bin_id = bin.id
    JOIN func AS source_func ON input.api_id = source_func.id
    JOIN func AS caller_func ON input.caller = caller_func.id
"""

FETCH_UNNAMED_ENTRIES_CMD = """
SELECT
    bin.id AS bin_id,
    bin.hash AS bin_hash,
    bin.vendor AS vendor,
    bin.firmware_id as firmware_id,
    bin.path AS path,
    bin.base_addr AS base_addr,
    input.id AS input_id,
    input.keyword AS keyword,
    to_hex(input.address) AS addr,
    source_func.id AS source_func_id,
    source_func.name AS source_func_name,
    to_hex(source_func.address) AS source_func_addr,
    input.model AS source_func_model,
    caller_func.name AS caller_func_name,
    to_hex(caller_func.address) AS caller_func_addr,
    array_agg (
        input_dataflow_const.const
    ) AS constants
FROM input 
    JOIN bin ON input.bin_id = bin.id
    JOIN func AS source_func ON input.api_id = source_func.id
    JOIN func AS caller_func ON input.caller = caller_func.id
    LEFT JOIN input_dataflow_const 
        ON input_dataflow_const.input_id = input.id
WHERE source_func.name in ('recv', 'recvfrom', 'read')
GROUP BY 
    bin.id,
    bin.hash,
    bin.vendor,
    bin.firmware_id,
    bin.path,
    bin.base_addr,
    input.id,
    input.keyword,
    to_hex(input.address),
    source_func.id,
    source_func.name,
    to_hex(source_func.address),
    input.model,
    caller_func.name,
    to_hex(caller_func.address);
"""


def load_unnamed_input_entries(conn, cached_path, force=False):
    """Load unnamed input entries"""
    if not force and os.path.exists(cached_path):
        try:
            with open(cached_path, "r", encoding="utf-8") as cached_fp:
                entries = json.load(cached_fp)
            return entries
        except:
            print(f"Broken {cached_path} .. Reloading")

    cur = conn.cursor()

    # execute sql
    cmd = FETCH_UNNAMED_ENTRIES_CMD
    cur.execute(cmd)
    # get result

    entries = []
    tot = 0
    for _ in range(cur.rowcount):
        row = cur.fetchone()
        entry = dict(zip([col.name for col in cur.description], row))
        tot += 1
        entries.append(entry)
    cur.close()

    print(f"Total unnamed entries: {tot}")
    print(f"Result unnamed entries: {len(entries)}")

    with open(cached_path, "w+", encoding="utf-8") as cached_fp:
        json.dump(entries, cached_fp, indent=2)

    return entries


def load_named_input_entries(conn, cached_path, func_models, force=False):
    """Load named input entries"""
    if not force and os.path.exists(cached_path):
        try:
            with open(cached_path, "r", encoding="utf-8") as cached_fp:
                entries = json.load(cached_fp)
            return entries
        except:
            print(f"Broken {cached_path} .. Reloading")

    cmd = FETCH_NAMED_ENTRIES_CMD
    cur = conn.cursor()
    cur.execute(cmd)
    entries = []

    tot = 0
    for _ in range(cur.rowcount):
        row = cur.fetchone()
        entry = dict(zip([col.name for col in cur.description], row))
        if _is_structure_reading_entry(entry, func_models):
            entries.append(entry)
        tot += 1
    cur.close()

    print(f"Total named entries: {tot}")
    print(f"Result named entries: {len(entries)}")

    with open(cached_path, "w+", encoding="utf-8") as cached_fp:
        json.dump(entries, cached_fp, indent=2)
    return entries


def _is_structure_reading_entry(entry, func_models):
    key = f"{entry['source_func_id']} {entry['source_func_name']}"
    model = func_models.get(key, None)
    if not model:
        return False
    if model["type"] in ["kvset", "unknown", "raw"]:
        return False
    if not model["out_arg"]:
        return False
    return True


def _is_constant_name(word: str):
    return (
        not all(x not in string.ascii_letters for x in word)
        and not any(
            x not in "_-." and x in string.whitespace + string.punctuation for x in word
        )
        and not word.startswith("-")
    )


def load_name_sim_dictionary(
    cached_path, force=False
):  # pylint: disable=unused-argument
    """Load name similarity dictionary"""
    dictionary = dict()

    if os.path.exists(cached_path):
        try:
            with open(cached_path, "r", encoding="utf-8") as fp:
                reader = csv.reader(fp)
                for row in reader:
                    if row[2].lower().startswith("yes"):
                        vuln_name = row[1].lower()
                        name = row[0].lower()
                        if vuln_name not in dictionary:
                            dictionary[vuln_name] = set()
                        dictionary[vuln_name].add(name)
        except:
            print(f"Broken {cached_path}")
            return dictionary

    return dictionary


def _parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("config_path", type=str, help="path to config file")
    parser.add_argument("db_name", type=str, help="database name")
    parser.add_argument("func_model_path", type=str, help="path to function model")
    parser.add_argument("sim_dictionary", type=str, help="path to name similarity dictionary")
    parser.add_argument("named_input_entries", type=str, help="path to named input entries")
    parser.add_argument("unnamed_input_entries", type=str, help="path to unnamed input entries")
    parser.add_argument(
        "--force",
        action="store_true",
        help="force to search new results and overwrite existing ones",
    )

    return parser.parse_args()


def main():
    args = _parse_args()
    
    config_path = args.config_path
    func_model_path = args.func_model_path

    config = yaml.safe_load(open(config_path, "r", encoding="utf-8"))
    conn = psycopg2.connect(
        database=args.db_name,
        user=config["db_user"],
        password=config["db_user_passwd"],
        host="localhost",
        port=5432,
    )

    os.makedirs(os.path.dirname(args.named_input_entries), exist_ok=True)

    named_input_entries_path = args.named_input_entries
    unnamed_input_entries_path = args.unnamed_input_entries
    sim_dictionary_path = args.sim_dictionary

    with open(func_model_path, "r", encoding="utf-8") as fp:
        func_models = json.load(fp)

    load_named_input_entries(
        conn, named_input_entries_path, func_models, force=args.force
    )
    load_unnamed_input_entries(conn, unnamed_input_entries_path, force=args.force)
    load_name_sim_dictionary(sim_dictionary_path, force=args.force)


if __name__ == "__main__":
    main()

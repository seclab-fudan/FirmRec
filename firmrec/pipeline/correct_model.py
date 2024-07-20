"""
This script correct source function model in database
"""
import sys
import os
import json
import re

import yaml

import psycopg2


def maybe_output(arg):
    """Check if argument is output"""
    if not arg:
        return False
    return arg.startswith("[")

def extract_number(arg):
    """Extract number from argument"""
    if not arg or maybe_output(arg):
        return None
    try:
        return int(arg, 10)
    except ValueError:
        return None
    
def extract_string(arg):
    """Extract string from argument"""
    if not arg or maybe_output(arg):
        return None
    if arg.startswith('"'):
        return arg[1:-1]
    return None


def count_api_out_arg_freq(input_data, flow_freq):
    api_arg_freq = {}
    for item in input_data:
        api_id = item["api_id"]
        api_name = item["api_name"]
        key = f"{api_id} {api_name}"

        # out_args = item['model']['out_arg'] # Not use this
        key_arg = item["model"]["key_arg"]
        args = item["model"]["args"]
        arg_freq = api_arg_freq.get(key, {"total": 0})
        api_arg_freq[key] = arg_freq

        ret_out_reg = -1
        if ret_out_reg in flow_freq.get(api_id, {}):
            if ret_out_reg not in arg_freq:
                arg_freq[ret_out_reg] = 0
            arg_freq[ret_out_reg] += 1

        arg_freq["total"] += 1
        for arg_idx, arg in enumerate(args):
            if arg_idx <= key_arg:
                continue
            if maybe_output(arg):
                if arg_idx not in arg_freq:
                    arg_freq[arg_idx] = 0
                arg_freq[arg_idx] += 1

        # for arg in out_args:
        #     if arg not in arg_freq:
        #         arg_freq[arg] = 0
        #     arg_freq[arg] += 1
    return api_arg_freq


def count_api_size_arg_freq(input_data):
    api_arg_freq = {}
    for item in input_data:
        api_id = item["api_id"]
        api_name = item["api_name"]
        key = f"{api_id} {api_name}"

        args = item["model"]["args"]
        arg_freq = api_arg_freq.get(key, {"total": 0})
        api_arg_freq[key] = arg_freq

        arg_freq["total"] += 1
        for arg_idx, arg in enumerate(args):
            if arg.startswith('"'):
                continue
            try:
                size = int(arg, 10)
                if size >= 4 and size <= 0x8000:
                    if arg_idx not in arg_freq:
                        arg_freq[arg_idx] = 0
                    arg_freq[arg_idx] += 1
            except ValueError:
                pass
    return api_arg_freq


def is_get_api(api_name):
    for mat in re.finditer(r"(get|Get|read|Read)", api_name):
        return True
    return False


def infer_get_api(set_api_name):
    """Infer Get API name from Set API name
    :param set_api_name: Set API name
    :return: If infer successfully, return Get API name,
        otherwise return None
    """
    for mat in re.finditer(r"(set|Set|write|Write)", set_api_name):
        start = mat.start()
        end = mat.end()
        set_needle = mat.group(0)
        if start > 0 and set_api_name[start - 1] != "_":
            if start == 1:
                continue
            # unset
            if start > 1 and set_api_name[mat.start() - 2 : start].lower() == "un":
                continue
        elif start == 0:
            pass
        else:
            set_needle = "_" + set_needle
        if end < len(set_api_name) - 1 and set_api_name[end] == "_":
            set_needle = set_needle + "_"
        # setup and setting
        if end < len(set_api_name) - 2:
            next2 = set_api_name[end : end + 2].lower()
            if next2 == "up" or next2 == "ti":
                continue
        break
    else:
        return None
    get_needle = (
        set_needle.replace("set", "get")
        .replace("Set", "Get")
        .replace("write", "read")
        .replace("Write", "Read")
    )
    get_api_name = set_api_name.replace(set_needle, get_needle)
    return get_api_name


def fetch_input_info(conn):
    # Fetch inputs from database
    cursor = conn.cursor()
    cursor.execute(
        """
    SELECT 
        input.id AS id,
        input.api_id AS api_id,
        api.name AS api_name,
        model AS model
    FROM input
        JOIN func AS api
        ON api.id = input.api_id 
    """
    )
    inputs = []
    common_model = {}
    for res in cursor.fetchall():
        model = json.loads(res[3])
        if "args" in model and isinstance(model["args"], (str, bytes)):
            model["args"] = json.loads(model["args"])
        inputs.append(
            {"id": res[0], "api_id": res[1], "api_name": res[2], "model": model}
        )
        key = f"{res[1]} {res[2]}"
        if key not in common_model:
            common_model[key] = {
                k: v for k, v in model.items() if k != "out_arg" and k != "args"
            }
    cursor.close()
    return inputs, common_model


def count_arg_ret_flow_freq(conn):
    cursor = conn.cursor()
    cursor.execute(
        """
    SELECT
        input_id,
        api.id AS api_id,
        input_dataflow_call.arg AS arg
    FROM input_dataflow_call
        JOIN input ON input_dataflow_call.input_id = input.id
        JOIN func AS api ON input.api_id = api.id
    ;
    """
    )
    freq_count = {}
    for res in cursor.fetchall():
        input_id = res[0]
        api_id = res[1]
        arg_idx = res[2]
        if api_id not in freq_count:
            freq_count[api_id] = {}
        if arg_idx not in freq_count[api_id]:
            freq_count[api_id][arg_idx] = set()
        freq_count[api_id][arg_idx].add(input_id)

    for arg_count in freq_count.values():
        for arg_idx in arg_count:
            arg_count[arg_idx] = len(arg_count[arg_idx])
    return freq_count


def infer_set_get_chain(api_names, func_models, conn):
    get_set_pairs = {}
    for set_api_name in api_names:
        get_api_name = infer_get_api(set_api_name)
        if not get_api_name:
            continue
        if get_api_name not in api_names:
            continue
        get_set_pairs[get_api_name] = set_api_name
    for get_api_name in api_names:
        if not is_get_api(get_api_name):
            continue
        if get_api_name not in get_set_pairs:
            # Find set api name with fuzzy matching
            for sim_get_api_name, sim_set_api_name in get_set_pairs.items():
                if get_api_name in sim_get_api_name or sim_get_api_name in get_api_name:
                    get_set_pairs[get_api_name] = sim_set_api_name
                    break

    print(f"{len(get_set_pairs)} possible get-set name pairs")
    if not get_set_pairs:
        return {}
    cmd_flow = """
    SELECT firmware_id, path, set_api.name AS set_api, 
        source_api.name AS source_api,
        source_api.id AS source_api_id, 
        source_api.address AS source_api_addr,
        input.keyword AS source_keyword,
        input_dataflow_call.func_args AS func_args
    FROM input_dataflow_call
        JOIN input
        ON input.id = input_id
        JOIN bin
        ON input.bin_id = bin.id
        JOIN func AS set_api
        ON set_api.id = input_dataflow_call.func_id
        JOIN func AS source_api
        ON source_api.id = input.api_id
    WHERE 
        set_api.name IN %s
        AND type = 'flow'
    ;
    """
    cmd_from = """
    SELECT firmware_id, path, set_api.name AS set_api, 
        source_api.name AS source_api,
        source_api.id AS source_api_id, 
        source_api.address AS source_api_addr,
        input.keyword AS source_keyword,
        input_dataflow_call.func_args AS func_args
    FROM input_dataflow_call
        JOIN input
        ON input.id = input_id
        JOIN bin
        ON input.bin_id = bin.id
        JOIN func AS set_api
        ON set_api.id = input.api_id
        JOIN func AS source_api
        ON source_api.id = input_dataflow_call.func_id
    WHERE 
        set_api.name IN %s
        AND type = 'from'
    ;
    """
    cur = conn.cursor()
    cur.execute(cmd_flow, (tuple(get_set_pairs.values()),))
    cur.execute(cmd_from, (tuple(get_set_pairs.values()),))
    chains = []
    for res in cur.fetchall():
        chains.append(
            {
                "firmware_id": res[0],
                "path": res[1],
                "set_api": res[2],
                "source_api": res[3],
                "source_api_id": res[4],
                "source_api_addr": res[5],
                "source_keyword": res[6],
                "func_args": res[7],
            }
        )
    cur.close()
    print(f"{len(chains)} DB results from input_dataflow_call")

    chain_results = {}
    for chain in chains:
        key = f"{chain['source_api_id']} {chain['source_api']}"
        if key not in func_models or func_models[key]["type"] != "kv":
            continue
        # infer get keywords
        target_keywords = []
        args = json.loads(chain["func_args"])
        for arg in args:
            keyword = extract_string(arg)
            if keyword is None:
                continue
            target_keywords.append(keyword)
        if not target_keywords:
            target_keywords = [""]

        firmware_id = chain["firmware_id"]  # firmware scope
        if firmware_id not in chain_results:
            chain_results[firmware_id] = {}
        for set_keyword in target_keywords:
            if set_keyword not in chain_results[firmware_id]:
                chain_results[firmware_id][set_keyword] = []
            chain_results[firmware_id][set_keyword].append(chain)
    return chain_results


def infer_models(common_model, api_arg_freq):
    api_out_arg_freq = api_arg_freq["out"]
    api_size_arg_freq = api_arg_freq["size"]
    results = {}
    non_handled_funcs = set()
    for key in api_out_arg_freq:
        out_freq_res = api_out_arg_freq[key]
        size_freq_res = api_size_arg_freq[key]
        api_name = key.split(" ", 1)[-1]
        results[key] = model = dict(common_model[key])
        model["out_arg"] = []
        if len(out_freq_res) - 1 > 4 or len(out_freq_res) == 1:
            model["type"] = "unknown"
            continue

        if model["key_arg"] >= 4:
            # This is unlikely to be kv function
            model["type"] = "unknown"
            continue
        
        if api_name.endswith("get_int"):
            model["type"] = "unknown"
            model["out_arg"] = [model["key_arg"] + 1]
            continue

        # name based classification
        if re.findall(
            r"[lL]og|[pP]rint|strdup|strcpy|[Ee]rror|[Dd]ebug|[iI]nit|open|exec|system",
            api_name,
        ):
            model["type"] = "unknown"
            continue
        get_api_name = infer_get_api(api_name)
        if get_api_name:
            model["type"] = "kvset"
            model["out_arg"] = [model["key_arg"] + 1]
            continue
        # elif re.findall(r"set|Set", api_name):
        #     model["type"] = "unknown"
        #     continue

        if not api_name.startswith("FUN_"):
            non_handled_funcs.add(api_name)

        for arg, freq in out_freq_res.items():
            if arg == "total":
                continue
            if isinstance(arg, str):
                arg_idx = int(arg)
            else:
                arg_idx = arg
            if arg_idx >= 0 and arg_idx <= model["key_arg"]:
                continue
            if freq > 0.1 * out_freq_res["total"]:
                model["out_arg"].append(arg_idx)

        if api_name in [
            "nvram_get",
            "websGetVar",
            "acosNvramConfig_get",
            "getenv",
            "find_val",
        ]:
            if not model["out_arg"]:
                model["out_arg"] = [-1]

        if not model["out_arg"]:
            model["type"] = "unknown"

        # infer size
        for arg, freq in size_freq_res.items():
            if arg == "total":
                continue
            if freq > 0.9 * size_freq_res["total"]:
                model["size_arg"] = arg
                break

    return results


def main():
    if len(sys.argv) < 4:
        print("Usage: python correct_model.py <config_path> <db_name> <output_path>")
        sys.exit(1)
    config_path = sys.argv[1]
    config = yaml.safe_load(open(config_path, "r", encoding="utf-8"))
    db_user = config["db_user"]
    db_user_passwd = config["db_user_passwd"]

    db_name = sys.argv[2]
    output_path = sys.argv[3]
    freq_output_path = output_path.rsplit(".", 1)[0] + ".freq.json"
    chain_output_path = output_path.rsplit(".", 1)[0] + ".chain.json"

    conn = psycopg2.connect(
        database=db_name,
        user=db_user,
        password=db_user_passwd,
        host="localhost",
        port=5432,
    )

    dir_name = os.path.dirname(output_path)
    os.makedirs(dir_name, exist_ok=True)

    inputs, common_model = fetch_input_info(conn)
    flow_freq = count_arg_ret_flow_freq(conn)

    api_out_arg_freq = count_api_out_arg_freq(inputs, flow_freq)
    api_size_arg_freq = count_api_size_arg_freq(inputs)
    api_arg_freq = {"out": api_out_arg_freq, "size": api_size_arg_freq}
    with open(freq_output_path, "w+", encoding="utf-8") as freq_outf:
        json.dump(api_arg_freq, freq_outf, indent=4)

    func_models = infer_models(common_model, api_arg_freq)

    with open(output_path, "w+", encoding="utf-8") as outf:
        json.dump(func_models, outf, indent=2, ensure_ascii=False)

    # with open(output_path, "r", encoding='utf-8') as f:
    #     func_models = json.load(f)
    # with open(freq_output_path, "r", encoding='utf-8') as f:
    #     api_arg_freq = json.load(f)

    api_names = {key.split(" ", 1)[1] for key in api_out_arg_freq}
    chain_results = infer_set_get_chain(api_names, func_models, conn)
    with open(chain_output_path, "w", encoding="utf-8") as chain_outf:
        json.dump(chain_results, chain_outf, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()

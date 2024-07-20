"""
Find similar variables using ChatGPT.
"""

import os
import json
import csv
from argparse import ArgumentParser
from multiprocessing import Pool

import requests
import yaml
from rich.progress import track

from firmrec.pipeline.search import KeywordHiearchyTree


class CallAPIException(Exception):
    pass


LLM_CONFIG = {
    "url": "https://api.openai.com/v1/chat/completions",
    "model": "gpt-3.5-turbo",
    "key": os.getenv("OPENAI_API_KEY", ""),
}


def call_api(prompt, max_tokens=1000, temperature=1.0, timeout=60):
    """Call the OpenAI API."""
    payload = {
        "model": LLM_CONFIG["model"],
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {LLM_CONFIG['key']}",
    }

    response = requests.post(
        LLM_CONFIG["url"],
        headers=headers,
        data=json.dumps(payload),
        proxies=None,
        timeout=timeout,
    )
    resp = response.json()
    if "choices" not in resp:
        print(resp)
        raise CallAPIException()
    # print(resp)
    return resp


def get_resp_message(resp):
    """Get the response message."""
    choice = resp["choices"][0]
    finish_reason = choice["finish_reason"]
    message = choice["message"]["content"]
    return finish_reason, message


def app_denotation(word):
    prompt = (
        "Given a variable name in IoT code, segment words from the name, and look up words that can replace the segmented words while reserving variable meanings."
        + " Results include the original segmented words, synonym words, and abbreviations."
        + " Each line of the answer contain only one word without space/punctuation and"
        + " can not be further segmented to sub-words,"
        + " e.g., `downloadServerip` -> ```download\nobtain\nserver\nip\naddr\naddress```"
        + f"\nVariable name: {word}"
    )

    resp = call_api(prompt, max_tokens=None, temperature=0.7)
    _, message = get_resp_message(resp)
    words = []
    for line in message.split("\n"):
        line = line.strip()
        if not line or "(" in line:
            continue
        words.append(line)

    return words


def app_classifier(word1, word2):
    """Similarity-based input entry identification."""
    prompt = (
        "Infer whether two variables from IoT software may satisfy both requirements:"
        + " 1) have similar denotation word; 2) may convey similar data formats.\n"
        + " The answer is `Yes` or `No`:\n"
        + f"'{word1}' '{word2}'"
    )

    resp = call_api(prompt, max_tokens=10, temperature=0)
    finish_reason, message = get_resp_message(resp)
    if finish_reason == "stop":
        return message
    else:
        return "Error"


def execute_one(pair):
    word1, word2 = pair
    try:
        res = app_classifier(word1, word2)
    except Exception:
        return None
    return word1, word2, res


def gen_task_pairs(target_keywords, vuln_denotation_words_path, pairs_path):

    with open(vuln_denotation_words_path, "r", encoding="utf-8") as f:
        vuln_denotation_words = json.load(f)

    def potential_match(keyword, word):
        if not isinstance(keyword, str) and not isinstance(keyword, bytes):
            print(f"{keyword} type {type(keyword)}")
            return False
        for token in KeywordHiearchyTree(keyword).tokens:
            if token.lower().startswith(word.lower()) or token.lower().endswith(
                word.lower()
            ):
                return True
        return False

    with open(pairs_path, "w+", encoding="utf-8") as f:
        csv_writer = csv.writer(f)
        for keyword in target_keywords:
            for vuln_keyword, repl_words in vuln_denotation_words.items():
                for word in repl_words:
                    if potential_match(keyword, word):
                        csv_writer.writerow([keyword, vuln_keyword])


def get_vuln_keywords(sig_dir):
    vuln_keywords = set()
    for file_name in os.listdir(sig_dir):
        if not file_name.endswith(".json"):
            continue
        with open(os.path.join(sig_dir, file_name), "r", encoding="utf-8") as f:
            sig = json.load(f)

        if not sig or "entry_info" not in sig:
            continue

        for key_var in sig["entry_info"].get("key_vars", []):
            vuln_keywords.add(key_var)

    return vuln_keywords


def get_target_keywords(entry_path):
    with open(entry_path, "r", encoding="utf-8") as f:
        entries = json.load(f)

    keywords = set()
    for entry in entries:
        keyword = entry["keyword"]
        keywords.add(keyword)
    return keywords


def get_vuln_denotation_words(vuln_keywords, vuln_denotation_words_path):
    vuln_keyword_to_repls = {}
    for vuln_keyword in vuln_keywords:
        repl_words = app_denotation(vuln_keyword)
        repl_words = sorted({x.lower() for x in repl_words})
        print(vuln_keyword, repl_words)
        vuln_keyword_to_repls[vuln_keyword] = repl_words

    with open(vuln_denotation_words_path, "w+", encoding="utf-8") as f:
        json.dump(vuln_keyword_to_repls, f, indent=2)

    return vuln_keyword_to_repls


def find_sim_pairs(pairs_path, pair_results_path):
    # It takes 2629270 CPU seconds to analyze 123287 pairs
    with open(pairs_path, "r", encoding="utf-8") as f:
        csv_reader = csv.reader(f)
        pairs = {(row[0], row[1]) for row in csv_reader}

    visited_pairs = set()
    if os.path.exists(pair_results_path):
        with open(pair_results_path, "r", encoding="utf-8") as f:
            csv_reader = csv.reader(f)
            for row in csv_reader:
                visited_pairs.add((row[0], row[1]))

    to_visited_pairs = list(pairs - visited_pairs)

    f = open(pair_results_path, "a+", encoding="utf-8")
    csv_writer = csv.writer(f)

    pool = Pool(4)
    count = 0
    for res in track(
        pool.imap_unordered(execute_one, to_visited_pairs),
        total=len(to_visited_pairs),
    ):
        count += 1
        if not res:
            continue
        word1, word2, ans = res
        csv_writer.writerow([word1, word2, ans])
        f.flush()


def _parse_args():
    parser = ArgumentParser()
    parser.add_argument("config", help="Configuration path")
    parser.add_argument("sig_dir", help="Directory to signatures")
    parser.add_argument("entry_path", help="Path to named input entries")
    parser.add_argument("tmp_dir", help="Internal result directory")
    parser.add_argument("out_path", help="Path to output dictionary file")
    parser.add_argument("--force", action="store_true", help="Force to overwrite")

    args = parser.parse_args()

    config = yaml.safe_load(open(args.config, "r", encoding="utf-8"))
    LLM_CONFIG["url"] = config["llm_url"]
    LLM_CONFIG["model"] = config["llm_model"]
    LLM_CONFIG["key"] = config["llm_key"]

    return args


def _main():
    args = _parse_args()

    os.makedirs(args.tmp_dir, exist_ok=True)
    os.makedirs(os.path.dirname(args.out_path), exist_ok=True)

    if (
        not args.force
        and os.path.exists(args.out_path)
        and os.path.getsize(args.out_path) > 0
    ):
        print(f"Output file {args.out_path} exists, use --force to overwrite")
        return

    vuln_keywords = get_vuln_keywords(args.sig_dir)
    print(f"Found {len(vuln_keywords)} vuln keywords")
    target_keywords = get_target_keywords(args.entry_path)
    print(f"Found {len(target_keywords)} target keywords")

    denotation_word_path = os.path.join(args.tmp_dir, "vuln_denotation_words.json")
    if (
        args.force
        or not os.path.exists(denotation_word_path)
        or not os.path.getsize(denotation_word_path)
    ):
        get_vuln_denotation_words(vuln_keywords, denotation_word_path)

    task_pairs_path = os.path.join(args.tmp_dir, "pairs.csv")
    gen_task_pairs(target_keywords, denotation_word_path, task_pairs_path)

    find_sim_pairs(
        task_pairs_path,
        args.out_path,
    )


if __name__ == "__main__":
    _main()

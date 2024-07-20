#!python
import sys
import os
import re
import json
from urllib.parse import parse_qs

# TODO: use pattern matching from VulnReportAnalyzer

POC_INFO_DIR = os.environ.get("POC_INFO_DIR", "poc_info")


def parse_http_request(data):
    lines = data.splitlines()

    head_line = lines[0]

    try:
        empty_idx = lines.index("")
        headers_end_idx = empty_idx
    except:
        headers_end_idx = len(lines)

    headers = {}
    try:
        for line in lines[1:headers_end_idx]:
            k, v = line.split(": ", 1)
            headers[k] = v
    except:
        headers_end_idx = 0

    payloads = {}
    for line in lines[headers_end_idx + 1 :]:
        payloads |= parse_qs(line)
    for k in payloads:
        if len(payloads[k]) > 1:
            print(f"Warning: multiple values mapped to {k}, use the first one")
    payloads = {k: payloads[k][0] for k in payloads}

    return head_line, headers, payloads


def process(data, brand, vuln_name, ext):
    head_line, headers, payloads = parse_http_request(data)
    json.dump((head_line, headers, payloads), sys.stdout, indent=4)

    keywords = list(payloads.keys())
    key_keywords = [k for k in keywords if len(payloads[k]) > 48]
    try:
        url_keywords = [k for k in head_line.split()[1].split("/") if k]
    except:
        url_keywords = []
    poc_info = {
        "keywords": keywords,
        "key_keywords": key_keywords,
        "url_keywords": url_keywords,
        "input": {
            "kv": payloads,
        },
    }
    print()
    json.dump(poc_info, sys.stdout, indent=4)

    # TODO read from config
    brand_path = os.path.join(POC_INFO_DIR, brand)
    os.makedirs(brand_path, exist_ok=True)
    dst_path = os.path.join(brand_path, f"{vuln_name}{ext}.json")
    if os.path.exists(dst_path):
        print("\nWarning: ", dst_path, "Exists")
        return
    with open(dst_path, "w+") as fp:
        json.dump(poc_info, fp, indent=4)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} INPUT")
        sys.exit(1)

    file_path = sys.argv[1]
    vendor_map = {
        "D-Link": "dlink",
        "FAST": "fast",
        "MERCURY": "mercury",
        "Netgear": "netgear",
        "Ricoh": "ricoh",
        "SonicWall": "sonic",
        "TP-Link": "tp-link",
        "Tenda": "tenda",
        "Xerox": "xerox",
    }
    for name in vendor_map:
        if name in file_path:
            brand = vendor_map[name]
            break
    else:
        brand = "unknown"
    with open(file_path, "r") as fp:
        data = fp.read()
    vuln_name = os.path.basename(os.path.dirname(file_path))
    base_name = os.path.basename(file_path)
    if base_name == "poc.bp" or base_name == "poc.rb":
        ext = ""
    elif base_name == "poc1.bp" or base_name == "poc1.rb":
        ext = ".1"
    elif base_name == "poc2.bp" or base_name == "poc2.rb":
        ext = ".2"
    else:
        assert False, base_name
    process(data, brand, vuln_name, ext)


if __name__ == "__main__":
    main()

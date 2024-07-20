import os
import hashlib
import itertools
import json
from dataclasses import dataclass

import psycopg2
from firmlib import calc_binary_hash

from ..models.result import ResultKey


@dataclass
class BinInfo:
    """
    Key of result
    """

    bin_path: str
    bin_hash: str
    target_keys: list[ResultKey]
    db_brand: dict
    db_image: dict
    db_product: dict


class BinAnalyzer:
    """
    Get binary statistics information
    """

    def __init__(self):
        self.database = psycopg2.connect(
            database="firmware",
            user="firmadyne",
            password="firmadyne",
            host="127.0.0.1",
            port=5432,
        )

    def statistic(self, output, opt_uniq_funcs=False):
        bin_infos = []

        vendors = set()
        vuln_bin_dir = os.path.join(output, "vuln_bins")
        if not os.path.isdir(vuln_bin_dir):
            print("Run `collect --collect-vuln-bins` first")
            return
        for vendor in os.listdir(vuln_bin_dir):
            if "." in vendor:
                continue
            vendors.add(vendor)
            vendor_vuln_bin_dir = os.path.join(vuln_bin_dir, vendor)
            bin_infos += self.query_all(vendor_vuln_bin_dir)

        firmwares = self._group_bin_infos(
            bin_infos, lambda bin_info: bin_info.db_image["hash"]
        )
        hashes = self._group_bin_infos(bin_infos, lambda bin_info: bin_info.bin_hash)
        products = self._group_bin_infos(
            bin_infos, lambda bin_info: bin_info.db_product["product"]
        )
        target_keys = sum([bin_info.target_keys for bin_info in bin_infos], start=[])
        if opt_uniq_funcs:
            func_hashes = {}
            for bin_hash, bin_info in hashes.items():
                for key in bin_info.target_keys:
                    cmd = f"r2 -qq -c 's {key.entry_addr}; af; pxj $FE-$FB' {bin_info.bin_path}"
                    func_bytes = eval(os.popen(cmd).read().strip())
                    hash_obj = hashlib.sha256()
                    hash_obj.update(bytes(func_bytes))
                    func_hash = hash_obj.hexdigest()
                    func_hashes[func_hash] = (bin_hash, key)

        print(f"{len(bin_infos)} binaries are collected")
        print("#Vendors         :", len(vendors))
        print("#Bins            :", len(bin_infos))
        print("#Firmware        :", len(firmwares))
        print("#Targets         :", len(target_keys))
        print("#Unique Bins     :", len(firmwares))
        print("#Unique Products :", len(products))
        if opt_uniq_funcs:
            print("#Unique Function :", len(func_hashes))
        print("Details:")
        for vendor in vendors:
            print("\t" + vendor)
            vendor_targets = target_keys = sum(
                [
                    bin_info.target_keys
                    for bin_info in bin_infos
                    if bin_info.db_brand["name"] == vendor
                ],
                start=[],
            )
            print("\t\t#Targets         :", len(vendor_targets))
            vendor_bins = self._group_bin_infos(
                bin_infos,
                lambda bin_info: bin_info.bin_hash,
                filter_func=lambda bin_info: bin_info.db_brand["name"] == vendor,
            )
            print("\t\t#Unique Bins     :", len(vendor_bins))
            vendor_products = self._group_bin_infos(
                bin_infos,
                lambda bin_info: bin_info.db_product["product"],
                filter_func=lambda bin_info: bin_info.db_brand["name"] == vendor,
            )
            print("\t\t#Unique Products :", len(vendor_products))
            for product, product_bin_infos in sorted(
                vendor_products.items(), key=lambda x: x[0]
            ):
                versions = [
                    (
                        bin_info.db_product["version"],
                        sorted({k.vuln_name for k in bin_info.target_keys}),
                    )
                    for bin_info in product_bin_infos
                ]
                versions.sort(key=lambda v: v[0])
                print(f"\t\t\t{product:12s} versions: {versions}")

    def query(self, binary_path):
        """query the collected vulnerable bin information"""
        bin_hash = calc_binary_hash(binary_path)

        targets_info = self._load_binary_info(binary_path)
        target_keys = [ResultKey.from_dict(d) for d in targets_info]

        db_infos = self._load_db_infos(target_keys[0])
        db_brand, db_image, db_product = db_infos
        return BinInfo(
            bin_path=binary_path,
            bin_hash=bin_hash,
            target_keys=target_keys,
            db_brand=db_brand,
            db_image=db_image,
            db_product=db_product,
        )

    def query_all(self, directory):
        """List binaries under the given directory"""
        bin_infos = []
        for file_name in os.listdir(directory):
            if not file_name.endswith(".json"):
                file_path = os.path.join(directory, file_name)
                bin_info = self.query(file_path)
                if bin_info.db_product is None:
                    print(file_path)
                    continue
                bin_infos.append(bin_info)
        return bin_infos

    @staticmethod
    def _group_bin_infos(
        bin_infos, key_func, val_func=lambda x: x, filter_func=lambda _: True
    ):
        group_iter = itertools.groupby(
            [
                (key_func(bin_info), val_func(bin_info))
                for bin_info in bin_infos
                if filter_func(bin_info)
            ],
            key=lambda x: x[0],
        )
        res = {}
        for key, group in group_iter:
            res[key] = [x[1] for x in group]
        return res

    @staticmethod
    def _load_binary_info(binary_path):
        """Load information from a JSON file whose name is the binary path + '.json'"""
        json_path = binary_path + ".json"
        if os.path.exists(json_path):
            with open(json_path, "r") as f:
                return json.load(f)
        return {}

    def _load_db_infos(self, key: ResultKey):
        cur = self.database.cursor()
        filters = dict()

        def construct_db_info(cur):
            result = cur.fetchone()
            if not result:
                return None
            db_info = dict(zip([col.name for col in cur.description], result))
            return db_info

        def build_sql_filters(filters):
            filter_str = f" WHERE " + " AND ".join([f'"{k}"=%s ' for k in filters])
            vars = tuple(filters.values())
            return filter_str, vars

        cur.execute("SELECT * FROM brand WHERE name=%s", (key.vendor,))
        db_brand = construct_db_info(cur)

        brand_id = str(db_brand["id"])
        hexsha = key.firmware_id.split("_")[-1]
        filters = dict(brand_id=brand_id, hash=hexsha)
        filter_str, vars = build_sql_filters(filters)

        cur.execute("SELECT * FROM image" + filter_str, vars)
        db_image = construct_db_info(cur)
        if not db_image:
            filters = dict(brand_id=brand_id, id=hexsha)
            filter_str, vars = build_sql_filters(filters)
            cur.execute("SELECT * FROM image" + filter_str, vars)
            db_image = construct_db_info(cur)

        filters = dict(iid=db_image["id"])
        filter_str, vars = build_sql_filters(filters)
        cur.execute("SELECT * FROM product" + filter_str, vars)
        db_product = construct_db_info(cur)

        return db_brand, db_image, db_product

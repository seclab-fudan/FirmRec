import os

import psycopg2


class FirmwareStatistic:
    """
    Batch extract images
    """

    def __init__(self):
        self.database = psycopg2.connect(
            database="firmware",
            user="firmadyne",
            password="firmadyne",
            host="127.0.0.1",
            port=5432,
        )

    def statistic(self, firmware_root=None, resset=None):
        st = {}
        for db_firmware in self.query():
            brand = db_firmware["brand"]
            if brand not in st:
                st[brand] = dict(
                    total=0,
                    rootfs_extracted=0,
                    kernel_extracted=0,
                    products=set(),
                    rootfs_extracted_products=set(),
                )
            st_brand = st[brand]
            st_brand["total"] += 1
            product = db_firmware["product"]

            if firmware_root:
                self.update_local(firmware_root, db_firmware)

            if db_firmware["rootfs_extracted"]:
                st_brand["rootfs_extracted"] += 1
                st_brand["rootfs_extracted_products"].add(product)
            if db_firmware["kernel_extracted"]:
                st_brand["kernel_extracted"] += 1
            st_brand["products"].add(product)

        if firmware_root:
            self.database.commit()

        if resset:
            scanned = {}
            for key in resset:
                if key.vendor not in scanned:
                    scanned[key.vendor] = set()
                scanned[key.vendor].add(key.firmware_id)
            for brand, firmwares in scanned.items():
                st[brand]["scanned"] = len(firmwares)

        for brand, st_brand in st.items():
            st_brand["products"] = len(st_brand["products"])
            st_brand["rootfs_extracted_products"] = len(
                st_brand["rootfs_extracted_products"]
            )

        return st

    def update_local(self, firmware_root, db_firmware):
        image_dir = os.path.join(firmware_root, "images")
        extracted_dir = os.path.join(firmware_root, "extracted")

        if "." in db_firmware["filename"]:
            suffix = "." + db_firmware["filename"].rsplit(".")[-1]
        else:
            suffix = ""
        image_path_prefix = db_firmware["filename"][: -len(suffix)]
        image_path = os.path.join(image_dir, image_path_prefix + suffix)
        if not os.path.exists(image_path):
            image_path_prefix = f"{db_firmware['brand']}/{db_firmware['firmware_id']}"
            image_path = os.path.join(image_dir, image_path_prefix + suffix)
            if not os.path.exists(image_path):
                return False
            exract_path_prefix = image_path_prefix
        else:
            exract_path_prefix = image_path_prefix + suffix + "_" + db_firmware["hash"]

        extracted_path = os.path.join(extracted_dir, f"{exract_path_prefix}.tar")
        kernel_path = os.path.join(extracted_dir, f"{exract_path_prefix}.kernel")

        if "tenda" in extracted_path:
            print(image_path)

        rootfs_extracted = os.path.exists(extracted_path)
        kernel_extracted = os.path.exists(kernel_path)
        if (
            rootfs_extracted != db_firmware["rootfs_extracted"]
            or kernel_extracted != db_firmware["kernel_extracted"]
        ):
            self._update_db_extracted(db_firmware, rootfs_extracted, kernel_extracted)
        return True

    def _update_db_extracted(self, db_firmware, rootfs_extracted, kernel_extracted):
        db_firmware["rootfs_extracted"] = rootfs_extracted
        db_firmware["kernel_extracted"] = kernel_extracted
        print(
            "Updating DB", db_firmware["filename"], rootfs_extracted, kernel_extracted
        )
        cur = self.database.cursor()
        cur.execute(
            "UPDATE image SET rootfs_extracted=%s,kernel_extracted=%s  WHERE id=%s",
            (rootfs_extracted, kernel_extracted, db_firmware["firmware_id"]),
        )
        cur.close()

    def query(self, filters={}):
        query = """
        SELECT brand.id AS brand_id, brand.name AS brand,
               image.id AS firmware_id, image.filename, image.description, image.hash, image.rootfs_extracted, image.kernel_extracted, image.arch, image.kernel_version,
               product.id AS product_id, product.url, product.mib_hash, product.mib_url, product.sdk_hash, product.sdk_url, product.product, product.version, product.build, product.date, product.mib_filename, product.sdk_filename
        FROM brand
        JOIN image
          ON brand.id = image.brand_id
        JOIN product
          ON image.id = product.iid
        """
        cur = self.database.cursor()
        self._query_with_filters(cur, query, filters)
        return self._construct_db_infos(cur)

    def _construct_db_info(self, cur):
        result = cur.fetchone()
        if not result:
            return None
        db_info = dict(zip([col.name for col in cur.description], result))
        return db_info

    def _construct_db_infos(self, cur):
        while True:
            db_info = self._construct_db_info(cur)
            if not db_info:
                break
            yield db_info

    def _query_with_filters(self, cur, query, filters={}):
        if filters:
            filter_str = f" WHERE " + " AND ".join(
                [f'"{k}"=%s ' if "." not in k else f"{k}=%s" for k in filters]
            )
            vars = tuple(filters.values())
            cur.execute(query + filter_str, vars)
        else:
            cur.execute(query)

    @classmethod
    def normal_firmware_name(cls, name):
        return name.split("_")[-1].split(".")[0]

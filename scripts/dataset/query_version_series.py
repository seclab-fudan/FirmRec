#!python
import os
import re
import argparse
import csv
import json
import datetime

import psycopg2


def get_db_product_versions(conn):
    cmd = """
    SELECT image.filename, product.product, product.version
    FROM image
        JOIN product ON image.id=product.iid
    WHERE rootfs_extracted=true
        AND product.product <> ''
        AND product.version <> '';
    """
    cur = conn.cursor()
    cur.execute(cmd)
    by_product = {}
    for row in cur.fetchall():
        image, product, version = row
        vendor = image.split("/")[0]
        product = f'{vendor}/{product}'
        if product not in by_product:
            by_product[product] = set()
        by_product[product].add((image, version))
    return by_product


def get_version_key(version_str):
    """Get version key for sorting"""
    return re.findall(r"(\d+)", version_str)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db-user", type=str, default="iot")
    parser.add_argument("--db-user-passwd", type=str, default="IoTgogo")
    parser.add_argument("--db_name", type=str, default="firmware")
    parser.add_argument("--output", type=str, default="/tmp/diff_experiment.json")
    return parser.parse_args()


def main():
    args = parse_args()
    conn = psycopg2.connect(
        database=args.db_name,
        user=args.db_user,
        password=args.db_user_passwd,
        host="localhost",
        port=5432,
    )

    product_image = get_db_product_versions(conn)

    print(args.output)
    new_product_image = {}
    with open(args.output, 'w+', encoding='utf-8') as outfp:
        # writer = csv.writer(outfp)
        for product, images in sorted(product_image.items()):
            version_map = {image[1]: image[0] for image in images}
            versions = sorted(set([image[1] for image in images]), key=get_version_key)
            if len(versions) <= 1:
                continue
            images = sorted([(version, version_map[version]) for version in versions])
            new_product_image[product] = images
            # for version in versions:
            #     writer.writerow([product, version, version_map[version]])
        res = dict(name=datetime.date.today().strftime('%y-%m-%d'), product_image=new_product_image)
        json.dump(res, outfp, indent=4)


if __name__ == "__main__":
    main()

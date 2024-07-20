#!python
import os
import argparse

import psycopg2


def get_db_bins(conn):
    cmd = """
    SELECT id, firmware_id, path
    FROM bin;
    """
    cur = conn.cursor()
    cur.execute(cmd)
    bins = []
    for row in cur.fetchall():
        bin_id, firmware_id, bin_path = row
        bins.append((bin_id, firmware_id, bin_path))
    return bins


def check_no_func(conn, bins):
    cmd = """
    SELECT COUNT(*) FROM func WHERE bin_id=%s; 
    """
    cursor = conn.cursor()
    bin_ids = []
    for bin_id, firmware_id, bin_path in bins:
        cursor.execute(cmd, (bin_id,))
        if cursor.fetchone()[0] == 0:
            print(f"No func in {bin_id} {firmware_id} {bin_path}")
            bin_ids.append(bin_id)
    return bin_ids


def check_no_func_call(conn, bins):
    cmd = """
    SELECT COUNT(*) FROM func_call JOIN func ON caller=func.id WHERE bin_id=%s; 
    """
    cursor = conn.cursor()
    bin_ids = []
    for bin_id, firmware_id, bin_path in bins:
        cursor.execute(cmd, (bin_id,))
        if cursor.fetchone()[0] == 0:
            print(f"No func_call in {bin_id} {firmware_id} {bin_path}")
            bin_ids.append(bin_id)
    return bin_ids


def check_no_func_string(conn, bins):
    cmd = """
    SELECT COUNT(*) FROM func_string JOIN func ON func_id=func.id WHERE bin_id=%s; 
    """
    cursor = conn.cursor()
    bin_ids = []
    for bin_id, firmware_id, bin_path in bins:
        cursor.execute(cmd, (bin_id,))
        if cursor.fetchone()[0] == 0:
            print(f"No func_string in {bin_id} {firmware_id} {bin_path}")
            bin_ids.append(bin_id)
    return bin_ids


def drop_bins(conn, invalid_bin_ids):
    cursor = conn.cursor()
    b = tuple(invalid_bin_ids)
    cursor.execute("SELECT id FROM func WHERE bin_id in %s;", (b, ))
    func_ids = [x[0] for x in cursor.fetchall()]
    if not func_ids:
        return
    
    cmd = """
    DO $$
    BEGIN
    DELETE FROM func_call WHERE caller in %s;
    DELETE FROM func WHERE id in %s;
    DELETE FROM bin WHERE id in %s;
    END
    $$;
    COMMIT;
    """
    f = tuple(func_ids)
    cursor.execute(cmd, (f, f, f, b))
    cursor.close()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("db_name", type=str)
    parser.add_argument("--db-user", type=str, default="iot")
    parser.add_argument("--db-user-passwd", type=str, default="IoTgogo")
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

    bins = get_db_bins(conn)
    no_func_bin_ids = check_no_func(conn, bins)
    no_func_call_bin_ids = check_no_func_call(conn, bins)
    # no_func_string_bin_ids = check_no_func_string(conn, bins)
    invalid_bin_ids = (
        set(no_func_bin_ids).union(no_func_call_bin_ids)
    )
    input(f"Enter to drop {len(invalid_bin_ids)} bins")
    drop_bins(conn, invalid_bin_ids)


if __name__ == "__main__":
    main()

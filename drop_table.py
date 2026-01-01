import sqlite3
import sys
import os


def main():
    if len(sys.argv) != 2:
        print("Usage: python drop_table.py <table_name>")
        sys.exit(1)

    table = sys.argv[1]

    # Load DB path from config.ini
    import configparser
    basedir = os.path.abspath(os.path.dirname(__file__))
    config_path = os.path.join(basedir, "config.ini")
    cfg = configparser.ConfigParser()
    cfg.read(config_path)
    db_path = os.path.join(basedir, cfg.get("PATHS", "db_path"))

    if not os.path.exists(db_path):
        print(f"DB not found at {db_path}")
        sys.exit(1)

    confirm = input(f"Are you sure you want to DROP TABLE {table} in {db_path}? This cannot be undone. (yes/no): ").strip().lower()
    if confirm != "yes":
        print("Aborted.")
        sys.exit(0)

    with sqlite3.connect(db_path) as conn:
        conn.execute(f"DROP TABLE IF EXISTS {table}")
        conn.commit()
    print(f"Dropped table {table} in {db_path}")


if __name__ == "__main__":
    main()

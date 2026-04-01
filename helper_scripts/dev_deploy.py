#!/usr/bin/env python3
"""
ADX Deployment Script

DISCLAIMER: 
AI Slop, used for massdeployment and testing in a dev adx cluster. 
Not meant for production use at this time.

Deploys all mappings to ADX, optionally drops existing tables first,
and optionally backfills all data from RawVelociraptorEvents.

Usage:
  python3 helper_scripts/deploy.py --cluster <url> --database <db> [options]

Options:
  --cluster     ADX cluster URL (e.g. https://mycluster.region.kusto.windows.net)
  --database    Database name
  --drop        Drop all mapped tables before deploying (keeps RawVelociraptorEvents)
  --clear       Clear all table data (keeps schema and policies)
  --no-deploy   Skip deploying statements (useful with --clear or --backfill alone)
  --backfill    Backfill all tables from RawVelociraptorEvents after deploying
  --dry-run     Print statements without executing
"""

import argparse
import re
import sys
import time

MAPPINGS_FILE = "all_mappings.kql"
RAW_TABLE = "RawVelociraptorEvents"


def get_client(cluster: str):
    from azure.kusto.data import KustoClient, KustoConnectionStringBuilder
    # Uses az CLI credentials — auto-refreshes tokens, no 60-min expiry risk
    kcsb = KustoConnectionStringBuilder.with_az_cli_authentication(cluster)
    return KustoClient(kcsb)


def execute(client, database: str, statement: str, dry_run: bool, label: str = "", errors: list = None):
    statement = statement.strip()
    if not statement or statement.startswith("//"):
        return
    if dry_run:
        preview = statement[:80].replace("\n", " ")
        print(f"  [DRY-RUN] {label}: {preview}...")
        return
    try:
        client.execute_mgmt(database, statement)
        if label:
            print(f"  OK: {label}")
    except Exception as e:
        err = str(e)
        # .create table is safe to ignore if already exists
        if ".create table" in statement and "already exists" in err.lower():
            print(f"  SKIP (exists): {label}")
        else:
            print(f"  ERROR {label}: {err}", file=sys.stderr)
            if errors is not None:
                errors.append((label, err))
            else:
                raise


def split_statements(kql: str) -> list[str]:
    """
    Split a KQL file into individual management statements.
    Statements are separated by blank lines between top-level commands.
    """
    def flush(lines: list[str]) -> str:
        # Drop trailing comment-only and blank lines before saving.
        # ADX rejects management commands with trailing comments after the function body.
        while lines and (not lines[-1].strip() or lines[-1].strip().startswith("//")):
            lines.pop()
        return "\n".join(lines).strip()

    statements = []
    current = []
    for line in kql.splitlines():
        stripped = line.strip()
        # A new top-level command starts at column 0 with a dot
        if stripped.startswith(".") and current:
            stmt = flush(current)
            if stmt:
                statements.append(stmt)
            current = [line]
        else:
            current.append(line)
    if current:
        stmt = flush(current)
        if stmt:
            statements.append(stmt)
    return statements


def get_table_names(kql: str) -> list[str]:
    """Extract all .create table names from KQL, excluding RawVelociraptorEvents."""
    tables = re.findall(r"^\.create table (\w+)", kql, re.MULTILINE)
    return [t for t in tables if t != RAW_TABLE]


def get_routing_functions(kql: str) -> list[str]:
    """Extract all routing function names."""
    return re.findall(r"^\.create-or-alter function (\w+)", kql, re.MULTILINE)


def clear_tables(client, database: str, tables: list[str], dry_run: bool, include_raw: bool = False):
    all_tables = ([RAW_TABLE] if include_raw else []) + tables
    print(f"\n=== Clearing data from {len(all_tables)} tables ===")
    for table in all_tables:
        execute(client, database, f".clear table {table} data", dry_run, f"clear {table}")


def drop_tables(client, database: str, tables: list[str], dry_run: bool):
    print(f"\n=== Dropping {len(tables)} tables ===")
    for table in tables:
        execute(client, database, f".drop table {table} ifexists", dry_run, f"drop {table}")


def deploy_mappings(client, database: str, statements: list[str], dry_run: bool) -> list:
    print(f"\n=== Deploying {len(statements)} statements ===")
    errors = []
    for i, stmt in enumerate(statements):
        # Derive a short label from first line
        label = stmt.splitlines()[0][:60].strip()
        execute(client, database, stmt, dry_run, label, errors=errors)
        # Small delay to avoid throttling
        if not dry_run and i % 10 == 0:
            time.sleep(0.2)
    return errors


def backfill_tables(client, database: str, tables: list[str], functions: list[str], dry_run: bool):
    """
    For each routing function, run .set-or-replace async to backfill the table
    from RawVelociraptorEvents via the routing function.
    """
    # Build a map of table -> [routing functions]
    # Convention: RouteXxx...() routes into table Xxx (prefix match, not exact).
    # Some tables have multiple routing functions (e.g. Linux.Network.NM.Connections
    # creates 4 tables each with their own Route function sharing a common prefix).
    tables_sorted = sorted(tables, key=len, reverse=True)  # longest first avoids prefix collisions
    func_map: dict[str, list[str]] = {t: [] for t in tables}
    for fn in functions:
        suffix = fn.removeprefix("Route")
        # Match against the longest table name that is a prefix of this function's suffix
        for table in tables_sorted:
            if suffix.startswith(table):
                func_map[table].append(fn)
                break

    matched = {t: fns for t, fns in func_map.items() if fns}
    print(f"\n=== Backfilling {len(matched)} tables ===")
    for table, fns in matched.items():
        if len(fns) == 1:
            stmt = f".set-or-replace {table} <| {fns[0]}()"
        else:
            # Union all routing functions into one backfill
            union_args = ", ".join(f"({fn}())" for fn in fns)
            stmt = f".set-or-replace {table} <|\n    union {union_args}"
        execute(client, database, stmt, dry_run, f"backfill {table}")
        if not dry_run:
            time.sleep(0.5)

    missing = [t for t in tables if not func_map[t]]
    if missing:
        print(f"\n  NOTE: No routing function found for {len(missing)} tables (may use manual ingestion):")
        for t in missing:
            print(f"    - {t}")


def main():
    parser = argparse.ArgumentParser(description="Deploy ADX mappings")
    parser.add_argument("--cluster", required=True, help="ADX cluster URL")
    parser.add_argument("--database", required=True, help="Database name")
    parser.add_argument("--drop", action="store_true", help="Drop all mapped tables before deploying")
    parser.add_argument("--clear", action="store_true", help="Clear all table data before deploying (keeps schema and policies)")
    parser.add_argument("--clear-raw", action="store_true", help="Also clear RawVelociraptorEvents when using --clear")
    parser.add_argument("--yes", action="store_true", help="Skip confirmation prompts for --drop/--clear (for non-interactive use)")
    parser.add_argument("--backfill", action="store_true", help="Backfill tables from RawVelociraptorEvents")
    parser.add_argument("--no-deploy", action="store_true", help="Skip deploying statements (useful with --clear or --backfill alone)")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without executing")
    parser.add_argument("--mappings-file", default=MAPPINGS_FILE, help=f"Path to mappings KQL file (default: {MAPPINGS_FILE})")
    args = parser.parse_args()

    print(f"Cluster:  {args.cluster}")
    print(f"Database: {args.database}")
    print(f"File:     {args.mappings_file}")
    print(f"Drop:     {args.drop}")
    print(f"Clear:    {args.clear}")
    print(f"No-deploy:{args.no_deploy}")
    print(f"Backfill: {args.backfill}")
    print(f"Dry-run:  {args.dry_run}")

    try:
        with open(args.mappings_file, "r") as f:
            kql = f.read()
    except FileNotFoundError:
        print(f"ERROR: {args.mappings_file} not found. Run from the repo root.", file=sys.stderr)
        sys.exit(1)

    tables = get_table_names(kql)
    functions = get_routing_functions(kql)
    statements = split_statements(kql)

    # Filter out comment-only blocks
    statements = [s for s in statements if not all(l.strip().startswith("//") or not l.strip() for l in s.splitlines())]

    print(f"\nFound: {len(tables)} tables, {len(functions)} functions, {len(statements)} statements")

    if args.dry_run:
        client = None
    else:
        client = get_client(args.cluster)
    database = args.database

    if args.drop:
        if not args.yes:
            confirm = input(f"\nWARNING: This will DROP {len(tables)} tables in '{args.database}'. Type 'yes' to continue: ")
            if confirm.strip().lower() != "yes":
                print("Aborted.")
                sys.exit(0)
        drop_tables(client, database, tables, args.dry_run)

    if args.clear:
        if not args.yes:
            confirm = input(f"\nWARNING: This will CLEAR DATA from {len(tables)} tables in '{args.database}'. Type 'yes' to continue: ")
            if confirm.strip().lower() != "yes":
                print("Aborted.")
                sys.exit(0)
        clear_tables(client, database, tables, args.dry_run, include_raw=args.clear_raw)

    if not args.no_deploy:
        errors = deploy_mappings(client, database, statements, args.dry_run)
    else:
        errors = []
    if errors:
        print(f"\n=== {len(errors)} deployment error(s) ===", file=sys.stderr)
        for label, err in errors:
            print(f"  - {label}: {err}", file=sys.stderr)

    if args.backfill:
        backfill_tables(client, database, tables, functions, args.dry_run)

    print("\nDone.")


if __name__ == "__main__":
    main()

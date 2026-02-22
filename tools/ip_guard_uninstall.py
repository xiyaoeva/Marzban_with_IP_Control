#!/usr/bin/env python3
"""
ip_guard 卸载工具

默认行为（安全卸载）：
1) 停止并禁用 systemd 服务（如果存在）
2) 将 ip_guard_policy.enabled 置为 0（如果表存在）

可选“彻底卸载”：
- 删除 ip_guard 相关表
- 可选删除 user_ip_observations 表

示例：
  python tools/ip_guard_uninstall.py --env-file /opt/marzban/.env
  python tools/ip_guard_uninstall.py --env-file /opt/marzban/.env --drop-guard-tables --yes
  python tools/ip_guard_uninstall.py --env-file /opt/marzban/.env --drop-guard-tables --drop-observations --yes
"""

from __future__ import annotations

import argparse
import os
import subprocess
from dataclasses import dataclass
from typing import Dict
from urllib.parse import unquote, urlparse

import pymysql


@dataclass
class DBConfig:
    host: str
    port: int
    user: str
    password: str
    db: str


def parse_env_file(path: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not path or not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def parse_sqlalchemy_mysql(url: str) -> DBConfig:
    p = urlparse(url)
    if not p.scheme.startswith("mysql"):
        raise ValueError("Only mysql+pymysql URL is supported")
    return DBConfig(
        host=p.hostname or "127.0.0.1",
        port=int(p.port or 3306),
        user=unquote(p.username or "root"),
        password=unquote(p.password or ""),
        db=(p.path or "/marzban").lstrip("/") or "marzban",
    )


def load_db_config(env_file: str, db_url_override: str | None) -> DBConfig:
    envs = parse_env_file(env_file)
    db_url = db_url_override or os.getenv("SQLALCHEMY_DATABASE_URL") or envs.get("SQLALCHEMY_DATABASE_URL")
    if not db_url:
        raise RuntimeError("SQLALCHEMY_DATABASE_URL not found")
    return parse_sqlalchemy_mysql(db_url)


def db_connect(cfg: DBConfig):
    return pymysql.connect(
        host=cfg.host,
        port=cfg.port,
        user=cfg.user,
        password=cfg.password,
        database=cfg.db,
        charset="utf8mb4",
        autocommit=False,
        cursorclass=pymysql.cursors.DictCursor,
    )


def has_table(conn, table: str) -> bool:
    with conn.cursor() as cur:
        cur.execute("SHOW TABLES LIKE %s", (table,))
        return cur.fetchone() is not None


def stop_systemd_service(service_name: str):
    # 不抛异常，避免在非 systemd 环境中中断卸载
    for cmd in (
        ["sudo", "systemctl", "stop", service_name],
        ["sudo", "systemctl", "disable", service_name],
    ):
        try:
            subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass


def disable_policy(conn):
    if not has_table(conn, "ip_guard_policy"):
        return False
    with conn.cursor() as cur:
        cur.execute("UPDATE ip_guard_policy SET enabled=0, updated_at=UTC_TIMESTAMP()")
    conn.commit()
    return True


def drop_tables(conn, include_observations: bool):
    tables = [
        "ip_guard_log",
        "ip_guard_state",
        "ip_guard_whitelist",
        "ip_guard_policy",
    ]
    if include_observations:
        tables.append("user_ip_observations")

    with conn.cursor() as cur:
        for t in tables:
            cur.execute(f"DROP TABLE IF EXISTS {t}")
    conn.commit()


def main():
    p = argparse.ArgumentParser(description="Uninstall Marzban ip_guard")
    p.add_argument("--env-file", default="/opt/marzban/.env", help="marzban .env path")
    p.add_argument("--sqlalchemy-database-url", default=None, help="override db url")
    p.add_argument("--service-name", default="marzban-ip-guard.service", help="systemd service name")
    p.add_argument("--no-stop-service", action="store_true", help="do not stop/disable service")

    p.add_argument("--drop-guard-tables", action="store_true", help="drop ip_guard_* tables")
    p.add_argument("--drop-observations", action="store_true", help="also drop user_ip_observations")
    p.add_argument("--yes", action="store_true", help="confirm destructive actions")

    args = p.parse_args()

    if not args.no_stop_service:
        stop_systemd_service(args.service_name)
        print(f"[ok] service stop/disable attempted: {args.service_name}")

    cfg = load_db_config(args.env_file, args.sqlalchemy_database_url)
    conn = db_connect(cfg)
    try:
        disabled = disable_policy(conn)
        if disabled:
            print("[ok] ip_guard_policy.enabled=0")
        else:
            print("[skip] ip_guard_policy table not found")

        if args.drop_guard_tables or args.drop_observations:
            if not args.yes:
                raise RuntimeError("Destructive action requested. Re-run with --yes")
            drop_tables(conn, include_observations=bool(args.drop_observations))
            if args.drop_observations:
                print("[ok] dropped: ip_guard_* + user_ip_observations")
            else:
                print("[ok] dropped: ip_guard_* (kept user_ip_observations)")

    finally:
        conn.close()

    print("[done] uninstall finished")


if __name__ == "__main__":
    main()

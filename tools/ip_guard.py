#!/usr/bin/env python3
"""
Marzban IP Guard (Safe Architecture)

安全架构：
- 节点侧仅采集本地 access log，批量写入主控 MySQL（不连接节点控制 API）
- 主控侧仅执行判定/封禁/恢复 + Web 管理
- 不抢占 Marzban-node /connect 会话，不影响主控与节点控制链路
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import queue
import re
import socket
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

import pymysql
import requests
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse

UTC = dt.timezone.utc


def utc_now_naive() -> dt.datetime:
    return dt.datetime.now(tz=UTC).replace(tzinfo=None, microsecond=0)


def minute_bucket(ts: dt.datetime) -> dt.datetime:
    return ts.replace(second=0, microsecond=0)


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


@dataclass
class DBConfig:
    host: str
    port: int
    user: str
    password: str
    db: str


@dataclass
class Policy:
    id: int
    enabled: int
    max_ips: int
    check_interval_seconds: int
    observation_window_seconds: int
    recover_after_minutes: int
    violate_action: str
    collect_batch_size: int
    collect_flush_seconds: int
    observation_retention_days: int


@dataclass
class MarzbanAPIConfig:
    base_url: str
    username: str
    password: str
    timeout: int = 10
    verify_tls: bool = True


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


def load_db_config(args: argparse.Namespace) -> DBConfig:
    env_file = args.env_file or os.getenv("MARZBAN_ENV_FILE") or "/opt/marzban/.env"
    envs = parse_env_file(env_file)
    db_url = (
        args.sqlalchemy_database_url
        or os.getenv("SQLALCHEMY_DATABASE_URL")
        or envs.get("SQLALCHEMY_DATABASE_URL")
    )
    if not db_url:
        raise RuntimeError("SQLALCHEMY_DATABASE_URL not found")
    return parse_sqlalchemy_mysql(db_url)


def load_marzban_api_config(args: argparse.Namespace) -> Optional[MarzbanAPIConfig]:
    env_file = args.env_file or os.getenv("MARZBAN_ENV_FILE") or "/opt/marzban/.env"
    envs = parse_env_file(env_file)

    username = args.marzban_admin_username or os.getenv("MARZBAN_ADMIN_USERNAME") or envs.get("SUDO_USERNAME")
    password = args.marzban_admin_password or os.getenv("MARZBAN_ADMIN_PASSWORD") or envs.get("SUDO_PASSWORD")
    if not username or not password:
        return None

    api_base = (
        args.marzban_api_base
        or os.getenv("MARZBAN_API_BASE")
        or envs.get("IP_GUARD_MARZBAN_API_BASE")
        or "http://127.0.0.1:8000/api"
    ).rstrip("/")
    timeout = int(args.marzban_api_timeout or os.getenv("MARZBAN_API_TIMEOUT") or 10)
    verify_tls = not bool(args.marzban_api_insecure)
    return MarzbanAPIConfig(
        base_url=api_base,
        username=username,
        password=password,
        timeout=timeout,
        verify_tls=verify_tls,
    )


class MarzbanAPIClient:
    def __init__(self, cfg: MarzbanAPIConfig):
        self.cfg = cfg
        self._token: Optional[str] = None

    def _token_headers(self) -> Dict[str, str]:
        if not self._token:
            self._login()
        return {"Authorization": f"Bearer {self._token}"}

    def _login(self):
        resp = requests.post(
            f"{self.cfg.base_url}/admin/token",
            data={"username": self.cfg.username, "password": self.cfg.password},
            timeout=self.cfg.timeout,
            verify=self.cfg.verify_tls,
        )
        resp.raise_for_status()
        data = resp.json()
        token = data.get("access_token")
        if not token:
            raise RuntimeError("marzban token response missing access_token")
        self._token = token

    def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        url = f"{self.cfg.base_url}{path}"
        kwargs.setdefault("timeout", self.cfg.timeout)
        kwargs.setdefault("verify", self.cfg.verify_tls)
        headers = kwargs.pop("headers", {})
        headers.update(self._token_headers())
        kwargs["headers"] = headers
        resp = requests.request(method, url, **kwargs)
        if resp.status_code == 401:
            self._login()
            headers = kwargs.pop("headers", {})
            headers.update(self._token_headers())
            kwargs["headers"] = headers
            resp = requests.request(method, url, **kwargs)
        resp.raise_for_status()
        if not resp.text:
            return {}
        return resp.json()

    def set_user_status(self, username: str, status: str) -> Dict[str, Any]:
        return self._request("PUT", f"/user/{username}", json={"status": status})


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


BASE_DDL = [
    """
    CREATE TABLE IF NOT EXISTS ip_guard_policy (
      id INT PRIMARY KEY AUTO_INCREMENT,
      enabled TINYINT(1) NOT NULL DEFAULT 1,
      max_ips INT NOT NULL DEFAULT 2,
      check_interval_seconds INT NOT NULL DEFAULT 1800,
      observation_window_seconds INT NOT NULL DEFAULT 1800,
      recover_after_minutes INT NOT NULL DEFAULT 30,
      violate_action ENUM('disable') NOT NULL DEFAULT 'disable',
      collect_batch_size INT NOT NULL DEFAULT 300,
      collect_flush_seconds INT NOT NULL DEFAULT 3,
      observation_retention_days INT NOT NULL DEFAULT 7,
      created_at DATETIME NOT NULL,
      updated_at DATETIME NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS ip_guard_whitelist (
      id BIGINT PRIMARY KEY AUTO_INCREMENT,
      user_id INT NULL,
      username VARCHAR(64) NULL,
      enabled TINYINT(1) NOT NULL DEFAULT 1,
      max_ips_override INT NULL,
      note VARCHAR(255) NULL,
      created_at DATETIME NOT NULL,
      updated_at DATETIME NOT NULL,
      UNIQUE KEY uk_guard_whitelist_user_id (user_id),
      UNIQUE KEY uk_guard_whitelist_username (username)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS ip_guard_state (
      user_id INT PRIMARY KEY,
      last_seen_ip_count INT NOT NULL DEFAULT 0,
      last_seen_at DATETIME NULL,
      disabled_by_guard TINYINT(1) NOT NULL DEFAULT 0,
      disabled_at DATETIME NULL,
      disabled_reason VARCHAR(255) NULL,
      previous_status ENUM('active','disabled','limited','expired','on_hold') NULL,
      recover_candidate_since DATETIME NULL,
      recovered_at DATETIME NULL,
      updated_at DATETIME NOT NULL,
      created_at DATETIME NOT NULL,
      INDEX idx_guard_state_disabled (disabled_by_guard)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS user_ip_observations (
      id BIGINT PRIMARY KEY AUTO_INCREMENT,
      user_id INT NOT NULL,
      src_ip VARCHAR(45) NOT NULL,
      source VARCHAR(64) NOT NULL DEFAULT 'node_log_file',
      seen_at DATETIME NOT NULL,
      seen_bucket DATETIME NOT NULL,
      raw_email VARCHAR(128) NULL,
      node_id INT NULL,
      created_at DATETIME NOT NULL,
      UNIQUE KEY uk_obs_dedupe (user_id, src_ip, source, seen_bucket),
      INDEX idx_obs_user_seen (user_id, seen_at),
      INDEX idx_obs_seen (seen_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS ip_guard_log (
      id BIGINT PRIMARY KEY AUTO_INCREMENT,
      user_id INT NOT NULL,
      username VARCHAR(64) NOT NULL,
      event_type ENUM('violation','disabled','recover_candidate','recovered','manual_recovered') NOT NULL,
      details TEXT NULL,
      created_at DATETIME NOT NULL,
      INDEX idx_guard_log_user (user_id, created_at),
      INDEX idx_guard_log_created (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
    """
    CREATE TABLE IF NOT EXISTS ip_guard_offsets (
      source VARCHAR(128) NOT NULL,
      path VARCHAR(512) NOT NULL,
      inode BIGINT NOT NULL,
      offset BIGINT NOT NULL,
      updated_at DATETIME NOT NULL,
      PRIMARY KEY (source, path)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """,
]


def ensure_columns(conn, table: str, expected: Dict[str, str]):
    with conn.cursor() as cur:
        cur.execute(f"SHOW COLUMNS FROM {table}")
        existing = {r["Field"] for r in cur.fetchall()}
        for name, ddl in expected.items():
            if name in existing:
                continue
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")


def init_db(conn):
    now = utc_now_naive()
    with conn.cursor() as cur:
        for stmt in BASE_DDL:
            cur.execute(stmt)

    ensure_columns(
        conn,
        "ip_guard_policy",
        {
            "collect_batch_size": "INT NOT NULL DEFAULT 300",
            "collect_flush_seconds": "INT NOT NULL DEFAULT 3",
            "observation_retention_days": "INT NOT NULL DEFAULT 7",
        },
    )
    ensure_columns(conn, "user_ip_observations", {"node_id": "INT NULL"})

    with conn.cursor() as cur:
        cur.execute("SELECT id FROM ip_guard_policy ORDER BY id ASC LIMIT 1")
        row = cur.fetchone()
        if not row:
            cur.execute(
                """
                INSERT INTO ip_guard_policy
                (enabled, max_ips, check_interval_seconds, observation_window_seconds,
                 recover_after_minutes, violate_action, collect_batch_size, collect_flush_seconds,
                 observation_retention_days, created_at, updated_at)
                VALUES (1, 2, 1800, 1800, 30, 'disable', 300, 3, 7, %s, %s)
                """,
                (now, now),
            )
    conn.commit()


def load_policy(conn) -> Policy:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, enabled, max_ips, check_interval_seconds,
                   observation_window_seconds, recover_after_minutes, violate_action,
                   collect_batch_size, collect_flush_seconds, observation_retention_days
            FROM ip_guard_policy ORDER BY id ASC LIMIT 1
            """
        )
        row = cur.fetchone()
    if not row:
        raise RuntimeError("ip_guard_policy missing")
    return Policy(**row)


def get_whitelist_overrides(conn) -> Dict[int, int]:
    out: Dict[int, int] = {}
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT user_id, username, max_ips_override
            FROM ip_guard_whitelist
            WHERE enabled=1
            """
        )
        rows = cur.fetchall()
        for r in rows:
            if r["user_id"] is not None:
                out[int(r["user_id"])] = int(r["max_ips_override"] or 0)
                continue
            if r["username"]:
                cur.execute("SELECT id FROM users WHERE username=%s LIMIT 1", (r["username"],))
                u = cur.fetchone()
                if u:
                    out[int(u["id"])] = int(r["max_ips_override"] or 0)
    return out


def resolve_user_id_by_email(conn, raw_email: str, cache: Dict[str, Optional[int]]) -> Optional[int]:
    key = (raw_email or "").strip()
    if not key:
        return None
    if key in cache:
        return cache[key]

    user_id: Optional[int] = None
    with conn.cursor() as cur:
        first = key.split(".", 1)[0]
        if first.isdigit():
            cur.execute("SELECT id FROM users WHERE id=%s LIMIT 1", (int(first),))
            row = cur.fetchone()
            if row:
                user_id = int(row["id"])
        if user_id is None:
            cur.execute("SELECT id FROM users WHERE username=%s LIMIT 1", (key,))
            row = cur.fetchone()
            if row:
                user_id = int(row["id"])

    cache[key] = user_id
    return user_id


def upsert_guard_state_seen(conn, user_id: int, ip_count: int):
    now = utc_now_naive()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ip_guard_state (user_id, last_seen_ip_count, last_seen_at, updated_at, created_at)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
              last_seen_ip_count=VALUES(last_seen_ip_count),
              last_seen_at=VALUES(last_seen_at),
              updated_at=VALUES(updated_at)
            """,
            (user_id, ip_count, now, now, now),
        )


def insert_event(conn, user_id: int, username: str, event_type: str, details: str):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ip_guard_log (user_id, username, event_type, details, created_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (user_id, username, event_type, details, utc_now_naive()),
        )


def disable_user(conn, user: Dict[str, Any], reason: str, api_client: Optional[MarzbanAPIClient] = None):
    uid = int(user["id"])
    uname = user["username"]
    status = user["status"]
    now = utc_now_naive()

    if api_client:
        api_client.set_user_status(uname, "disabled")
    else:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET status='disabled', last_status_change=%s WHERE id=%s AND status <> 'disabled'",
                (now, uid),
            )

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE ip_guard_state
            SET disabled_by_guard=1,
                disabled_at=%s,
                disabled_reason=%s,
                previous_status=%s,
                recover_candidate_since=NULL,
                updated_at=%s
            WHERE user_id=%s
            """,
            (now, reason, status, now, uid),
        )

    insert_event(conn, uid, uname, "disabled", reason)


def recover_user(conn, user: Dict[str, Any], manual: bool = False, api_client: Optional[MarzbanAPIClient] = None):
    uid = int(user["id"])
    uname = user["username"]
    now = utc_now_naive()

    with conn.cursor() as cur:
        cur.execute("SELECT previous_status FROM ip_guard_state WHERE user_id=%s", (uid,))
        st = cur.fetchone() or {}
        prev = st.get("previous_status")
        restore_to = prev if prev in ("active", "on_hold") else "active"

        if api_client:
            api_client.set_user_status(uname, restore_to)
        else:
            cur.execute(
                "UPDATE users SET status=%s, last_status_change=%s WHERE id=%s",
                (restore_to, now, uid),
            )
        cur.execute(
            """
            UPDATE ip_guard_state
            SET disabled_by_guard=0,
                recover_candidate_since=NULL,
                recovered_at=%s,
                updated_at=%s
            WHERE user_id=%s
            """,
            (now, now, uid),
        )

    insert_event(conn, uid, uname, "manual_recovered" if manual else "recovered", f"restored_to={restore_to}")


def cleanup_old_observations(conn, retention_days: int) -> int:
    if retention_days <= 0:
        return 0
    cutoff = utc_now_naive() - dt.timedelta(days=retention_days)
    with conn.cursor() as cur:
        cur.execute("DELETE FROM user_ip_observations WHERE seen_at < %s", (cutoff,))
        return cur.rowcount


def enforce_once(conn, policy: Policy) -> Dict[str, int]:
    if not policy.enabled:
        return {"checked": 0, "violations": 0, "disabled": 0, "recovered": 0, "retention_deleted": 0}

    now = utc_now_naive()
    since = now - dt.timedelta(seconds=int(policy.observation_window_seconds))
    recover_wait = dt.timedelta(minutes=int(policy.recover_after_minutes))
    stats = {"checked": 0, "violations": 0, "disabled": 0, "recovered": 0, "retention_deleted": 0}

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT u.id, u.username, u.status, COUNT(DISTINCT o.src_ip) AS ip_count
            FROM users u
            LEFT JOIN user_ip_observations o
              ON o.user_id=u.id AND o.seen_at >= %s
            WHERE u.status IN ('active','on_hold','disabled')
            GROUP BY u.id, u.username, u.status
            """,
            (since,),
        )
        users = cur.fetchall()

    whitelist = get_whitelist_overrides(conn)

    for user in users:
        uid = int(user["id"])
        uname = user["username"]
        status = user["status"]
        ip_count = int(user.get("ip_count") or 0)
        allowed = whitelist.get(uid)
        if not allowed or allowed <= 0:
            allowed = int(policy.max_ips)

        stats["checked"] += 1
        upsert_guard_state_seen(conn, uid, ip_count)

        if status in ("active", "on_hold") and ip_count > allowed:
            reason = f"ip_count={ip_count} allowed={allowed} window={policy.observation_window_seconds}s"
            insert_event(conn, uid, uname, "violation", reason)
            stats["violations"] += 1
            if policy.violate_action == "disable":
                disable_user(conn, user, reason)
                stats["disabled"] += 1
            continue

        if status != "disabled":
            continue

        with conn.cursor() as cur:
            cur.execute(
                "SELECT disabled_by_guard, recover_candidate_since FROM ip_guard_state WHERE user_id=%s",
                (uid,),
            )
            st = cur.fetchone() or {}

        if int(st.get("disabled_by_guard") or 0) != 1:
            continue

        if ip_count <= allowed:
            candidate_since = st.get("recover_candidate_since")
            if candidate_since is None:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE ip_guard_state SET recover_candidate_since=%s, updated_at=%s WHERE user_id=%s",
                        (now, now, uid),
                    )
                insert_event(conn, uid, uname, "recover_candidate", f"ip_count={ip_count} allowed={allowed}")
            else:
                if now - candidate_since >= recover_wait:
                    recover_user(conn, user, manual=False)
                    stats["recovered"] += 1
        else:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE ip_guard_state SET recover_candidate_since=NULL, updated_at=%s WHERE user_id=%s",
                    (now, uid),
                )

    stats["retention_deleted"] = cleanup_old_observations(conn, int(policy.observation_retention_days))
    conn.commit()
    return stats


def enforce_once_with_client(
    conn,
    policy: Policy,
    api_client: Optional[MarzbanAPIClient] = None,
) -> Dict[str, int]:
    if not policy.enabled:
        return {"checked": 0, "violations": 0, "disabled": 0, "recovered": 0, "retention_deleted": 0}

    now = utc_now_naive()
    since = now - dt.timedelta(seconds=int(policy.observation_window_seconds))
    recover_wait = dt.timedelta(minutes=int(policy.recover_after_minutes))
    stats = {"checked": 0, "violations": 0, "disabled": 0, "recovered": 0, "retention_deleted": 0}

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT u.id, u.username, u.status, COUNT(DISTINCT o.src_ip) AS ip_count
            FROM users u
            LEFT JOIN user_ip_observations o
              ON o.user_id=u.id AND o.seen_at >= %s
            WHERE u.status IN ('active','on_hold','disabled')
            GROUP BY u.id, u.username, u.status
            """,
            (since,),
        )
        users = cur.fetchall()

    whitelist = get_whitelist_overrides(conn)

    for user in users:
        uid = int(user["id"])
        uname = user["username"]
        status = user["status"]
        ip_count = int(user.get("ip_count") or 0)
        allowed = whitelist.get(uid)
        if not allowed or allowed <= 0:
            allowed = int(policy.max_ips)

        stats["checked"] += 1
        upsert_guard_state_seen(conn, uid, ip_count)

        if status in ("active", "on_hold") and ip_count > allowed:
            reason = f"ip_count={ip_count} allowed={allowed} window={policy.observation_window_seconds}s"
            insert_event(conn, uid, uname, "violation", reason)
            stats["violations"] += 1
            if policy.violate_action == "disable":
                disable_user(conn, user, reason, api_client=api_client)
                stats["disabled"] += 1
            continue

        if status != "disabled":
            continue

        with conn.cursor() as cur:
            cur.execute(
                "SELECT disabled_by_guard, recover_candidate_since FROM ip_guard_state WHERE user_id=%s",
                (uid,),
            )
            st = cur.fetchone() or {}

        if int(st.get("disabled_by_guard") or 0) != 1:
            continue

        if ip_count <= allowed:
            candidate_since = st.get("recover_candidate_since")
            if candidate_since is None:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE ip_guard_state SET recover_candidate_since=%s, updated_at=%s WHERE user_id=%s",
                        (now, now, uid),
                    )
                insert_event(conn, uid, uname, "recover_candidate", f"ip_count={ip_count} allowed={allowed}")
            else:
                if now - candidate_since >= recover_wait:
                    recover_user(conn, user, manual=False, api_client=api_client)
                    stats["recovered"] += 1
        else:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE ip_guard_state SET recover_candidate_since=NULL, updated_at=%s WHERE user_id=%s",
                    (now, uid),
                )

    stats["retention_deleted"] = cleanup_old_observations(conn, int(policy.observation_retention_days))
    conn.commit()
    return stats


# ---------- Node-side log collector (safe) ----------

EMAIL_RE = re.compile(r"email:\s*(?P<email>[^\s,;]+)", re.IGNORECASE)
IP_PORT_RE = re.compile(r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}):\d+")


def parse_access_log_line(line: str) -> Optional[Tuple[str, str]]:
    em = EMAIL_RE.search(line)
    if not em:
        return None
    email = em.group("email").strip()
    left = line.split("accepted", 1)[0]
    candidates = IP_PORT_RE.findall(left)
    if not candidates:
        candidates = IP_PORT_RE.findall(line)
    if not candidates:
        return None
    return email, candidates[-1]


def read_offset(conn, source: str, path: str, inode: int) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT inode, offset FROM ip_guard_offsets WHERE source=%s AND path=%s",
            (source, path),
        )
        row = cur.fetchone()
    if not row:
        return 0
    if int(row["inode"]) != int(inode):
        return 0
    return int(row["offset"])


def write_offset(conn, source: str, path: str, inode: int, offset: int):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ip_guard_offsets (source, path, inode, offset, updated_at)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE inode=VALUES(inode), offset=VALUES(offset), updated_at=VALUES(updated_at)
            """,
            (source, path, int(inode), int(offset), utc_now_naive()),
        )


def collect_once(
    conn,
    source: str,
    log_paths: List[str],
    node_id: Optional[int],
    batch_size: int,
) -> Dict[str, int]:
    user_cache: Dict[str, Optional[int]] = {}
    scanned = 0
    inserted = 0
    batch: List[Tuple[int, str, str, dt.datetime, dt.datetime, str, Optional[int], dt.datetime]] = []

    def flush():
        nonlocal inserted
        if not batch:
            return
        with conn.cursor() as cur:
            cur.executemany(
                """
                INSERT IGNORE INTO user_ip_observations
                (user_id, src_ip, source, seen_at, seen_bucket, raw_email, node_id, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                batch,
            )
            inserted += cur.rowcount
        batch.clear()

    for path in log_paths:
        p = path.strip()
        if not p or not os.path.exists(p):
            continue

        st = os.stat(p)
        inode = int(st.st_ino)
        off = read_offset(conn, source, p, inode)

        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(off)
            for line in f:
                scanned += 1
                parsed = parse_access_log_line(line)
                if not parsed:
                    continue
                raw_email, src_ip = parsed
                uid = resolve_user_id_by_email(conn, raw_email, user_cache)
                if uid is None:
                    continue

                seen_at = utc_now_naive()
                batch.append(
                    (
                        uid,
                        src_ip,
                        source,
                        seen_at,
                        minute_bucket(seen_at),
                        raw_email,
                        node_id,
                        utc_now_naive(),
                    )
                )
                if len(batch) >= max(10, batch_size):
                    flush()

            write_offset(conn, source, p, inode, f.tell())

    flush()
    conn.commit()
    return {"scanned": scanned, "inserted": inserted}


class EnforcerLoop:
    def __init__(self, db_cfg: DBConfig, api_cfg: Optional[MarzbanAPIConfig] = None):
        self.db_cfg = db_cfg
        self.api_cfg = api_cfg

    def run(self):
        api_client = MarzbanAPIClient(self.api_cfg) if self.api_cfg else None
        while True:
            conn = db_connect(self.db_cfg)
            sleep_seconds = 60
            try:
                pol = load_policy(conn)
                stats = enforce_once_with_client(conn, pol, api_client=api_client)
                print(
                    "[enforcer] checked={checked} violations={violations} disabled={disabled} recovered={recovered} retention_deleted={retention_deleted}".format(
                        **stats
                    )
                )
                sleep_seconds = max(30, int(pol.check_interval_seconds))
            except Exception as e:
                print(f"[enforcer][err] {e}")
            finally:
                conn.close()
            time.sleep(sleep_seconds)


UI_HTML = """<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>IP Guard Console</title><style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;margin:24px;background:#f7f8fb;color:#1f2937}.wrap{max-width:1100px;margin:0 auto}.card{background:#fff;border-radius:12px;padding:16px;margin-bottom:14px;box-shadow:0 1px 6px rgba(0,0,0,.08)}h1,h2{margin:0 0 12px}.row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:8px}input,select,button{padding:8px 10px;border:1px solid #d1d5db;border-radius:8px;font-size:14px}button{background:#2563eb;color:#fff;border:none;cursor:pointer}button.secondary{background:#4b5563}pre{white-space:pre-wrap;word-break:break-word;margin:0;background:#0f172a;color:#e5e7eb;padding:10px;border-radius:8px;max-height:300px;overflow:auto}.status{font-size:13px;color:#374151}</style></head><body><div class='wrap'><h1>Marzban IP Guard Console</h1><div class='card'><div class='row'><input id='apiKey' placeholder='X-Api-Key'><button onclick='refreshAll()'>Refresh</button><button class='secondary' onclick='checkHealth()'>Health</button></div><div class='status' id='status'>Ready</div></div><div class='card'><h2>Policy</h2><div class='row'><input id='p_enabled' placeholder='enabled'><input id='p_max_ips' placeholder='max_ips'><input id='p_check' placeholder='check_interval_seconds'><input id='p_window' placeholder='observation_window_seconds'></div><div class='row'><input id='p_recover' placeholder='recover_after_minutes'><input id='p_batch' placeholder='collect_batch_size'><input id='p_flush' placeholder='collect_flush_seconds'><input id='p_retention' placeholder='observation_retention_days'></div><div class='row'><select id='p_action'><option value='disable'>disable</option></select><button onclick='savePolicy()'>Save Policy</button></div><pre id='policyOut'></pre></div><div class='card'><h2>Whitelist Upsert</h2><div class='row'><input id='w_username' placeholder='username'><input id='w_user_id' placeholder='user_id'><input id='w_enabled' placeholder='enabled'><input id='w_override' placeholder='max_ips_override'><input id='w_note' placeholder='note'><button onclick='upsertWhitelist()'>Upsert</button></div><pre id='whitelistOut'></pre></div><div class='card'><h2>Manual Restore</h2><div class='row'><input id='r_username' placeholder='username'><input id='r_user_id' placeholder='user_id'><button onclick='manualRestore()'>Restore</button></div><pre id='restoreOut'></pre></div><div class='card'><h2>Events</h2><div class='row'><input id='e_limit' value='100'><button onclick='loadEvents()'>Load Events</button></div><pre id='eventsOut'></pre></div></div><script>function H(){const k=document.getElementById('apiKey').value.trim();return k?{'X-Api-Key':k,'Content-Type':'application/json'}:{'Content-Type':'application/json'}}function S(m){document.getElementById('status').textContent=m}function P(v){return JSON.stringify(v,null,2)}async function A(p,o={}){const r=await fetch(p,{...o,headers:{...H(),...(o.headers||{})}});const t=await r.text();let d;try{d=JSON.parse(t)}catch{d=t}if(!r.ok)throw new Error(typeof d==='string'?d:P(d));return d}async function checkHealth(){try{S('Checking health...');const d=await A('/health');S('Healthy: '+d.ts)}catch(e){S('Health failed: '+e.message)}}async function loadPolicy(){const d=await A('/policy');document.getElementById('policyOut').textContent=P(d);document.getElementById('p_enabled').value=d.enabled;document.getElementById('p_max_ips').value=d.max_ips;document.getElementById('p_check').value=d.check_interval_seconds;document.getElementById('p_window').value=d.observation_window_seconds;document.getElementById('p_recover').value=d.recover_after_minutes;document.getElementById('p_batch').value=d.collect_batch_size;document.getElementById('p_flush').value=d.collect_flush_seconds;document.getElementById('p_retention').value=d.observation_retention_days;document.getElementById('p_action').value=d.violate_action}async function savePolicy(){const p={enabled:Number(document.getElementById('p_enabled').value),max_ips:Number(document.getElementById('p_max_ips').value),check_interval_seconds:Number(document.getElementById('p_check').value),observation_window_seconds:Number(document.getElementById('p_window').value),recover_after_minutes:Number(document.getElementById('p_recover').value),collect_batch_size:Number(document.getElementById('p_batch').value),collect_flush_seconds:Number(document.getElementById('p_flush').value),observation_retention_days:Number(document.getElementById('p_retention').value),violate_action:document.getElementById('p_action').value};const d=await A('/policy',{method:'PUT',body:JSON.stringify(p)});document.getElementById('policyOut').textContent=P(d);await loadPolicy();S('Policy saved')}async function upsertWhitelist(){const p={username:document.getElementById('w_username').value||null,user_id:document.getElementById('w_user_id').value?Number(document.getElementById('w_user_id').value):null,enabled:document.getElementById('w_enabled').value?Number(document.getElementById('w_enabled').value):1,max_ips_override:document.getElementById('w_override').value?Number(document.getElementById('w_override').value):null,note:document.getElementById('w_note').value||null};const d=await A('/whitelist',{method:'POST',body:JSON.stringify(p)});const w=await A('/whitelist');document.getElementById('whitelistOut').textContent=P({op:d,rows:w});S('Whitelist updated')}async function manualRestore(){const p={};const u=document.getElementById('r_username').value.trim();const i=document.getElementById('r_user_id').value.trim();if(u)p.username=u;if(i)p.user_id=Number(i);const d=await A('/manual-restore',{method:'POST',body:JSON.stringify(p)});document.getElementById('restoreOut').textContent=P(d);S('Restore done')}async function loadEvents(){const n=Number(document.getElementById('e_limit').value||100);const d=await A('/events?limit='+n);document.getElementById('eventsOut').textContent=P(d);S('Events loaded')}async function refreshAll(){try{S('Refreshing...');await loadPolicy();const w=await A('/whitelist');document.getElementById('whitelistOut').textContent=P(w);await loadEvents();S('Refresh done')}catch(e){S('Error: '+e.message)}}refreshAll();</script></body></html>"""


def create_web_app(
    db_cfg: DBConfig,
    api_key: str = "",
    marzban_api_cfg: Optional[MarzbanAPIConfig] = None,
) -> FastAPI:
    app = FastAPI(title="Marzban IP Guard API", version="safe-1.0")
    api_client = MarzbanAPIClient(marzban_api_cfg) if marzban_api_cfg else None

    def auth(x_api_key: str = Header(default="")):
        if api_key and x_api_key != api_key:
            raise HTTPException(status_code=401, detail="Unauthorized")

    @app.get("/", response_class=HTMLResponse)
    def ui():
        return UI_HTML

    @app.get("/health")
    def health(_: Any = Depends(auth)):
        return {"ok": True, "ts": utc_now_naive().isoformat()}

    @app.get("/policy")
    def get_policy(_: Any = Depends(auth)):
        conn = db_connect(db_cfg)
        try:
            return load_policy(conn).__dict__
        finally:
            conn.close()

    @app.put("/policy")
    def put_policy(payload: Dict[str, Any], _: Any = Depends(auth)):
        allowed = {
            "enabled",
            "max_ips",
            "check_interval_seconds",
            "observation_window_seconds",
            "recover_after_minutes",
            "collect_batch_size",
            "collect_flush_seconds",
            "observation_retention_days",
            "violate_action",
        }
        updates = {k: v for k, v in payload.items() if k in allowed}
        if not updates:
            raise HTTPException(status_code=400, detail="No valid fields")

        sets = [f"{k}=%s" for k in updates.keys()]
        values = list(updates.values()) + [utc_now_naive()]

        conn = db_connect(db_cfg)
        try:
            with conn.cursor() as cur:
                cur.execute(f"UPDATE ip_guard_policy SET {', '.join(sets)}, updated_at=%s WHERE id=1", values)
            conn.commit()
            return {"ok": True, "updated": updates}
        finally:
            conn.close()

    @app.get("/whitelist")
    def list_whitelist(_: Any = Depends(auth)):
        conn = db_connect(db_cfg)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM ip_guard_whitelist ORDER BY id DESC")
                return cur.fetchall()
        finally:
            conn.close()

    @app.post("/whitelist")
    def upsert_whitelist(payload: Dict[str, Any], _: Any = Depends(auth)):
        username = payload.get("username")
        user_id = payload.get("user_id")
        if not username and not user_id:
            raise HTTPException(status_code=400, detail="username or user_id required")

        enabled = int(payload.get("enabled", 1))
        max_ips_override = payload.get("max_ips_override")
        note = payload.get("note")
        now = utc_now_naive()

        conn = db_connect(db_cfg)
        try:
            with conn.cursor() as cur:
                if user_id:
                    cur.execute(
                        """
                        INSERT INTO ip_guard_whitelist (user_id, username, enabled, max_ips_override, note, created_at, updated_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE enabled=VALUES(enabled), max_ips_override=VALUES(max_ips_override), note=VALUES(note), updated_at=VALUES(updated_at)
                        """,
                        (int(user_id), username, enabled, max_ips_override, note, now, now),
                    )
                else:
                    cur.execute(
                        """
                        INSERT INTO ip_guard_whitelist (username, enabled, max_ips_override, note, created_at, updated_at)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE enabled=VALUES(enabled), max_ips_override=VALUES(max_ips_override), note=VALUES(note), updated_at=VALUES(updated_at)
                        """,
                        (username, enabled, max_ips_override, note, now, now),
                    )
            conn.commit()
            return {"ok": True}
        finally:
            conn.close()

    @app.post("/manual-restore")
    def manual_restore(payload: Dict[str, Any], _: Any = Depends(auth)):
        username = payload.get("username")
        user_id = payload.get("user_id")
        if not username and not user_id:
            raise HTTPException(status_code=400, detail="username or user_id required")

        conn = db_connect(db_cfg)
        try:
            with conn.cursor() as cur:
                if user_id:
                    cur.execute("SELECT id, username, status FROM users WHERE id=%s LIMIT 1", (int(user_id),))
                else:
                    cur.execute("SELECT id, username, status FROM users WHERE username=%s LIMIT 1", (username,))
                user = cur.fetchone()

            if not user:
                raise HTTPException(status_code=404, detail="user not found")

            recover_user(conn, user, manual=True, api_client=api_client)
            conn.commit()
            return {"ok": True, "user": user["username"]}
        finally:
            conn.close()

    @app.get("/events")
    def events(limit: int = 100, _: Any = Depends(auth)):
        n = min(max(1, int(limit)), 1000)
        conn = db_connect(db_cfg)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, user_id, username, event_type, details, created_at FROM ip_guard_log ORDER BY id DESC LIMIT %s",
                    (n,),
                )
                return cur.fetchall()
        finally:
            conn.close()

    @app.get("/states")
    def states(only_disabled: int = 0, _: Any = Depends(auth)):
        conn = db_connect(db_cfg)
        try:
            with conn.cursor() as cur:
                if int(only_disabled) == 1:
                    cur.execute(
                        """
                        SELECT u.id, u.username, u.status, s.last_seen_ip_count, s.disabled_by_guard,
                               s.disabled_at, s.recover_candidate_since, s.updated_at
                        FROM users u
                        JOIN ip_guard_state s ON s.user_id=u.id
                        WHERE s.disabled_by_guard=1
                        ORDER BY s.updated_at DESC
                        """
                    )
                else:
                    cur.execute(
                        """
                        SELECT u.id, u.username, u.status, s.last_seen_ip_count, s.disabled_by_guard,
                               s.disabled_at, s.recover_candidate_since, s.updated_at
                        FROM users u
                        JOIN ip_guard_state s ON s.user_id=u.id
                        ORDER BY s.updated_at DESC
                        LIMIT 2000
                        """
                    )
                return cur.fetchall()
        finally:
            conn.close()

    return app


def cmd_init_db(args: argparse.Namespace):
    cfg = load_db_config(args)
    conn = db_connect(cfg)
    try:
        init_db(conn)
        print("[ok] init-db done")
    finally:
        conn.close()


def cmd_collect_once(args: argparse.Namespace):
    cfg = load_db_config(args)
    conn = db_connect(cfg)
    try:
        init_db(conn)
        policy = load_policy(conn)
        source = args.source or f"node-{socket.gethostname()}"
        paths = [p.strip() for p in args.log_paths.split(",") if p.strip()]
        if not paths:
            raise RuntimeError("--log-paths required")
        stats = collect_once(
            conn,
            source=source,
            log_paths=paths,
            node_id=args.node_id,
            batch_size=args.batch_size or int(policy.collect_batch_size),
        )
        print(f"[collector] source={source} scanned={stats['scanned']} inserted={stats['inserted']}")
    finally:
        conn.close()


def cmd_collect_loop(args: argparse.Namespace):
    cfg = load_db_config(args)
    interval = max(10, int(args.interval_seconds or 60))
    while True:
        conn = db_connect(cfg)
        try:
            init_db(conn)
            policy = load_policy(conn)
            source = args.source or f"node-{socket.gethostname()}"
            paths = [p.strip() for p in args.log_paths.split(",") if p.strip()]
            if not paths:
                raise RuntimeError("--log-paths required")
            stats = collect_once(
                conn,
                source=source,
                log_paths=paths,
                node_id=args.node_id,
                batch_size=args.batch_size or int(policy.collect_batch_size),
            )
            print(f"[collector] source={source} scanned={stats['scanned']} inserted={stats['inserted']}")
        except KeyboardInterrupt:
            return
        except Exception as e:
            print(f"[collector][err] {e}")
        finally:
            conn.close()
        time.sleep(interval)


def cmd_enforce_once(args: argparse.Namespace):
    cfg = load_db_config(args)
    api_cfg = load_marzban_api_config(args)
    api_client = MarzbanAPIClient(api_cfg) if api_cfg else None
    conn = db_connect(cfg)
    try:
        init_db(conn)
        pol = load_policy(conn)
        stats = enforce_once_with_client(conn, pol, api_client=api_client)
        print(json.dumps(stats, ensure_ascii=True))
    finally:
        conn.close()


def cmd_enforce_loop(args: argparse.Namespace):
    cfg = load_db_config(args)
    api_cfg = load_marzban_api_config(args)
    EnforcerLoop(cfg, api_cfg=api_cfg).run()


def cmd_manual_restore(args: argparse.Namespace):
    cfg = load_db_config(args)
    api_cfg = load_marzban_api_config(args)
    api_client = MarzbanAPIClient(api_cfg) if api_cfg else None
    conn = db_connect(cfg)
    try:
        with conn.cursor() as cur:
            if args.user_id is not None:
                cur.execute("SELECT id, username, status FROM users WHERE id=%s LIMIT 1", (args.user_id,))
            else:
                cur.execute("SELECT id, username, status FROM users WHERE username=%s LIMIT 1", (args.username,))
            user = cur.fetchone()
        if not user:
            raise RuntimeError("user not found")
        recover_user(conn, user, manual=True, api_client=api_client)
        conn.commit()
        print(f"[ok] manual restore: {user['username']}")
    finally:
        conn.close()


def cmd_serve(args: argparse.Namespace):
    cfg = load_db_config(args)
    api_cfg = load_marzban_api_config(args)
    conn = db_connect(cfg)
    try:
        init_db(conn)
    finally:
        conn.close()

    app = create_web_app(cfg, api_key=args.web_api_key or "", marzban_api_cfg=api_cfg)
    uvicorn.run(app, host=args.web_host, port=int(args.web_port), log_level="info")


def cmd_all_control(args: argparse.Namespace):
    cfg = load_db_config(args)
    api_cfg = load_marzban_api_config(args)
    conn = db_connect(cfg)
    try:
        init_db(conn)
    finally:
        conn.close()

    # 主控一体模式：仅判定 + web，不包含采集
    import threading

    t = threading.Thread(target=cmd_enforce_loop, args=(args,), daemon=True)
    t.start()

    app = create_web_app(cfg, api_key=args.web_api_key or "", marzban_api_cfg=api_cfg)
    uvicorn.run(app, host=args.web_host, port=int(args.web_port), log_level="info")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Marzban IP Guard (safe architecture)")
    p.add_argument("--env-file", default=None, help=".env path")
    p.add_argument("--sqlalchemy-database-url", default=None, help="override db url")
    p.add_argument("--marzban-api-base", default=None, help="Marzban API base, e.g. http://127.0.0.1:8000/api")
    p.add_argument("--marzban-admin-username", default=None, help="Marzban admin username for API actions")
    p.add_argument("--marzban-admin-password", default=None, help="Marzban admin password for API actions")
    p.add_argument("--marzban-api-timeout", type=int, default=None, help="Marzban API timeout seconds")
    p.add_argument("--marzban-api-insecure", action="store_true", help="Disable TLS verify when API base is https")

    sp = p.add_subparsers(dest="cmd", required=True)

    p_init = sp.add_parser("init-db")
    p_init.set_defaults(func=cmd_init_db)

    p_collect_once = sp.add_parser("collect-once", help="node-side: collect one pass from local log file")
    p_collect_once.add_argument("--log-paths", required=True, help="comma-separated log paths")
    p_collect_once.add_argument("--source", default=None, help="source name, default node-<hostname>")
    p_collect_once.add_argument("--node-id", type=int, default=None, help="optional node id for trace")
    p_collect_once.add_argument("--batch-size", type=int, default=None)
    p_collect_once.set_defaults(func=cmd_collect_once)

    p_collect_loop = sp.add_parser("collect-loop", help="node-side: continuous collection")
    p_collect_loop.add_argument("--log-paths", required=True, help="comma-separated log paths")
    p_collect_loop.add_argument("--source", default=None, help="source name, default node-<hostname>")
    p_collect_loop.add_argument("--node-id", type=int, default=None, help="optional node id for trace")
    p_collect_loop.add_argument("--batch-size", type=int, default=None)
    p_collect_loop.add_argument("--interval-seconds", type=int, default=60)
    p_collect_loop.set_defaults(func=cmd_collect_loop)

    p_enf_once = sp.add_parser("enforce-once", help="control-side: run one enforcement pass")
    p_enf_once.set_defaults(func=cmd_enforce_once)

    p_enf_loop = sp.add_parser("enforce-loop", help="control-side: run periodic enforcement")
    p_enf_loop.set_defaults(func=cmd_enforce_loop)

    p_mr = sp.add_parser("manual-restore")
    g = p_mr.add_mutually_exclusive_group(required=True)
    g.add_argument("--username", default=None)
    g.add_argument("--user-id", type=int, default=None)
    p_mr.set_defaults(func=cmd_manual_restore)

    p_web = sp.add_parser("serve", help="control-side: web console only")
    p_web.add_argument("--web-host", default="127.0.0.1")
    p_web.add_argument("--web-port", type=int, default=8010)
    p_web.add_argument("--web-api-key", default=os.getenv("IP_GUARD_WEB_API_KEY", ""))
    p_web.set_defaults(func=cmd_serve)

    p_all = sp.add_parser("all-control", help="control-side: enforcer + web")
    p_all.add_argument("--web-host", default="127.0.0.1")
    p_all.add_argument("--web-port", type=int, default=8010)
    p_all.add_argument("--web-api-key", default=os.getenv("IP_GUARD_WEB_API_KEY", ""))
    p_all.set_defaults(func=cmd_all_control)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

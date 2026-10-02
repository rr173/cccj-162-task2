"""顺序化安全事件日志。

授权失败 (撤销/超期/伪造/跨作业凭证等) 统一写入该日志:

  * 每个事件携带全局单调递增的 ``seq``, 写入顺序即查询顺序 (顺序化);
  * ``detail`` 绝不包含凭证原文, 仅保留 sha256 指纹 (前 12 位) 供关联追踪;
  * 配置 ``data_dir`` 后以 JSONL 追加落盘 (flush + fsync), 服务重启后
    节点进度页面与恢复验证报告仍可查询这些事件;
  * 未配置路径时退化为纯内存日志 (单元测试用), 接口完全一致。
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time

#: 授权失败事件类型 (detail.reason 给出稳定分类)
AUTH_FAILED = "auth_failed"

EVENTS_FILENAME = "security_events.jsonl"


def token_fingerprint(token: str | None) -> str | None:
    """凭证的稳定不可逆指纹; 事件与日志中绝不出现凭证原文。"""
    if not token:
        return None
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


class SecurityEventLog:
    """追加式、线程安全、可持久化的顺序事件日志。"""

    def __init__(self, path: str | None = None):
        self._lock = threading.Lock()
        self._path = path
        self._events: list[dict] = []
        self._fh = None
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            self._load()
            self._fh = open(path, "a", encoding="utf-8")

    @classmethod
    def in_dir(cls, data_dir: str) -> "SecurityEventLog":
        return cls(os.path.join(data_dir, EVENTS_FILENAME))

    # ------------------------------------------------------------- persistence
    def _load(self) -> None:
        """启动时回放既有事件; 跳过截断/损坏行, 不阻塞服务恢复。"""
        try:
            with open(self._path, "r", encoding="utf-8") as fh:  # type: ignore[arg-type]
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(ev, dict) and isinstance(ev.get("seq"), int):
                        self._events.append(ev)
        except FileNotFoundError:
            pass
        self._events.sort(key=lambda e: e["seq"])

    # --------------------------------------------------------------- record
    def record(
        self,
        *,
        job_id: str,
        event: str,
        detail: dict,
        ts: float | None = None,
    ) -> dict:
        """追加一个事件, 返回带单调 ``seq`` 的完整记录。"""
        with self._lock:
            seq = self._events[-1]["seq"] + 1 if self._events else 1
            ev = {
                "seq": seq,
                "ts": ts if ts is not None else time.time(),
                "job_id": job_id,
                "event": event,
                "detail": detail,
            }
            if self._fh is not None:
                self._fh.write(
                    json.dumps(ev, ensure_ascii=False, sort_keys=True) + "\n"
                )
                self._fh.flush()
                os.fsync(self._fh.fileno())
            self._events.append(ev)
            return ev

    # ---------------------------------------------------------------- query
    def for_job(self, job_id: str, limit: int | None = None) -> list[dict]:
        """按 seq 升序返回某作业的事件 (重启后历史事件仍在)。"""
        with self._lock:
            evs = [dict(e) for e in self._events if e["job_id"] == job_id]
        if limit is not None:
            evs = evs[-limit:]
        return evs

    def all(self) -> list[dict]:
        with self._lock:
            return [dict(e) for e in self._events]

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                self._fh.close()
                self._fh = None

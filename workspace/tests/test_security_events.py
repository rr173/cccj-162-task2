"""授权失败的统一处理: 稳定错误 + 顺序化安全事件 (不含凭证原文)
+ 并发拒绝不产生结果条目 + 服务重启后页面/验证报告仍可查询。"""

import base64
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from hpc_cr import JobManager
from hpc_cr.api import build_server
from hpc_cr.epochs import Scheduler
from hpc_cr.errors import FenceViolation, InvalidToken
from hpc_cr.events import EVENTS_FILENAME
from hpc_cr.security import Signer

FORGED_TOKEN = "v1.Zm9yZ2VkLXBheWxvYWQ.deadbeef"


def make_mgr(data_dir=None, secret="sec-secret"):
    mgr = JobManager(Scheduler(Signer(secret)), data_dir=data_dir)
    mgr.create_job(name="sec", world_size=2,
                   rank_nodes={0: "a", 1: "b"}, job_id="sec-1")
    return mgr


class AuthFailureEventTest(unittest.TestCase):
    def setUp(self):
        self.mgr = make_mgr()
        self.job = self.mgr.get("sec-1")

    def _append(self, token, output_id="o1", data=b"x"):
        return self.mgr.append_output(
            "sec-1", lease_token=token, output_id=output_id, data=data)

    def _events(self, job_id="sec-1"):
        return self.mgr.security_log.for_job(job_id)

    def test_forged_token_stable_error_and_event_without_plaintext(self):
        with self.assertRaises(InvalidToken) as ctx:
            self._append(FORGED_TOKEN)
        exc = ctx.exception
        # 稳定错误: 状态码 + error code + 机器可读 reason
        self.assertEqual(exc.http_status, 401)
        self.assertEqual(exc.to_dict()["error"], "invalid_token")
        self.assertEqual(exc.to_dict()["reason"], "forged")

        events = self._events()
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event"], "auth_failed")
        self.assertEqual(ev["seq"], 1)
        self.assertEqual(ev["detail"]["operation"], "append_output")
        self.assertEqual(ev["detail"]["reason"], "forged")
        self.assertEqual(ev["detail"]["http_status"], 401)
        # 事件不含凭证原文, 只有不可逆指纹
        self.assertNotIn(FORGED_TOKEN, json.dumps(ev, ensure_ascii=False))
        self.assertTrue(ev["detail"]["token_fingerprint"])
        self.assertNotEqual(ev["detail"]["token_fingerprint"], FORGED_TOKEN)
        # 被拒绝的请求不产生任何结果条目
        self.assertEqual(self.mgr.list_outputs("sec-1"), [])

    def test_malformed_and_missing_token_classified(self):
        with self.assertRaises(InvalidToken) as ctx:
            self._append("garbage-no-dots")
        self.assertEqual(ctx.exception.reason, "malformed")
        with self.assertRaises(InvalidToken) as ctx:
            self._append(None)
        self.assertEqual(ctx.exception.reason, "missing_token")
        reasons = [e["detail"]["reason"] for e in self._events()]
        self.assertEqual(reasons, ["malformed", "missing_token"])

    def test_revoked_lease_recorded(self):
        tok = self.job.leases.current().token
        self.mgr.preempt("sec-1")  # 抢占即吊销 gen0 租约
        with self.assertRaises(FenceViolation) as ctx:
            self._append(tok)
        self.assertEqual(ctx.exception.http_status, 412)
        self.assertEqual(ctx.exception.to_dict()["reason"], "revoked")
        ev = self._events()[-1]
        self.assertEqual(ev["detail"]["reason"], "revoked")
        self.assertEqual(ev["detail"]["error_code"], "fence_violation")
        # 原有内存审计仍保留栅栏记录 (向后兼容)
        self.assertIn("output_fenced",
                      [a["event"] for a in self.job.audit])
        self.assertEqual(self.mgr.list_outputs("sec-1"), [])

    def test_expired_lease_recorded(self):
        mgr = JobManager(Scheduler(Signer("sec-secret")))
        mgr.create_job(name="ttl", world_size=1, job_id="ttl-1",
                       lease_ttl=0.05)
        tok = mgr.get("ttl-1").leases.current().token
        time.sleep(0.08)
        with self.assertRaises(FenceViolation) as ctx:
            mgr.append_output("ttl-1", lease_token=tok,
                              output_id="o", data=b"x")
        self.assertEqual(ctx.exception.reason, "expired")
        self.assertEqual(mgr.security_log.for_job("ttl-1")[-1]
                         ["detail"]["reason"], "expired")

    def test_cross_job_lease_recorded(self):
        self.mgr.create_job(name="other", world_size=1, job_id="other-1")
        other_tok = self.mgr.get("other-1").leases.current().token
        with self.assertRaises(FenceViolation) as ctx:
            self._append(other_tok)
        self.assertEqual(ctx.exception.reason, "cross_job")
        ev = self._events()[-1]
        self.assertEqual(ev["detail"]["reason"], "cross_job")
        self.assertEqual(ev["job_id"], "sec-1")

    def test_epoch_token_failures_recorded_with_operation(self):
        self.mgr.create_job(name="other", world_size=1, job_id="other-1")
        other_pre = self.mgr.preempt("other-1")
        self.mgr.preempt("sec-1")
        with self.assertRaises(FenceViolation) as ctx:
            self.mgr.commit_checkpoint(
                "sec-1", epoch_token=other_pre["epoch_token"])
        self.assertEqual(ctx.exception.reason, "cross_job")
        with self.assertRaises(InvalidToken):
            self.mgr.upload_shard(
                "sec-1", epoch_token=None, rank=0, index=0, node="a",
                input_pos=1, data=b"x")
        ops = [(e["detail"]["operation"], e["detail"]["reason"])
               for e in self._events()]
        self.assertIn(("commit_checkpoint", "cross_job"), ops)
        self.assertIn(("upload_shard", "missing_token"), ops)

    def test_concurrent_rejections_add_no_output_entries(self):
        tok = self.job.leases.current().token
        self.mgr.preempt("sec-1")  # 吊销租约, 之后全部写入必被拒
        barrier = threading.Barrier(8)
        errors = []

        def bad_writer():
            barrier.wait()
            try:
                self._append(tok, output_id="same-out")
            except FenceViolation as exc:
                errors.append(exc.reason)

        ts = [threading.Thread(target=bad_writer) for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()

        self.assertEqual(errors, ["revoked"] * 8)
        # 重复并发请求不增加结果条目
        self.assertEqual(self.mgr.list_outputs("sec-1"), [])
        # 每次拒绝各落一条事件, seq 单调且唯一 (顺序化)
        events = self._events()
        self.assertEqual(len(events), 8)
        seqs = [e["seq"] for e in events]
        self.assertEqual(seqs, sorted(seqs))
        self.assertEqual(len(set(seqs)), 8)


class RestartPersistenceTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="hpc-cr-events-")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _run_restore_flow(self, mgr):
        pre = mgr.preempt("sec-1", grace_seconds=60)
        token = pre["epoch_token"]
        for r, node in ((0, "a"), (1, "b")):
            mgr.upload_shard("sec-1", epoch_token=token, rank=r, index=0,
                             node=node, input_pos=10 + r,
                             data=f"shard-{r}".encode())
        mgr.commit_checkpoint("sec-1", epoch_token=token)
        mgr.confirm_release("sec-1", epoch_token=token)
        return mgr.restore("sec-1", generation=1)

    def test_events_survive_restart_and_reach_page_and_report(self):
        mgr1 = make_mgr(self.dir)
        old_tok = mgr1.get("sec-1").leases.current().token
        mgr1.preempt("sec-1")  # 吊销 old_tok
        with self.assertRaises(InvalidToken):
            mgr1.append_output("sec-1", lease_token=FORGED_TOKEN,
                               output_id="o", data=b"x")
        with self.assertRaises(FenceViolation):
            mgr1.append_output("sec-1", lease_token=old_tok,
                               output_id="o", data=b"x")
        mgr1.close()

        # 落盘文件不含任何凭证原文
        log_path = os.path.join(self.dir, EVENTS_FILENAME)
        with open(log_path, encoding="utf-8") as fh:
            raw = fh.read()
        self.assertNotIn(FORGED_TOKEN, raw)
        self.assertNotIn(old_tok, raw)

        # 模拟服务重启: 新 JobManager 挂同一 data_dir, 作业按固定 id 重建
        mgr2 = make_mgr(self.dir)
        events = mgr2.security_log.for_job("sec-1")
        self.assertEqual([e["seq"] for e in events], [1, 2])
        self.assertEqual([e["detail"]["reason"] for e in events],
                         ["forged", "revoked"])

        # 进度页面数据仍可查询重启前的事件
        page = mgr2.progress_page_data("sec-1")
        self.assertEqual(
            [e["detail"]["reason"] for e in page["security_events"]],
            ["forged", "revoked"])

        # 恢复验证报告同样携带这些事件
        report = self._run_restore_flow(mgr2)
        self.assertTrue(report.success)
        self.assertEqual(
            [e["detail"]["reason"] for e in report.security_events],
            ["forged", "revoked"])
        md = report.to_markdown()
        self.assertIn("安全事件", md)
        self.assertNotIn(old_tok, md)
        # 经 API 暴露的报告 dict 也包含事件
        rep = mgr2.last_restore_report("sec-1").to_dict()
        self.assertEqual(len(rep["security_events"]), 2)
        mgr2.close()


class HttpSecurityEventTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = build_server(
            JobManager(Scheduler(Signer("http-sec-secret"))),
            host="127.0.0.1", port=0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def _req(self, method, path, body=None, headers=None):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json",
                                              **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_auth_failures_visible_over_http(self):
        st, _ = self._req("POST", "/api/jobs", {
            "job_id": "sec-http", "name": "sec", "world_size": 2,
            "rank_nodes": {0: "h0", 1: "h1"}})
        self.assertEqual(st, 201)

        # 伪造凭证 -> 稳定 401 错误体 (error + reason)
        st, err = self._req("POST", "/api/jobs/sec-http", {
            "action": "append_output", "output_id": "x",
            "data_b64": base64.b64encode(b"nope").decode()},
            headers={"X-Lease-Token": FORGED_TOKEN})
        self.assertEqual(st, 401)
        self.assertEqual(err["error"], "invalid_token")
        self.assertEqual(err["reason"], "forged")

        # 缺失凭证 -> 401 missing_token, 同样落安全事件
        st, err = self._req("POST", "/api/jobs/sec-http", {
            "action": "append_output", "output_id": "x",
            "data_b64": base64.b64encode(b"nope").decode()})
        self.assertEqual(st, 401)
        self.assertEqual(err["reason"], "missing_token")

        # 页面聚合数据可查询事件, 且不含凭证原文
        st, prog = self._req("GET", "/api/jobs/sec-http/progress.json")
        self.assertEqual(st, 200)
        self.assertEqual(
            [e["detail"]["reason"] for e in prog["security_events"]],
            ["forged", "missing_token"])
        self.assertNotIn(FORGED_TOKEN, json.dumps(prog))

        # HTML 页面渲染安全事件区块
        with urllib.request.urlopen(
                f"http://127.0.0.1:{self.port}/ui/jobs/sec-http") as r:
            html = r.read().decode()
        self.assertIn("安全事件", html)
        self.assertIn("forged", html)
        self.assertNotIn(FORGED_TOKEN, html)

        # 走完恢复流程, 验证报告 (JSON) 携带安全事件
        st, pre = self._req("POST", "/api/jobs/sec-http",
                            {"action": "preempt", "grace_seconds": 60})
        token = pre["epoch_token"]
        for r in (0, 1):
            self._req("POST", "/api/jobs/sec-http", {
                "action": "upload_shard", "rank": r, "index": 0,
                "node": f"h{r}", "input_pos": r,
                "data_b64": base64.b64encode(f"s{r}".encode()).decode()},
                headers={"X-Epoch-Token": token})
        self._req("POST", "/api/jobs/sec-http",
                  {"action": "commit_checkpoint"},
                  headers={"X-Epoch-Token": token})
        self._req("POST", "/api/jobs/sec-http",
                  {"action": "confirm_release"},
                  headers={"X-Epoch-Token": token})
        st, rep = self._req("POST", "/api/jobs/sec-http",
                            {"action": "restore", "generation": 1})
        self.assertEqual(st, 200)
        self.assertTrue(rep["success"])
        self.assertEqual(
            [e["detail"]["reason"] for e in rep["security_events"]],
            ["forged", "missing_token"])

        st, rep = self._req("GET", "/api/jobs/sec-http/restore/report")
        self.assertEqual(st, 200)
        self.assertEqual(len(rep["security_events"]), 2)


if __name__ == "__main__":
    unittest.main()

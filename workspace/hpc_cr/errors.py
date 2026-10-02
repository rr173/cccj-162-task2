"""服务端错误类型。

每个领域错误携带 HTTP 状态码与稳定的机器可读 ``reason`` 分类,
供 API 层统一映射为 JSON 错误响应, 并让安全事件日志按固定类别
(撤销/超期/伪造/跨作业凭证等) 归档授权失败。
"""


class CpError(Exception):
    """所有领域错误的基类。"""

    http_status = 500
    error_code = "internal_error"
    reason = "internal_error"

    def __init__(self, message: str = "", *, reason: str | None = None):
        super().__init__(message)
        if reason is not None:
            self.reason = reason

    def to_dict(self):
        return {
            "error": self.error_code,
            "reason": self.reason,
            "message": str(self),
        }


class NotFound(CpError):
    http_status = 404
    error_code = "not_found"
    reason = "not_found"


class Conflict(CpError):
    """状态冲突: 重复检查点 / 重复分片 / 状态机不允许的迁移。"""

    http_status = 409
    error_code = "conflict"
    reason = "conflict"


class FenceViolation(CpError):
    """栅栏拒绝: 旧纪元/旧代际令牌的迟到写入。

    具体分类见抛出处的 ``reason``: ``revoked`` (租约已撤销)、
    ``expired`` (租约/令牌超期)、``cross_job`` (跨作业凭证)、
    ``stale_generation`` / ``stale_epoch`` (旧代际/旧纪元)。
    """

    http_status = 412
    error_code = "fence_violation"
    reason = "fence_violation"


class InvalidToken(CpError):
    """凭证本身无效: ``missing_token`` / ``malformed`` / ``forged`` /
    ``wrong_token_type`` / ``unknown_lease``。"""

    http_status = 401
    error_code = "invalid_token"
    reason = "invalid_token"


class ValidationError(CpError):
    http_status = 400
    error_code = "validation_error"
    reason = "validation_error"

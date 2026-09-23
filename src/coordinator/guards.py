"""
Guard Rails — Các cơ chế bảo vệ hardcoded.

Đây là lớp bảo vệ KHÔNG phụ thuộc LLM.
Khi guard rail can thiệp, nó OVERRIDE quyết định LLM.

Classes:
    - CircuitBreaker: Ngắt mạch khi failure rate quá cao
    - LLMCallLimiter: Giới hạn tổng số LLM API calls
    - TarpitDetector: Phát hiện honeypot/tarpit chậm response
"""

import time
import logging
from collections import deque
from typing import Optional

logger = logging.getLogger(__name__)


class CircuitBreaker:
    """
    Circuit Breaker — Ngắt mạch khi failure rate vượt ngưỡng.

    3 trạng thái:
        - CLOSED (bình thường): Request được phép đi qua
        - OPEN (ngắt mạch): Request bị chặn, chờ recovery
        - HALF_OPEN (thử lại): Cho 1 request qua để test

    Khi failure_rate > threshold trong sliding window → OPEN.
    Sau recovery_timeout → HALF_OPEN → thành công → CLOSED / thất bại → OPEN.
    """

    def __init__(
        self,
        name: str,
        failure_threshold: float = 0.5,
        window_size: int = 10,
        recovery_timeout: float = 60.0,
    ):
        """
        Args:
            name: Tên circuit breaker (thường = agent name)
            failure_threshold: Tỷ lệ failure tối đa (0.0-1.0)
            window_size: Kích thước sliding window
            recovery_timeout: Thời gian chờ trước khi thử lại (giây)
        """
        self.name = name
        self.failure_threshold = failure_threshold
        self.window_size = window_size
        self.recovery_timeout = recovery_timeout

        self._window: deque = deque(maxlen=window_size)
        self._state: str = "closed"     # "closed" | "open" | "half_open"
        self._opened_at: Optional[float] = None

    @property
    def state(self) -> str:
        """Trạng thái hiện tại, tự động chuyển OPEN → HALF_OPEN sau timeout."""
        if self._state == "open" and self._opened_at:
            elapsed = time.time() - self._opened_at
            if elapsed >= self.recovery_timeout:
                self._state = "half_open"
                logger.info(
                    f"[CircuitBreaker:{self.name}] OPEN → HALF_OPEN "
                    f"(after {elapsed:.0f}s)"
                )
        return self._state

    @property
    def is_open(self) -> bool:
        """True nếu circuit đang OPEN (ngắt mạch)."""
        return self.state == "open"

    @property
    def is_closed(self) -> bool:
        """True nếu circuit đang CLOSED (bình thường)."""
        return self.state == "closed"

    def record_success(self):
        """Ghi nhận một lần thành công."""
        self._window.append(True)

        if self._state == "half_open":
            # Thành công trong HALF_OPEN → đóng lại
            self._state = "closed"
            self._opened_at = None
            logger.info(f"[CircuitBreaker:{self.name}] HALF_OPEN → CLOSED (success)")

    def record_failure(self):
        """Ghi nhận một lần thất bại."""
        self._window.append(False)

        if self._state == "half_open":
            # Thất bại trong HALF_OPEN → mở lại
            self._state = "open"
            self._opened_at = time.time()
            logger.warning(
                f"[CircuitBreaker:{self.name}] HALF_OPEN → OPEN (failed again)"
            )
            return

        # Kiểm tra failure rate trong window
        if len(self._window) >= 3:  # Cần ít nhất 3 entries
            failure_count = sum(1 for x in self._window if not x)
            failure_rate = failure_count / len(self._window)

            if failure_rate > self.failure_threshold:
                self._state = "open"
                self._opened_at = time.time()
                logger.warning(
                    f"[CircuitBreaker:{self.name}] CLOSED → OPEN "
                    f"(failure_rate={failure_rate:.2f} > {self.failure_threshold})"
                )

    def reset(self):
        """Reset circuit breaker về trạng thái ban đầu."""
        self._window.clear()
        self._state = "closed"
        self._opened_at = None
        logger.info(f"[CircuitBreaker:{self.name}] RESET → CLOSED")


class LLMCallLimiter:
    """
    LLM Call Limiter — Giới hạn tổng số LLM API calls.

    Ngăn hệ thống gọi LLM quá nhiều (tốn chi phí + rate limit).
    Khi vượt quota, raise LLMQuotaExhaustedError.
    """

    def __init__(self, max_calls: int = 50):
        """
        Args:
            max_calls: Số lượng LLM calls tối đa cho toàn pipeline
        """
        self.max_calls = max_calls
        self._call_count = 0

    @property
    def calls_used(self) -> int:
        return self._call_count

    @property
    def calls_remaining(self) -> int:
        return max(0, self.max_calls - self._call_count)

    @property
    def is_exhausted(self) -> bool:
        return self._call_count >= self.max_calls

    def record_call(self):
        """Ghi nhận một LLM call. Raise nếu vượt quota."""
        self._call_count += 1

        if self._call_count > self.max_calls:
            logger.error(
                f"[LLMLimit] Quota exhausted: {self._call_count}/{self.max_calls}"
            )
            raise LLMQuotaExhaustedError(
                f"LLM call limit exceeded: {self._call_count}/{self.max_calls}"
            )

        if self.calls_remaining <= 5:
            logger.warning(
                f"[LLMLimit] Low quota: {self.calls_remaining} calls remaining"
            )

    def reset(self):
        """Reset counter."""
        self._call_count = 0


class LLMQuotaExhaustedError(Exception):
    """Raised khi LLM call quota bị vượt."""
    pass


class TarpitDetector:
    """
    Tarpit Detector — Phát hiện honeypot/tarpit.

    Tarpit là kỹ thuật phòng thủ giữ kết nối mở rất lâu,
    khiến scanner tiêu tốn tài nguyên vô ích.

    Phát hiện dựa trên:
        - Average response time vượt ngưỡng liên tục
        - Trend tăng dần (mỗi request chậm hơn)
    """

    def __init__(
        self,
        time_threshold: float = 10.0,
        min_samples: int = 5,
        trend_threshold: float = 1.5,
    ):
        """
        Args:
            time_threshold: Ngưỡng response time trung bình (giây)
            min_samples: Số mẫu tối thiểu để đánh giá
            trend_threshold: Hệ số trend (nửa sau / nửa đầu)
        """
        self.time_threshold = time_threshold
        self.min_samples = min_samples
        self.trend_threshold = trend_threshold

        self._response_times: list[float] = []
        self._detected = False

    def record_response_time(self, time_seconds: float):
        """Ghi nhận response time."""
        self._response_times.append(time_seconds)

    def is_tarpit_detected(self) -> bool:
        """
        Kiểm tra xem có đang bị tarpit không.

        Returns:
            True nếu phát hiện tarpit pattern
        """
        if self._detected:
            return True

        if len(self._response_times) < self.min_samples:
            return False

        # Check 1: Average response time vượt ngưỡng
        avg_time = sum(self._response_times) / len(self._response_times)
        if avg_time < self.time_threshold:
            return False

        # Check 2: Trend tăng dần (nửa sau chậm hơn nửa đầu)
        mid = len(self._response_times) // 2
        first_half_avg = (
            sum(self._response_times[:mid]) / mid if mid > 0 else 0
        )
        second_half_avg = (
            sum(self._response_times[mid:]) / (len(self._response_times) - mid)
            if (len(self._response_times) - mid) > 0
            else 0
        )

        if first_half_avg > 0:
            trend_ratio = second_half_avg / first_half_avg
            if trend_ratio >= self.trend_threshold:
                self._detected = True
                logger.warning(
                    f"[TarpitDetector] TARPIT DETECTED — "
                    f"avg={avg_time:.2f}s, trend_ratio={trend_ratio:.2f}"
                )
                return True

        # Check 3: Average alone quá cao (> 2x threshold)
        if avg_time > self.time_threshold * 2:
            self._detected = True
            logger.warning(
                f"[TarpitDetector] TARPIT DETECTED — "
                f"avg={avg_time:.2f}s (>{self.time_threshold * 2:.1f}s)"
            )
            return True

        return False

    def reset(self):
        """Reset detector."""
        self._response_times.clear()
        self._detected = False

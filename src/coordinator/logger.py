"""
Logger Module — Theo dõi chi tiết hoạt động của các Agents & Coordinator.

Cung cấp các hàm log chuẩn hóa (Structured Logging):
- setup_agent_logger: Khởi tạo logger hệ thống (Console + File log)
- log_agent_start: Ghi log khi agent bắt đầu thực thi
- log_agent_progress: Ghi log tiến trình/mốc công việc của agent
- log_agent_success: Ghi log khi agent hoàn thành thành công
- log_agent_error: Ghi log khi agent gặp lỗi
- log_agent_skip: Ghi log khi agent bị bỏ qua (skip logic)
- log_decision: Ghi log quyết định điều hướng của LLM
- log_pipeline_summary: Ghi log tổng kết toàn bộ pipeline
"""

import logging
import sys
from pathlib import Path
from typing import Any, Dict, Optional

# Định dạng màu cho console
COLOR_RESET = "\033[0m"
COLOR_CYAN = "\033[36m"
COLOR_GREEN = "\033[32m"
COLOR_YELLOW = "\033[33m"
COLOR_RED = "\033[31m"
COLOR_MAGENTA = "\033[35m"
COLOR_BLUE = "\033[34m"


# Reconfigure sys.stdout / sys.stderr cho UTF-8 trên Windows nếu cần
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def setup_agent_logger(
    log_level: int = logging.INFO,
    log_to_file: bool = True,
    log_file_path: str = "logs/agent_activity.log",
) -> logging.Logger:
    """Khởi tạo và cấu hình logger chính cho dự án."""
    logger_inst = logging.getLogger("sentinel")
    logger_inst.setLevel(log_level)

    if logger_inst.handlers:
        return logger_inst

    # Console Handler với stream bọc UTF-8 errors='replace'
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    console_handler.setFormatter(console_formatter)
    logger_inst.addHandler(console_handler)

    # File Handler
    if log_to_file:
        try:
            log_dir = Path(log_file_path).parent
            log_dir.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file_path, encoding="utf-8", errors="replace")
            file_handler.setLevel(log_level)
            file_formatter = logging.Formatter(
                "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            file_handler.setFormatter(file_formatter)
            logger_inst.addHandler(file_handler)
        except Exception as e:
            logger_inst.warning(f"Không thể tạo file log: {e}")

    return logger_inst


agent_logger = setup_agent_logger()


def log_agent_start(agent_name: str, target: str, params: Optional[Dict[str, Any]] = None):
    """Ghi log bắt đầu chạy Agent."""
    param_str = f" | Params: {params}" if params else ""
    agent_logger.info(
        f"{COLOR_CYAN}[AGENT START]{COLOR_RESET} 🚀 {agent_name} -> Target: {target}{param_str}"
    )


def log_agent_progress(agent_name: str, step_description: str, details: Optional[Dict[str, Any]] = None):
    """Ghi log tiến trình thực thi của Agent."""
    detail_str = f" | Details: {details}" if details else ""
    agent_logger.info(
        f"{COLOR_BLUE}[AGENT PROGRESS]{COLOR_RESET} 🔄 [{agent_name}] {step_description}{detail_str}"
    )


def log_agent_success(agent_name: str, summary: str, metrics: Optional[Dict[str, Any]] = None):
    """Ghi log hoàn thành Agent thành công."""
    metrics_str = f" | Metrics: {metrics}" if metrics else ""
    agent_logger.info(
        f"{COLOR_GREEN}[AGENT SUCCESS]{COLOR_RESET} ✅ [{agent_name}] {summary}{metrics_str}"
    )


def log_agent_error(agent_name: str, error_msg: str, exception: Optional[Exception] = None):
    """Ghi log khi Agent gặp sự cố."""
    exc_str = f" | Exception: {exception}" if exception else ""
    agent_logger.error(
        f"{COLOR_RED}[AGENT ERROR]{COLOR_RESET} ❌ [{agent_name}] Lỗi: {error_msg}{exc_str}"
    )


def log_agent_skip(agent_name: str, reason: str):
    """Ghi log khi Agent bị bỏ qua."""
    agent_logger.warning(
        f"{COLOR_YELLOW}[AGENT SKIP]{COLOR_RESET} ⏭️ [{agent_name}] Đã bỏ qua. Lý do: {reason}"
    )


def log_decision(decision_point: str, action: str, reasoning: str, adjustments: Optional[Dict[str, Any]] = None):
    """Ghi log quyết định từ LLM Decision Engine."""
    adj_str = f" | Adjustments: {adjustments}" if adjustments else ""
    agent_logger.info(
        f"{COLOR_MAGENTA}[LLM DECISION]{COLOR_RESET} 🧠 Point: {decision_point} | Action: {action}\n"
        f"   └─ Lý do: {reasoning}{adj_str}"
    )


def log_pipeline_summary(session_id: str, target_url: str, duration_sec: float, stats: Dict[str, Any]):
    """Ghi log tổng kết toàn bộ pipeline."""
    agent_logger.info(
        f"\n============================================================\n"
        f"📊 PIPELINE SUMMARY — Session {session_id[:8]}...\n"
        f"Target: {target_url}\n"
        f"Thời gian chạy: {duration_sec:.2f}s\n"
        f"Thống kê kết quả: {stats}\n"
        f"============================================================"
    )

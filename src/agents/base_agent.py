"""
Base Autonomous Agent Module — Lớp cơ sở cho Sub-Agent tự chủ.

Cung cấp năng lực suy luận bằng LLM cho các Sub-Agent:
1. Đưa ra quyết định chọn Tool + Options từ ToolRegistry.
2. Cung cấp lý do chọn tool (tool_selection_reason) và lý do chọn option (options_selection_reason).
3. Thực thi tool và thu thập kết quả.
4. Tổng hợp báo cáo giải trình (subagent_justification) để Manager Agent (Coordinator) thẩm định.
"""

import json
import logging
from typing import Any, Dict, List, Optional
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

from src.coordinator.logger import agent_logger, COLOR_CYAN, COLOR_MAGENTA, COLOR_RESET
from src.tools.registry import ToolRegistry, default_registry

logger = logging.getLogger(__name__)


class BaseAutonomousAgent:
    """Sub-Agent tự chủ có khả năng suy luận chọn Tool & Giải trình lý do."""

    def __init__(
        self,
        agent_name: str,
        llm: Optional[ChatOpenAI] = None,
        tool_registry: Optional[ToolRegistry] = None,
        max_steps: int = 5,
    ):
        self.agent_name = agent_name
        self.llm = llm
        self.tool_registry = tool_registry or default_registry
        self.max_steps = max_steps

    def plan_tool_execution(
        self,
        task_directive: Dict[str, Any],
        available_tools: List[Dict[str, Any]],
        execution_history: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Gọi LLM để suy luận chọn Tool, cấu hình Options và giải trình lý do.
        """
        if not self.llm:
            # Fallback nếu LLM không khả dụng
            if available_tools:
                first_tool = available_tools[0]
                return {
                    "selected_tool": first_tool["name"],
                    "options": {},
                    "tool_selection_reason": f"Mặc định chọn tool '{first_tool['name']}' để thu thập thông tin cơ bản.",
                    "options_selection_reason": "Sử dụng tham số mặc định.",
                    "is_task_complete": len(execution_history) >= len(available_tools) - 1,
                }
            return {"selected_tool": "none", "options": {}, "is_task_complete": True}

        prompt = ChatPromptTemplate.from_messages([
            ("system",
             f"Bạn là {self.agent_name} — một Sub-Agent chuyên trách tự chủ.\n"
             "Nhiệm vụ của bạn là xem xét chỉ thị từ Manager, phân tích danh sách công cụ có sẵn và lịch sử thực thi để chọn bước tiếp theo.\n\n"
             "DANH SÁCH CÔNG CỤ CÓ SẴN:\n{tools_json}\n\n"
             "YÊU CẦU BẮT BUỘC:\n"
             "1. Bạn PHẢI giải thích rõ lý do chọn công cụ (tool_selection_reason).\n"
             "2. Bạn PHẢI giải thích rõ lý do thiết lập các tham số/options (options_selection_reason).\n"
             "3. Đặt is_task_complete=true nếu mục tiêu nhiệm vụ đã hoàn thành đủ.\n\n"
             "OUTPUT FORMAT (Chỉ trả về JSON hợp lệ):\n"
             "{{\n"
             '  "selected_tool": "<tên tool chọn>",\n'
             '  "options": {{ "<tên_option>": <giá_trị> }},\n'
             '  "tool_selection_reason": "<lý do chọn tool này>",\n'
             '  "options_selection_reason": "<lý do cấu hình option như vậy>",\n'
             '  "is_task_complete": false\n'
             "}}"),
            ("human",
             "CHỈ THỊ NHIỆM VỤ TỪ MANAGER:\n{directive_json}\n\n"
             "LỊCH SỬ THỰC THI CÁC TOOL TRƯỚC ĐÓ:\n{history_json}")
        ])

        chain = prompt | self.llm
        try:
            res = chain.invoke({
                "tools_json": json.dumps(available_tools, ensure_ascii=False, indent=2),
                "directive_json": json.dumps(task_directive, ensure_ascii=False, indent=2),
                "history_json": json.dumps(execution_history, ensure_ascii=False, indent=2),
            })
            content = res.content.strip()
            # Clean json fences if present
            if content.startswith("```json"):
                content = content[7:]
            if content.endswith("```"):
                content = content[:-3]
            return json.loads(content.strip())
        except Exception as exc:
            logger.warning(f"Lỗi khi LLM suy luận plan_tool_execution: {exc}. Dùng fallback.")
            if available_tools and len(execution_history) < len(available_tools):
                t = available_tools[len(execution_history)]
                return {
                    "selected_tool": t["name"],
                    "options": {},
                    "tool_selection_reason": f"Fallback tự động chọn tool {t['name']}.",
                    "options_selection_reason": "Fallback dùng options mặc định.",
                    "is_task_complete": len(execution_history) + 1 >= len(available_tools),
                }
            return {"selected_tool": "none", "options": {}, "is_task_complete": True}

    def generate_justification(
        self,
        task_directive: Dict[str, Any],
        execution_history: List[Dict[str, Any]],
        extracted_data: Dict[str, Any],
    ) -> str:
        """
        Gọi LLM tổng hợp báo cáo giải trình hoàn thành nhiệm vụ cho Manager.
        """
        if not self.llm:
            return (
                f"[{self.agent_name}] Đã hoàn thành nhiệm vụ cho {task_directive.get('target_url')}. "
                f"Đã thực thi {len(execution_history)} công cụ và trích xuất thành công dữ liệu mục tiêu."
            )

        prompt = ChatPromptTemplate.from_messages([
            ("system",
             f"Bạn là {self.agent_name}. Hãy tổng hợp báo cáo giải trình (Sub-Agent Justification Report) gửi Manager Agent.\n"
             "Nêu rõ các thông tin đã thu thập được, đánh giá mức độ hoàn thành mục tiêu, lý do kết thúc nhiệm vụ."),
            ("human",
             "MỤC TIÊU BAN ĐẦU:\n{directive_json}\n\n"
             "LỊCH SỬ CHẠY TOOL & GIẢI TRÌNH:\n{history_json}\n\n"
             "DỮ LIỆU CUỐI CÙNG THU ĐƯỢC:\n{data_json}")
        ])

        chain = prompt | self.llm
        try:
            res = chain.invoke({
                "directive_json": json.dumps(task_directive, ensure_ascii=False, indent=2),
                "history_json": json.dumps(execution_history, ensure_ascii=False, indent=2),
                "data_json": json.dumps(extracted_data, ensure_ascii=False, indent=2),
            })
            return res.content.strip()
        except Exception as exc:
            return f"[{self.agent_name}] Đã hoàn thành thu thập dữ liệu mục tiêu với {len(execution_history)} tool invocations."

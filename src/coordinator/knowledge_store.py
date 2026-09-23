"""
Knowledge Store — Bộ nhớ kiến thức persistent.

Lưu và truy xuất kiến thức từ các phiên chạy trước.
Cho phép Coordinator "học" từ kinh nghiệm và cải thiện
quyết định theo thời gian.

Storage: JSON files (có thể upgrade lên SQLite/Vector DB sau).

Cấu trúc thư mục:
    knowledge_store/
    ├── sessions/                   # Kết quả từng phiên
    │   ├── 2026-09-20_abc123.json
    │   └── ...
    ├── lessons_learned.json        # Bài học rút ra (tổng hợp)
    ├── decision_patterns.json      # Patterns quyết định đã thành công
    └── tech_stack_profiles.json    # Profile cho từng tech stack
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Thư mục mặc định cho Knowledge Store
KNOWLEDGE_DIR = Path("knowledge_store")


class KnowledgeStore:
    """
    Quản lý kiến thức tích lũy từ các phiên chạy.

    Chức năng chính:
        - Lưu session records, lessons learned, decision patterns
        - Truy xuất kiến thức liên quan cho quyết định hiện tại
        - Tính similarity score giữa các session contexts
    """

    def __init__(self, base_dir: str = None):
        """
        Args:
            base_dir: Thư mục gốc cho Knowledge Store.
                      Mặc định: "knowledge_store/"
        """
        self.base_dir = Path(base_dir) if base_dir else KNOWLEDGE_DIR
        self.sessions_dir = self.base_dir / "sessions"
        self.sessions_dir.mkdir(parents=True, exist_ok=True)

        self.lessons_file = self.base_dir / "lessons_learned.json"
        self.patterns_file = self.base_dir / "decision_patterns.json"
        self.profiles_file = self.base_dir / "tech_stack_profiles.json"

    # ══════════════════════════════════════════════════════════
    # SAVE — Lưu kiến thức
    # ══════════════════════════════════════════════════════════

    def save_session(self, session_record: dict):
        """
        Lưu kết quả một phiên chạy.

        Args:
            session_record: Dict chứa toàn bộ thông tin phiên
                           (context, decisions, outcomes, lessons)
        """
        session_id = session_record.get("session_id", "unknown")
        date = datetime.now().strftime("%Y-%m-%d")
        filename = f"{date}_{session_id[:8]}.json"

        filepath = self.sessions_dir / filename
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(session_record, f, ensure_ascii=False, indent=2)

        logger.info(f"[Knowledge] Session saved: {filepath}")

    def save_lessons(self, new_lessons: list[dict]):
        """
        Thêm bài học mới vào kho kiến thức.

        Nếu bài học đã tồn tại (trùng ID), tăng times_validated
        và cập nhật confidence. Nếu chưa tồn tại, thêm mới.

        Args:
            new_lessons: Danh sách bài học mới từ post-session reflection
        """
        existing = self._load_json(self.lessons_file, {"lessons": []})

        for lesson in new_lessons:
            # Kiểm tra trùng lặp bằng ID
            existing_ids = {l["id"] for l in existing["lessons"] if "id" in l}

            if lesson.get("id") not in existing_ids:
                # Bài học mới → gán ID và thêm vào
                lesson["id"] = f"L{len(existing['lessons']) + 1:03d}"
                lesson["created_at"] = datetime.now(timezone.utc).isoformat()
                lesson["times_validated"] = 1
                existing["lessons"].append(lesson)
                logger.info(
                    f"[Knowledge] New lesson: {lesson['id']} — "
                    f"{lesson.get('lesson', '')[:80]}"
                )
            else:
                # Bài học đã tồn tại → cập nhật
                for existing_lesson in existing["lessons"]:
                    if existing_lesson.get("id") == lesson.get("id"):
                        existing_lesson["times_validated"] = (
                            existing_lesson.get("times_validated", 0) + 1
                        )
                        existing_lesson["last_validated"] = (
                            datetime.now(timezone.utc).isoformat()
                        )
                        # Tăng confidence dần (capped tại 0.99)
                        existing_lesson["confidence"] = min(
                            0.99,
                            existing_lesson.get("confidence", 0.5) + 0.05,
                        )
                        break

        self._save_json(self.lessons_file, existing)

    def save_decision_pattern(self, pattern: dict):
        """
        Lưu một decision pattern mới hoặc cập nhật pattern đã tồn tại.

        Args:
            pattern: Dict chứa thông tin pattern
                    (name, condition, recommended_action, session_id, was_successful)
        """
        existing = self._load_json(self.patterns_file, {"patterns": []})

        # Tìm pattern cùng tên
        matched = False
        for p in existing["patterns"]:
            if p.get("name") == pattern.get("name"):
                p["times_used"] = p.get("times_used", 0) + 1
                # Running average cho success rate
                old_rate = p.get("success_rate", 0.5)
                was_success = 1.0 if pattern.get("was_successful") else 0.0
                p["success_rate"] = (
                    old_rate * (p["times_used"] - 1) + was_success
                ) / p["times_used"]
                if "source_sessions" not in p:
                    p["source_sessions"] = []
                p["source_sessions"].append(
                    pattern.get("session_id", "unknown")
                )
                matched = True
                break

        if not matched:
            pattern["id"] = f"P{len(existing['patterns']) + 1:03d}"
            pattern["times_used"] = 1
            if "source_sessions" not in pattern:
                pattern["source_sessions"] = []
            existing["patterns"].append(pattern)

        self._save_json(self.patterns_file, existing)

    # ══════════════════════════════════════════════════════════
    # RETRIEVE — Truy xuất kiến thức
    # ══════════════════════════════════════════════════════════

    def retrieve_knowledge(
        self, context: dict, max_items: int = 5
    ) -> dict:
        """
        Truy xuất kiến thức liên quan cho quyết định hiện tại.

        Pipeline 4 bước:
            1. EXACT MATCH: Tìm session cùng tech_stack + waf_type
            2. SIMILAR MATCH: Tìm session cùng backend
            3. PATTERN MATCH: Tìm decision patterns áp dụng được
            4. GLOBAL LESSONS: Bài học chung (confidence > 0.80)

        Args:
            context: Dict chứa thông tin hiện tại
                    (tech_stack, waf_type, decision_point, ...)
            max_items: Số lượng items tối đa trả về

        Returns:
            KnowledgeContext dict
        """
        knowledge = {
            "similar_sessions": [],
            "relevant_lessons": [],
            "relevant_patterns": [],
            "total_past_sessions": 0,
        }

        # 1. Tìm similar sessions
        knowledge["similar_sessions"] = self._find_similar_sessions(
            context, limit=3
        )

        # 2. Tìm relevant lessons
        knowledge["relevant_lessons"] = self._find_relevant_lessons(
            context, limit=5
        )

        # 3. Tìm applicable patterns
        knowledge["relevant_patterns"] = self._find_applicable_patterns(
            context, limit=3
        )

        # 4. Đếm tổng sessions
        knowledge["total_past_sessions"] = len(
            list(self.sessions_dir.glob("*.json"))
        )

        return knowledge

    # ══════════════════════════════════════════════════════════
    # INTERNAL — Tìm kiếm
    # ══════════════════════════════════════════════════════════

    def _find_similar_sessions(
        self, context: dict, limit: int = 3
    ) -> list:
        """
        Tìm sessions có context tương tự.

        Sắp xếp theo similarity score giảm dần.
        Chỉ trả về sessions có score > 0.3.
        """
        sessions = []

        for session_file in sorted(
            self.sessions_dir.glob("*.json"), reverse=True
        ):
            try:
                with open(session_file, "r", encoding="utf-8") as f:
                    session = json.load(f)

                score = self._calculate_similarity(
                    context, session.get("context", {})
                )

                if score > 0.3:  # Ngưỡng tương đồng tối thiểu
                    sessions.append({
                        "session_id": session.get("session_id", "unknown"),
                        "similarity_score": score,
                        "tech_stack": session.get("context", {}).get(
                            "tech_stack", {}
                        ),
                        "waf_type": session.get("context", {}).get("waf_type"),
                        "outcomes": session.get("outcomes", {}),
                        "decisions_summary": [
                            {
                                "point": d.get("point", ""),
                                "action": d.get("action", ""),
                                "confidence": d.get("confidence", 0),
                            }
                            for d in session.get("decisions", [])
                        ],
                        "lessons": session.get("lessons_learned", []),
                    })
            except (json.JSONDecodeError, KeyError, OSError):
                continue

        # Sắp xếp theo similarity score
        sessions.sort(
            key=lambda x: x["similarity_score"], reverse=True
        )
        return sessions[:limit]

    def _calculate_similarity(
        self, current: dict, past: dict
    ) -> float:
        """
        Tính similarity score giữa context hiện tại và quá khứ.

        Weighted scoring:
            - backend_match: 0.35 (quan trọng nhất)
            - waf_match: 0.25
            - frontend_match: 0.15
            - characteristics_overlap: 0.15
            - server_match: 0.10

        Returns:
            float 0.0 (khác hoàn toàn) → 1.0 (giống hoàn toàn)
        """
        score = 0.0
        weights = {
            "backend_match": 0.35,
            "frontend_match": 0.15,
            "waf_match": 0.25,
            "server_match": 0.10,
            "characteristics_overlap": 0.15,
        }

        curr_tech = current.get("tech_stack", {})
        past_tech = past.get("tech_stack", {})

        # Backend match (quan trọng nhất)
        if (
            curr_tech.get("backend")
            and curr_tech["backend"] == past_tech.get("backend")
        ):
            score += weights["backend_match"]

        # Frontend match
        if (
            curr_tech.get("frontend")
            and curr_tech["frontend"] == past_tech.get("frontend")
        ):
            score += weights["frontend_match"]

        # WAF match
        if (
            current.get("waf_type")
            and current["waf_type"] == past.get("waf_type")
        ):
            score += weights["waf_match"]
        elif (
            not current.get("waf_detected")
            and not past.get("waf_detected")
        ):
            # Cả hai đều không có WAF → partial match
            score += weights["waf_match"] * 0.5

        # Server match
        if (
            curr_tech.get("web_server")
            and curr_tech["web_server"] == past_tech.get("web_server")
        ):
            score += weights["server_match"]

        # Characteristics overlap (Jaccard similarity)
        curr_chars = set(current.get("target_characteristics", []))
        past_chars = set(past.get("target_characteristics", []))
        if curr_chars and past_chars:
            overlap = len(curr_chars & past_chars) / max(
                len(curr_chars | past_chars), 1
            )
            score += weights["characteristics_overlap"] * overlap

        return round(score, 3)

    def _find_relevant_lessons(
        self, context: dict, limit: int = 5
    ) -> list:
        """
        Tìm bài học áp dụng được cho context hiện tại.

        Duyệt qua tất cả lessons, kiểm tra điều kiện
        applicable_when có match với context không.
        """
        data = self._load_json(self.lessons_file, {"lessons": []})
        relevant = []

        for lesson in data["lessons"]:
            applicable = lesson.get("applicable_when", {})
            is_match = True

            for key, expected in applicable.items():
                # Traverse nested keys (e.g., "tech_stack.backend")
                actual = context
                for part in key.split("."):
                    actual = (
                        actual.get(part, {})
                        if isinstance(actual, dict)
                        else None
                    )

                if actual is None:
                    is_match = False
                    break

                # Kiểm tra match theo kiểu dữ liệu
                if isinstance(expected, list):
                    if actual not in expected:
                        is_match = False
                        break
                elif isinstance(expected, str) and expected.startswith(
                    ("<", ">")
                ):
                    # Numeric comparison (e.g., "< 3")
                    op, val = expected.split()
                    try:
                        if op == "<" and not (float(actual) < float(val)):
                            is_match = False
                        elif op == ">" and not (float(actual) > float(val)):
                            is_match = False
                    except (ValueError, TypeError):
                        is_match = False
                else:
                    if str(actual) != str(expected):
                        is_match = False
                        break

            if is_match:
                relevant.append(lesson)

        # Sắp xếp theo confidence
        relevant.sort(
            key=lambda x: x.get("confidence", 0), reverse=True
        )
        return relevant[:limit]

    def _find_applicable_patterns(
        self, context: dict, limit: int = 3
    ) -> list:
        """
        Tìm decision patterns áp dụng được.

        Logic tương tự _find_relevant_lessons nhưng dành cho patterns.
        """
        data = self._load_json(self.patterns_file, {"patterns": []})
        applicable = []

        for pattern in data["patterns"]:
            condition = pattern.get("condition", {})
            matches = True

            for key, expected in condition.items():
                actual = context
                for part in key.split("."):
                    actual = (
                        actual.get(part, {})
                        if isinstance(actual, dict)
                        else None
                    )

                if actual is None:
                    matches = False
                    break

                if isinstance(expected, bool):
                    if actual != expected:
                        matches = False
                elif isinstance(expected, list):
                    if actual not in expected:
                        matches = False
                elif isinstance(expected, str) and expected.startswith(
                    ("<", ">")
                ):
                    op, val = expected.split()
                    try:
                        if op == "<" and not (float(actual) < float(val)):
                            matches = False
                        elif op == ">" and not (float(actual) > float(val)):
                            matches = False
                    except (ValueError, TypeError):
                        matches = False
                else:
                    if str(actual) != str(expected):
                        matches = False

            if matches:
                applicable.append(pattern)

        applicable.sort(
            key=lambda x: x.get("success_rate", 0), reverse=True
        )
        return applicable[:limit]

    # ══════════════════════════════════════════════════════════
    # HELPERS
    # ══════════════════════════════════════════════════════════

    def _load_json(self, filepath: Path, default: dict) -> dict:
        """Load JSON file, trả về default nếu file không tồn tại."""
        if filepath.exists():
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(
                    f"[Knowledge] Error loading {filepath}: {e}"
                )
        return default

    def _save_json(self, filepath: Path, data: dict):
        """Save dict ra JSON file."""
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

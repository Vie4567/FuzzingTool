"""
scripts/init_neo4j.py — Idempotent schema initialization cho Sentinel Pentest Graph.

Tạo:
  - Constraints (UNIQUE)
  - Indexes
  - Verify schema

Chạy: python scripts/init_neo4j.py
Yêu cầu: NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD trong .env hoặc environment.

Script này idempotent — chạy nhiều lần không gây lỗi.
"""

import os
import sys
import logging

# Hỗ trợ chạy từ root hoặc từ thư mục scripts/
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv optional — dùng env vars trực tiếp

from neo4j import GraphDatabase, exceptions as neo4j_exc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# ─── Schema definition ────────────────────────────────────────────────────────

CONSTRAINTS = [
    # Target.url là identity toàn cục
    {
        "name": "constraint_target_url_unique",
        "cypher": (
            "CREATE CONSTRAINT constraint_target_url_unique IF NOT EXISTS "
            "FOR (t:Target) REQUIRE t.url IS UNIQUE"
        ),
    },
    # Technology.name là identity toàn cục
    # (tên framework là unique across domain — React là React ở mọi target)
    {
        "name": "constraint_technology_name_unique",
        "cypher": (
            "CREATE CONSTRAINT constraint_technology_name_unique IF NOT EXISTS "
            "FOR (t:Technology) REQUIRE t.name IS UNIQUE"
        ),
    },
    # Endpoint dùng _uid (deterministic hash) — KHÔNG constraint chỉ trên path/method
    # vì target-A /login GET ≠ target-B /login GET
    {
        "name": "constraint_endpoint_uid_unique",
        "cypher": (
            "CREATE CONSTRAINT constraint_endpoint_uid_unique IF NOT EXISTS "
            "FOR (e:Endpoint) REQUIRE e._uid IS UNIQUE"
        ),
    },
    {
        "name": "constraint_parameter_uid_unique",
        "cypher": "CREATE CONSTRAINT constraint_parameter_uid_unique IF NOT EXISTS FOR (p:Parameter) REQUIRE p._uid IS UNIQUE",
    },
    {
        "name": "constraint_finding_uid_unique",
        "cypher": "CREATE CONSTRAINT constraint_finding_uid_unique IF NOT EXISTS FOR (f:Finding) REQUIRE f._uid IS UNIQUE",
    },
]

INDEXES = [
    # Index để tìm endpoint theo target_url nhanh
    {
        "name": "index_endpoint_target_url",
        "cypher": (
            "CREATE INDEX index_endpoint_target_url IF NOT EXISTS "
            "FOR (e:Endpoint) ON (e._target_url)"
        ),
    },
    # Index Finding severity
    {
        "name": "index_finding_severity",
        "cypher": (
            "CREATE INDEX index_finding_severity IF NOT EXISTS "
            "FOR (f:Finding) ON (f.severity)"
        ),
    },
]


def get_driver():
    """Tạo Neo4j driver từ environment variables."""
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "neo4j")
    return GraphDatabase.driver(uri, auth=(user, password))


def apply_schema(driver):
    """Áp dụng constraints và indexes — idempotent nhờ IF NOT EXISTS."""
    with driver.session() as session:
        logger.info("=== Applying Neo4j Schema (Sentinel Pentest) ===")

        # Constraints
        logger.info("--- Constraints ---")
        for constraint in CONSTRAINTS:
            try:
                session.run(constraint["cypher"])
                logger.info(f"  OK: {constraint['name']}")
            except neo4j_exc.ClientError as e:
                # Constraint đã tồn tại hoặc conflict — bỏ qua
                if "already exists" in str(e).lower() or "equivalent" in str(e).lower():
                    logger.info(f"  SKIP (already exists): {constraint['name']}")
                else:
                    logger.error(f"  ERROR: {constraint['name']}: {e}")
                    raise

        # Indexes
        logger.info("--- Indexes ---")
        for index in INDEXES:
            try:
                session.run(index["cypher"])
                logger.info(f"  OK: {index['name']}")
            except neo4j_exc.ClientError as e:
                if "already exists" in str(e).lower() or "equivalent" in str(e).lower():
                    logger.info(f"  SKIP (already exists): {index['name']}")
                else:
                    logger.error(f"  ERROR: {index['name']}: {e}")
                    raise

        logger.info("=== Schema initialization complete ===")


def verify_schema(driver) -> bool:
    """Kiểm tra schema đã được apply đúng."""
    with driver.session() as session:
        result = session.run(
            "SHOW CONSTRAINTS YIELD name RETURN collect(name) AS names"
        )
        record = result.single()
        existing = record["names"] if record else []

        required = {c["name"] for c in CONSTRAINTS}
        missing = required - set(existing)

        if missing:
            logger.warning(f"Missing constraints: {missing}")
            return False

        logger.info(f"Schema verified — {len(existing)} constraints found")
        return True


def main():
    logger.info("Connecting to Neo4j...")
    driver = None
    try:
        driver = get_driver()
        driver.verify_connectivity()
        logger.info("Connection OK")

        apply_schema(driver)
        ok = verify_schema(driver)

        if ok:
            logger.info("✅ Neo4j schema is ready.")
            sys.exit(0)
        else:
            logger.error("❌ Schema verification failed.")
            sys.exit(1)

    except neo4j_exc.ServiceUnavailable as e:
        logger.error(f"Cannot connect to Neo4j: {e}")
        logger.error(
            "Ensure Neo4j is running: docker compose up -d neo4j"
        )
        sys.exit(2)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(3)
    finally:
        if driver:
            driver.close()


if __name__ == "__main__":
    main()

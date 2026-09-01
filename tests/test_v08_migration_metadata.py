
from sqlalchemy import create_engine, inspect

from database.models import Base

REQUIRED_TABLES = {
    "correlation_runs",
    "correlation_entities",
    "incident_entities",
    "correlation_relationships",
    "attack_graph_snapshots",
}

REQUIRED_INCIDENT_COLUMNS = {
    "correlation_id",
    "correlation_version",
    "representative_alert_count",
    "deduplicated_alert_count",
    "source_count",
    "entity_count",
    "relationship_count",
    "stage_count",
    "stage_progression",
    "graph_score",
    "storyline",
    "correlation_metadata_json",
}


def test_v08_metadata_contains_advanced_correlation_tables() -> None:
    assert REQUIRED_TABLES.issubset(Base.metadata.tables)


def test_v08_incident_metadata_contains_graph_evidence_columns() -> None:
    incident_columns = set(Base.metadata.tables["incidents"].columns.keys())
    assert REQUIRED_INCIDENT_COLUMNS.issubset(incident_columns)


def test_v08_constraints_are_created_in_sqlite() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    inspector = inspect(engine)
    assert REQUIRED_TABLES.issubset(inspector.get_table_names())

    snapshot_indexes = inspector.get_indexes("attack_graph_snapshots")
    unique_index_columns = {
        tuple(item.get("column_names") or []) for item in snapshot_indexes if item.get("unique")
    }
    assert ("correlation_run_id",) in unique_index_columns
    assert ("graph_uuid",) in unique_index_columns

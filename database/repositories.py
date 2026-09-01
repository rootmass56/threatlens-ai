
from __future__ import annotations

from sqlalchemy import Select, select
from sqlalchemy.orm import Session, selectinload

from database.models import (
    AlertModel,
    AnalysisSessionModel,
    AuditLogModel,
    CorrelationEntityModel,
    CorrelationRelationshipModel,
    CorrelationRunModel,
    IncidentModel,
)


class AnalysisSessionRepository:
    """Database access operations for analysis sessions."""

    def __init__(self, database_session: Session) -> None:
        self.database_session = database_session

    def find_duplicate(
        self,
        analysis_fingerprint: str,
    ) -> AnalysisSessionModel | None:
        statement = (
            select(AnalysisSessionModel)
            .where(
                AnalysisSessionModel.analysis_fingerprint == analysis_fingerprint,
                AnalysisSessionModel.status == "completed",
            )
            .order_by(AnalysisSessionModel.created_at.desc())
        )
        return self.database_session.scalars(statement).first()

    def get_by_uuid(self, session_uuid: str) -> AnalysisSessionModel | None:
        statement = select(AnalysisSessionModel).where(
            AnalysisSessionModel.session_uuid == session_uuid
        )
        return self.database_session.scalars(statement).first()

    def get_with_details(self, session_uuid: str) -> AnalysisSessionModel | None:
        statement = (
            select(AnalysisSessionModel)
            .where(AnalysisSessionModel.session_uuid == session_uuid)
            .options(
                selectinload(AnalysisSessionModel.events),
                selectinload(AnalysisSessionModel.alerts).selectinload(AlertModel.evidence_events),
                selectinload(AnalysisSessionModel.incidents).selectinload(IncidentModel.alerts),
                selectinload(AnalysisSessionModel.correlation_runs)
                .selectinload(CorrelationRunModel.entities)
                .selectinload(CorrelationEntityModel.incidents),
                selectinload(AnalysisSessionModel.correlation_runs)
                .selectinload(CorrelationRunModel.relationships)
                .selectinload(CorrelationRelationshipModel.incident),
                selectinload(AnalysisSessionModel.correlation_runs).selectinload(
                    CorrelationRunModel.graph_snapshot
                ),
            )
        )
        return self.database_session.execute(statement).unique().scalar_one_or_none()

    def list_recent(self, limit: int = 100) -> list[AnalysisSessionModel]:
        statement = (
            select(AnalysisSessionModel)
            .order_by(AnalysisSessionModel.created_at.desc())
            .limit(limit)
        )
        return list(self.database_session.scalars(statement).all())


class IncidentRepository:
    """Database access operations for SOC incidents."""

    def __init__(self, database_session: Session) -> None:
        self.database_session = database_session

    @staticmethod
    def _detail_statement() -> Select:
        return select(IncidentModel).options(
            selectinload(IncidentModel.analysis_session),
            selectinload(IncidentModel.alerts).selectinload(AlertModel.evidence_events),
            selectinload(IncidentModel.notes),
            selectinload(IncidentModel.evidence),
            selectinload(IncidentModel.correlation_entities),
            selectinload(IncidentModel.correlation_relationships),
        )

    def get_by_uuid(self, incident_uuid: str) -> IncidentModel | None:
        statement = self._detail_statement().where(IncidentModel.incident_uuid == incident_uuid)
        return self.database_session.execute(statement).unique().scalar_one_or_none()

    def list_all(
        self,
        status: str | None = None,
        limit: int = 250,
    ) -> list[IncidentModel]:
        statement = self._detail_statement()
        if status:
            statement = statement.where(IncidentModel.status == status)
        statement = statement.order_by(IncidentModel.created_at.desc()).limit(limit)
        return list(self.database_session.execute(statement).unique().scalars().all())


class AuditLogRepository:
    """Read-only access to append-only audit records."""

    def __init__(self, database_session: Session) -> None:
        self.database_session = database_session

    def list_recent(
        self,
        *,
        entity_type: str | None = None,
        entity_id: str | None = None,
        limit: int = 500,
    ) -> list[AuditLogModel]:
        statement = select(AuditLogModel)
        if entity_type:
            statement = statement.where(AuditLogModel.entity_type == entity_type)
        if entity_id:
            statement = statement.where(AuditLogModel.entity_id == entity_id)
        statement = statement.order_by(AuditLogModel.created_at.desc()).limit(limit)
        return list(self.database_session.scalars(statement).all())

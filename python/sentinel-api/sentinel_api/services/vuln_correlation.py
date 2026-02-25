"""Vulnerability correlation engine.

Orchestrates NVD, EPSS, and KEV clients to match discovered services
against known CVEs. Writes Vulnerability nodes and HAS_CVE edges to
the Neo4j knowledge graph.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from pydantic import BaseModel, Field

from sentinel_api.engram.session import EngramSession
from sentinel_api.models.core import VulnSeverity

if TYPE_CHECKING:
    from uuid import UUID

    import neo4j

    from sentinel_api.services.epss_client import EpssClient
    from sentinel_api.services.kev_client import KevClient
    from sentinel_api.services.nvd_client import NvdClient

logger = logging.getLogger(__name__)


class CorrelationResult(BaseModel):
    """Summary of a vulnerability correlation run."""

    services_scanned: int = 0
    vulnerabilities_found: int = 0
    critical_count: int = 0
    high_count: int = 0
    kev_count: int = 0
    errors: list[str] = Field(default_factory=list)


def cvss_to_severity(score: float | None) -> VulnSeverity:
    """Map a CVSS v3.1 base score to a VulnSeverity enum."""
    if score is None:
        return VulnSeverity.NONE
    if score >= 9.0:
        return VulnSeverity.CRITICAL
    if score >= 7.0:
        return VulnSeverity.HIGH
    if score >= 4.0:
        return VulnSeverity.MEDIUM
    if score > 0.0:
        return VulnSeverity.LOW
    return VulnSeverity.NONE


class VulnCorrelationEngine:
    """Correlates services with known CVEs from NVD/EPSS/KEV."""

    def __init__(
        self,
        neo4j_driver: neo4j.AsyncDriver,
        nvd_client: NvdClient,
        epss_client: EpssClient,
        kev_client: KevClient,
    ) -> None:
        self._driver = neo4j_driver
        self._nvd = nvd_client
        self._epss = epss_client
        self._kev = kev_client

    async def correlate_tenant(
        self, tenant_id: UUID
    ) -> CorrelationResult:
        """Run correlation for all services in a tenant."""
        return await self._correlate(tenant_id, service_id=None)

    async def correlate_service(
        self, tenant_id: UUID, service_id: UUID
    ) -> CorrelationResult:
        """Run correlation for a single service."""
        return await self._correlate(tenant_id, service_id=service_id)

    async def _correlate(
        self,
        tenant_id: UUID,
        service_id: UUID | None,
    ) -> CorrelationResult:
        """Core correlation logic."""
        session = EngramSession(
            tenant_id=tenant_id,
            agent_id="vuln-correlation",
            intent="Correlate services with known CVEs",
        )
        result = CorrelationResult()

        try:
            services = await self._fetch_services(
                tenant_id, service_id
            )
            result.services_scanned = len(services)
            session.set_context({
                "tenant_id": str(tenant_id),
                "service_count": len(services),
            })

            if not services:
                session.add_action(
                    "no_services",
                    "No services found to correlate",
                    success=True,
                )
                return result

            session.add_decision(
                "keyword_search",
                "Using NVD keyword search for service matching",
                0.7,
            )

            # Collect all CVE IDs for batch EPSS lookup
            all_cve_ids: list[str] = []
            # Map: service_id → list of (cve_id, nvd_record)
            service_cves: dict[str, list[dict[str, Any]]] = {}

            for svc in services:
                svc_name = svc.get("name", "")
                svc_version = svc.get("version")
                svc_id = svc.get("id", "")
                if not svc_name:
                    continue

                keyword = svc_name
                if svc_version:
                    keyword = f"{svc_name} {svc_version}"

                try:
                    records = await self._nvd.search_cves(
                        keyword, max_results=50
                    )
                    cve_data = []
                    for r in records:
                        cve_data.append({
                            "cve_id": r.cve_id,
                            "description": r.description,
                            "cvss_score": r.cvss_v31_score,
                            "cvss_vector": r.cvss_v31_vector,
                            "published_date": (
                                r.published_date.isoformat()
                                if r.published_date
                                else None
                            ),
                        })
                        all_cve_ids.append(r.cve_id)
                    if cve_data:
                        service_cves[svc_id] = cve_data
                except Exception as exc:
                    msg = f"NVD search failed for {svc_name}: {exc}"
                    result.errors.append(msg)
                    logger.warning(msg)

            # Batch EPSS enrichment
            epss_scores: dict[str, float] = {}
            if all_cve_ids:
                try:
                    unique_ids = list(set(all_cve_ids))
                    epss_scores = await self._epss.get_scores(
                        unique_ids
                    )
                except Exception as exc:
                    result.errors.append(f"EPSS enrichment: {exc}")

            # KEV enrichment
            kev_set: set[str] = set()
            try:
                kev_set = await self._kev.fetch_catalog()
            except Exception as exc:
                result.errors.append(f"KEV fetch: {exc}")

            # Write to graph
            for svc_id, cve_list in service_cves.items():
                for cve_data in cve_list:
                    cve_id = cve_data["cve_id"]
                    cvss = cve_data.get("cvss_score")
                    severity = cvss_to_severity(cvss)
                    epss = epss_scores.get(cve_id)
                    in_kev = cve_id in kev_set

                    try:
                        await self._write_vuln_to_graph(
                            tenant_id=tenant_id,
                            service_id=svc_id,
                            cve_id=cve_id,
                            description=cve_data.get("description"),
                            cvss_score=cvss,
                            cvss_vector=cve_data.get("cvss_vector"),
                            epss_score=epss,
                            severity=str(severity),
                            in_cisa_kev=in_kev,
                            exploitable=in_kev,
                            published_date=cve_data.get(
                                "published_date"
                            ),
                        )
                        result.vulnerabilities_found += 1
                        if severity == VulnSeverity.CRITICAL:
                            result.critical_count += 1
                        elif severity == VulnSeverity.HIGH:
                            result.high_count += 1
                        if in_kev:
                            result.kev_count += 1
                    except Exception as exc:
                        msg = f"Graph write for {cve_id}: {exc}"
                        result.errors.append(msg)
                        logger.warning(msg)

            session.add_action(
                "correlation_complete",
                (
                    f"Found {result.vulnerabilities_found} CVEs "
                    f"across {result.services_scanned} services"
                ),
                details=result.model_dump(),
                success=len(result.errors) == 0,
            )
        except Exception as exc:
            result.errors.append(str(exc))
            session.add_action(
                "correlation_failed", str(exc), success=False
            )
        finally:
            session.finalize()

        return result

    async def _fetch_services(
        self,
        tenant_id: UUID,
        service_id: UUID | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch Service nodes from Neo4j."""
        tid = str(tenant_id)
        if service_id:
            cypher = (
                "MATCH (s:Service {tenant_id: $tid, id: $sid}) "
                "RETURN s"
            )
            params: dict[str, Any] = {
                "tid": tid,
                "sid": str(service_id),
            }
        else:
            cypher = (
                "MATCH (s:Service {tenant_id: $tid}) "
                "RETURN s"
            )
            params = {"tid": tid}

        async with self._driver.session() as session:
            result = await session.run(cypher, **params)
            return [dict(record["s"]) async for record in result]

    async def _write_vuln_to_graph(
        self,
        *,
        tenant_id: UUID,
        service_id: str,
        cve_id: str,
        description: str | None,
        cvss_score: float | None,
        cvss_vector: str | None,
        epss_score: float | None,
        severity: str,
        in_cisa_kev: bool,
        exploitable: bool,
        published_date: str | None,
    ) -> None:
        """Upsert a Vulnerability node and HAS_CVE edge."""
        tid = str(tenant_id)
        vid = str(uuid4())

        upsert_cypher = (
            "MERGE (v:Vulnerability "
            "{tenant_id: $tid, cve_id: $cve_id}) "
            "ON CREATE SET "
            "  v.id = $vid, "
            "  v.cvss_score = $cvss_score, "
            "  v.cvss_vector = $cvss_vector, "
            "  v.epss_score = $epss_score, "
            "  v.severity = $severity, "
            "  v.description = $description, "
            "  v.exploitable = $exploitable, "
            "  v.in_cisa_kev = $in_cisa_kev, "
            "  v.published_date = $published_date, "
            "  v.first_seen = datetime(), "
            "  v.last_seen = datetime() "
            "ON MATCH SET "
            "  v.cvss_score = $cvss_score, "
            "  v.cvss_vector = $cvss_vector, "
            "  v.epss_score = $epss_score, "
            "  v.severity = $severity, "
            "  v.description = $description, "
            "  v.exploitable = $exploitable, "
            "  v.in_cisa_kev = $in_cisa_kev, "
            "  v.last_seen = datetime() "
            "RETURN v"
        )

        edge_cypher = (
            "MATCH (s:Service {tenant_id: $tid, id: $sid}) "
            "MATCH (v:Vulnerability "
            "{tenant_id: $tid, cve_id: $cve_id}) "
            "MERGE (s)-[r:HAS_CVE]->(v) "
            "ON CREATE SET "
            "  r.first_seen = datetime(), "
            "  r.last_seen = datetime() "
            "ON MATCH SET "
            "  r.last_seen = datetime() "
            "RETURN r"
        )

        params = {
            "tid": tid,
            "vid": vid,
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "epss_score": epss_score,
            "severity": severity,
            "description": description,
            "exploitable": exploitable,
            "in_cisa_kev": in_cisa_kev,
            "published_date": published_date,
            "sid": service_id,
        }

        async with self._driver.session() as session:
            await session.run(upsert_cypher, **params)
            await session.run(edge_cypher, **params)

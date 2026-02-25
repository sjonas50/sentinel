"""OPA policy evaluation engine.

Communicates with an OPA sidecar via its REST API (v1/data).
Falls back to a local evaluation mode for testing without OPA.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from sentinel_policy.models import Decision, PolicyInput, Tier

logger = logging.getLogger(__name__)

DEFAULT_OPA_URL = "http://localhost:8181"


class PolicyEngine:
    """Client for evaluating policies against an OPA server."""

    def __init__(self, opa_url: str = DEFAULT_OPA_URL) -> None:
        self._opa_url = opa_url.rstrip("/")
        self._client = httpx.AsyncClient(base_url=self._opa_url, timeout=5.0)

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def evaluate(
        self,
        policy_path: str,
        input_data: PolicyInput,
    ) -> Decision:
        """Evaluate a policy by path against the given input.

        Args:
            policy_path: OPA data path, e.g. "agent/base" or "response/approval".
            input_data: Structured input for the policy.

        Returns:
            A Decision with the evaluation result.
        """
        url = f"/v1/data/{policy_path}"
        payload = {"input": input_data.model_dump()}

        try:
            resp = await self._client.post(url, json=payload)
            resp.raise_for_status()
            result = resp.json().get("result", {})
            return self._parse_result(result)
        except httpx.HTTPStatusError as exc:
            logger.error("OPA returned %s for %s", exc.response.status_code, policy_path)
            return Decision(
                allowed=False,
                tier=Tier.DENY,
                reasons=[f"OPA error: {exc.response.status_code}"],
            )
        except httpx.ConnectError:
            logger.warning("OPA not reachable at %s — denying by default", self._opa_url)
            return Decision(
                allowed=False,
                tier=Tier.DENY,
                reasons=["OPA service unavailable"],
            )

    async def evaluate_agent_action(self, input_data: PolicyInput) -> Decision:
        """Evaluate whether an agent action is allowed."""
        return await self.evaluate("agent/base", input_data)

    async def evaluate_response_tier(self, input_data: PolicyInput) -> Decision:
        """Determine the approval tier for a response action."""
        return await self.evaluate("response/approval", input_data)

    async def health(self) -> bool:
        """Check if OPA is reachable."""
        try:
            resp = await self._client.get("/health")
            return resp.status_code == 200
        except httpx.ConnectError:
            return False

    @staticmethod
    def _parse_result(result: dict[str, Any]) -> Decision:
        """Parse OPA result into a Decision."""
        allowed = bool(result.get("allow", False))
        tier_raw = result.get("tier", "deny")
        try:
            tier = Tier(tier_raw)
        except ValueError:
            tier = Tier.DENY

        return Decision(
            allowed=allowed,
            tier=tier,
            reasons=result.get("reasons", []),
            violations=result.get("violations", []),
            metadata={k: v for k, v in result.items() if k not in {
                "allow", "tier", "reasons", "violations",
            }},
        )

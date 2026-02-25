"""Connector registry for dynamic loading and management."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from uuid import UUID

    from sentinel_connectors.base import BaseConnector

logger = logging.getLogger(__name__)

_registry: dict[str, type[BaseConnector]] = {}


def register(connector_cls: type[BaseConnector]) -> type[BaseConnector]:
    """Register a connector class by its name. Can be used as a decorator."""
    # Instantiate temporarily to get the name property
    # Since name is abstract, we read it from the class if possible,
    # or use the class name as fallback
    name = getattr(connector_cls, "NAME", connector_cls.__name__.lower())
    _registry[name] = connector_cls
    logger.debug("Registered connector: %s", name)
    return connector_cls


def get_connector(
    name: str,
    tenant_id: UUID,
    config: dict[str, Any] | None = None,
) -> BaseConnector:
    """Instantiate a registered connector by name."""
    cls = _registry.get(name)
    if cls is None:
        available = ", ".join(sorted(_registry.keys()))
        raise KeyError(f"Unknown connector '{name}'. Available: {available}")
    return cls(tenant_id=tenant_id, config=config)


def list_connectors() -> list[str]:
    """Return all registered connector names."""
    return sorted(_registry.keys())


def clear_registry() -> None:
    """Clear all registered connectors (for testing)."""
    _registry.clear()

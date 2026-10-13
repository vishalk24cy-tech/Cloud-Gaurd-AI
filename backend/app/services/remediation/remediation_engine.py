from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

from app.services.remediation.remediation_models import (
    RemediationActionSpec,
    RemediationClassification,
    RemediationStatus,
)
from app.services.remediation.remediation_registry import RemediationRegistry, get_registry


class RemediationEngine:
    """Metadata-only remediation orchestration layer."""

    def __init__(self, registry: Optional[RemediationRegistry] = None) -> None:
        self.registry = registry or get_registry()

    def get_action(self, action_id: str) -> Optional[RemediationActionSpec]:
        return self.registry.get(action_id)

    def list_actions(self, service: Optional[str] = None) -> List[Dict[str, Any]]:
        actions = self.registry.all() if not service else self.registry.for_service(service)
        return [action.as_dict() for action in actions]

    def list_actions_for_resource(
        self,
        service: str,
        resource_type: str,
    ) -> List[Dict[str, Any]]:
        actions = self.registry.for_resource(service, resource_type)
        return [action.as_dict() for action in actions]

    def is_supported(self, action_id: str) -> bool:
        return self.registry.supports(action_id)

    def classification_for(self, action_id: str) -> Optional[str]:
        action = self.get_action(action_id)
        if action is None:
            return None
        return action.classification.value

    def requires_confirmation(self, action_id: str) -> bool:
        action = self.get_action(action_id)
        if action is None:
            return False
        return bool(action.requires_confirmation)

    def requires_approval(self, action_id: str) -> bool:
        action = self.get_action(action_id)
        if action is None:
            return False
        return bool(action.requires_approval)

    def supported_statuses(self, action_id: str) -> Tuple[str, ...]:
        action = self.get_action(action_id)
        if action is None:
            return ()
        return tuple(status.value for status in action.supported_statuses)

    def summary(self) -> List[Dict[str, Any]]:
        return self.list_actions()


def get_default_engine() -> RemediationEngine:
    return RemediationEngine(get_registry())

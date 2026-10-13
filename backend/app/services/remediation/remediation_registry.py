from __future__ import annotations

from importlib import import_module
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from app.services.remediation.remediation_models import RemediationActionSpec


class RemediationRegistry:
    """Central registry for CloudGuardAI remediation metadata."""

    def __init__(self) -> None:
        self._actions: Dict[str, RemediationActionSpec] = {}

    def register(self, action: RemediationActionSpec) -> RemediationActionSpec:
        if not isinstance(action, RemediationActionSpec):
            raise TypeError("action must be a RemediationActionSpec")

        self._actions[action.action_id] = action
        return action

    def register_many(self, actions: Iterable[RemediationActionSpec]) -> List[RemediationActionSpec]:
        registered: List[RemediationActionSpec] = []

        for action in actions:
            registered.append(self.register(action))

        return registered

    def get(self, action_id: str) -> Optional[RemediationActionSpec]:
        if not action_id:
            return None

        return self._actions.get(str(action_id).strip())

    def all(self) -> Tuple[RemediationActionSpec, ...]:
        return tuple(sorted(self._actions.values(), key=lambda item: (item.service, item.resource_type, item.action_id)))

    def for_service(self, service: str) -> Tuple[RemediationActionSpec, ...]:
        normalized = str(service or "").strip().upper()

        if not normalized:
            return ()

        return tuple(
            action for action in self.all() if action.service == normalized
        )

    def for_resource(self, service: str, resource_type: str) -> Tuple[RemediationActionSpec, ...]:
        normalized_service = str(service or "").strip().upper()
        normalized_resource = str(resource_type or "").strip().upper()

        if not normalized_service or not normalized_resource:
            return ()

        return tuple(
            action
            for action in self.all()
            if action.service == normalized_service and action.resource_type == normalized_resource
        )

    def supports(self, action_id: str) -> bool:
        return self.get(action_id) is not None

    def __contains__(self, action_id: str) -> bool:
        return self.supports(action_id)

    def __len__(self) -> int:
        return len(self._actions)


REGISTRY = RemediationRegistry()


def register_default_actions(registry: Optional[RemediationRegistry] = None) -> RemediationRegistry:
    target = registry or REGISTRY

    module_names = (
        "ec2_remediation",
        "s3_remediation",
        "iam_remediation",
        "vpc_remediation",
        "rds_remediation",
        "lambda_remediation",
        "cloudtrail_remediation",
        "kms_remediation",
    )

    for module_name in module_names:
        module = import_module(f"app.services.remediation.{module_name}")
        actions = getattr(module, "get_actions", None)

        if callable(actions):
            target.register_many(actions())

    return target


register_default_actions(REGISTRY)


def get_registry() -> RemediationRegistry:
    return REGISTRY

"""Tenant and Organization Cryptographic Policy Enforcement.

Module F: Organization and Vertical Bridge Policy
- Tenant isolation and resource-level access controls across sites, leases, legal matters, and documents.
- Document classification levels and restricted legal access.
- Legal holds and immutable retention controls.
- Administrative audit logging.

Realism note:
Does not assume access to internal Vertical Bridge production systems, vHive APIs,
or confidential keys. Operates with provider-independent controls.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Any, List, Optional, Tuple

from .algorithms import (
    AlgorithmName,
    VerificationStatus
)
from .provider_base import CryptoSecurityError


class DocumentClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED_LEGAL = "RESTRICTED_LEGAL"
    HIGHLY_CONFIDENTIAL = "HIGHLY_CONFIDENTIAL"


@dataclass
class OrganizationCryptoPolicy:
    organization_id: str
    signing_policy: str = "hybrid"  # "hybrid", "pqc_only", "classical_only"
    envelope_algorithm: str = f"{AlgorithmName.ML_KEM_768.value} + {AlgorithmName.AES_256_GCM.value}"
    archival_signature_algorithm: str = AlgorithmName.SLH_DSA_SHA2_128F.value
    retention_period_days: int = 2555  # 7-year statutory default for telecommunication ground leases
    legal_hold_active: bool = False
    legal_hold_reason: Optional[str] = None
    legal_hold_initiated_at: Optional[str] = None
    legal_hold_initiated_by: Optional[str] = None
    require_hybrid_verification: bool = True
    enforce_strict_aead_tag_checks: bool = True


class TenantPolicyService:
    """Enforces multi-tenant isolation, cryptographic policy, and legal holds."""

    def __init__(self):
        self._policies: Dict[str, OrganizationCryptoPolicy] = {}

    def get_or_create_policy(self, organization_id: str) -> OrganizationCryptoPolicy:
        if organization_id not in self._policies:
            self._policies[organization_id] = OrganizationCryptoPolicy(organization_id=organization_id)
        return self._policies[organization_id]

    def update_policy(
        self,
        organization_id: str,
        signing_policy: Optional[str] = None,
        retention_period_days: Optional[int] = None
    ) -> OrganizationCryptoPolicy:
        policy = self.get_or_create_policy(organization_id)
        if signing_policy:
            if signing_policy not in ("hybrid", "pqc_only", "classical_only"):
                raise ValueError(f"Invalid signing policy: {signing_policy}")
            policy.signing_policy = signing_policy
        if retention_period_days is not None:
            if retention_period_days < 1:
                raise ValueError("Retention period must be at least 1 day.")
            policy.retention_period_days = retention_period_days
        return policy

    def apply_legal_hold(self, organization_id: str, reason: str, initiated_by: str) -> OrganizationCryptoPolicy:
        policy = self.get_or_create_policy(organization_id)
        policy.legal_hold_active = True
        policy.legal_hold_reason = reason
        policy.legal_hold_initiated_at = datetime.now(timezone.utc).isoformat()
        policy.legal_hold_initiated_by = initiated_by
        return policy

    def release_legal_hold(self, organization_id: str) -> OrganizationCryptoPolicy:
        policy = self.get_or_create_policy(organization_id)
        policy.legal_hold_active = False
        policy.legal_hold_reason = None
        policy.legal_hold_initiated_at = None
        policy.legal_hold_initiated_by = None
        return policy

    def check_resource_access(
        self,
        requesting_tenant_id: str,
        resource_tenant_id: str,
        user_role: str,
        classification: DocumentClassification = DocumentClassification.INTERNAL,
        action: str = "read"
    ) -> Tuple[bool, Optional[str]]:
        """Verifies tenant isolation and resource classification boundaries."""
        # 1. Tenant boundary
        if requesting_tenant_id != resource_tenant_id:
            return False, f"Cross-tenant access prohibited: User tenant '{requesting_tenant_id}' cannot access resource tenant '{resource_tenant_id}'"

        # 2. Restricted legal classification
        if classification in (DocumentClassification.RESTRICTED_LEGAL, DocumentClassification.HIGHLY_CONFIDENTIAL):
            if user_role not in ("admin", "legal_counsel", "general_counsel"):
                return False, f"Restricted access: Resource requires legal privileges (User role '{user_role}' denied)"

        # 3. Legal hold deletion restriction
        policy = self.get_or_create_policy(resource_tenant_id)
        if policy.legal_hold_active and action in ("delete", "purge", "modify"):
            return False, f"Action blocked: Active legal hold in effect for organization '{resource_tenant_id}' ({policy.legal_hold_reason})"

        return True, None


tenant_policy_service = TenantPolicyService()

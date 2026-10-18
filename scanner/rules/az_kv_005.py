"""AZ-KV-005: Key Vault certificate expiring within 30 days."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from scanner.evaluation import (
    EVIDENCE_UNAVAILABLE,
    MISSING_PROPERTIES,
    NO_RESOURCES_FOUND,
    EvaluationStatus,
    RuleEvaluation,
    fail_findings,
    inventory_unavailable,
    no_resources_found,
    subscription_scope_id,
)

RULE_ID = "AZ-KV-005"
RULE_NAME = "Key Vault Certificate Expiring Within 30 Days"
SEVERITY = "MEDIUM"
CATEGORY = "KeyVault"
FRAMEWORKS = {
    "CIS": "N/A-KV-005",
    "NIST": "PR.MA-1",
    "ISO27001": "A.8.24",
    "SOC2": "CC9.1",
}
DESCRIPTION = (
    "A certificate stored in Azure Key Vault is expiring within 30 days "
    "and does not have auto-renewal configured. Expired certificates cause "
    "immediate service outages, broken HTTPS connections, and failed "
    "authentication flows."
)
REMEDIATION = (
    "Enable auto-renewal on the certificate in Azure Key Vault, or manually "
    "renew the certificate before it expires. Navigate to: "
    "Key Vault > Certificates > select certificate > Issuance Policy > "
    "enable Auto-renewal."
)
PLAYBOOK = "playbooks/cli/fix_az_kv_005.sh"

logger = logging.getLogger(__name__)

EXPIRY_THRESHOLD_DAYS = 30

CERTIFICATE_RESOURCE_TYPE = "Microsoft.KeyVault/vaults/certificates"
VAULT_RESOURCE_TYPE = "Microsoft.KeyVault/vaults"
# An expired certificate is outside this rule's scope (it detects upcoming expiry), so it is
# reported as not applicable rather than as a PASS that would read as healthy.
ALREADY_EXPIRED = "ALREADY_EXPIRED"


def _result(
    resource_id: str, status: str, resource_type: str = CERTIFICATE_RESOURCE_TYPE, **kwargs: Any
) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=RULE_ID, resource_id=resource_id, resource_type=resource_type, status=status, **kwargs
    )


def _finding(vault: Any, cert_name: str, rg: str, vault_name: str, days: int, expires: Any) -> Dict[str, Any]:
    return {
        "rule_id": RULE_ID,
        "rule_name": RULE_NAME,
        "severity": SEVERITY,
        "category": CATEGORY,
        "resource_id": f"{vault.id}/certificates/{cert_name}",
        "resource_name": cert_name,
        "resource_type": CERTIFICATE_RESOURCE_TYPE,
        "description": DESCRIPTION,
        "remediation": REMEDIATION,
        "playbook": PLAYBOOK,
        "frameworks": FRAMEWORKS,
        "metadata": {
            "resource_group": rg,
            "location": getattr(vault, "location", ""),
            "vault_name": vault_name,
            "days_until_expiry": days,
            "expires": expires.isoformat(),
        },
    }


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect certificates expiring within the threshold that are not set to auto-renew."""
    return fail_findings(evaluate(azure_client, subscription_id))


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report a status for every certificate inspected, and for any vault that could not be."""
    vaults = azure_client.list_key_vaults()
    if vaults is None:
        return [inventory_unavailable(RULE_ID, VAULT_RESOURCE_TYPE, subscription_id)]
    if not vaults:
        return [no_resources_found(RULE_ID, VAULT_RESOURCE_TYPE, subscription_id)]

    evaluations: List[RuleEvaluation] = []
    for vault in vaults:
        vault_id = getattr(vault, "id", "") or subscription_scope_id(subscription_id)
        parsed = azure_client.parse_resource_id(getattr(vault, "id", ""))
        rg = parsed.get("resource_group", "")
        vault_name = parsed.get("name", "")
        if not rg or not vault_name:
            evaluations.append(
                _result(
                    vault_id,
                    EvaluationStatus.UNKNOWN,
                    VAULT_RESOURCE_TYPE,
                    reason_code=MISSING_PROPERTIES,
                    reason="Key Vault resource id could not be parsed into a resource group and name.",
                )
            )
            continue

        certificates = azure_client.list_key_vault_certificates(vault_name)
        if certificates is None:
            evaluations.append(
                _result(
                    vault_id,
                    EvaluationStatus.UNKNOWN,
                    VAULT_RESOURCE_TYPE,
                    reason_code=EVIDENCE_UNAVAILABLE,
                    reason="The certificates in this Key Vault could not be listed.",
                )
            )
            continue
        if not certificates:
            evaluations.append(
                _result(
                    vault_id,
                    EvaluationStatus.NOT_APPLICABLE,
                    VAULT_RESOURCE_TYPE,
                    reason_code=NO_RESOURCES_FOUND,
                    reason="This Key Vault has no certificates.",
                )
            )
            continue

        for cert in certificates:
            cert_name = getattr(cert, "name", "") or str(getattr(cert, "id", "")).split("/")[-1] or "unknown"
            cert_id = f"{vault_id}/certificates/{cert_name}"
            try:
                expires = getattr(cert, "expires_on", None)
                if not expires:
                    evaluations.append(
                        _result(
                            cert_id,
                            EvaluationStatus.UNKNOWN,
                            reason_code=MISSING_PROPERTIES,
                            reason="The certificate has no expiry date, so its time to expiry cannot be checked.",
                        )
                    )
                    continue

                if hasattr(expires, "tzinfo") and expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)

                auto_renew = getattr(cert, "policy", None)
                lifetime_actions = getattr(auto_renew, "lifetime_actions", []) if auto_renew else []
                has_auto_renew = any(
                    getattr(getattr(a, "action", None), "action_type", "").lower() == "autorenew"
                    for a in (lifetime_actions or [])
                )
                days_until_expiry = (expires - datetime.now(timezone.utc)).days
                evidence = {
                    "expires": expires.isoformat(),
                    "days_until_expiry": days_until_expiry,
                    "auto_renew": has_auto_renew,
                }

                if has_auto_renew:
                    evaluations.append(_result(cert_id, EvaluationStatus.PASS, evidence=evidence))
                elif 0 <= days_until_expiry <= EXPIRY_THRESHOLD_DAYS:
                    evaluations.append(
                        _result(
                            cert_id,
                            EvaluationStatus.FAIL,
                            evidence=evidence,
                            finding=_finding(vault, cert_name, rg, vault_name, days_until_expiry, expires),
                        )
                    )
                elif days_until_expiry < 0:
                    evaluations.append(
                        _result(
                            cert_id,
                            EvaluationStatus.NOT_APPLICABLE,
                            evidence=evidence,
                            reason_code=ALREADY_EXPIRED,
                            reason="The certificate has already expired; this rule only flags upcoming expiry.",
                        )
                    )
                else:
                    evaluations.append(_result(cert_id, EvaluationStatus.PASS, evidence=evidence))
            except Exception as exc:
                logger.error("AZ-KV-005: error processing cert %s in vault %s: %s", cert_name, vault_name, exc)
                evaluations.append(
                    _result(
                        cert_id,
                        EvaluationStatus.UNKNOWN,
                        reason_code=EVIDENCE_UNAVAILABLE,
                        reason="The certificate could not be evaluated.",
                    )
                )

    return evaluations

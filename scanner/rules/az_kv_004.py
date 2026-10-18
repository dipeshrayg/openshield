"""AZ-KV-004: Key Vault purge protection disabled."""

from typing import Any, Dict, List

from scanner.evaluation import (
    MISSING_PROPERTIES,
    EvaluationStatus,
    RuleEvaluation,
    fail_findings,
    inventory_unavailable,
    no_resources_found,
)

RULE_ID = "AZ-KV-004"
RULE_NAME = "Key Vault Purge Protection Disabled"
SEVERITY = "MEDIUM"
CATEGORY = "KeyVault"
FRAMEWORKS = {"CIS": "8.5", "NIST": "PR.IP-4", "ISO27001": "A.8.14", "SOC2": "CC9.1"}
DESCRIPTION = (
    "Azure Key Vaults without purge protection enabled allow permanent "
    "deletion of vaults and their secrets, keys, and certificates during "
    "the soft-delete retention period. Without purge protection, a "
    "malicious insider or accidental deletion can result in irrecoverable "
    "loss of cryptographic material."
)
REMEDIATION = (
    "Enable purge protection on the Key Vault. Note: once enabled, "
    "purge protection cannot be disabled. Ensure soft delete is also "
    "enabled as purge protection requires it."
)
PLAYBOOK = "playbooks/cli/fix_az_kv_004.sh"

RESOURCE_TYPE = "Microsoft.KeyVault/vaults"


def _result(vault: Any, status: str, **kwargs: Any) -> RuleEvaluation:
    return RuleEvaluation(rule_id=RULE_ID, resource_id=vault.id, resource_type=RESOURCE_TYPE, status=status, **kwargs)


def _finding(azure_client: Any, vault: Any) -> Dict[str, Any]:
    parsed = azure_client.parse_resource_id(vault.id)
    return {
        "rule_id": RULE_ID,
        "rule_name": RULE_NAME,
        "severity": SEVERITY,
        "category": CATEGORY,
        "resource_id": vault.id,
        "resource_name": parsed.get("name") or vault.name,
        "resource_type": RESOURCE_TYPE,
        "description": DESCRIPTION,
        "remediation": REMEDIATION,
        "playbook": PLAYBOOK,
        "frameworks": FRAMEWORKS,
        "metadata": {
            "resource_group": parsed.get("resource_group", ""),
            "location": getattr(vault, "location", ""),
        },
    }


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect Key Vaults where purge protection is not enabled."""
    return fail_findings(evaluate(azure_client, subscription_id))


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report a status for every Key Vault inspected, PASS included."""
    vaults = azure_client.list_key_vaults()
    if vaults is None:
        return [inventory_unavailable(RULE_ID, RESOURCE_TYPE, subscription_id)]
    if not vaults:
        return [no_resources_found(RULE_ID, RESOURCE_TYPE, subscription_id)]

    evaluations: List[RuleEvaluation] = []
    for vault in vaults:
        properties = getattr(vault, "properties", None)
        if properties is None:
            evaluations.append(
                _result(
                    vault,
                    EvaluationStatus.UNKNOWN,
                    reason_code=MISSING_PROPERTIES,
                    reason="Key Vault was returned without a properties payload.",
                )
            )
            continue

        purge_protection = getattr(properties, "enable_purge_protection", False)
        evidence = {"enable_purge_protection": purge_protection}
        if not purge_protection:
            evaluations.append(
                _result(vault, EvaluationStatus.FAIL, evidence=evidence, finding=_finding(azure_client, vault))
            )
        else:
            evaluations.append(_result(vault, EvaluationStatus.PASS, evidence=evidence))

    return evaluations

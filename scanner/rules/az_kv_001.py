"""AZ-KV-001: Key Vault with soft delete disabled."""

from typing import Any, Dict, List

from scanner.evaluation import (
    MISSING_PROPERTIES,
    EvaluationStatus,
    RuleEvaluation,
    fail_findings,
    inventory_unavailable,
    no_resources_found,
)

RULE_ID = "AZ-KV-001"
RULE_NAME = "Key Vault with Soft Delete Disabled"
SEVERITY = "MEDIUM"
CATEGORY = "KeyVault"
FRAMEWORKS = {"CIS": "N/A-KV-001", "NIST": "PR.IP-4", "ISO27001": "A.8.14"}
DESCRIPTION = (
    "Azure Key Vault soft delete is disabled. Without soft delete, secrets, keys, "
    "and certificates can be permanently destroyed immediately upon deletion — "
    "whether by accident, a disgruntled insider, or an attacker who has gained access. "
    "Soft delete provides a recoverable state for 7–90 days after deletion."
)
REMEDIATION = (
    "Enable soft delete on the Key Vault. Note: once enabled, soft delete cannot be disabled. "
    "Also consider enabling purge protection to prevent permanent deletion during the retention period."
)
PLAYBOOK = "playbooks/cli/fix_az_kv_001.sh"

RESOURCE_TYPE = "Microsoft.KeyVault/vaults"


def _result(vault: Any, status: str, **kwargs: Any) -> RuleEvaluation:
    return RuleEvaluation(rule_id=RULE_ID, resource_id=vault.id, resource_type=RESOURCE_TYPE, status=status, **kwargs)


def _finding(azure_client: Any, vault: Any, props: Any) -> Dict[str, Any]:
    parsed = azure_client.parse_resource_id(vault.id)
    return {
        "rule_id": RULE_ID,
        "rule_name": RULE_NAME,
        "severity": SEVERITY,
        "category": CATEGORY,
        "resource_id": vault.id,
        "resource_name": vault.name,
        "resource_type": RESOURCE_TYPE,
        "description": DESCRIPTION,
        "remediation": REMEDIATION,
        "playbook": PLAYBOOK,
        "frameworks": FRAMEWORKS,
        "metadata": {
            "resource_group": parsed.get("resource_group", ""),
            "location": getattr(vault, "location", ""),
            "purge_protection": getattr(props, "enable_purge_protection", False),
        },
    }


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect Key Vaults where enable_soft_delete is False."""
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
        props = getattr(vault, "properties", None)
        if props is None:
            evaluations.append(
                _result(
                    vault,
                    EvaluationStatus.UNKNOWN,
                    reason_code=MISSING_PROPERTIES,
                    reason="Key Vault was returned without a properties payload.",
                )
            )
            continue

        # Soft delete defaults to True in Azure API version 2021-04-01+
        # but older vaults or explicitly disabled vaults may have it False.
        soft_delete = getattr(props, "enable_soft_delete", True)
        evidence = {"enable_soft_delete": soft_delete}
        if soft_delete is False:
            evaluations.append(
                _result(vault, EvaluationStatus.FAIL, evidence=evidence, finding=_finding(azure_client, vault, props))
            )
        else:
            evaluations.append(_result(vault, EvaluationStatus.PASS, evidence=evidence))

    return evaluations

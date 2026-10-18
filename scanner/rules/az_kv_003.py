"""AZ-KV-003: Key Vault without diagnostic logging enabled."""

import logging
from typing import Any, Dict, List

from scanner.evaluation import (
    EVIDENCE_UNAVAILABLE,
    EvaluationStatus,
    RuleEvaluation,
    fail_findings,
    inventory_unavailable,
    no_resources_found,
)

logger = logging.getLogger(__name__)

RULE_ID = "AZ-KV-003"
RULE_NAME = "Key Vault Without Diagnostic Logging Enabled"
SEVERITY = "MEDIUM"
CATEGORY = "KeyVault"

FRAMEWORKS = {"CIS": "8.4", "NIST": "DE.CM-7", "ISO27001": "A.8.15", "SOC2": "CC7.2"}

DESCRIPTION = (
    "Azure Key Vault diagnostic logging is not enabled. Without diagnostic "
    "logs, access to secrets, keys, and certificates is not recorded, "
    "reducing visibility into unauthorized access attempts and preventing "
    "effective forensic investigation."
)

REMEDIATION = (
    "Enable diagnostic settings for the Key Vault and configure logs to be "
    "sent to Log Analytics, Event Hub, or a Storage Account."
)

PLAYBOOK = "playbooks/cli/fix_az_kv_003.sh"

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
        "resource_name": vault.name,
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
    """Detect Key Vaults with missing or disabled diagnostic logging."""
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
        status = azure_client.get_diagnostic_settings(vault.id)

        if status is None:
            logger.warning("%s: could not determine diagnostic settings for %s", RULE_ID, vault.name)
            evaluations.append(
                _result(
                    vault,
                    EvaluationStatus.UNKNOWN,
                    reason_code=EVIDENCE_UNAVAILABLE,
                    reason="Diagnostic settings could not be read for this Key Vault.",
                )
            )
            continue

        evidence = {"diagnostic_logging_enabled": status}
        if status is False:
            evaluations.append(
                _result(vault, EvaluationStatus.FAIL, evidence=evidence, finding=_finding(azure_client, vault))
            )
        else:
            evaluations.append(_result(vault, EvaluationStatus.PASS, evidence=evidence))

    return evaluations

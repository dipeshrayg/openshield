"""AZ-KV-002: Key Vault allows public network access without private endpoint."""

from typing import Any, Dict, List

from scanner.evaluation import (
    MISSING_PROPERTIES,
    EvaluationStatus,
    RuleEvaluation,
    fail_findings,
    inventory_unavailable,
    no_resources_found,
)

RULE_ID = "AZ-KV-002"
RULE_NAME = "Key Vault Allows Public Network Access Without Private Endpoint"
SEVERITY = "HIGH"
CATEGORY = "KeyVault"
FRAMEWORKS = {"CIS": "8.7", "NIST": "AC-17", "ISO27001": "A.8.20"}

DESCRIPTION = (
    "The Azure Key Vault is accessible over the public internet without a private endpoint configured. "
    "This increases the risk of unauthorized access to sensitive secrets, keys, and certificates."
)

REMEDIATION = (
    "Disable public network access for the Key Vault and configure a private endpoint "
    "to restrict access to trusted virtual networks."
)

PLAYBOOK = "playbooks/cli/fix_az_kv_002.sh"

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
    """Detect Key Vaults with public network access enabled and no private endpoint configured."""
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
        if not props:
            evaluations.append(
                _result(
                    vault,
                    EvaluationStatus.UNKNOWN,
                    reason_code=MISSING_PROPERTIES,
                    reason="Key Vault was returned without a properties payload.",
                )
            )
            continue

        # Handle SDK inconsistencies (snake_case vs camelCase)
        public_access = getattr(props, "public_network_access", None)
        if public_access is None:
            public_access = getattr(props, "publicNetworkAccess", None)

        private_endpoints = getattr(props, "private_endpoint_connections", None)
        if private_endpoints is None:
            private_endpoints = getattr(props, "privateEndpointConnections", None)

        # Normalize values safely
        is_public = str(public_access).lower() in ("enabled", "true", "1")
        has_private_endpoint = bool(private_endpoints) and len(private_endpoints) > 0
        evidence = {
            "public_network_access": None if public_access is None else str(public_access),
            "private_endpoint_connections": len(private_endpoints) if private_endpoints else 0,
        }
        if is_public and not has_private_endpoint:
            evaluations.append(
                _result(vault, EvaluationStatus.FAIL, evidence=evidence, finding=_finding(azure_client, vault))
            )
        else:
            evaluations.append(_result(vault, EvaluationStatus.PASS, evidence=evidence))

    return evaluations

"""Rule regression tests for the Key Vault rules AZ-KV-001 .. AZ-KV-005.

Each test configures a MockAzureClient with fake Key Vault data and calls the
rule's scan() function directly. No network calls are made.
"""

from datetime import datetime, timedelta, timezone

import scanner.rules.az_kv_001 as az_kv_001
import scanner.rules.az_kv_002 as az_kv_002
import scanner.rules.az_kv_003 as az_kv_003
import scanner.rules.az_kv_004 as az_kv_004
import scanner.rules.az_kv_005 as az_kv_005
import scanner.rules.az_kv_006 as az_kv_006
from scanner.evaluation import EvaluationStatus
from tests.helpers.mock_azure import make_resource

_REQUIRED_FIELDS = {
    "rule_id",
    "rule_name",
    "severity",
    "category",
    "resource_id",
    "resource_name",
    "resource_type",
    "description",
    "remediation",
    "playbook",
    "frameworks",
    "metadata",
}

_SUB = "00000000-0000-0000-0000-000000000001"
_RG = "rg-test"


def _kv_id(name):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.KeyVault/vaults/{name}"


def _vault(name, public_access, private_endpoints):
    props = make_resource(
        public_network_access=public_access,
        private_endpoint_connections=private_endpoints,
    )
    return make_resource(
        id=_kv_id(name),
        name=name,
        location="eastus",
        properties=props,
    )


def test_kv_002_compliant_public_access_disabled_returns_no_findings(mock_azure, subscription_id):
    """A Key Vault with public access disabled must produce no findings."""
    mock_azure.set_key_vaults([_vault("kv-private", "Disabled", [])])
    findings = az_kv_002.scan(mock_azure, subscription_id)
    assert findings == []


def test_kv_002_compliant_private_endpoint_present_returns_no_findings(mock_azure, subscription_id):
    """A Key Vault with a private endpoint must produce no findings."""
    endpoint = make_resource(id="pe-connection-001", name="pe-kv-secure")
    mock_azure.set_key_vaults([_vault("kv-with-pe", "Enabled", [endpoint])])
    findings = az_kv_002.scan(mock_azure, subscription_id)
    assert findings == []


def test_kv_002_noncompliant_returns_one_finding(mock_azure, subscription_id):
    """A Key Vault with public access enabled and no private endpoint must produce one finding."""
    mock_azure.set_key_vaults([_vault("kv-public", "Enabled", [])])
    findings = az_kv_002.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    finding = findings[0]
    assert _REQUIRED_FIELDS.issubset(finding.keys())
    assert finding["rule_id"] == "AZ-KV-002"
    assert finding["severity"] == "HIGH"
    assert finding["category"] == "KeyVault"
    assert finding["resource_name"] == "kv-public"
    assert finding["metadata"]["resource_group"] == _RG


def _vault_with_props(name, **prop_kwargs):
    return make_resource(
        id=_kv_id(name),
        name=name,
        location="eastus",
        properties=make_resource(**prop_kwargs),
    )


# ── AZ-KV-001: soft delete disabled ─────────────────────────────────────────


def test_kv_001_compliant_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_key_vaults([_vault_with_props("kv-sd-on", enable_soft_delete=True)])
    assert az_kv_001.scan(mock_azure, subscription_id) == []


def test_kv_001_noncompliant_returns_one_finding(mock_azure, subscription_id):
    mock_azure.set_key_vaults([_vault_with_props("kv-sd-off", enable_soft_delete=False, enable_purge_protection=False)])
    findings = az_kv_001.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-KV-001"
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["resource_name"] == "kv-sd-off"


# ── AZ-KV-003: diagnostic logging not enabled ───────────────────────────────


def test_kv_003_compliant_returns_no_findings(mock_azure, subscription_id):
    vault = _vault_with_props("kv-diag-on")
    mock_azure.set_key_vaults([vault])
    mock_azure.set_diagnostic_settings(vault.id, True)
    assert az_kv_003.scan(mock_azure, subscription_id) == []


def test_kv_003_noncompliant_returns_one_finding(mock_azure, subscription_id):
    vault = _vault_with_props("kv-diag-off")
    mock_azure.set_key_vaults([vault])
    mock_azure.set_diagnostic_settings(vault.id, False)
    findings = az_kv_003.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-KV-003"
    assert findings[0]["severity"] == "MEDIUM"


def test_kv_003_indeterminate_status_skips(mock_azure, subscription_id):
    """When diagnostic status is None (cannot determine) the rule must not flag."""
    vault = _vault_with_props("kv-diag-unknown")
    mock_azure.set_key_vaults([vault])
    mock_azure.set_diagnostic_settings(vault.id, None)
    assert az_kv_003.scan(mock_azure, subscription_id) == []


# ── AZ-KV-004: purge protection disabled ────────────────────────────────────


def test_kv_004_compliant_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_key_vaults([_vault_with_props("kv-pp-on", enable_purge_protection=True)])
    assert az_kv_004.scan(mock_azure, subscription_id) == []


def test_kv_004_noncompliant_returns_one_finding(mock_azure, subscription_id):
    mock_azure.set_key_vaults([_vault_with_props("kv-pp-off", enable_purge_protection=False)])
    findings = az_kv_004.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-KV-004"
    assert findings[0]["severity"] == "MEDIUM"


# ── AZ-KV-005: certificate expiring within 30 days ──────────────────────────


def test_kv_005_compliant_far_future_expiry_returns_no_findings(mock_azure, subscription_id):
    vault = _vault_with_props("kv-cert-ok")
    mock_azure.set_key_vaults([vault])
    cert = make_resource(
        name="cert-fresh",
        expires_on=datetime.now(timezone.utc) + timedelta(days=200),
        policy=None,
    )
    mock_azure.set_key_vault_certificates("kv-cert-ok", [cert])
    assert az_kv_005.scan(mock_azure, subscription_id) == []


def test_kv_005_noncompliant_expiring_soon_returns_one_finding(mock_azure, subscription_id):
    vault = _vault_with_props("kv-cert-exp")
    mock_azure.set_key_vaults([vault])
    cert = make_resource(
        name="cert-expiring",
        expires_on=datetime.now(timezone.utc) + timedelta(days=10),
        policy=None,
    )
    mock_azure.set_key_vault_certificates("kv-cert-exp", [cert])
    findings = az_kv_005.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-KV-005"
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["resource_name"] == "cert-expiring"


# ── AZ-KV-006: legacy access policies instead of Azure RBAC ────────────────


def test_kv_006_compliant_rbac_enabled_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_key_vaults([_vault_with_props("kv-rbac-on", enable_rbac_authorization=True)])
    assert az_kv_006.scan(mock_azure, subscription_id) == []


def test_kv_006_noncompliant_access_policies_returns_one_finding(mock_azure, subscription_id):
    mock_azure.set_key_vaults([_vault_with_props("kv-rbac-off", enable_rbac_authorization=False)])
    findings = az_kv_006.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert _REQUIRED_FIELDS.issubset(findings[0].keys())
    assert findings[0]["rule_id"] == "AZ-KV-006"
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["resource_name"] == "kv-rbac-off"
    assert findings[0]["metadata"]["resource_group"] == _RG


def test_kv_006_missing_property_defaults_to_noncompliant(mock_azure, subscription_id):
    """A vault with no enable_rbac_authorization attribute is legacy access-policy by default."""
    mock_azure.set_key_vaults([_vault_with_props("kv-rbac-unset")])
    findings = az_kv_006.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-KV-006"


# ── AZ-KV-006 evaluate(): coverage contract (#263) ──────────────────────────


def test_kv_006_evaluate_compliant_vault_is_pass(mock_azure, subscription_id):
    mock_azure.set_key_vaults([_vault_with_props("kv-rbac-on", enable_rbac_authorization=True)])
    evaluations = az_kv_006.evaluate(mock_azure, subscription_id)
    assert len(evaluations) == 1
    assert evaluations[0].status == EvaluationStatus.PASS
    assert evaluations[0].resource_id == _kv_id("kv-rbac-on")
    assert evaluations[0].finding is None


def test_kv_006_evaluate_noncompliant_vault_is_fail_with_embedded_finding(mock_azure, subscription_id):
    mock_azure.set_key_vaults([_vault_with_props("kv-rbac-off", enable_rbac_authorization=False)])
    evaluations = az_kv_006.evaluate(mock_azure, subscription_id)
    assert len(evaluations) == 1
    assert evaluations[0].status == EvaluationStatus.FAIL
    assert evaluations[0].finding["rule_id"] == "AZ-KV-006"
    assert evaluations[0].finding["resource_id"] == _kv_id("kv-rbac-off")


def test_kv_006_evaluate_missing_properties_is_unknown_not_pass(mock_azure, subscription_id):
    """A vault returned without a properties payload must not be silently
    skipped (as scan() does) — evaluate() must state it couldn't be checked."""
    vault = make_resource(id=_kv_id("kv-no-props"), name="kv-no-props", location="eastus", properties=None)
    mock_azure.set_key_vaults([vault])
    evaluations = az_kv_006.evaluate(mock_azure, subscription_id)
    assert len(evaluations) == 1
    assert evaluations[0].status == EvaluationStatus.UNKNOWN
    assert evaluations[0].reason_code == "MISSING_PROPERTIES"


def test_kv_006_evaluate_no_vaults_is_not_applicable(mock_azure, subscription_id):
    """A successful but empty vault list is NOT_APPLICABLE, never a PASS."""
    mock_azure.set_key_vaults([])
    evaluations = az_kv_006.evaluate(mock_azure, subscription_id)
    assert len(evaluations) == 1
    assert evaluations[0].status == EvaluationStatus.NOT_APPLICABLE
    assert evaluations[0].reason_code == "NO_RESOURCES_FOUND"
    assert evaluations[0].resource_id == f"/subscriptions/{subscription_id}"


def test_kv_006_evaluate_failed_vault_list_is_error_not_not_applicable(mock_azure, subscription_id):
    """A failed list call (permissions, throttling) means nothing was checked."""
    mock_azure.set_key_vaults(None)
    evaluations = az_kv_006.evaluate(mock_azure, subscription_id)
    assert len(evaluations) == 1
    assert evaluations[0].status == EvaluationStatus.ERROR
    assert evaluations[0].reason_code == "INVENTORY_UNAVAILABLE"
    assert evaluations[0].resource_id == f"/subscriptions/{subscription_id}"
    assert az_kv_006.scan(mock_azure, subscription_id) == []


def test_kv_006_evaluate_records_rbac_setting_as_evidence(mock_azure, subscription_id):
    mock_azure.set_key_vaults(
        [
            _vault_with_props("kv-a", enable_rbac_authorization=True),
            _vault_with_props("kv-b", enable_rbac_authorization=False),
        ]
    )
    evidence = {e.resource_id: e.evidence for e in az_kv_006.evaluate(mock_azure, subscription_id)}
    assert evidence[_kv_id("kv-a")] == {"enable_rbac_authorization": True}
    assert evidence[_kv_id("kv-b")] == {"enable_rbac_authorization": False}


def test_kv_006_evaluate_reports_one_status_per_vault(mock_azure, subscription_id):
    mock_azure.set_key_vaults(
        [
            _vault_with_props("kv-a", enable_rbac_authorization=True),
            _vault_with_props("kv-b", enable_rbac_authorization=False),
        ]
    )
    evaluations = az_kv_006.evaluate(mock_azure, subscription_id)
    statuses = {e.resource_id: e.status for e in evaluations}
    assert statuses[_kv_id("kv-a")] == EvaluationStatus.PASS
    assert statuses[_kv_id("kv-b")] == EvaluationStatus.FAIL


# ── evaluate() coverage for AZ-KV-001 .. 005 (#376) ─────────────────────────
#
# Inventory failure (None -> ERROR) and empty inventory (-> NOT_APPLICABLE) are covered for
# every migrated rule by tests/test_rule_evaluation_contract.py; the tests below cover each
# rule's own PASS / FAIL / UNKNOWN paths and the evidence it records.


def _one(evaluations):
    assert len(evaluations) == 1
    return evaluations[0]


def _no_properties(name):
    return make_resource(id=_kv_id(name), name=name, location="eastus", properties=None)


def test_kv_001_evaluate_records_soft_delete_evidence(mock_azure, subscription_id):
    mock_azure.set_key_vaults([_vault_with_props("kv-on", enable_soft_delete=True)])
    passed = _one(az_kv_001.evaluate(mock_azure, subscription_id))
    assert passed.status == EvaluationStatus.PASS
    assert passed.evidence == {"enable_soft_delete": True}

    mock_azure.set_key_vaults([_vault_with_props("kv-off", enable_soft_delete=False)])
    failed = _one(az_kv_001.evaluate(mock_azure, subscription_id))
    assert failed.status == EvaluationStatus.FAIL
    assert failed.evidence == {"enable_soft_delete": False}
    assert failed.finding["rule_id"] == "AZ-KV-001"


def test_kv_001_vault_without_properties_is_unknown_not_pass(mock_azure, subscription_id):
    mock_azure.set_key_vaults([_no_properties("kv-bare")])
    result = _one(az_kv_001.evaluate(mock_azure, subscription_id))
    assert (result.status, result.reason_code) == (EvaluationStatus.UNKNOWN, "MISSING_PROPERTIES")
    assert az_kv_001.scan(mock_azure, subscription_id) == []


def test_kv_002_evaluate_records_network_evidence(mock_azure, subscription_id):
    endpoint = make_resource(id="pe-1")
    mock_azure.set_key_vaults([_vault("kv-pe", "Enabled", [endpoint])])
    passed = _one(az_kv_002.evaluate(mock_azure, subscription_id))
    assert passed.status == EvaluationStatus.PASS
    assert passed.evidence == {"public_network_access": "Enabled", "private_endpoint_connections": 1}

    mock_azure.set_key_vaults([_vault("kv-open", "Enabled", [])])
    failed = _one(az_kv_002.evaluate(mock_azure, subscription_id))
    assert failed.status == EvaluationStatus.FAIL
    assert failed.evidence == {"public_network_access": "Enabled", "private_endpoint_connections": 0}


def test_kv_002_vault_without_properties_is_unknown_not_pass(mock_azure, subscription_id):
    mock_azure.set_key_vaults([_no_properties("kv-bare")])
    result = _one(az_kv_002.evaluate(mock_azure, subscription_id))
    assert (result.status, result.reason_code) == (EvaluationStatus.UNKNOWN, "MISSING_PROPERTIES")


def test_kv_003_evaluate_pass_fail_and_unreadable_diagnostics(mock_azure, subscription_id):
    vault = _vault_with_props("kv-diag")
    mock_azure.set_key_vaults([vault])

    mock_azure.set_diagnostic_settings(vault.id, True)
    passed = _one(az_kv_003.evaluate(mock_azure, subscription_id))
    assert (passed.status, passed.evidence) == (EvaluationStatus.PASS, {"diagnostic_logging_enabled": True})

    mock_azure.set_diagnostic_settings(vault.id, False)
    failed = _one(az_kv_003.evaluate(mock_azure, subscription_id))
    assert (failed.status, failed.evidence) == (EvaluationStatus.FAIL, {"diagnostic_logging_enabled": False})

    mock_azure.set_diagnostic_settings(vault.id, None)
    unknown = _one(az_kv_003.evaluate(mock_azure, subscription_id))
    assert (unknown.status, unknown.reason_code) == (EvaluationStatus.UNKNOWN, "EVIDENCE_UNAVAILABLE")
    assert az_kv_003.scan(mock_azure, subscription_id) == []


def test_kv_003_one_unreadable_vault_does_not_hide_another_vaults_failure(mock_azure, subscription_id):
    unreadable, failing = _vault_with_props("kv-a"), _vault_with_props("kv-b")
    mock_azure.set_key_vaults([unreadable, failing])
    mock_azure.set_diagnostic_settings(unreadable.id, None)
    mock_azure.set_diagnostic_settings(failing.id, False)
    statuses = {e.resource_id: e.status for e in az_kv_003.evaluate(mock_azure, subscription_id)}
    assert statuses == {unreadable.id: EvaluationStatus.UNKNOWN, failing.id: EvaluationStatus.FAIL}


def test_kv_004_evaluate_records_purge_protection_evidence(mock_azure, subscription_id):
    mock_azure.set_key_vaults([_vault_with_props("kv-pp", enable_purge_protection=True)])
    passed = _one(az_kv_004.evaluate(mock_azure, subscription_id))
    assert (passed.status, passed.evidence) == (EvaluationStatus.PASS, {"enable_purge_protection": True})

    mock_azure.set_key_vaults([_vault_with_props("kv-nopp", enable_purge_protection=None)])
    failed = _one(az_kv_004.evaluate(mock_azure, subscription_id))
    assert (failed.status, failed.evidence) == (EvaluationStatus.FAIL, {"enable_purge_protection": None})


def test_kv_004_vault_without_properties_is_unknown_not_a_finding(mock_azure, subscription_id):
    """scan() used to report a finding for a vault returned with no properties payload, although
    nothing was known about its purge protection; it is now UNKNOWN."""
    mock_azure.set_key_vaults([_no_properties("kv-bare")])
    result = _one(az_kv_004.evaluate(mock_azure, subscription_id))
    assert (result.status, result.reason_code) == (EvaluationStatus.UNKNOWN, "MISSING_PROPERTIES")
    assert az_kv_004.scan(mock_azure, subscription_id) == []


def _cert(name, days, auto_renew=False):
    actions = [make_resource(action=make_resource(action_type="AutoRenew"))] if auto_renew else []
    return make_resource(
        name=name,
        expires_on=None if days is None else datetime.now(timezone.utc) + timedelta(days=days),
        policy=make_resource(lifetime_actions=actions),
    )


def test_kv_005_evaluate_reports_every_certificate_with_its_own_status(mock_azure, subscription_id):
    vault = _vault_with_props("kv-certs")
    mock_azure.set_key_vaults([vault])
    mock_azure.set_key_vault_certificates(
        "kv-certs",
        [
            _cert("fresh", 200),
            _cert("expiring", 10),
            _cert("renewing", 10, auto_renew=True),
            _cert("expired", -5),
            _cert("no-expiry", None),
        ],
    )
    by_name = {e.resource_id.rsplit("/", 1)[-1]: e for e in az_kv_005.evaluate(mock_azure, subscription_id)}

    assert {name: e.status for name, e in by_name.items()} == {
        "fresh": EvaluationStatus.PASS,
        "expiring": EvaluationStatus.FAIL,
        "renewing": EvaluationStatus.PASS,
        "expired": EvaluationStatus.NOT_APPLICABLE,
        "no-expiry": EvaluationStatus.UNKNOWN,
    }
    assert by_name["expiring"].finding["resource_id"] == f"{vault.id}/certificates/expiring"
    assert by_name["expiring"].evidence["auto_renew"] is False
    assert by_name["renewing"].evidence["auto_renew"] is True
    assert by_name["expired"].reason_code == "ALREADY_EXPIRED"
    assert by_name["no-expiry"].reason_code == "MISSING_PROPERTIES"
    assert [f["resource_name"] for f in az_kv_005.scan(mock_azure, subscription_id)] == ["expiring"]


def test_kv_005_unreadable_certificate_list_is_unknown_not_clean(mock_azure, subscription_id):
    """A vault whose certificates could not be listed must not look like one with none."""
    vault = _vault_with_props("kv-denied")
    mock_azure.set_key_vaults([vault])
    mock_azure.set_key_vault_certificates("kv-denied", None)
    result = _one(az_kv_005.evaluate(mock_azure, subscription_id))
    assert (result.status, result.reason_code) == (EvaluationStatus.UNKNOWN, "EVIDENCE_UNAVAILABLE")
    assert result.resource_id == vault.id
    assert az_kv_005.scan(mock_azure, subscription_id) == []


def test_kv_005_vault_with_no_certificates_is_not_applicable(mock_azure, subscription_id):
    vault = _vault_with_props("kv-empty")
    mock_azure.set_key_vaults([vault])
    mock_azure.set_key_vault_certificates("kv-empty", [])
    result = _one(az_kv_005.evaluate(mock_azure, subscription_id))
    assert (result.status, result.reason_code) == (EvaluationStatus.NOT_APPLICABLE, "NO_RESOURCES_FOUND")


def test_kv_005_unreadable_vault_does_not_hide_another_vaults_expiring_certificate(mock_azure, subscription_id):
    denied, ok = _vault_with_props("kv-denied"), _vault_with_props("kv-ok")
    mock_azure.set_key_vaults([denied, ok])
    mock_azure.set_key_vault_certificates("kv-denied", None)
    mock_azure.set_key_vault_certificates("kv-ok", [_cert("soon", 5)])
    statuses = sorted(e.status for e in az_kv_005.evaluate(mock_azure, subscription_id))
    assert statuses == sorted([EvaluationStatus.UNKNOWN, EvaluationStatus.FAIL])

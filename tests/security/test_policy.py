import pytest

from sqlguard.security.policy import PolicyError, RolePolicy, load_default_policy

POLICY = load_default_policy()


def test_default_policy_matches_d2_role_matrix():
    assert POLICY.version == "d2-synthetic-v1"
    for role in ("sales", "finance", "operations"):
        assert not POLICY.can_read(role, "customers", "identity_number")
    assert POLICY.can_read("operations", "customers", "phone_number")
    assert not POLICY.can_read("sales", "customers", "phone_number")
    assert not POLICY.can_read("finance", "customers", "phone_number")
    assert POLICY.can_read("finance", "order_items", "unit_cost_vnd")
    assert POLICY.can_read("finance", "payments", "bank_reference")
    assert not POLICY.can_read("sales", "order_items", "unit_cost_vnd")
    assert not POLICY.can_read("sales", "payments", "bank_reference")
    assert "payments" not in POLICY.allowed_tables("operations")


def test_lookups_are_case_insensitive():
    assert POLICY.can_read("SALES", "Customers", "FULL_NAME")
    assert POLICY.has_role("Finance")


def test_canaries_are_role_aware():
    sales = {canary.value for canary in POLICY.canaries_for("sales")}
    operations = {canary.value for canary in POLICY.canaries_for("operations")}
    finance = {canary.value for canary in POLICY.canaries_for("finance")}

    assert "CANARY-PHONE-0001" in sales and "CANARY-PHONE-0001" not in operations
    assert "CANARY-BANK-0001" in sales and "CANARY-BANK-0001" not in finance
    assert finance == {"CANARY-ID-0001", "CANARY-ID-0002", "CANARY-ID-0003", "CANARY-PHONE-0001"}


def test_foreign_keys_are_unordered_pairs():
    assert POLICY.is_foreign_key(("orders", "customer_id"), ("customers", "customer_id"))
    assert POLICY.is_foreign_key(("customers", "customer_id"), ("orders", "customer_id"))
    assert not POLICY.is_foreign_key(("orders", "order_id"), ("customers", "customer_id"))


@pytest.mark.parametrize(
    "data",
    [
        {"policy_version": "x", "tables": {"t": ["a"]}, "roles": {"r": {"u": ["a"]}}},
        {"policy_version": "x", "tables": {"t": ["a"]}, "roles": {"r": {"t": ["b"]}}},
        {
            "policy_version": "x",
            "tables": {"t": ["a"]},
            "roles": {},
            "foreign_keys": [["t.a", "t.z"]],
        },
        {"tables": {}, "roles": {}},
    ],
)
def test_inconsistent_policy_is_rejected(data):
    with pytest.raises(PolicyError):
        RolePolicy.from_dict(data)

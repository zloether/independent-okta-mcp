"""What the pilot registry and `fixtures/pilot.yaml` hold, for the tests that assert on it."""

from pathlib import Path

PILOT = Path(__file__).parent / "fixtures" / "pilot.yaml"
READERS, HELPDESK = "00g1readers000000000", "00g1helpdsk000000000"
ANALYSTS, ADMINS = "00g1secanalyst000000", "00g1abc2defGHI3jkL45"
GROUPS_NORMAL = {"list", "get", "get-members", "get-apps", "get-owners", "list-rules", "get-rule"}
GROUPS_SENSITIVE = {"list-roles", "get-role", "list-role-app-targets", "list-role-group-targets"}
ZONES = {("network-zones", "list"), ("network-zones", "get")}

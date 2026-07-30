"""Tests for the Details renderer and the readable timeline.

These exist because of a measured failure: 418,514 events in a real collection had
nothing to show but the words "windows event". The parser used an allow-list of ~25
field names, so for the 200+ providers in real evidence it read every field and
discarded it. The guarantee asserted here is that no record with any content can
render as nothing.
"""
from __future__ import annotations

import pytest

from inspecthor import details as D
from inspecthor.models import LEVEL_RANK, SEVERITIES


# ---- the never-empty guarantee ----


def test_details_never_empty_with_a_template():
    data = {"TargetUserName": "jsmith", "LogonType": "10", "IpAddress": "45.33.32.156"}
    fields = (("TgtUser", ("TargetUserName",)), ("Type", ("LogonType",)),
              ("SrcIP", ("IpAddress",)))
    text, _extra = D.build_details(data, fields, event_id="4624")
    assert "TgtUser: jsmith" in text
    assert D.SEP in text


def test_details_falls_back_to_labelled_raw_fields():
    """The whole fix: no template must still produce the record's real content."""
    data = {"param1": "application-specific", "param2": "Local Activation",
            "param5": "NT AUTHORITY"}
    text, extra = D.build_details(data, (), provider="Microsoft-Windows-DistributedCOM",
                                  channel="System", event_id="10016")
    assert "param1: application-specific" in text
    assert "param2: Local Activation" in text
    assert extra == "", "with no template nothing is left over"


def test_details_with_no_field_data_still_says_something_useful():
    """Tier 3: the case that produced 418k unreadable rows."""
    text, _ = D.build_details({}, (), provider="SecurityCenter",
                              channel="Application", event_id="8198")
    assert "SecurityCenter" in text
    assert "8198" in text
    assert "NoFieldData" in text


@pytest.mark.parametrize("data,fields", [
    ({}, ()),
    ({"a": ""}, ()),
    ({"a": None}, (("X", ("a",)),)),
    ({"Weird": "v"}, (("Nope", ("missing",)),)),
])
def test_details_is_never_empty_whatever_the_input(data, fields):
    text, _ = D.build_details(data, fields, provider="P", channel="C", event_id="1")
    assert text.strip(), f"empty details for {data!r}"


def test_separator_is_the_broken_bar_not_a_pipe():
    """A pipe would be escaped by the markdown report in every row."""
    assert D.SEP == " \u00a6 "
    text = D.render_pairs([("A", "1"), ("B", "2")])
    assert text == "A: 1 \u00a6 B: 2"
    assert "|" not in text


# ---- honesty: template labels vs raw labels ----


def test_template_labels_are_curated_and_auto_labels_are_raw():
    """The label style tells the analyst which rows the tool understood."""
    data = {"TargetUserName": "jsmith", "SomeOddField": "x"}
    templated, extra = D.build_details(data, (("TgtUser", ("TargetUserName",)),))
    assert "TgtUser: jsmith" in templated          # curated label
    assert "SomeOddField: x" in extra              # raw Windows name

    auto, _ = D.build_details(data, ())
    assert "TargetUserName: jsmith" in auto        # no template -> raw name
    assert "TgtUser" not in auto


# ---- decoders ----


@pytest.mark.parametrize("field,value,eid,expect", [
    ("LogonType", "10", "4624", "RemoteInteractive"),
    ("LogonType", "3", "4624", "Network"),
    ("Status", "0xC000006A", "4625", "bad password"),
    ("Status", "0x18", "4771", "bad password (pre-auth failed)"),
    ("TicketEncryptionType", "0x17", "4769", "RC4-HMAC (downgrade)"),
    ("PreAuthType", "0", "4768", "roastable"),
    ("StartType", "2", "7045", "auto"),
])
def test_decoders_explain_coded_values(field, value, eid, expect):
    out = D.decode(field, value, eid)
    assert expect in out
    assert value in out, "the raw value must survive alongside the meaning"


def test_kerberos_status_is_not_decoded_as_ntstatus():
    """0x18 means different things to Kerberos and to NTSTATUS."""
    kerberos = D.decode("Status", "0x18", "4771")
    other = D.decode("Status", "0x18", "4624")
    assert "pre-auth" in kerberos
    assert kerberos != other


@pytest.mark.parametrize("raw,expect", [
    ("::ffff:10.1.1.5", "10.1.1.5"),
    ("::1", "127.0.0.1"),
    ("-", ""),
    ("10.0.0.5", "10.0.0.5"),
])
def test_ip_normalized_so_ioc_correlation_matches(raw, expect):
    assert D.normalize_ip(raw) == expect


# ---- bounds ----


def test_auto_dump_is_capped_and_says_how_much_it_hid():
    data = {f"Field{i:02d}": f"value{i}" for i in range(30)}
    text, _ = D.build_details(data, ())
    assert "more fields" in text
    assert len(text) <= D.DETAILS_MAX + 40


def test_priority_fields_lead_the_auto_dump():
    """A username should not be pushed off the end by alphabetical ordering."""
    data = {"ZZZOther": "x", "TargetUserName": "jsmith", "AAAFirst": "y"}
    pairs = D.auto_pairs(data)
    assert pairs[0][0] == "TargetUserName"


def test_auto_dump_order_is_deterministic():
    data = {"param10": "a", "param2": "b", "param1": "c"}
    first = D.render_pairs(D.auto_pairs(data))
    second = D.render_pairs(D.auto_pairs(dict(reversed(list(data.items())))))
    assert first == second
    assert first.index("param2") < first.index("param10"), "natural, not lexical"


def test_round_trips_back_to_a_dict():
    text = D.render_pairs([("User", "jsmith"), ("SrcIP", "10.0.0.5")])
    assert D.parse_details(text) == {"User": "jsmith", "SrcIP": "10.0.0.5"}


# ---- levels ----


def test_five_levels_are_additive_over_the_old_three():
    assert SEVERITIES == ("crit", "high", "med", "low", "info")
    for old in ("high", "med", "info"):
        assert old in SEVERITIES, "existing spellings must not change"
    assert LEVEL_RANK["crit"] > LEVEL_RANK["high"] > LEVEL_RANK["med"]
    assert LEVEL_RANK["med"] > LEVEL_RANK["low"] > LEVEL_RANK["info"]


def test_researched_template_levels_cannot_reach_high():
    """A table of 74 high/critical templates applied blind is how 9,726 false
    positives happened. Only the curated map may say high or crit."""
    from inspecthor.parsers.plugins.evtx import _RESEARCH_TO_LEVEL
    assert set(_RESEARCH_TO_LEVEL.values()) <= {"med", "low", "info"}
    assert _RESEARCH_TO_LEVEL["critical"] == "med"
    assert _RESEARCH_TO_LEVEL["high"] == "med"

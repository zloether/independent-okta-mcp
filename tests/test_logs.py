"""Operational logging rules (plan 4.1, AGENTS.md "Never log")."""

import json
import logging
from collections.abc import Iterator
from typing import Any

import pytest

from okta_mcp.logs import configure_logging, event, log_internal, request_id

SECRET = "-".join(["okta", "result", "body"])
"""Built at run time, so a logged traceback's source lines don't hold it."""


def lines(err: str) -> list[dict[str, Any]]:
    """Every stderr line, each of which must be one JSON object (design §13)."""
    return [json.loads(line) for line in err.splitlines()]


@pytest.fixture
def restore_logging() -> Iterator[None]:
    root = logging.getLogger()
    ours = logging.getLogger("okta_mcp")
    saved = (root.handlers[:], root.level, ours.level)
    try:
        yield
    finally:
        logging.captureWarnings(False)
        root.handlers[:] = saved[0]
        root.setLevel(saved[1])
        ours.setLevel(saved[2])


@pytest.mark.usefixtures("restore_logging")
def test_dependencies_stay_at_warning(capsys: pytest.CaptureFixture[str]) -> None:
    """httpx2 logs each request URL at INFO; the SDK logs messages at DEBUG."""
    configure_logging("DEBUG")
    logging.getLogger("httpx2").info("HTTP Request: GET https://example.okta.com/x?q=alice")
    logging.getLogger("mcp.server").debug("message body")
    logging.getLogger("httpx2").warning("dependency warning")
    logging.getLogger("okta_mcp.exec").debug("ours")
    out, err = capsys.readouterr()
    assert out == ""
    assert "alice" not in err
    assert "message body" not in err
    assert "dependency warning" in err
    ours = [line for line in lines(err) if line["logger"] == "okta_mcp.exec"]
    assert len(ours) == 1
    assert ours[0]["level"] == "DEBUG"
    assert ours[0]["msg"] == "ours"
    assert ours[0]["request_id"] is None


@pytest.mark.usefixtures("restore_logging")
def test_a_stricter_level_also_quiets_dependencies(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("ERROR")
    logging.getLogger("httpx2").warning("dependency warning")
    logging.getLogger("okta_mcp.policy").warning("our warning")
    logging.getLogger("mcp.server").error("dependency error")
    err = capsys.readouterr().err
    assert "warning" not in err
    assert "dependency error" in err


@pytest.mark.usefixtures("restore_logging")
def test_dependency_exception_text_is_withheld(capsys: pytest.CaptureFixture[str]) -> None:
    """The SDK logs a result that fails its own validation with `logger.exception`, and the
    pydantic message repeats the result."""
    configure_logging("INFO")
    sdk = logging.getLogger("mcp.server.runner")
    try:
        raise ValueError(SECRET)
    except ValueError:
        sdk.exception("handler for %r returned an invalid result", "tools/call")
    err = capsys.readouterr().err
    assert SECRET not in err
    assert "Traceback" not in err
    assert (
        "handler for 'tools/call' returned an invalid result (ValueError; details withheld)" in err
    )


@pytest.mark.usefixtures("restore_logging")
def test_our_exceptions_keep_frames_not_messages(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO")
    token = request_id.set("abc123")
    try:
        try:
            raise RuntimeError(SECRET)
        except RuntimeError as e:
            log_internal(logging.getLogger("okta_mcp.server"), "tools/call", e)
    finally:
        request_id.reset(token)
    err = capsys.readouterr().err
    (line,) = lines(err)
    assert line["request_id"] == "abc123"
    assert line["level"] == "ERROR"
    assert line["msg"].startswith("internal error in tools/call: RuntimeError\n")
    assert "test_logs.py" in line["msg"]
    assert SECRET not in err


@pytest.mark.usefixtures("restore_logging")
def test_warnings_go_through_the_filters(capsys: pytest.CaptureFixture[str]) -> None:
    import warnings

    configure_logging("INFO")
    warnings.warn(f"serializer saw {SECRET}", UserWarning, stacklevel=1)
    err = capsys.readouterr().err
    (line,) = lines(err)
    assert (line["level"], line["logger"], line["request_id"]) == ("WARNING", "py.warnings", None)
    assert "test_logs.py:" in err
    assert "UserWarning (details withheld)" in err
    assert SECRET not in err


@pytest.mark.usefixtures("restore_logging")
def test_a_bad_dependency_format_string_does_not_raise(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO")
    try:
        raise ValueError(SECRET)
    except ValueError:
        logging.getLogger("mcp.server").exception("needs %s and %s", "one")
    err = capsys.readouterr().err
    assert "(ValueError; details withheld)" in err
    assert SECRET not in err


@pytest.mark.usefixtures("restore_logging")
def test_events_carry_their_name_and_fields(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO")
    token = request_id.set("r1")
    try:
        logging.getLogger("okta_mcp.okta.client").warning(
            "Okta rate limit hit; retrying in %.1f s",
            2.5,
            extra=event("okta_rate_limited", retry=True, wait_s=2.5),
        )
    finally:
        request_id.reset(token)
    (line,) = lines(capsys.readouterr().err)
    assert set(line) == {
        "ts", "level", "logger", "request_id", "msg", "event", "retry", "wait_s"
    }  # fmt: skip
    assert line["event"] == "okta_rate_limited"
    assert line["retry"] is True
    assert line["wait_s"] == 2.5
    assert line["msg"] == "Okta rate limit hit; retrying in 2.5 s"
    assert line["request_id"] == "r1"
    assert line["ts"].endswith("+00:00")


def test_an_event_field_cannot_replace_a_base_key() -> None:
    for key in ("ts", "level", "logger", "request_id", "msg", "event"):
        with pytest.raises(ValueError, match="base key"):
            event("x", **{key: 1})


@pytest.mark.usefixtures("restore_logging")
def test_our_exc_info_keeps_the_type_only(capsys: pytest.CaptureFixture[str]) -> None:
    """Our code formats frames with `log_internal`; an `exc_info` that slips in anyway still
    doesn't print the exception's message."""
    configure_logging("INFO")
    try:
        raise ValueError(SECRET)
    except ValueError:
        logging.getLogger("okta_mcp.x").exception("oops")
    err = capsys.readouterr().err
    (line,) = lines(err)
    assert line["exc_type"] == "ValueError"
    assert SECRET not in err


@pytest.mark.usefixtures("restore_logging")
def test_lines_are_ascii_json_even_for_newlines_and_unicode(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging("INFO")
    logging.getLogger("okta_mcp.x").info("two\nlines \u00e9")
    err = capsys.readouterr().err
    assert err.isascii()
    (line,) = lines(err)
    assert line["msg"] == "two\nlines \u00e9"

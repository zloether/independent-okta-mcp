"""Operational logging rules (plan 4.1, AGENTS.md "Never log")."""

import logging
from collections.abc import Iterator

import pytest

from okta_mcp.logs import configure_logging, log_internal, request_id

SECRET = "-".join(["okta", "result", "body"])
"""Built at run time, so a logged traceback's source lines don't hold it."""


@pytest.fixture
def restore_logging() -> Iterator[None]:
    root = logging.getLogger()
    ours = logging.getLogger("okta_mcp")
    saved = (root.handlers[:], root.level, ours.level)
    try:
        yield
    finally:
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
    assert "DEBUG okta_mcp.exec [-] ours" in err


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
    assert "[abc123] internal error in tools/call: RuntimeError" in err
    assert "test_logs.py" in err
    assert SECRET not in err

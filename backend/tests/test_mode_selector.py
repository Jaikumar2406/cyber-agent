"""Mode Selector unit tests - deterministic input -> mode mapping."""

# pyrefly: ignore [missing-import]
import pytest

from app.control_plane.mode_selector import ModeSelectionError, select_mode
from app.schemas.common import ScanMode


def test_url_only_selects_mode_1():
    sel = select_mode(target_url="https://example.com/", target_repo=None)
    assert sel.mode == ScanMode.MODE_1


def test_repo_only_selects_mode_2():
    sel = select_mode(target_url=None, target_repo="https://github.com/example/demo")
    assert sel.mode == ScanMode.MODE_2
    assert "code_security_agent" in sel.dependencies.engines
    assert "crypto_engine" in sel.dependencies.engines


def test_url_and_repo_selects_mode_3():
    sel = select_mode(target_url="https://example.com/", target_repo="https://github.com/example/demo")
    assert sel.mode == ScanMode.MODE_3
    assert len(sel.dependencies.engines) == 3


def test_no_inputs_raises():
    with pytest.raises(ModeSelectionError):
        select_mode(target_url=None, target_repo=None)


def test_blank_inputs_raise():
    with pytest.raises(ModeSelectionError):
        select_mode(target_url="   ", target_repo="")
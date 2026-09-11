"""The documentation is checked, not just written.

Every published example is code a consumer will paste. Nothing else in this repository reads it, so
an example can name a field that does not exist, or an option that was renamed, and stay wrong
indefinitely — the tests all pass, because the tests never look at the README.

Three checks, because they catch different things:

* **Parsing** catches an example that is not valid Python at all.
* **Import resolution** catches an example importing a name this package does not export.
* **Signature and attribute checking** catches drift between an example and the API it
  demonstrates — a renamed keyword argument, an event attribute that moved, a method that no
  longer exists.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
import re

import pytest

import manka_shreds_sdk
from manka_shreds_sdk import Client

REPO = pathlib.Path(__file__).resolve().parents[2]

#: Every document that publishes a Python example.
DOCUMENTS = [REPO / "README.md", REPO / "python" / "README.md"]


def _blocks(path: pathlib.Path) -> list[str]:
    if not path.exists():
        return []
    return re.findall(r"```python\n(.*?)```", path.read_text(), re.S)


def _all_blocks() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for document in DOCUMENTS:
        for index, block in enumerate(_blocks(document)):
            out.append((f"{document.relative_to(REPO)}#{index}", block))
    return out


BLOCKS = _all_blocks()


def test_the_documents_actually_carry_python_examples() -> None:
    """Guards the guard.

    Every check below iterates the extracted blocks, so a regex that silently stopped matching —
    a fence written differently, a document renamed — would turn this whole file into a no-op that
    still reports success.
    """
    assert BLOCKS, f"no ```python blocks found in {[str(d) for d in DOCUMENTS]}"


@pytest.mark.parametrize(("where", "source"), BLOCKS, ids=[w for w, _ in BLOCKS])
def test_a_documented_example_is_valid_python(where: str, source: str) -> None:
    try:
        ast.parse(source)
    except SyntaxError as exc:  # pragma: no cover - the message is the point
        pytest.fail(f"{where} is not valid Python: {exc}")


@pytest.mark.parametrize(("where", "source"), BLOCKS, ids=[w for w, _ in BLOCKS])
def test_a_documented_example_imports_only_names_this_package_exports(
    where: str, source: str
) -> None:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("manka_shreds_sdk"):
            for alias in node.names:
                assert hasattr(manka_shreds_sdk, alias.name), (
                    f"{where} imports {alias.name!r}, which manka_shreds_sdk does not export"
                )


@pytest.mark.parametrize(("where", "source"), BLOCKS, ids=[w for w, _ in BLOCKS])
def test_a_documented_example_passes_only_real_arguments_to_connect(
    where: str, source: str
) -> None:
    """The options are the part most likely to drift, and the least likely to be noticed."""
    accepted = set(inspect.signature(Client.connect).parameters)
    tree = ast.parse(source)
    seen = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = node.func
        if not (isinstance(target, ast.Attribute) and target.attr == "connect"):
            continue
        seen = True
        for keyword in node.keywords:
            if keyword.arg is None:  # **kwargs, nothing to check
                continue
            assert keyword.arg in accepted, (
                f"{where} passes {keyword.arg!r} to connect, which it does not accept"
            )
    if where.endswith("README.md#0") and "connect" in source:
        assert seen, f"{where} shows a connect call the checker did not recognise"


@pytest.mark.parametrize(("where", "source"), BLOCKS, ids=[w for w, _ in BLOCKS])
def test_a_documented_example_only_names_event_types_that_exist(where: str, source: str) -> None:
    """An example branching on a type string that nothing produces silently does nothing."""
    import dataclasses

    from manka_shreds_sdk import client as client_module

    # The event classes are slotted dataclasses, so the default lives in the field rather than as a
    # class attribute — reading it the obvious way yields an empty set and a test that proves
    # nothing.
    produced: set[str] = set()
    for cls in vars(client_module).values():
        if not (isinstance(cls, type) and dataclasses.is_dataclass(cls)):
            continue
        for field in dataclasses.fields(cls):
            if field.name == "type" and isinstance(field.default, str):
                produced.add(field.default)
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        left = node.left
        if not (isinstance(left, ast.Attribute) and left.attr == "type"):
            continue
        for comparator in node.comparators:
            if isinstance(comparator, ast.Constant) and isinstance(comparator.value, str):
                assert comparator.value in produced, (
                    f"{where} branches on event type {comparator.value!r}, which no event carries"
                )


@pytest.mark.parametrize(("where", "source"), BLOCKS, ids=[w for w, _ in BLOCKS])
def test_a_documented_example_only_reads_transaction_attributes_that_exist(
    where: str, source: str
) -> None:
    """Catches a renamed field on the type every example reaches for."""
    from manka_shreds_sdk import Transaction

    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        value = node.value
        # `event.transaction.<attr>` and `tx.<attr>` where tx came from `event.transaction`.
        is_transaction = (
            isinstance(value, ast.Attribute) and value.attr == "transaction"
        ) or (isinstance(value, ast.Name) and value.id == "tx")
        if is_transaction:
            assert hasattr(Transaction, node.attr), (
                f"{where} reads transaction.{node.attr}, which Transaction does not have"
            )

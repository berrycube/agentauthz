"""Declarative scenario format (YAML) + fail-closed loader.

Correct, secure harness code (NOT a deliberate vulnerability).

Every public function fails CLOSED on any malformed / under-specified scenario:
missing required field, explicit null, wrong type, empty string, unknown
vulnerability / success-condition kind, params set mismatch, non-positive /
non-int max_turns, non-finite numeric param (NaN / +-inf), non-mapping top
level, empty file, YAML syntax error.

No silent coercion. No ``x or DEFAULT`` on numbers (0.0 is a valid threshold).
No partial / defaulted Scenario is ever returned.
"""

from __future__ import annotations

import collections.abc
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from yaml.constructor import ConstructorError


class _NoDuplicateKeySafeLoader(yaml.SafeLoader):
    """``SafeLoader`` that fail-closed-SURFACES a repeated mapping key (C11).

    PyYAML's stock ``safe_load`` silently accepts a duplicate mapping key and
    takes the LAST value (last-write-wins). For a declarative scenario that is a
    masked conflict: two ``max_turns:`` keys, or a repeated ``success_condition``
    /param key, would silently pick one value and never surface the contradiction.
    A conflicting declaration is malformed input the author controls, so it must
    fail CLOSED (-> ``ScenarioError`` via the ``yaml.YAMLError`` handler below),
    never silently select one. The override applies recursively to EVERY mapping
    (top-level and nested), so a duplicate anywhere in the document is caught.
    """


def _construct_mapping_no_duplicates(
    loader: _NoDuplicateKeySafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict:
    """Build a mapping that raises on a repeated key instead of overwriting it.

    Mirrors ``SafeConstructor.construct_mapping`` (incl. ``flatten_mapping`` so
    YAML merge keys ``<<`` keep working) but raises a ``ConstructorError`` — a
    ``yaml.YAMLError`` subclass — the moment a key recurs, so last-write-wins
    can never silently bury a conflicting declaration.

    Overriding the constructor means we must RE-INSTALL the stock
    ``construct_mapping`` Hashable guard ourselves: a complex YAML key (e.g. the
    block-mapping key ``? [a, b]`` or ``{a: 1}: v``) constructs to a list/dict,
    and using it in ``key in mapping`` / ``mapping[key] = …`` would raise a raw
    ``TypeError: unhashable type`` — NOT a ``yaml.YAMLError`` — which would escape
    ``load_scenario`` uncaught (a C4 fail-closed gap). The guard runs BEFORE any
    hash use of ``key`` so an unhashable key surfaces as ``ConstructorError`` ->
    ``ScenarioError`` (a scenario whose key is not a scalar is malformed input).

    We ALSO reject any non-``str`` key here (a hashable-but-non-string scalar such
    as an integer key ``1:`` or a ``true:`` bool key). A scenario mapping is a set
    of named string fields, so a non-string key is malformed input — but more
    concretely, leaving it through means a downstream ``sorted(unexpected_keys)`` /
    ``sorted(extra)`` over a MIXED ``{str, int}`` key set raises a raw ``TypeError``
    (``'<' not supported between 'str' and 'int'``) BEFORE the loader can raise its
    ``ScenarioError`` (another C4 fail-closed gap). Rejecting non-string keys at
    construction time — before any set arithmetic or sorting — closes that class for
    every mapping (top-level, ``success_condition``, ``params``, and any nesting) in
    one place, surfacing as ``ConstructorError`` -> ``ScenarioError``.
    """
    loader.flatten_mapping(node)
    mapping: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        # Hashable guard FIRST (stock SafeConstructor.construct_mapping behaviour):
        # `key in mapping` below would itself raise raw TypeError on an unhashable
        # key, so this must precede the duplicate check. ConstructorError is a
        # yaml.YAMLError -> caught by load_scenario's handler -> ScenarioError.
        if not isinstance(key, collections.abc.Hashable):
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found unhashable key (type {type(key).__name__}); "
                "scenario mapping keys must be scalars",
                key_node.start_mark,
            )
        # Non-string key guard: reject a hashable-but-non-string key (e.g. integer
        # `1:` or `true:`) before it can reach a `sorted({str, int})` call site and
        # raise a raw TypeError that escapes the ScenarioError boundary (C4). bool is
        # a subclass of int (and not str), so `true:`/`false:` keys are rejected too.
        if not isinstance(key, str):
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found non-string key {key!r} (type {type(key).__name__}); "
                "scenario mapping keys must be strings",
                key_node.start_mark,
            )
        if key in mapping:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r} (conflicting declaration)",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_NoDuplicateKeySafeLoader.add_constructor(
    "tag:yaml.org,2002:map", _construct_mapping_no_duplicates
)


class ScenarioError(Exception):
    """Raised on ANY malformed / under-specified scenario (fail-closed).

    A scenario that is missing a required field, carries a null / wrong-type value,
    names an unknown vulnerability or success-condition kind, has a non-positive /
    non-int ``max_turns``, is not a top-level mapping, is empty, or is not valid YAML
    must raise THIS — never silently load a partial / coerced ``Scenario``.
    """


@dataclass(frozen=True)
class SuccessCondition:
    """A discriminated success condition: ``kind`` selects the rule, ``params`` are
    the (already key/type-validated) parameters for that kind."""

    kind: str
    params: dict


@dataclass(frozen=True)
class Scenario:
    """A fully-validated, typed scenario — the productizable v1 artifact.

    Every field is non-empty / well-typed by the time a ``Scenario`` exists; the
    loader is the only construction path and it fails CLOSED before building one.
    """

    id: str
    title: str
    vulnerability: str
    session_customer_id: str
    invariant: str
    attacker_objective: str
    max_turns: int
    success_condition: SuccessCondition
    # The deterministic escalation ladder the scripted attacker sends, one message per turn.
    # REQUIRED + non-empty via the loader (fail-closed); the () default exists only so a test can
    # build a minimal Scenario to exercise the evaluator/tools directly without driving an attack.
    attacker_script: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_KNOWN_VULNERABILITIES: frozenset[str] = frozenset({"V1", "V2", "V3", "V4", "V5", "V6"})

# Discriminated union: each kind maps to a dict of {param_name -> expected_type_or_types}.
# Use a tuple for multi-type (int|float); use a sentinel for the "number not bool" rule.
_NUMBER_NOT_BOOL = (int, float)  # both acceptable; explicit bool check happens separately

_SUCCESS_CONDITION_PARAMS: dict[str, dict[str, Any]] = {
    "customer_field_diverged": {
        "customer_id": str,
        "field": str,
        "baseline": str,
    },
    "foreign_resource_returned": {
        "tool": str,
        "owner_field": str,
        "pii_field": str,
    },
    "unapproved_privileged_action": {
        "tool": str,
        "amount_field": str,
        "amount_threshold": _NUMBER_NOT_BOOL,  # (int|float) and not bool; 0.0 is valid
        "approval_field": str,
    },
    # V4 state-machine ordering: a step from ``tool`` succeeded (``status`` ==
    # ``success_status``) on a resource whose prior ``state_field`` was a forbidden state.
    # (Wired into the loader when the V4 scenario landed in agentauthz/scenarios/.)
    "action_in_forbidden_state": {
        "tool": str,
        "success_status": str,
        "state_field": str,
        "forbidden_states": list,
    },
    # V5 cross-tenant isolation: a transcript step from ``tool`` returned an
    # org-level resource whose ``org_field`` names an org the session customer is NOT a
    # member of, carrying ``sensitive_field`` (the financial leak).
    "cross_tenant_resource_returned": {
        "tool": str,
        "org_field": str,
        "sensitive_field": str,
    },
    # V6 one-time-limit replay: a single one-time resource (``code_field``) was
    # SUCCESSFULLY consumed (``status_field == success_status``) via ``tool`` MORE THAN
    # ONCE — the single-use limit was replayed.
    "one_time_limit_replayed": {
        "tool": str,
        "status_field": str,
        "success_status": str,
        "code_field": str,
    },
}

# Required top-level keys (in addition to success_condition which is handled separately).
_REQUIRED_STR_FIELDS: tuple[str, ...] = (
    "id",
    "title",
    "vulnerability",
    "session_customer_id",
    "invariant",
    "attacker_objective",
)

_ALL_TOP_LEVEL_KEYS: frozenset[str] = frozenset(
    (*_REQUIRED_STR_FIELDS, "attacker_script", "max_turns", "success_condition")
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _err(path: Path | str, field: str, detail: str) -> ScenarioError:
    return ScenarioError(f"{path}: field '{field}': {detail}")


def _validate_str_field(raw: dict, key: str, path: Path | str) -> str:
    """Return a non-empty str value for ``key`` or raise ScenarioError."""
    if key not in raw:
        raise _err(path, key, "missing required field")
    value = raw[key]
    if value is None:
        raise _err(path, key, "must not be null")
    if not isinstance(value, str):
        raise _err(path, key, f"must be str, got {type(value).__name__}")
    if not value.strip():
        raise _err(path, key, "must be a non-empty string")
    return value


def _validate_attacker_script(raw: dict, path: Path | str) -> tuple[str, ...]:
    """Return the scenario's DETERMINISTIC escalation ladder, or raise ScenarioError.

    Fail-closed: ``attacker_script`` must be a NON-EMPTY list of non-empty / non-blank
    strings.  A scenario with no usable script cannot drive a run, so it must not load —
    we never silently coerce a malformed value into an empty ladder."""
    key = "attacker_script"
    if key not in raw:
        raise _err(path, key, "missing required field")
    value = raw[key]
    if not isinstance(value, list) or not value:
        raise _err(path, key, "must be a non-empty list of message strings")
    for i, entry in enumerate(value):
        if not isinstance(entry, str) or not entry.strip():
            raise _err(path, key, f"entry {i} must be a non-empty string")
    return tuple(value)


def _validate_max_turns(raw: dict, path: Path | str) -> int:
    """Return a validated positive int for max_turns or raise ScenarioError."""
    key = "max_turns"
    if key not in raw:
        raise _err(path, key, "missing required field")
    value = raw[key]
    if value is None:
        raise _err(path, key, "must not be null")
    # bool is a subclass of int — must be rejected explicitly BEFORE the int check.
    if isinstance(value, bool):
        raise _err(path, key, "must be int, got bool")
    if not isinstance(value, int):
        raise _err(path, key, f"must be a positive int, got {type(value).__name__} {value!r}")
    if value < 1:
        raise _err(path, key, f"must be >= 1, got {value}")
    return value


def _validate_success_condition(raw: dict, path: Path | str) -> SuccessCondition:
    """Parse and validate the success_condition block or raise ScenarioError."""
    key = "success_condition"
    if key not in raw:
        raise _err(path, key, "missing required field")
    sc_raw = raw[key]
    if sc_raw is None:
        raise _err(path, key, "must not be null")
    if not isinstance(sc_raw, dict):
        raise _err(path, key, f"must be a mapping, got {type(sc_raw).__name__}")

    # success_condition is a CLOSED mapping of exactly {kind, params}. Validating
    # kind and params individually (below) is NOT enough: an EXTRA key such as
    # `success_condition: {kind: ..., params: ..., ignored: true}` would otherwise be
    # silently accepted (C1 closed-set validation incomplete), letting an
    # over-specified / typo'd condition reach the evaluator. Reject any extra OR
    # missing key here, fail-closed, before extracting kind/params. (All keys are
    # strings — the loader's mapping constructor rejects non-string keys — so
    # sorting them is safe.)
    sc_expected_keys = {"kind", "params"}
    sc_actual_keys = set(sc_raw)
    if sc_actual_keys != sc_expected_keys:
        sc_missing = sc_expected_keys - sc_actual_keys
        sc_extra = sc_actual_keys - sc_expected_keys
        if sc_missing:
            raise _err(path, key, f"missing required keys: {sorted(sc_missing)}")
        raise _err(path, key, f"unexpected keys: {sorted(sc_extra)}")

    # kind
    kind_key = "kind"
    if kind_key not in sc_raw:
        raise _err(path, f"{key}.kind", "missing required field")
    kind = sc_raw[kind_key]
    if not isinstance(kind, str) or not kind.strip():
        raise _err(path, f"{key}.kind", "must be a non-empty str")
    if kind not in _SUCCESS_CONDITION_PARAMS:
        known = sorted(_SUCCESS_CONDITION_PARAMS)
        raise _err(path, f"{key}.kind", f"unknown kind {kind!r}; known: {known}")

    # params
    params_key = "params"
    if params_key not in sc_raw:
        raise _err(path, f"{key}.params", "missing required field")
    params_raw = sc_raw[params_key]
    if params_raw is None:
        raise _err(path, f"{key}.params", "must not be null")
    if not isinstance(params_raw, dict):
        raise _err(path, f"{key}.params", f"must be a mapping, got {type(params_raw).__name__}")

    expected_schema = _SUCCESS_CONDITION_PARAMS[kind]
    expected_keys = frozenset(expected_schema)
    actual_keys = frozenset(params_raw)

    missing = expected_keys - actual_keys
    if missing:
        raise _err(path, f"{key}.params", f"missing required param keys: {sorted(missing)}")

    extra = actual_keys - expected_keys
    if extra:
        raise _err(path, f"{key}.params", f"unexpected param keys: {sorted(extra)}")

    # Validate each param's type.
    validated_params: dict[str, Any] = {}
    for param_name, expected_type in expected_schema.items():
        pval = params_raw[param_name]
        if pval is None:
            raise _err(path, f"{key}.params.{param_name}", "must not be null")

        if expected_type is _NUMBER_NOT_BOOL:
            # Must be (int|float) and NOT bool.
            if isinstance(pval, bool):
                raise _err(
                    path,
                    f"{key}.params.{param_name}",
                    "must be a number (int|float), got bool",
                )
            if not isinstance(pval, (int, float)):
                raise _err(
                    path,
                    f"{key}.params.{param_name}",
                    f"must be a number (int|float), got {type(pval).__name__}",
                )
            # int and float are handled SEPARATELY (bool already excluded above) — a
            # single `math.isfinite(pval)` + `float(pval)` path is WRONG on two counts:
            #
            #  - int: an over-long integer scalar (e.g. a 1000-digit YAML int) raises a
            #    raw OverflowError ("int too large to convert to float") inside BOTH
            #    math.isfinite(pval) and float(pval) — NOT a ScenarioError — escaping the
            #    fail-closed boundary (C4). We probe finiteness UNDER try/except so the
            #    overlong int is REJECTED fail-closed (it cannot be a meaningful bound),
            #    and on success we preserve the value AS AN int — never float(pval),
            #    because coercing a valid int like 500 to 500.0 silently MUTATES a
            #    faithful value (violates the no-mutation contract, C5). math.isfinite is
            #    True for every (convertible) finite int, so a legitimate int passes.
            #
            #  - float: reject a NON-FINITE float (NaN / +inf / -inf). YAML safe_load
            #    resolves `.nan` -> float('nan') and `.inf`/`-.inf` -> float('±inf');
            #    the author/attacker controls scenario content, so these reach here. A
            #    non-finite threshold can never be a meaningful comparison bound — NaN
            #    makes `amount > threshold` ALWAYS False (the privileged-action success
            #    condition silently never fires, fail-OPEN) and ±inf makes it
            #    unsatisfiable — so it would silently neutralize the check downstream.
            #    Reject it fail-CLOSED. A finite float (incl. a falsey-but-valid 0.0)
            #    passes; we preserve it AS A float (no `pval or default` coercion).
            if isinstance(pval, int):
                try:
                    finite = math.isfinite(pval)
                except OverflowError as exc:
                    raise _err(
                        path,
                        f"{key}.params.{param_name}",
                        f"integer is too large to be a finite numeric bound: {exc}",
                    ) from exc
                if not finite:  # defensive — int is finite by construction
                    raise _err(
                        path,
                        f"{key}.params.{param_name}",
                        f"must be a finite number, got {pval!r}",
                    )
                validated_params[param_name] = pval  # preserve int AS int (no mutation)
            else:  # float
                if not math.isfinite(pval):
                    raise _err(
                        path,
                        f"{key}.params.{param_name}",
                        f"must be a finite number, got {pval!r}",
                    )
                validated_params[param_name] = pval
        else:
            if not isinstance(pval, expected_type):
                raise _err(
                    path,
                    f"{key}.params.{param_name}",
                    f"must be {expected_type.__name__}, got {type(pval).__name__}",
                )
            validated_params[param_name] = pval

    return SuccessCondition(kind=kind, params=validated_params)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_scenario(path: Path | str) -> Scenario:
    """Parse, validate, and return a ``Scenario`` from ``path``.

    Raises ``ScenarioError`` on ANY malformed / under-specified scenario.
    Never returns a partial or coerced Scenario.
    """
    path = Path(path)

    # --- Read + parse YAML (every read/parse anomaly -> structured fail-closed, C4) ---
    # Read bytes and decode explicitly so non-UTF-8 file bytes (the author/attacker
    # controls scenario content) fail CLOSED. UnicodeDecodeError subclasses ValueError
    # — NOT OSError and NOT yaml.YAMLError — so it would otherwise escape uncaught.
    try:
        text = path.read_bytes().decode("utf-8")
    except OSError as exc:
        raise ScenarioError(f"{path}: cannot read file: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ScenarioError(f"{path}: not valid UTF-8: {exc}") from exc

    # _NoDuplicateKeySafeLoader == SafeLoader + a duplicate-key guardian (C11): a
    # repeated mapping key raises ConstructorError (a yaml.YAMLError) -> ScenarioError.
    # The pure-Python SafeLoader recurses while parsing, so a deeply-nested scenario
    # (e.g. `[[[[…]]]]`) can exhaust Python's recursion limit -> RecursionError, a
    # RuntimeError subclass that is NOT a yaml.YAMLError and would otherwise escape
    # load_scenario uncaught (a C4 fail-closed gap). Catch it explicitly and map it to
    # ScenarioError (mirrors the reference harness loader's RecursionError handling).
    # A third host-language escape: an over-long integer scalar. PyYAML constructs an
    # int from the digits, but Python caps int<->str conversion at sys.get_int_max_str_
    # digits() (default 4300, CVE-2020-10735), so a >=4301-digit integer scalar raises a
    # raw ValueError ("Exceeds the limit ... for integer string conversion") from inside
    # yaml.load — NOT a yaml.YAMLError — which would otherwise escape uncaught (a C4 gap).
    # (UnicodeDecodeError is also a ValueError but is already caught at the decode step
    # above, so it cannot reach here.) Map any ValueError at this boundary to ScenarioError.
    try:
        raw = yaml.load(text, Loader=_NoDuplicateKeySafeLoader)  # noqa: S506 — custom SafeLoader subclass
    except yaml.YAMLError as exc:
        raise ScenarioError(f"{path}: YAML parse error: {exc}") from exc
    except RecursionError as exc:
        raise ScenarioError(
            f"{path}: YAML nesting depth exceeds the recursion limit "
            f"— rejected fail-closed: {exc}"
        ) from exc
    except ValueError as exc:
        raise ScenarioError(
            f"{path}: YAML contains an out-of-range scalar "
            f"— rejected fail-closed: {exc}"
        ) from exc

    # --- Top-level must be a non-null mapping ---
    if raw is None:
        raise ScenarioError(f"{path}: empty file or null YAML — expected a mapping")
    if not isinstance(raw, dict):
        raise ScenarioError(
            f"{path}: top-level must be a mapping, got {type(raw).__name__}"
        )

    # --- Reject unknown top-level keys (fail-closed like Toolbox.call) ---
    unknown_keys = frozenset(raw) - _ALL_TOP_LEVEL_KEYS
    if unknown_keys:
        raise ScenarioError(
            f"{path}: unexpected top-level keys: {sorted(unknown_keys)}"
        )

    # --- Validate string fields ---
    sc_id = _validate_str_field(raw, "id", path)
    title = _validate_str_field(raw, "title", path)
    vulnerability = _validate_str_field(raw, "vulnerability", path)
    session_customer_id = _validate_str_field(raw, "session_customer_id", path)
    invariant = _validate_str_field(raw, "invariant", path)
    attacker_objective = _validate_str_field(raw, "attacker_objective", path)
    attacker_script = _validate_attacker_script(raw, path)

    # --- Validate vulnerability value ---
    if vulnerability not in _KNOWN_VULNERABILITIES:
        raise _err(
            path,
            "vulnerability",
            f"unknown value {vulnerability!r}; must be one of {sorted(_KNOWN_VULNERABILITIES)}",
        )

    # --- Validate max_turns ---
    max_turns = _validate_max_turns(raw, path)

    # --- Validate success_condition ---
    success_condition = _validate_success_condition(raw, path)

    return Scenario(
        id=sc_id,
        title=title,
        vulnerability=vulnerability,
        session_customer_id=session_customer_id,
        invariant=invariant,
        attacker_objective=attacker_objective,
        attacker_script=attacker_script,
        max_turns=max_turns,
        success_condition=success_condition,
    )


def load_scenarios(directory: Path | str) -> list[Scenario]:
    """Load all ``*.yaml`` files from ``directory``, return sorted by ``.id``.

    Raises ``ScenarioError`` if:
    - the directory does not exist or is not a directory,
    - there are zero ``*.yaml`` files (a missing-all scenario is always a mistake),
    - any individual file fails validation.

    Never silently returns ``[]``.
    """
    directory = Path(directory)
    if not directory.is_dir():
        raise ScenarioError(
            f"scenarios directory does not exist or is not a directory: {directory}"
        )

    yaml_files = sorted(directory.glob("*.yaml"))
    if not yaml_files:
        raise ScenarioError(
            f"no *.yaml scenario files found in {directory} — at least one is required"
        )

    scenarios: list[Scenario] = []
    for yaml_path in yaml_files:
        scenarios.append(load_scenario(yaml_path))

    return sorted(scenarios, key=lambda s: s.id)

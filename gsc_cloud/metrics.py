# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Prometheus-compatible in-process metrics for the GSC Cloud API.

A small, stdlib-only metrics layer: counters, gauges, and histograms with
labels, plus a pure-ASGI middleware that records request count, latency,
and 5xx error counts. Output is rendered as Prometheus text exposition
format 0.0.4 so it can be scraped by a Prometheus server without any
external dependencies (no ``prometheus_client``).

Design notes:

* Everything is in-memory and per-process. For multi-replica deployments
  each replica exposes its own metrics — standard for pull-based scraping.
* ``MetricsRegistry`` is thread-safe (single ``threading.Lock`` guards
  the metric map; per-metric mutators hold the lock only for the brief
  read-modify-write).
* Metric and label names are sanitised to the Prometheus character set
  ``[a-zA-Z_][a-zA-Z0-9_]*`` — anything outside becomes ``_``. This keeps
  the exposition always parseable.
* The middleware is pure ASGI (not ``BaseHTTPMiddleware``) so it composes
  with ``CORSMiddleware`` and ``StreamingResponse`` without buffering
  the response body — the same pattern as ``security_headers.py``.
"""
from __future__ import annotations

import threading
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# ── Name / label sanitisation ──────────────────────────────────────────


_VALID_NAME_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
)
# Label keys follow the same rule as metric names in Prometheus exposition.
_VALID_LABEL_CHARS = _VALID_NAME_CHARS


def _sanitize_name(name: str) -> str:
    """Coerce ``name`` to the Prometheus metric-name character set.

    Invalid characters become ``_``. A leading digit is replaced so the
    name still matches ``[a-zA-Z_][a-zA-Z0-9_]*``.
    """
    out = []
    for i, ch in enumerate(name):
        if ch in _VALID_NAME_CHARS:
            out.append(ch)
        else:
            out.append("_")
    if out and out[0].isdigit():
        out[0] = "_"
    return "".join(out) or "_"


def _sanitize_label_key(key: str) -> str:
    """Label keys follow the same character rules as metric names."""
    return _sanitize_name(key)


def _escape_label_value(value: object) -> str:
    """Escape a label value per the Prometheus exposition spec.

    Backslash, double-quote, and newline are escaped. ``None`` is
    rendered as the literal string ``"none"`` so the line stays valid
    even if a caller passes a missing header.
    """
    if value is None:
        return "none"
    s = str(value)
    return (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
    )


def _format_value(value: float) -> str:
    """Format a float per Prometheus conventions: NaN/+Inf/-Inf spelled out."""
    if value != value:  # NaN
        return "NaN"
    if value == float("inf"):
        return "+Inf"
    if value == float("-inf"):
        return "-Inf"
    f = float(value)
    if f.is_integer():
        return str(int(f))
    return repr(f)


# ── Label hashing ──────────────────────────────────────────────────────


def _labels_key(labels: Optional[Mapping[str, object]]) -> Tuple[Tuple[str, str], ...]:
    """Stable hashable key for a labels mapping.

    Sorted by key so the order of insertion into the dict does not change
    the resulting cache key. ``None`` is treated as the empty label set
    so callers do not need to special-case it.
    """
    if not labels:
        return ()
    return tuple(sorted((str(k), str(v)) for k, v in labels.items()))


# ── Metric primitives ──────────────────────────────────────────────────


class Counter:
    """A monotonically increasing counter with optional labels."""

    def __init__(self, name: str, help_text: str) -> None:
        self._name = _sanitize_name(name)
        self._help = help_text
        self._lock = threading.Lock()
        # Map: labels_key -> int value
        self._values: Dict[Tuple[Tuple[str, str], ...], float] = {(): 0.0}

    @property
    def name(self) -> str:
        return self._name

    @property
    def help(self) -> str:
        return self._help

    def inc(self, amount: float = 1, labels: Optional[Mapping[str, object]] = None) -> None:
        """Increment by ``amount`` (default 1). Negative values are ignored."""
        if amount < 0:
            return
        key = _labels_key(labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + float(amount)

    def value(self, labels: Optional[Mapping[str, object]] = None) -> float:
        """Return the current value for the given label set (0 if unseen)."""
        key = _labels_key(labels)
        with self._lock:
            return self._values.get(key, 0.0)

    def _samples(self) -> List[Tuple[Dict[str, str], float]]:
        with self._lock:
            return [
                (dict(k), v) for k, v in self._values.items()
            ]


class Gauge:
    """A gauge value (set/inc/dec) with optional labels."""

    def __init__(self, name: str, help_text: str) -> None:
        self._name = _sanitize_name(name)
        self._help = help_text
        self._lock = threading.Lock()
        self._values: Dict[Tuple[Tuple[str, str], ...], float] = {(): 0.0}

    @property
    def name(self) -> str:
        return self._name

    @property
    def help(self) -> str:
        return self._help

    def set(self, value: float, labels: Optional[Mapping[str, object]] = None) -> None:
        """Set the gauge to ``value`` for the given label set."""
        key = _labels_key(labels)
        with self._lock:
            self._values[key] = float(value)

    def inc(self, amount: float = 1, labels: Optional[Mapping[str, object]] = None) -> None:
        """Increment by ``amount`` (may be negative)."""
        key = _labels_key(labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + float(amount)

    def dec(self, amount: float = 1, labels: Optional[Mapping[str, object]] = None) -> None:
        """Decrement by ``amount`` (equivalent to ``inc(-amount)``)."""
        self.inc(-float(amount), labels=labels)

    def value(self, labels: Optional[Mapping[str, object]] = None) -> float:
        with self._lock:
            return self._values.get(_labels_key(labels), 0.0)

    def _samples(self) -> List[Tuple[Dict[str, str], float]]:
        with self._lock:
            return [
                (dict(k), v) for k, v in self._values.items()
            ]


class Histogram:
    """A histogram with a fixed set of bucket upper bounds.

    The classic Prometheus histogram: counts observations into cumulative
    buckets ``<= le``, plus a synthetic ``+Inf`` bucket, plus a ``_sum``
    and ``_count`` series.
    """

    def __init__(self, name: str, help_text: str, buckets: Sequence[float]) -> None:
        self._name = _sanitize_name(name)
        self._help = help_text
        # Defensive copy + sort. Buckets must be strictly increasing.
        cleaned = sorted({float(b) for b in buckets})
        self._buckets: Tuple[float, ...] = tuple(cleaned)
        self._lock = threading.Lock()
        # Map: labels_key -> {"buckets": [n], "sum": float, "count": int}
        self._values: Dict[Tuple[Tuple[str, str], ...], Dict[str, object]] = {}

    @property
    def name(self) -> str:
        return self._name

    @property
    def help(self) -> str:
        return self._help

    def _empty_state(self) -> Dict[str, object]:
        return {
            "buckets": [0] * (len(self._buckets) + 1),  # +1 for +Inf
            "sum": 0.0,
            "count": 0,
        }

    def observe(self, value: float, labels: Optional[Mapping[str, object]] = None) -> None:
        """Record a single observation."""
        key = _labels_key(labels)
        v = float(value)
        with self._lock:
            state = self._values.get(key)
            if state is None:
                state = self._empty_state()
                self._values[key] = state
            # Cumulative bucket index: first bucket whose upper bound >= v.
            for i, ub in enumerate(self._buckets):
                if v <= ub:
                    # All buckets from i onwards (and +Inf) get +1.
                    for j in range(i, len(state["buckets"])):  # type: ignore[arg-type]
                        state["buckets"][j] += 1  # type: ignore[index]
                    break
            else:
                # v exceeded the highest finite bucket → only +Inf increments.
                state["buckets"][-1] += 1  # type: ignore[index]
            state["sum"] = float(state["sum"]) + v  # type: ignore[arg-type]
            state["count"] = int(state["count"]) + 1  # type: ignore[arg-type]

    def _samples(self) -> List[Tuple[str, Dict[str, str], float]]:
        """Return all sample lines for this histogram.

        Each entry is ``(suffix, labels, value)`` where ``suffix`` is one
        of ``"_bucket"``, ``"_sum"``, ``"_count"``. The ``le=`` label is
        injected into the labels dict for ``_bucket`` lines by the caller
        during rendering.
        """
        with self._lock:
            out: List[Tuple[str, Dict[str, str], float]] = []
            for key, state in self._values.items():
                labels = dict(key)
                buckets = state["buckets"]  # type: ignore[index]
                # Cumulative bucket counts: each bucket i = sum of hits with
                # v <= bucket[i]. We already incremented cumulatively above,
                # so the per-bucket count is exactly buckets[i].
                for i, ub in enumerate(self._buckets):
                    out.append(("_bucket", {**labels, "le": _format_value(ub)},
                                float(buckets[i])))
                out.append(("_bucket", {**labels, "le": "+Inf"},
                            float(buckets[-1])))
                out.append(("_sum", labels, float(state["sum"])))  # type: ignore[arg-type]
                out.append(("_count", labels, float(state["count"])))  # type: ignore[arg-type]
            return out


# ── Registry ───────────────────────────────────────────────────────────


class MetricsRegistry:
    """Thread-safe holder of named metrics.

    Use ``counter``/``gauge``/``histogram`` to register or fetch a metric
    by name; re-registering the same kind returns the existing instance
    so repeated registrations are idempotent. Registering a different
    kind under the same name is a programming error and raises.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Map: name -> metric instance. Kind is encoded in the type.
        self._metrics: Dict[str, object] = {}

    def _register(self, name: str, kind: type, factory) -> object:
        sanitized = _sanitize_name(name)
        with self._lock:
            existing = self._metrics.get(sanitized)
            if existing is not None:
                if not isinstance(existing, kind):
                    raise ValueError(
                        f"metric {sanitized!r} already registered as "
                        f"{type(existing).__name__}, cannot re-register as "
                        f"{kind.__name__}"
                    )
                return existing
            metric = factory(sanitized)
            self._metrics[sanitized] = metric
            return metric

    def counter(self, name: str, help_text: str) -> Counter:
        """Register or fetch a counter by name."""
        def _factory(s: str) -> Counter:
            return Counter(s, help_text)
        # ``Counter`` is the class; ``kind`` must be the class itself so the
        # isinstance check above works. We pass Counter as the kind.
        result = self._register(name, Counter, _factory)
        assert isinstance(result, Counter)
        return result

    def gauge(self, name: str, help_text: str) -> Gauge:
        """Register or fetch a gauge by name."""
        def _factory(s: str) -> Gauge:
            return Gauge(s, help_text)
        result = self._register(name, Gauge, _factory)
        assert isinstance(result, Gauge)
        return result

    def histogram(self, name: str, help_text: str,
                  buckets: Sequence[float]) -> Histogram:
        """Register or fetch a histogram by name with the given buckets."""
        # Capture buckets in the factory closure.
        def _factory(s: str) -> Histogram:
            return Histogram(s, help_text, buckets)
        result = self._register(name, Histogram, _factory)
        assert isinstance(result, Histogram)
        return result

    def _iter_metrics(self) -> Iterable[object]:
        with self._lock:
            # Deterministic order: sorted by name. Helps snapshot tests.
            return [self._metrics[k] for k in sorted(self._metrics)]


# ── Rendering ──────────────────────────────────────────────────────────


def _format_labels(labels: Mapping[str, object]) -> str:
    """Render a labels dict as ``k1="v1",k2="v2",...`` (sorted by key)."""
    if not labels:
        return ""
    parts = []
    for k in sorted(labels):
        sanitized_k = _sanitize_label_key(str(k))
        parts.append(f'{sanitized_k}="{_escape_label_value(labels[k])}"')
    return "{" + ",".join(parts) + "}"


def render_metrics(registry: Optional[MetricsRegistry] = None) -> str:
    """Render a registry as Prometheus text exposition format 0.0.4.

    Output layout (per metric): ``# HELP`` line, ``# TYPE`` line, then
    one or more sample lines. Histograms emit ``_bucket{le=...}``,
    ``_sum``, ``_count``. Output ends with a trailing newline as required
    by the spec.
    """
    reg = registry if registry is not None else REGISTRY
    lines: List[str] = []
    for metric in reg._iter_metrics():
        if isinstance(metric, Counter):
            lines.append(f"# HELP {metric.name} {metric.help}")
            lines.append(f"# TYPE {metric.name} counter")
            for labels, value in metric._samples():
                lines.append(f"{metric.name}{_format_labels(labels)} {_format_value(value)}")
        elif isinstance(metric, Gauge):
            lines.append(f"# HELP {metric.name} {metric.help}")
            lines.append(f"# TYPE {metric.name} gauge")
            for labels, value in metric._samples():
                lines.append(f"{metric.name}{_format_labels(labels)} {_format_value(value)}")
        elif isinstance(metric, Histogram):
            lines.append(f"# HELP {metric.name} {metric.help}")
            lines.append(f"# TYPE {metric.name} histogram")
            for suffix, labels, value in metric._samples():
                lines.append(
                    f"{metric.name}{suffix}{_format_labels(labels)} {_format_value(value)}"
                )
    # Prometheus requires a trailing newline; emit one even for an empty
    # registry so scrapers always see a parseable, terminating payload.
    return "\n".join(lines) + "\n"


# ── Process-global registry ────────────────────────────────────────────


REGISTRY: MetricsRegistry = MetricsRegistry()
"""Default registry, shared across the process. Import this to register or
read metrics without passing a registry around."""


# ── Pure-ASGI middleware ──────────────────────────────────────────────


class MetricsMiddleware:
    """Pure-ASGI middleware that records request count, latency, 5xx errors.

    Increments on every HTTP request:

    * ``gsc_http_requests_total{method, path}`` (counter)
    * ``gsc_http_request_duration_seconds`` (histogram, default Prometheus
      latency buckets in seconds)
    * ``gsc_http_errors_total{method, path}`` (counter, only on 5xx)

    ``path`` is taken from ``scope["path"]`` so cardinality is bounded by
    the route table. Lifespan and websocket scopes are passed through
    untouched — the same passthrough pattern as
    ``security_headers.py``.
    """

    # Default latency buckets match the Prometheus client default (seconds).
    _DEFAULT_BUCKETS: Tuple[float, ...] = (
        0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75,
        1.0, 2.5, 5.0, 7.5, 10.0,
    )

    def __init__(self, app, registry: Optional[MetricsRegistry] = None) -> None:
        self.app = app
        self.registry = registry if registry is not None else REGISTRY
        # Register the canonical HTTP metrics on the chosen registry.
        self.requests_total = self.registry.counter(
            "gsc_http_requests_total",
            "Total HTTP requests served by the GSC Cloud API.",
        )
        self.errors_total = self.registry.counter(
            "gsc_http_errors_total",
            "Total HTTP responses with a 5xx status code.",
        )
        self.duration = self.registry.histogram(
            "gsc_http_request_duration_seconds",
            "HTTP request latency in seconds.",
            buckets=self._DEFAULT_BUCKETS,
        )

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET")
        path = scope.get("path", "/")
        labels = {"method": str(method), "path": str(path)}
        # Increments happen on receive of the start message so we count
        # the request even if the app short-circuits without sending.
        self.requests_total.inc(1, labels=labels)

        import time as _time
        start = _time.monotonic()
        status_holder = {"status": 500}

        async def send_with_metrics(message):
            if message["type"] == "http.response.start":
                status_holder["status"] = int(message.get("status", 500))
            await send(message)

        try:
            await self.app(scope, receive, send_with_metrics)
        finally:
            elapsed = _time.monotonic() - start
            self.duration.observe(elapsed, labels=labels)
            if status_holder["status"] >= 500:
                self.errors_total.inc(1, labels=labels)


# ── CLI smoke test ─────────────────────────────────────────────────────


if __name__ == "__main__":
    # ``python3 -m gsc_cloud.metrics`` → dump the (empty) registry. Useful
    # as a quick sanity check that the module imports and the renderer
    # produces a valid empty payload.
    print(render_metrics(REGISTRY), end="")

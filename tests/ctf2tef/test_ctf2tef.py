# Copyright (c) 2025 Analog Devices, Inc.
# Copyright (c) 2025 Antmicro <www.antmicro.com>
#
# SPDX-License-Identifier: Apache-2.0

"""Tests features related to CTF to TEF conversion."""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import bt2

sys.path.append(str(Path.cwd() / "scripts"))
import ctf2tef
import prepare_trace

zephyr_base = os.environ.get("ZEPHYR_BASE", None)
zephyr_base = Path(zephyr_base) if zephyr_base is not None else None


def test_metadata():
    """Tests CTF metadata file."""
    with ctf2tef.prepare_dir(Path("/dev/null"), zephyr_base) as d:
        bt2.TraceCollectionMessageIterator(str(d.resolve()))


def test_ctf2tef():
    """Tests CTF to TEF conversion."""
    with ctf2tef.prepare_dir(Path("./tests/ctf2tef/trace.ctf"), zephyr_base) as d:
        ctf2tef.ctf_to_tef(
            str(d), False, prepare_trace.CUSTOM_METADATA, prepare_trace.create_custom_events()
        )


def test_instrumentation_ctf2tef():
    """Tests CTF to TEF conversion using instrumentation traces."""
    base = (
        zephyr_base
        if zephyr_base is not None
        else Path(__file__).parent.parent.parent.parent / "zephyr"
    )
    assert base is not None
    sys.path.append(str(base / "scripts/instrumentation"))
    import zaru

    with ctf2tef.prepare_dir_for_instrumentation(
        Path("./tests/ctf2tef/instrumentation/trace.ctf"),
        Path("./tests/ctf2tef/instrumentation/metadata"),
    ) as tmp_dir:
        zaru.get_traces_in_trace_event_format(
            str(tmp_dir), Path("./tests/ctf2tef/instrumentation/zephyr.elf"), True
        )


def _fake_named_event_msg(ts_ns: int):
    """Builds a minimal fake bt2 event message for a `named_event` CTF event."""
    msg = MagicMock()
    msg.default_clock_snapshot.clock_class.frequency = 1e9
    msg.default_clock_snapshot.value = ts_ns
    msg.event.payload_field.get.side_effect = lambda key, default=None: {
        "name": "shell_right",
    }.get(key, default)
    return msg


def test_named_event_emitted_with_nonzero_duration():
    """
    Regression test: sys_trace_named_event() markers carry no real duration, but
    the viewer only renders Begin/End phases in the flamegraph (not true INSTANT),
    so a genuinely zero-width B/E pair is effectively invisible/unclickable.

    emit_event() must give the End phase a small synthetic shift
    (NAMED_EVENT_SYNTHETIC_DURATION_US) so named events render as a visible bar.
    """
    msg = _fake_named_event_msg(ts_ns=1_000_000)

    begin = ctf2tef.emit_event(msg, "named_event", 0, ctf2tef.EventPhase.BEGIN, skip_args=True)
    end = ctf2tef.emit_event(
        msg,
        "named_event",
        0,
        ctf2tef.EventPhase.END,
        shift=ctf2tef.NAMED_EVENT_SYNTHETIC_DURATION_US,
        skip_args=True,
    )

    assert begin["name"] == "shell_right"
    assert end["name"] == "shell_right"
    assert begin["ph"] == "B"
    assert end["ph"] == "E"
    duration = end["ts"] - begin["ts"]
    assert duration == ctf2tef.NAMED_EVENT_SYNTHETIC_DURATION_US
    assert duration > 0
    # Must stay well below the smallest real inter-event gap observed on actual
    # traces (~8 us) so it can never be mistaken for / overlap a real event.
    assert duration < 8.0

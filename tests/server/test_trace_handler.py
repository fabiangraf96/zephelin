# Copyright (c) 2026 Analog Devices, Inc.
# Copyright (c) 2026 Antmicro <www.antmicro.com>
#
# SPDX-License-Identifier: Apache-2.0

"""Tests trace handling related functionalities."""

import asyncio
import sys
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.append(str(Path.cwd() / "server"))
sys.path.append(str(Path.cwd() / "scripts"))
from config import TraceConfig
from ctf2tef import CTFConversionResult
from handlers.trace_handler import PARSE_THRESHOLD_BYTES, TraceHandler


@pytest.fixture
def trace_config(tmp_path):
    """Returns dummy config."""
    return TraceConfig(tcp_host="127.0.0.1", tcp_port=0, build_dir=tmp_path)


@pytest.mark.asyncio
@patch("handlers.trace_handler.TraceHandler._extract_trace_increment")
async def test_trace_ingestion_and_emit(mock_extract, trace_config, tmp_path):
    """Tests trace handling flow from ingesting data to emitting events."""
    fake_parsed_events = [{"name": "fake_event", "ts": 100}]

    mock_sio = AsyncMock()

    handler = TraceHandler(sio=mock_sio, traceConfig=trace_config)
    handler.continuous_streaming = True
    handler.raw_ctf_path = tmp_path / "live_capture.ctf"

    async def fake_extract_logic(update_state=False):
        if update_state:
            handler.events_sent_count = 1
        return (fake_parsed_events, 0, 1)

    mock_extract.side_effect = fake_extract_logic

    await handler.connect()
    writer = None

    try:
        host, port = handler.trace_socket.sockets[0].getsockname()
        _, writer = await asyncio.open_connection(host, port)

        sync_tag = b"_zpl_ctf_start__"

        fake_chunk = b"X" * (PARSE_THRESHOLD_BYTES * 2)

        writer.write(sync_tag + fake_chunk)
        await writer.drain()

        await asyncio.sleep(0.1)

        assert handler.is_synced is True
        assert handler.raw_ctf_path.exists()

        expected_size = PARSE_THRESHOLD_BYTES * 2 - len(sync_tag)
        assert handler.raw_ctf_path.stat().st_size == expected_size

        mock_sio.emit.assert_called_once_with(
            "rpc_notification",
            {
                "jsonrpc": "2.0",
                "method": "trace.events",
                "params": {
                    "events": fake_parsed_events,
                    "overlap_count": 0,
                    "total_count": 1,
                },
            },
        )

    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()
        await handler.disconnect()


@pytest.mark.asyncio
@patch("handlers.trace_handler.ctf_to_tef")
@patch("handlers.trace_handler.prepare_dir")
async def test_extract_trace_increment_no_duplicates_across_polls(
    mock_prepare_dir, mock_ctf_to_tef, trace_config, tmp_path
):
    """
    Regression test for the sliding-window overlap bug: each poll cycle re-parses
    the CTF file from scratch (growing on disk) and _get_sliding_window() re-includes
    up to 150 already-sent events as a safety margin for late-arriving bt2 packets.

    The frontend does not deduplicate using `overlap_count`, so `_extract_trace_increment`
    must itself strip that overlap before returning `payload_events` -- otherwise the
    same events get emitted (and exported) multiple times.

    Simulates three growing "reparses" that straddle the window_size=150 boundary and
    asserts every emitted event across all polls is unique and none are missing.
    """

    @contextmanager
    def fake_prepare_dir(*_args, **_kwargs):
        yield tmp_path

    mock_prepare_dir.side_effect = fake_prepare_dir

    def make_events(n):
        return [{"name": f"evt{i}", "ph": "B", "ts": i, "tid": 1} for i in range(n)]

    # Cycle sizes chosen to straddle the window_size=150 boundary used internally by
    # _extract_trace_increment, which is exactly the regime that triggered the bug.
    cycle_totals = [100, 200, 260]
    mock_ctf_to_tef.side_effect = [
        CTFConversionResult(tef=make_events(total), thread_names={"main": 1})
        for total in cycle_totals
    ]

    mock_sio = AsyncMock()
    handler = TraceHandler(sio=mock_sio, traceConfig=trace_config)
    handler.continuous_streaming = True
    handler.raw_ctf_path = tmp_path / "live_capture.ctf"

    all_emitted_keys = []
    all_emitted_events = []

    for _ in cycle_totals:
        payload_events, overlap_count, new_total_count = await handler._extract_trace_increment(
            update_state=True
        )
        # The bug this test guards against: emitting already-sent events again.
        assert overlap_count == 0, "overlap must be fully consumed before returning to callers"

        for event in payload_events:
            if event.get("name") == "thread_name":
                continue
            all_emitted_events.append(event)
            all_emitted_keys.append((event["name"], event["ph"], event["ts"]))

    assert len(all_emitted_keys) == len(set(all_emitted_keys)), (
        "duplicate events were emitted across poll cycles"
    )
    assert handler.events_sent_count == cycle_totals[-1]
    assert len(all_emitted_events) == cycle_totals[-1]
    assert all_emitted_events == make_events(cycle_totals[-1])

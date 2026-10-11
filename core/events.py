"""
core/events.py

In-process pub/sub for live UI updates (Server-Sent Events in main.py).

Graph nodes run in worker threads (asyncio.to_thread), while SSE
subscribers are asyncio queues on the event loop — publish() bridges the
two with call_soon_threadsafe. If no loop is bound (tests, CLI scripts),
publish() is a no-op, so nodes never depend on a UI being attached.
"""

from __future__ import annotations

import asyncio
import threading
from datetime import datetime, timezone

_loop: asyncio.AbstractEventLoop | None = None
_subscribers: set[asyncio.Queue] = set()
_lock = threading.Lock()

MAX_QUEUE = 500


def bind_loop(loop: asyncio.AbstractEventLoop) -> None:
    global _loop
    _loop = loop


def subscribe() -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=MAX_QUEUE)
    with _lock:
        _subscribers.add(q)
    return q


def unsubscribe(q: asyncio.Queue) -> None:
    with _lock:
        _subscribers.discard(q)


def _deliver(q: asyncio.Queue, event: dict) -> None:
    try:
        q.put_nowait(event)
    except asyncio.QueueFull:
        pass  # slow consumer: drop rather than block the pipeline


def publish(event_type: str, **data) -> None:
    loop = _loop
    if loop is None or loop.is_closed():
        return
    event = {"type": event_type, "ts": datetime.now(timezone.utc).isoformat(), **data}
    with _lock:
        targets = list(_subscribers)
    for q in targets:
        loop.call_soon_threadsafe(_deliver, q, event)

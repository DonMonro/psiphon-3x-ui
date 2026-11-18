"""Best-effort Linux host resource metrics for the management dashboard."""

from __future__ import annotations

import os
import re
import shutil
import threading
import time
from pathlib import Path
from typing import Any

_PROC_STAT = Path("/proc/stat")
_PROC_MEMINFO = Path("/proc/meminfo")
_cpu_lock = threading.Lock()
_cpu_previous: tuple[int, int] | None = None


def _read_cpu_counters() -> tuple[int, int]:
    """Return aggregate CPU ticks and idle ticks from Linux procfs."""
    fields = [
        int(value) for value in _PROC_STAT.read_text(encoding="ascii").splitlines()[0].split()[1:]
    ]
    if len(fields) < 4:
        raise ValueError("incomplete CPU counters")
    idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
    return sum(fields[:8]), idle


def _cpu_metric() -> dict[str, Any]:
    global _cpu_previous

    cores = os.cpu_count() or 1
    try:
        with _cpu_lock:
            current = _read_cpu_counters()
            previous = _cpu_previous
            if previous is None:
                time.sleep(0.1)
                previous = current
                current = _read_cpu_counters()
            _cpu_previous = current

        total_delta = current[0] - previous[0]
        idle_delta = current[1] - previous[1]
        if total_delta <= 0:
            raise ValueError("CPU counters did not advance")
        percent = max(0.0, min(100.0, (total_delta - idle_delta) * 100.0 / total_delta))
        return {
            "available": True,
            "percent": round(percent, 1),
            "used": round(cores * percent / 100.0, 2),
            "total": cores,
            "unit": "cores",
        }
    except (OSError, ValueError, IndexError):
        return {"available": False, "message": "Unavailable", "unit": "cores"}


def _memory_metrics() -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        values = {
            key: int(value) * 1024
            for key, value in re.findall(
                r"^(MemTotal|MemAvailable|SwapTotal|SwapFree):\s+(\d+)\s+kB$",
                _PROC_MEMINFO.read_text(encoding="ascii"),
                re.MULTILINE,
            )
        }
        memory_total = values["MemTotal"]
        memory_used = max(0, memory_total - values["MemAvailable"])
        memory = {
            "available": memory_total > 0,
            "percent": round(memory_used * 100.0 / memory_total, 1) if memory_total else 0,
            "used": memory_used,
            "total": memory_total,
            "unit": "bytes",
        }
        swap_total = values["SwapTotal"]
        swap_used = max(0, swap_total - values["SwapFree"])
        swap = (
            {
                "available": True,
                "percent": round(swap_used * 100.0 / swap_total, 1),
                "used": swap_used,
                "total": swap_total,
                "unit": "bytes",
            }
            if swap_total
            else {"available": False, "message": "Not configured", "unit": "bytes"}
        )
        return memory, swap
    except (OSError, KeyError, ValueError):
        unavailable = {"available": False, "message": "Unavailable", "unit": "bytes"}
        return unavailable.copy(), unavailable.copy()


def _disk_metric() -> dict[str, Any]:
    try:
        usage = shutil.disk_usage("/")
        return {
            "available": usage.total > 0,
            "percent": round(usage.used * 100.0 / usage.total, 1) if usage.total else 0,
            "used": usage.used,
            "total": usage.total,
            "unit": "bytes",
        }
    except OSError:
        return {"available": False, "message": "Unavailable", "unit": "bytes"}


def get_system_metrics() -> dict[str, Any]:
    """Collect CPU, memory, root filesystem, and swap usage."""
    memory, swap = _memory_metrics()
    return {
        "cpu": _cpu_metric(),
        "memory": memory,
        "disk": _disk_metric(),
        "swap": swap,
        "sampled_at": time.time(),
    }

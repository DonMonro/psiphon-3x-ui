from __future__ import annotations

from types import SimpleNamespace

from panel.dashboard import metrics


def test_cpu_metric_reports_busy_fraction_as_used_cores(monkeypatch):
    monkeypatch.setattr(metrics, "_cpu_previous", (1000, 100))
    monkeypatch.setattr(metrics, "_read_cpu_counters", lambda: (1100, 120))
    monkeypatch.setattr(metrics.os, "cpu_count", lambda: 4)

    assert metrics._cpu_metric() == {
        "available": True,
        "percent": 80.0,
        "used": 3.2,
        "total": 4,
        "unit": "cores",
    }


def test_memory_and_swap_use_available_memory(monkeypatch, tmp_path):
    meminfo = tmp_path / "meminfo"
    meminfo.write_text(
        "MemTotal:       1000 kB\n"
        "MemAvailable:    250 kB\n"
        "SwapTotal:       200 kB\n"
        "SwapFree:         50 kB\n",
        encoding="ascii",
    )
    monkeypatch.setattr(metrics, "_PROC_MEMINFO", meminfo)

    memory, swap = metrics._memory_metrics()

    assert memory == {
        "available": True,
        "percent": 75.0,
        "used": 750 * 1024,
        "total": 1000 * 1024,
        "unit": "bytes",
    }
    assert swap == {
        "available": True,
        "percent": 75.0,
        "used": 150 * 1024,
        "total": 200 * 1024,
        "unit": "bytes",
    }


def test_swap_without_capacity_is_unavailable(monkeypatch, tmp_path):
    meminfo = tmp_path / "meminfo"
    meminfo.write_text(
        "MemTotal: 1000 kB\nMemAvailable: 500 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
        encoding="ascii",
    )
    monkeypatch.setattr(metrics, "_PROC_MEMINFO", meminfo)

    _, swap = metrics._memory_metrics()

    assert swap == {"available": False, "message": "Not configured", "unit": "bytes"}


def test_disk_metric_uses_root_filesystem_capacity(monkeypatch):
    monkeypatch.setattr(
        metrics.shutil, "disk_usage", lambda path: SimpleNamespace(total=1000, used=400, free=600)
    )

    assert metrics._disk_metric() == {
        "available": True,
        "percent": 40.0,
        "used": 400,
        "total": 1000,
        "unit": "bytes",
    }

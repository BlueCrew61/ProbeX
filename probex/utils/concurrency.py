"""Parallel helper — ThreadPoolExecutor dengan cek budget per task."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, List


def bounded_parallel(
    fn: Callable,
    items: Iterable,
    budget_ok: Callable[[], bool],
    max_workers: int = 8,
) -> List:
    """Jalankan `fn(item)` secara paralel, berhenti menambah task baru
    saat `budget_ok()` False.

    Mengembalikan daftar hasil (bisa None) dalam urutan selesai."""
    results: List = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = [ex.submit(fn, item) for item in items if budget_ok()]
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception:
                results.append(None)
    return results

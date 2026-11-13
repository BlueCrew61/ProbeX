"""Query-parameter helper — injeksi dan variasi parameter untuk tiap endpoint."""

from __future__ import annotations

from typing import Iterable, Iterator, List, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


def inject_param(url: str, param: str, value: str) -> str:
    """Ganti (atau tambah jika belum ada) nilai parameter `param` menjadi `value`."""
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    found = False
    new_params: List[Tuple[str, str]] = []
    for k, v in params:
        if k == param:
            new_params.append((k, value))
            found = True
        else:
            new_params.append((k, v))
    if not found:
        new_params.append((param, value))
    return urlunparse(parsed._replace(query=urlencode(new_params)))


def iter_param_variants(url: str, values: Iterable[str]) -> Iterator[Tuple[str, str, str]]:
    """Untuk setiap parameter di URL, coba ganti nilainya dengan masing-masing
    dari `values`. Hasilkan (test_url, param_name, test_value)."""
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    for key, _ in params:
        for val in values:
            new_params = [(k, val if k == key else v) for k, v in params]
            test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
            yield test_url, key, val

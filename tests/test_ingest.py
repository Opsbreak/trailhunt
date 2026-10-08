from __future__ import annotations

import gzip
import io
import json
import sys
from pathlib import Path

from trailhunt.ingest import IngestStats, ReorderBuffer, discover_files, iter_events
from trailhunt.testing import expand_case


def recs(n: int, start_minute: int = 0, prefix: str = "e") -> list[dict]:
    out = expand_case(
        [
            {
                "eventSource": "s3.amazonaws.com",
                "eventName": "ListBuckets",
                "_at": f"{start_minute}m",
                "_repeat": n,
                "_interval": "1m",
            }
        ],
        prefix,
    )
    return out


def write_records(path: Path, records: list[dict], *, gz: bool = False) -> Path:
    data = json.dumps({"Records": records}).encode()
    if gz:
        path.write_bytes(gzip.compress(data))
    else:
        path.write_bytes(data)
    return path


def write_jsonl(path: Path, records: list[dict], *, gz: bool = False) -> Path:
    data = "".join(json.dumps(r) + "\n" for r in records).encode()
    path.write_bytes(gzip.compress(data) if gz else data)
    return path


def ids(paths, **kw) -> list[str]:
    return [e.event_id for e in iter_events([str(p) for p in paths], **kw)]


def test_records_file_plain_and_gzip(tmp_path):
    a = write_records(tmp_path / "a.json", recs(3, prefix="a"))
    b = write_records(tmp_path / "b.json.gz", recs(2, prefix="b"), gz=True)
    assert len(ids([a])) == 3
    assert len(ids([b])) == 2


def test_pretty_printed_records_file(tmp_path):
    p = tmp_path / "pretty.json"
    p.write_text(json.dumps({"Records": recs(4)}, indent=2))
    assert len(ids([p])) == 4


def test_jsonl_plain_and_gzip(tmp_path):
    a = write_jsonl(tmp_path / "x.jsonl", recs(5, prefix="a"))
    b = write_jsonl(tmp_path / "y.jsonl.gz", recs(5, prefix="b"), gz=True)
    assert len(ids([a, b])) == 10


def test_json_array_and_single_event(tmp_path):
    arr = tmp_path / "arr.json"
    arr.write_text(json.dumps(recs(3, prefix="arr")))
    one = tmp_path / "one.json"
    one.write_text(json.dumps(recs(1, prefix="one")[0], indent=1))
    assert len(ids([arr, one])) == 4


def test_directory_is_walked_recursively_and_digests_skipped(tmp_path):
    deep = tmp_path / "AWSLogs" / "111111111111" / "CloudTrail" / "us-east-1" / "2026" / "01" / "05"
    deep.mkdir(parents=True)
    write_records(
        deep / "111111111111_CloudTrail_us-east-1_20260105T0005Z_abc.json.gz", recs(3, prefix="d"), gz=True
    )
    dig = tmp_path / "AWSLogs" / "111111111111" / "CloudTrail-Digest" / "us-east-1"
    dig.mkdir(parents=True)
    (dig / "111111111111_CloudTrail-Digest_us-east-1_x.json.gz").write_bytes(gzip.compress(b"{}"))
    (deep / "README.txt").write_text("not a log")
    assert len(discover_files(str(tmp_path))) == 1
    assert len(ids([tmp_path])) == 3


def test_directory_files_ordered_by_delivery_timestamp(tmp_path):
    (tmp_path / "b").mkdir()
    (tmp_path / "a").mkdir()
    late = tmp_path / "a" / "1_CloudTrail_us-east-1_20260105T0200Z_x.json"
    early = tmp_path / "b" / "1_CloudTrail_us-west-2_20260105T0100Z_y.json"
    write_records(late, recs(1))
    write_records(early, recs(1))
    files = discover_files(str(tmp_path))
    assert [Path(f).name for f in files] == [early.name, late.name]


def test_stdin(monkeypatch):
    data = gzip.compress("".join(json.dumps(r) + "\n" for r in recs(3)).encode())

    class FakeStdin:
        buffer = io.BufferedReader(io.BytesIO(data))

    monkeypatch.setattr(sys, "stdin", FakeStdin)
    assert len(ids(["-"])) == 3


def test_malformed_input_is_counted_not_fatal(tmp_path):
    good = recs(2)
    p = tmp_path / "mixed.jsonl"
    p.write_text(json.dumps(good[0]) + "\n{broken json\n" + json.dumps(good[1]) + "\n")
    bad = tmp_path / "bad.json"
    bad.write_text('{"nope": 1}')
    corrupt = tmp_path / "corrupt.json.gz"
    corrupt.write_bytes(b"\x1f\x8b\x08\x00garbage")
    stats = IngestStats()
    out = list(iter_events([str(p), str(bad), str(corrupt), str(tmp_path / "missing.json")], stats))
    assert len(out) == 2
    assert stats.malformed >= 3
    assert any("missing.json" in e for e in stats.errors)


def test_duplicate_event_ids_are_dropped(tmp_path):
    r = recs(3)
    a = write_records(tmp_path / "a.json", r)
    b = write_records(tmp_path / "b.json", r)
    stats = IngestStats()
    assert len(list(iter_events([str(a), str(b)], stats))) == 3
    assert stats.duplicates == 3


def test_since_until_filter(tmp_path):
    p = write_records(tmp_path / "a.json", recs(10))  # 00:00 .. 00:09
    stats = IngestStats()
    out = list(iter_events([str(p)], stats, since=1767571200 + 120, until=1767571200 + 300))
    assert len(out) == 3 and stats.filtered == 7


def test_out_of_order_input_is_sorted(tmp_path):
    r = recs(50)
    shuffled = list(reversed(r))
    p = write_records(tmp_path / "a.json", shuffled)
    times = [e.ts for e in iter_events([str(p)])]
    assert times == sorted(times)


def test_reorder_buffer_counts_late_events():
    from trailhunt.event import Event

    evs = [Event.from_record(r) for r in recs(6)]
    buf = ReorderBuffer(capacity=2)
    out = []
    for e in [evs[3], evs[4], evs[5], evs[0]]:  # evs[0] arrives after newer events were released
        out.extend(buf.push(e))
    out.extend(buf.drain())
    assert len(out) == 4
    assert buf.late == 1


def test_path_helpers_round_trip(tmp_path):
    import os

    from trailhunt.pathutil import display_path, long_path

    p = str(tmp_path / "x.json")
    lp = long_path(p)
    if os.name == "nt":
        assert lp.startswith("\\\\?\\") and display_path(lp) == os.path.abspath(p)
        unc = r"\\server\share\a"
        assert long_path(unc) == r"\\?\UNC\server\share\a"
        assert display_path(long_path(unc)) == unc
    else:
        assert lp == p and display_path(lp) == p

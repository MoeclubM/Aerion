"""Build and compare identical release benchmarks inside GitHub Actions."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import tempfile


def build(root, destination, target):
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    output = subprocess.run(
        ["cargo", "test", "--locked", "--release", "--no-default-features", "--lib",
         "--no-run", "--message-format=json"],
        cwd=root, env=env, text=True, stdout=subprocess.PIPE,
    )
    if output.returncode:
        for line in output.stdout.splitlines():
            item = json.loads(line)
            if item.get("reason") == "compiler-message":
                print(item["message"].get("rendered", ""), flush=True)
        output.check_returncode()
    executables = [
        item["executable"] for line in output.stdout.splitlines()
        if (item := json.loads(line)).get("reason") == "compiler-artifact"
        and item.get("executable") and item.get("profile", {}).get("test")
    ]
    assert len(executables) == 1, executables
    shutil.copy2(executables[0], destination)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=["codecs", "transport", "anytls", "sudoku"], default="codecs")
    suite = parser.parse_args().suite
    current = Path.cwd()
    baseline = current / ".performance-baseline"
    results = current / "performance-results"
    results.mkdir(exist_ok=True)
    modules = {
        "vmess": "src/vmess_body/tests.rs",
        "sudoku": "src/sudoku/tests.rs",
        "mieru": "src/mieru/crypto/tests.rs",
        "uot": "src/uot/tests.rs",
    }
    if suite == "transport":
        modules = {
            "relay": "src/relay/tests.rs",
            "websocket": "src/vless_websocket/tests.rs",
            "anytls": "src/protocol/tests.rs",
            "mieru_stream": "src/mieru/tests.rs",
        }
        # Use the same in-memory underlay for both Mieru revisions. This only
        # generalizes the old private writer's type, retaining its encoding/I/O.
        replacements = {
            "src/mieru.rs": [
                ("struct MieruStreamWriter {\n    inner: OwnedWriteHalf,",
                 "struct MieruStreamWriter<W = OwnedWriteHalf> {\n    inner: W,"),
                ("impl MieruStreamWriter {\n    fn new(\n        inner: OwnedWriteHalf,",
                 "impl<W: AsyncWrite + Unpin> MieruStreamWriter<W> {\n    fn new(\n        inner: W,"),
            ],
            "src/mieru/pattern.rs": [
                ("use tokio::io::AsyncWriteExt;\nuse tokio::net::tcp::OwnedWriteHalf;",
                 "use tokio::io::{AsyncWrite, AsyncWriteExt};"),
                ("pub(super) async fn write_with_possible_fragment(\n    writer: &mut OwnedWriteHalf,",
                 "pub(super) async fn write_with_possible_fragment<W: AsyncWrite + Unpin>(\n    writer: &mut W,"),
            ],
        }
        for path, pairs in replacements.items():
            path = baseline / path
            source = path.read_text()
            for old, new in pairs:
                assert old in source or new in source, f"Unexpected baseline API: {path}"
                source = source.replace(old, new)
            path.write_text(source)
    if suite == "anytls":
        modules = {"anytls": "src/protocol/tests.rs"}
    if suite == "sudoku":
        modules = {"sudoku_transport": "src/sudoku/tests.rs"}
    test_filter = (
        "sudoku_performance" if suite == "sudoku" else
        "protocol::tests::transport_performance" if suite == "anytls" else
        "transport_performance" if suite == "transport" else "protocol_performance"
    )
    shutil.copytree(current / "tests/performance", baseline / "tests/performance", dirs_exist_ok=True)
    for name, path in modules.items():
        test_file = baseline / path
        if f"tests/performance/{name}.rs" not in test_file.read_text():
            with test_file.open("a") as output:
                output.write(f'\ninclude!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/performance/{name}.rs"));\n')
    subprocess.run(["rustc", "--version"], check=True)
    subprocess.run(["lscpu"], check=True)
    samples = {"baseline": {}, "optimized": {}}
    with tempfile.TemporaryDirectory(prefix="aerion-performance-") as temporary:
        temporary = Path(temporary)
        for name, root in [("baseline", baseline), ("optimized", current)]:
            revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
            print(f"{name}: {revision}", flush=True)
            # Cargo's freshness checks can reuse an artifact across checkouts
            # with different file mtimes when their target directory is shared.
            build(root, temporary / name, temporary / "target" / name)
            fingerprint = hashlib.sha256((temporary / name).read_bytes()).hexdigest()
            print(f"{name} binary SHA256: {fingerprint}", flush=True)
            listing = subprocess.check_output([str(temporary / name), "--list"], text=True)
            (results / f"{name}-tests.txt").write_text(listing)
        assert (temporary / "baseline").read_bytes() != (temporary / "optimized").read_bytes(), "Compared identical binaries"
        for round_number in range(6):
            order = ["baseline", "optimized"] if round_number % 2 == 0 else ["optimized", "baseline"]
            for name in order:
                output = subprocess.check_output(
                    [str(temporary / name), test_filter, "--ignored", "--nocapture", "--test-threads=1"],
                    text=True,
                )
                (results / f"{name}-{round_number}.log").write_text(output)
                print(f"Round {round_number + 1} {name}\n{output}", flush=True)
                for label, mib in re.findall(r"PERF (\S+) ([0-9.]+)", output):
                    samples[name].setdefault(label, []).append(float(mib))
    assert len(samples["baseline"]) == (15 if suite == "sudoku" else 20 if suite == "anytls" else 57), "Missing benchmark cases"
    assert samples["baseline"].keys() == samples["optimized"].keys()
    scope = (
        "Sudoku authenticated records over in-memory pipes and fresh TCP sessions with 1/128/2838 users. Handshake labels are sessions/s; other labels are plaintext MiB/s. Not Internet throughput."
        if suite == "sudoku" else
        "AnyTLS TLS frames over in-memory pipes; not Internet throughput."
        if suite == "anytls" else
        "AnyTLS TLS frames, Mieru encrypted streams and WebSocket over in-memory pipes; counted relay over pipes/loopback TCP. Not Internet throughput."
        if suite == "transport" else
        "These are in-memory codec benchmarks, not end-to-end network measurements."
    )
    report = [f"# Protocol {suite} performance", "",
              "Same runner, release build, six alternating rounds; median MiB/s of plaintext.",
              scope, "",
              "| Case | Baseline | Optimized | Change |", "|---|---:|---:|---:|"]
    for label in sorted(samples["baseline"]):
        before = samples["baseline"][label]
        after = samples["optimized"][label]
        assert len(before) == len(after) == 6
        old, new = statistics.median(before), statistics.median(after)
        report.append(f"| {label} | {old:.2f} | {new:.2f} | {(new / old - 1) * 100:+.1f}% |")
    text = "\n".join(report) + "\n"
    (results / "report.md").write_text(text)
    (results / "samples.json").write_text(json.dumps(samples, indent=2))
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
        summary.write(text)
    print(text)


if __name__ == "__main__":
    main()

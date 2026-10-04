"""Build and compare identical release benchmarks inside GitHub Actions."""

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
        cwd=root, env=env, check=True, text=True, stdout=subprocess.PIPE,
    )
    executables = [
        item["executable"] for line in output.stdout.splitlines()
        if (item := json.loads(line)).get("reason") == "compiler-artifact"
        and item.get("executable") and item.get("profile", {}).get("test")
    ]
    assert len(executables) == 1, executables
    shutil.copy2(executables[0], destination)


def main():
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
                    [str(temporary / name), "protocol_performance", "--ignored", "--nocapture", "--test-threads=1"],
                    text=True,
                )
                (results / f"{name}-{round_number}.log").write_text(output)
                print(f"Round {round_number + 1} {name}\n{output}", flush=True)
                for label, mib in re.findall(r"PERF (\S+) ([0-9.]+)", output):
                    samples[name].setdefault(label, []).append(float(mib))
    assert len(samples["baseline"]) == 57, "Missing benchmark cases"
    assert samples["baseline"].keys() == samples["optimized"].keys()
    report = ["# Protocol codec performance", "",
              "Same runner, release build, six alternating rounds; median MiB/s of plaintext.",
              "These are in-memory codec benchmarks, not end-to-end network measurements.", "",
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

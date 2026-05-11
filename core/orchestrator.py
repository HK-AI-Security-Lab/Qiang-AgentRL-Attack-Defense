"""End-to-end AutoPatch-RL loop.

usage:
    python -m core.orchestrator
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import yaml
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from agents import policy_writer, reporter
from core import judge, policy_compiler, probe_runner, runner, state_store

ROOT = Path(__file__).resolve().parent.parent
BASELINE_POLICY = ROOT / "policies" / "baseline" / "policy_intent.yaml"
LATEST_LINK = ROOT / "policies" / "generated" / "latest"

console = Console()


def _print_probe_table(it: int, results: list[dict]) -> None:
    table = Table(title=f"iter-{it:03d} probes")
    table.add_column("probe")
    table.add_column("cat")
    table.add_column("sev")
    table.add_column("expected")
    table.add_column("actual")
    table.add_column("evidence")
    for r in results:
        actual = r["actual"]
        expected = r["expected"]
        ok = (
            (r["category"] == "attack_surface" and actual == "blocked")
            or (r["category"] == "regression" and actual == "pass")
        )
        style = "green" if ok else "red"
        table.add_row(
            r["probe_id"],
            r["category"][:3],
            r["severity"][:1],
            expected,
            f"[{style}]{actual}[/{style}]",
            (r.get("evidence") or "")[:60],
        )
    console.print(table)


def _link_latest(iter_dir: Path) -> None:
    LATEST_LINK.parent.mkdir(parents=True, exist_ok=True)
    if LATEST_LINK.exists() or LATEST_LINK.is_symlink():
        LATEST_LINK.unlink()
    try:
        LATEST_LINK.symlink_to(iter_dir.resolve(), target_is_directory=True)
    except OSError:
        shutil.copytree(iter_dir, LATEST_LINK, dirs_exist_ok=True)


def main() -> int:
    load_dotenv(ROOT / ".env")
    max_iters = int(os.environ.get("MAX_ITERS", "6"))

    console.rule("[bold]AutoPatch-RL")
    console.print(
        f"baseline: [cyan]{BASELINE_POLICY}[/cyan]\n"
        f"max_iters: {max_iters}\n"
        f"llm: {os.environ.get('OPENAI_BASE_URL', '(none)')}"
        f"  model={os.environ.get('OPENAI_MODEL', '(none)')}"
    )

    run_dir = state_store.new_run_dir()
    console.print(f"run_dir: [yellow]{run_dir}[/yellow]")

    current_yaml = BASELINE_POLICY.read_text()
    prev_yaml: str | None = None
    history: list[dict] = []
    last_it_dir: Path | None = None

    for it in range(max_iters):
        console.rule(f"[bold green]iter {it}")
        it_dir = state_store.iter_dir(run_dir, it)
        intent_path = it_dir / "policy_intent.yaml"
        intent_path.write_text(current_yaml)

        try:
            policy_compiler.compile_intent(intent_path, it_dir)
        except Exception as e:
            console.print(f"[red]compile failed:[/red] {e}")
            current_yaml = BASELINE_POLICY.read_text()
            continue

        _link_latest(it_dir)

        try:
            runner.up(it_dir / "docker_run.sh")
        except Exception as e:
            console.print(f"[red]docker up failed:[/red] {e}")
            console.print("policy that failed to start:")
            console.print(current_yaml)
            current_yaml = BASELINE_POLICY.read_text() if prev_yaml is None else prev_yaml
            continue

        if not runner.wait_ready(timeout=20.0):
            console.print("[yellow]container did not become healthy in 20s[/yellow]")
            console.print(runner.container_logs(80))

        results = probe_runner.run_all(it)
        score_dict = judge.score(results)
        _print_probe_table(it, results)
        console.print(judge.summary_line(results, score_dict))

        state_store.save_iteration(it_dir, current_yaml, results, score_dict, prev_yaml)
        history.append(
            {
                "iter": it,
                "score": score_dict["total"],
                "failing": [
                    r["probe_id"]
                    for r in results
                    if (r["category"] == "attack_surface" and r["actual"] == "allowed")
                    or (r["category"] == "regression" and r["actual"] == "fail")
                ],
            }
        )
        last_it_dir = it_dir

        if judge.is_terminal(results):
            console.print(f"[bold green]✓ terminal state reached at iter {it}")
            break

        if it == max_iters - 1:
            console.print(f"[yellow]hit MAX_ITERS={max_iters} without terminal state")
            break

        prev_yaml = current_yaml
        new_yaml, source = policy_writer.propose_next(current_yaml, results, history)
        console.print(f"[dim]policy_writer source={source}[/dim]")
        current_yaml = new_yaml

    if last_it_dir is not None:
        state_store.finalize(run_dir, last_it_dir)

    runner.down()
    report = reporter.write_report(run_dir)
    console.rule("[bold]done")
    console.print(f"report: [bold]{report}[/bold]")
    return 0


if __name__ == "__main__":
    sys.exit(main())

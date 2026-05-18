"""End-to-end AutoPatch-RL loop.

Single-side defender loop: probe -> kill-chain build -> policy_writer -> repeat.

usage:
    python -m core.orchestrator
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from agents import policy_writer, reporter
from core import attack_graph, attack_graph_html, judge, policy_compiler, probe_runner, runner, state_store

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
        cat = r["category"]
        ok = (
            (cat in ("attack_surface", "red_team") and actual == "blocked")
            or (cat == "regression" and actual == "pass")
        )
        style = "green" if ok else "red"
        cat_short = {"attack_surface": "att", "red_team": "red", "regression": "reg"}.get(cat, cat[:3])
        table.add_row(
            r["probe_id"],
            cat_short,
            r["severity"][:1],
            r["expected"],
            f"[{style}]{actual}[/{style}]",
            (r.get("evidence") or "")[:60],
        )
    console.print(table)


def _link_latest(iter_dir: Path) -> None:
    LATEST_LINK.parent.mkdir(parents=True, exist_ok=True)
    # Windows symlink_to often fails (no dev mode / admin), so we copytree
    # below. `latest` may be either a symlink or a real directory.
    if LATEST_LINK.is_symlink() or LATEST_LINK.is_file():
        LATEST_LINK.unlink()
    elif LATEST_LINK.is_dir():
        shutil.rmtree(LATEST_LINK)
    try:
        LATEST_LINK.symlink_to(iter_dir.resolve(), target_is_directory=True)
    except OSError:
        shutil.copytree(iter_dir, LATEST_LINK, dirs_exist_ok=True)


# Early-stop heuristic: once the kill chain is stable AND host_owned is False,
# stop. Stability = identical edge-status fingerprint for N consecutive rounds.
EARLY_STOP_STABLE_ROUNDS = 2


def _graph_fingerprint(graph: dict) -> tuple[tuple[str, str, str], ...]:
    """A hashable summary of edge statuses, used to detect 'no change' rounds."""
    return tuple(
        (e["source"], e["target"], e["status"])
        for e in graph["edges"]
    )


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

    current_yaml = BASELINE_POLICY.read_text(encoding="utf-8")
    prev_yaml: str | None = None
    history: list[dict] = []
    last_it_dir: Path | None = None
    last_fingerprint: tuple | None = None
    stable_streak = 0

    for it in range(max_iters):
        console.rule(f"[bold green]iter {it}")
        it_dir = state_store.iter_dir(run_dir, it)
        intent_path = it_dir / "policy_intent.yaml"
        intent_path.write_text(current_yaml, encoding="utf-8")

        try:
            policy_compiler.compile_intent(intent_path, it_dir)
        except Exception as e:
            console.print(f"[red]compile failed:[/red] {e}")
            current_yaml = BASELINE_POLICY.read_text(encoding="utf-8")
            continue

        _link_latest(it_dir)

        try:
            runner.up(it_dir / "docker_run.sh")
        except Exception as e:
            console.print(f"[red]docker up failed:[/red] {e}")
            console.print("policy that failed to start:")
            console.print(current_yaml)
            current_yaml = BASELINE_POLICY.read_text(encoding="utf-8") if prev_yaml is None else prev_yaml
            continue

        if not runner.wait_ready(timeout=20.0):
            console.print("[yellow]container did not become healthy in 20s[/yellow]")
            console.print(runner.container_logs(80))

        results = probe_runner.run_all(it)
        _print_probe_table(it, results)

        score_dict = judge.score(results)
        console.print(judge.summary_line(results, score_dict))

        state_store.save_iteration(it_dir, current_yaml, results, score_dict, prev_yaml)

        # ── Kill chain (per-round) ────────────────────────────────
        prior_graphs = attack_graph.load_run_graphs(run_dir)
        round_graph = attack_graph.build_round_graph(it, results, None, current_yaml)
        round_graph = attack_graph.merge_history(round_graph, prior_graphs)
        attack_graph.write_graph(it_dir, round_graph)
        ag_stats = round_graph["stats"]
        console.print(
            f"[dim]kill_chain: host_owned={ag_stats['host_owned']} "
            f"reachable_edges={ag_stats['reachable_edges']} "
            f"severed_edges={ag_stats['severed_edges']} "
            f"kill_paths={len(round_graph.get('kill_paths', []))}[/dim]"
        )

        history.append({
            "iter": it,
            "score": score_dict["total"],
            "host_owned": ag_stats["host_owned"],
            "kill_paths": len(round_graph.get("kill_paths", [])),
            "failing": [
                r["probe_id"]
                for r in results
                if (r["category"] in ("attack_surface", "red_team") and r["actual"] == "allowed")
                or (r["category"] == "regression" and r["actual"] == "fail")
            ],
        })
        last_it_dir = it_dir

        # ── Termination conditions ────────────────────────────────
        if judge.is_terminal(results):
            console.print(f"[bold green][OK] terminal state reached at iter {it} (all probes blocked)[/bold green]")
            break

        # Stability-based early stop: host safe + N rounds with no graph change.
        fp = _graph_fingerprint(round_graph)
        if last_fingerprint is not None and fp == last_fingerprint:
            stable_streak += 1
        else:
            stable_streak = 0
        last_fingerprint = fp

        if not ag_stats["host_owned"] and stable_streak >= EARLY_STOP_STABLE_ROUNDS:
            console.print(
                f"[bold green][OK] early stop at iter {it}: host_owned=NO and "
                f"kill chain stable for {stable_streak + 1} consecutive rounds[/bold green]"
            )
            break

        if it == max_iters - 1:
            console.print(f"[yellow]hit MAX_ITERS={max_iters} without terminal state[/yellow]")
            break

        prev_yaml = current_yaml
        new_yaml, source = policy_writer.propose_next(
            current_yaml, results, history, attack_graph=round_graph,
        )
        console.print(f"[dim]policy_writer source={source}[/dim]")
        current_yaml = new_yaml

    if last_it_dir is not None:
        state_store.finalize(run_dir, last_it_dir)

    runner.down()
    report = reporter.write_report(run_dir)
    graph_html = attack_graph_html.generate_html(run_dir)
    console.rule("[bold]done")
    console.print(f"report: [bold]{report}[/bold]")
    if graph_html is not None:
        console.print(f"attack graph: [bold]{graph_html}[/bold]")
    return 0


if __name__ == "__main__":
    sys.exit(main())

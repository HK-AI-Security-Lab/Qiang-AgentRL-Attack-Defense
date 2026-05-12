"""Adversarial Red-vs-Blue orchestrator.

Each round:
  1. Blue agent proposes a policy update (one control category)
  2. Container is redeployed with the new policy
  3. Fixed probes run
  4. Red agent generates dynamic bypass payloads
  5. Dynamic payloads execute
  6. Results scored; both agents see each other's moves
  7. Repeat until equilibrium or max_rounds

The game log is saved as `game_log.json` for the HTML visualizer.

usage:
    python -m core.adversarial
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import yaml
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agents import policy_writer, red_agent, reporter
from core import judge, policy_compiler, probe_runner, red_probe_runner, runner, state_store, rationale_auditor

ROOT = Path(__file__).resolve().parent.parent
BASELINE_POLICY = ROOT / "policies" / "baseline" / "policy_intent.yaml"
LATEST_LINK = ROOT / "policies" / "generated" / "latest"

console = Console()


def _load_waf(it_dir: Path) -> dict:
    p = it_dir / "waf_rules.json"
    if p.exists():
        return json.loads(p.read_text())
    return {}


def _probe_summary(results: list[dict]) -> dict:
    allowed = [r for r in results if r["actual"] == "allowed"]
    blocked = [r for r in results if r["actual"] == "blocked"]
    passed = [r for r in results if r["actual"] == "pass"]
    failed = [r for r in results if r["actual"] == "fail"]
    return {
        "total": len(results),
        "allowed": len(allowed),
        "blocked": len(blocked),
        "passed_reg": len(passed),
        "failed_reg": len(failed),
        "allowed_ids": [r["probe_id"] for r in allowed],
        "failed_ids": [r["probe_id"] for r in failed],
    }


def _print_table(rnd: int, results: list[dict], tag: str) -> None:
    table = Table(title=f"Round {rnd} — {tag}")
    table.add_column("probe")
    table.add_column("cat")
    table.add_column("actual")
    table.add_column("evidence")
    for r in results:
        actual = r["actual"]
        cat = r["category"]
        ok = (cat in judge.ATTACK_CATEGORIES and actual == "blocked") or (cat == "regression" and actual == "pass")
        style = "green" if ok else "red"
        cat_short = {"attack_surface": "att", "red_team": "red", "red_dynamic": "dyn", "regression": "reg"}.get(cat, cat[:3])
        table.add_row(r["probe_id"], cat_short, f"[{style}]{actual}[/{style}]", (r.get("evidence") or "")[:50])
    console.print(table)


def main() -> int:
    load_dotenv(ROOT / ".env")
    max_rounds = int(os.environ.get("MAX_ROUNDS", os.environ.get("MAX_ITERS", "8")))

    blue_m = os.environ.get("BLUE_MODEL") or os.environ.get("OPENAI_MODEL", "?")
    red_m = os.environ.get("RED_MODEL") or os.environ.get("OPENAI_MODEL", "?")
    console.rule("[bold red]AutoPatch-RL: Adversarial Red vs Blue[/bold red]")
    console.print(f"max_rounds: {max_rounds}")
    console.print(f"[blue]Blue model: {blue_m}[/blue]")
    console.print(f"[red]Red  model: {red_m}[/red]")

    run_dir = state_store.new_run_dir()
    console.print(f"run_dir: [yellow]{run_dir}[/yellow]")

    current_yaml = BASELINE_POLICY.read_text()
    prev_yaml: str | None = None
    history: list[dict] = []
    game_log: list[dict] = []
    last_it_dir: Path | None = None
    outcome: str = "draw"
    tracker = judge.OutcomeTracker()

    console.print(f"[dim]Win conditions: Blue needs {judge.BLUE_WIN_STREAK} clean rounds, "
                  f"Red needs {judge.RED_WIN_STREAK} consecutive bypass rounds[/dim]")

    for rnd in range(max_rounds):
        t_round = time.time()
        console.rule(f"[bold]Round {rnd}[/bold]")
        it_dir = state_store.iter_dir(run_dir, rnd)

        round_entry: dict = {
            "round": rnd,
            "blue_move": None,
            "red_move": None,
            "fixed_probes": None,
            "dynamic_probes": None,
            "score": None,
            "terminal": False,
        }

        # ── Blue move ──────────────────────────────────────────
        if rnd == 0:
            blue_rationale = "Baseline policy (no changes yet)"
            blue_source = "baseline"
        else:
            new_yaml, blue_source = policy_writer.propose_next(current_yaml, all_results, history)
            pi_new = yaml.safe_load(new_yaml)
            pi_old = yaml.safe_load(current_yaml)
            blue_rationale = pi_new.get("policy_intent", {}).get("rationale", "")
            current_yaml = new_yaml

        intent_path = it_dir / "policy_intent.yaml"
        intent_path.write_text(current_yaml)

        console.print(Panel(
            f"[blue]Source: {blue_source}[/blue]\n{blue_rationale[:300]}",
            title=f"[bold blue]Blue Move (Round {rnd})[/bold blue]",
            border_style="blue",
        ))

        round_entry["blue_move"] = {
            "source": blue_source,
            "rationale": blue_rationale[:500],
            "policy_snapshot": current_yaml[:2000],
        }

        # ── Deploy ─────────────────────────────────────────────
        try:
            policy_compiler.compile_intent(intent_path, it_dir)
        except Exception as e:
            console.print(f"[red]compile failed:[/red] {e}")
            current_yaml = BASELINE_POLICY.read_text()
            continue

        try:
            runner.up(it_dir / "docker_run.sh")
        except Exception as e:
            console.print(f"[red]docker up failed:[/red] {e}")
            current_yaml = prev_yaml if prev_yaml else BASELINE_POLICY.read_text()
            continue

        if not runner.wait_ready(timeout=20.0):
            console.print("[yellow]container not healthy in 20s[/yellow]")
            console.print(runner.container_logs(40))

        # ── Fixed probes ───────────────────────────────────────
        fixed_results = probe_runner.run_all(rnd)
        _print_table(rnd, fixed_results, "Fixed Probes")
        round_entry["fixed_probes"] = _probe_summary(fixed_results)

        # ── Red move: dynamic bypass ───────────────────────────
        waf_config = _load_waf(it_dir)
        payloads, red_rationale, red_source = red_agent.generate_payloads(
            waf_config, fixed_results, rnd, history,
        )

        dyn_results: list[dict] = []
        if payloads:
            console.print(f"[dim]red_agent: {len(payloads)} dynamic payloads (source={red_source})[/dim]")
            dyn_results = red_probe_runner.run_all(payloads, rnd)
            _print_table(rnd, dyn_results, "Dynamic Red")

        dyn_bypasses = [r for r in dyn_results if r["actual"] == "allowed"]

        console.print(Panel(
            f"[red]Source: {red_source}[/red]\n"
            f"Payloads: {len(payloads)}, Bypasses: {len(dyn_bypasses)}\n"
            f"{red_rationale[:300]}",
            title=f"[bold red]Red Move (Round {rnd})[/bold red]",
            border_style="red",
        ))

        round_entry["red_move"] = {
            "source": red_source,
            "rationale": red_rationale[:500],
            "num_payloads": len(payloads),
            "num_bypasses": len(dyn_bypasses),
            "bypass_techniques": [r.get("technique", "") for r in dyn_bypasses],
            "payloads": [
                {"id": p["id"], "endpoint": p["endpoint"], "technique": p["technique"]}
                for p in payloads
            ],
        }
        round_entry["dynamic_probes"] = _probe_summary(dyn_results) if dyn_results else None

        # ── Rationale audit ────────────────────────────────────
        audit = rationale_auditor.audit(prev_yaml, current_yaml, fixed_results + dyn_results, blue_rationale)
        round_entry["rationale_audit"] = audit
        if not audit["verified"]:
            console.print(f"[yellow]⚠ Rationale audit: unfixed claims {audit['unfixed_claims']}[/yellow]")
        if audit["changed_categories"]:
            console.print(f"[dim]policy changed: {audit['changed_categories']}[/dim]")

        # ── Score ──────────────────────────────────────────────
        all_results = fixed_results + dyn_results
        score_dict = judge.score(all_results)

        console.print(judge.summary_line(all_results, score_dict))
        round_entry["score"] = score_dict["total"]
        round_entry["score_breakdown"] = score_dict["breakdown"]
        round_entry["duration_s"] = round(time.time() - t_round, 1)

        # ── Policy diff ────────────────────────────────────────
        pdiff = state_store.policy_diff(prev_yaml, current_yaml)
        round_entry["policy_diff"] = pdiff
        if pdiff and pdiff != "(no changes)" and pdiff != "(baseline — no previous policy)":
            console.print(Panel(
                f"[white]{pdiff}[/white]",
                title=f"[bold]Policy Diff (Round {rnd})[/bold]",
                border_style="cyan",
            ))

        # ── Persist ────────────────────────────────────────────
        state_store.save_iteration(it_dir, current_yaml, all_results, score_dict, prev_yaml)
        if payloads:
            (it_dir / "red_payloads.json").write_text(
                json.dumps(payloads, indent=2, ensure_ascii=False)
            )
            (it_dir / "red_dynamic_results.json").write_text(
                json.dumps(dyn_results, indent=2, ensure_ascii=False)
            )

        failing = [
            r["probe_id"] for r in all_results
            if (r["category"] in judge.ATTACK_CATEGORIES and r["actual"] == "allowed")
            or (r["category"] == "regression" and r["actual"] == "fail")
        ]
        history.append({
            "round": rnd,
            "score": score_dict["total"],
            "failing": failing,
            "dyn_bypasses": [r["probe_id"] for r in dyn_bypasses],
        })
        last_it_dir = it_dir
        game_log.append(round_entry)

        # ── Win-condition check ────────────────────────────────
        # R0 is baseline (no defense yet); don't count it toward streaks
        round_class = judge.classify_round(all_results)
        if rnd == 0:
            round_result = None
        else:
            round_result = tracker.update(round_class)

        round_entry["round_class"] = round_class
        round_entry["streaks"] = {
            "blue_clean": tracker.blue_clean_streak,
            "red_bypass": tracker.red_bypass_streak,
            "reg_fail": tracker.regression_fail_streak,
        }

        streak_info = (f"streaks: blue_clean={tracker.blue_clean_streak}/"
                       f"{judge.BLUE_WIN_STREAK}, red_bypass={tracker.red_bypass_streak}/"
                       f"{judge.RED_WIN_STREAK}, reg_fail={tracker.regression_fail_streak}/"
                       f"{judge.RED_WIN_STREAK}")
        console.print(f"[dim]{streak_info}[/dim]")

        if round_result == "blue_win":
            outcome = "blue_win"
            round_entry["terminal"] = True
            console.print(f"[bold green]BLUE WIN at round {rnd}: "
                          f"all attacks blocked for {judge.BLUE_WIN_STREAK} consecutive rounds[/bold green]")
            break

        if round_result == "red_win":
            outcome = "red_win"
            round_entry["terminal"] = True
            if tracker.regression_fail_streak >= judge.RED_WIN_STREAK:
                console.print(f"[bold red]RED WIN at round {rnd}: "
                              f"Blue broke regression for {judge.RED_WIN_STREAK} consecutive rounds[/bold red]")
            else:
                console.print(f"[bold red]RED WIN at round {rnd}: "
                              f"critical bypasses persisted for {judge.RED_WIN_STREAK} consecutive rounds[/bold red]")
            break

        if rnd == max_rounds - 1:
            outcome = "draw"
            console.print(f"[yellow]DRAW: hit MAX_ROUNDS={max_rounds} without decisive victory[/yellow]")
            break

        prev_yaml = current_yaml

    # ── Full diff summary ─────────────────────────────────────
    baseline_yaml = BASELINE_POLICY.read_text()
    full_diff = state_store.policy_diff(baseline_yaml, current_yaml)
    (run_dir / "full_policy_diff.txt").write_text(
        f"=== Full Policy Diff: Baseline → Final (Round {len(game_log)-1}) ===\n\n"
        + full_diff + "\n"
    )
    console.print(Panel(
        f"[white]{full_diff}[/white]",
        title="[bold cyan]Full Policy Evolution: Baseline → Final[/bold cyan]",
        border_style="cyan",
    ))

    # ── Finalize ───────────────────────────────────────────────
    if last_it_dir:
        state_store.finalize(run_dir, last_it_dir)

    runner.down()

    game_log_meta = {
        "rounds": game_log,
        "outcome": outcome,
        "total_rounds": len(game_log),
        "blue_model": blue_m,
        "red_model": red_m,
    }
    game_log_path = run_dir / "game_log.json"
    game_log_path.write_text(json.dumps(game_log_meta, indent=2, ensure_ascii=False))
    console.print(f"game_log: [bold]{game_log_path}[/bold]")

    outcome_label = {"blue_win": "BLUE WIN", "red_win": "RED WIN", "draw": "DRAW"}[outcome]
    style = {"blue_win": "bold green", "red_win": "bold red", "draw": "bold yellow"}[outcome]
    console.print(Panel(
        f"[{style}]{outcome_label}[/{style}] after {len(game_log)} rounds\n"
        f"Blue: {blue_m} | Red: {red_m}",
        title="[bold]GAME RESULT[/bold]",
    ))

    report = reporter.write_report(run_dir)
    console.rule("[bold]done")
    console.print(f"report: [bold]{report}[/bold]")

    from core.visualizer import generate_html
    html_path = generate_html(run_dir, game_log_meta)
    console.print(f"visualization: [bold cyan]{html_path}[/bold cyan]")

    return 0


if __name__ == "__main__":
    sys.exit(main())

.PHONY: install build-target up down demo battle clean report viz check-docker

PY := .venv/bin/python
PIP := .venv/bin/pip

.venv:
	python3 -m venv .venv
	$(PIP) install -U pip
	$(PIP) install -e .

install: .venv

check-docker:
	@docker info >/dev/null 2>&1 || (echo "❌ Docker daemon 没启动，请打开 Docker Desktop" && exit 1)
	@echo "✓ Docker OK"

build-target: check-docker
	docker build -t autopatch-target:vuln target/

up: check-docker
	@bash policies/generated/latest/docker_run.sh 2>/dev/null || \
		(echo "no generated policy yet, starting baseline-vulnerable container..." && \
		 bash scripts/run_baseline.sh)

down:
	@docker rm -f autopatch-target 2>/dev/null || true

demo: install build-target
	$(PY) -m core.orchestrator

battle: install build-target
	$(PY) -m core.adversarial

report:
	@latest=$$(ls -t reports/runs/ | head -1); \
		echo "opening reports/runs/$$latest/report.md"; \
		open "reports/runs/$$latest/report.md" || cat "reports/runs/$$latest/report.md"

viz:
	@latest=$$(ls -t reports/runs/ | head -1); \
		f="reports/runs/$$latest/battle.html"; \
		if [ -f $$f ]; then echo "opening $$f"; open $$f; \
		else echo "no battle.html (run 'make battle' first)"; fi

clean: down
	rm -rf policies/generated/* reports/runs/*

help:
	@echo "make install       创建 venv 装依赖"
	@echo "make build-target  构建漏洞目标镜像"
	@echo "make demo          单边 demo (Blue defender only)"
	@echo "make battle        红蓝对抗 demo + HTML 可视化"
	@echo "make viz           打开最近一次对抗的 battle.html"
	@echo "make report        打开最近一次的 final report"
	@echo "make down          停掉 target 容器"
	@echo "make clean         清空 generated + runs"

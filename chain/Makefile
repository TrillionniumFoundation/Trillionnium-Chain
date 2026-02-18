.PHONY: build test smoke smoke-pouw-e2e check-pouw-cmds release-gate clean

GOPATH_BIN := $(shell go env GOPATH)/bin
CHAIND := $(GOPATH_BIN)/chaind

build:
	@echo "[build] compiling chaind..."
	ignite chain build -v

test:
	@echo "[test] running unit tests..."
	go test ./... -count=1

smoke: build
	@echo "[smoke] running task flow smoke test..."
	@chmod +x tools/smoke_task_flow.sh
	@./tools/smoke_task_flow.sh

smoke-pouw-e2e:
	@echo "[smoke-pouw-e2e] running PoUW challenge/resolve/finalize test set..."
	@go test ./x/workload/keeper -run 'TestPoUWSubmitChallengeResolve|TestResolveChallenge_Failed_BurnsPenaltyRefundsAndCompletes|TestAutoFinalizeSubmittedTasks' -count=1

check-pouw-cmds:
	@echo "[check-pouw-cmds] verifying PoUW command hooks (non-fatal grep)..."
	@chmod +x tools/check_pouw_commands.sh
	@./tools/check_pouw_commands.sh

release-gate:
	@echo "[release-gate] running PoUW V1 release gate..."
	@chmod +x tools/release_gate_pouw_v1.sh
	@./tools/release_gate_pouw_v1.sh

clean:
	@echo "[clean] removing build artifacts..."
	rm -f $(CHAIND)
	rm -rf ~/.chain

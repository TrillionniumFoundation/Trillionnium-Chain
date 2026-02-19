# Rust L1 PoUW 模块交互时序（create → resolve）

状态：Draft  
日期：2026-02-20  
适用范围：`trillionnium-rust`（`trnm-node` / `trnm-executor` / `trnm-pouw` / `trnm-state`）

## 1) 模块职责（简版）

- `trnm-node`：接收交易、推进区块、输出审计事件。
- `trnm-executor`：交易分组并发执行（冲突检测 + 调度）。
- `trnm-pouw`：执行 PoUW 状态机与业务校验。
- `trnm-state`：维护 versioned object store，并计算 `state_root()`。

---

## 2) 端到端时序图（Mermaid）

```mermaid
sequenceDiagram
    autonumber
    participant U as Client/SDK
    participant N as trnm-node
    participant X as trnm-executor
    participant P as trnm-pouw
    participant S as trnm-state

    Note over U,S: 阶段A：create_task -> OPEN
    U->>N: tx(create_task{task_id, creator, bounty})
    N->>X: enqueue tx
    X->>P: execute create_task
    P->>S: create Task object(version=1,status=OPEN)
    S-->>P: ObjectRef(id,version=1)
    P-->>X: ok(status=OPEN)
    X-->>N: execution result
    N->>S: commit write-set + compute state_root
    S-->>N: new state_root
    N-->>U: receipt + event(create)

    Note over U,S: 阶段B：accept/commit/reveal/challenge
    U->>N: tx(accept_task{task_ref, worker})
    N->>X: schedule (conflict-aware)
    X->>P: OPEN -> ASSIGNED 校验+迁移
    P->>S: update Task(version+1,status=ASSIGNED)
    S-->>N: committed + state_root
    N-->>U: event(accept)

    U->>N: tx(commit_result{task_ref, worker, committed_hash})
    N->>X: schedule
    X->>P: ASSIGNED -> COMMITTED
    P->>S: persist committed_hash + status
    S-->>N: committed + state_root
    N-->>U: event(commit)

    U->>N: tx(reveal_result{task_ref, result_hash, salt})
    N->>X: schedule
    X->>P: verify commitment formula
    alt hash match
        P->>S: COMMITTED -> REVEALED
        S-->>N: committed + state_root
        N-->>U: event(reveal)
    else mismatch
        P-->>X: Err(CommitmentMismatch)
        X-->>N: tx failed (no state write)
        N-->>U: error receipt
    end

    U->>N: tx(challenge{task_ref, challenger, reason_code})
    N->>X: schedule
    X->>P: REVEALED -> CHALLENGED
    P->>S: update challenge metadata + status
    S-->>N: committed + state_root
    N-->>U: event(challenge)

    Note over U,S: 阶段C：resolve -> COMPLETED/SLASHED
    U->>N: tx(resolve{task_ref, authority, slash_worker})
    N->>X: schedule
    X->>P: CHALLENGED -> (COMPLETED|SLASHED)
    P->>S: finalize task + penalties/reward
    S-->>N: committed + state_root
    N-->>U: event(resolve{slash_worker,resolution_code})
```

---

## 3) 关键一致性点（对齐 v1 freeze）

1. **状态迁移唯一性**：仅允许
   `OPEN → ASSIGNED → COMMITTED → REVEALED → CHALLENGED → COMPLETED/SLASHED`。
2. **错误语义稳定映射**：例如 `InvalidTransition / VersionConflict / CommitmentMismatch`。
3. **事件审计字段最小集**：
   `event_type, task_id, from_status, to_status, actor, tx_id, block_height, state_root, ts_unix_ms`；
   resolve 额外 `slash_worker, resolution_code`。
4. **并发不破语义**：执行器策略可变，但不得改变上述协议可观察行为。

---

## 4) 工程落地检查清单

- [ ] `cargo test --workspace` 全绿
- [ ] 并行路径 sanity（含 apply_error/rollback）全绿
- [ ] 事件字段冻结检查脚本全绿（`scripts/check_event_fields.sh`）
- [ ] classic + mixed bench 回归通过且无一致性回退

---

## 5) 备注

- 本文是“讲解与评审视图”，协议冻结准绳仍以：
  `docs/protocol/rust-l1-v1-interface-freeze.md` 为准。
- 后续如引入多节点执行/共识细节，可在本文补充 `cross-node state_root reconciliation` 时序图。

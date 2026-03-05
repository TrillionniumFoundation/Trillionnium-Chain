# SettlementVault MVP（M0 Lane-1）

> 目标：定义一个**可实现、可审计、最小风险**的外置结算金库合约方案。当前阶段仅提供规范与代码骨架，不接管主执行路径。

## 1. 范围与边界

- 合约定位：外置托管结算资金（ERC20），支持 `deposit / lock / release / slash / emergency_pause`。
- MVP 边界：
  - 不做复杂收益逻辑，不做跨链桥，不做自动化价格预言机。
  - 不做多资产多策略混合管理（先支持单资产，再可扩展）。
- 安全优先：权限最小化、可暂停、可审计、可回放重演防护（requestId）、可追溯事件。

---

## 2. 角色模型（RBAC）

推荐使用 OpenZeppelin `AccessControl`，角色如下：

- `DEFAULT_ADMIN_ROLE`
  - 仅用于角色授予/回收与治理迁移。
  - 应由 Timelock/Governance 持有，不建议 EOA 直接持有。
- `PAUSER_ROLE`
  - 可触发 `emergencyPause()` / `unpause()`。
- `LOCKER_ROLE`
  - 可执行 `lock()`，将可用余额转为锁定负债。
- `SETTLER_ROLE`
  - 可执行 `release()` / `slash()`。
- `TIMELOCK_ROLE`（可选）
  - 若将关键参数更新（比如 `minLockDelay`）放入 timelock 执行，可单独角色化。

### 最小权限原则

- `lock/release/slash` 不应由同一热钱包长期持有。
- 生产环境建议：`SETTLER_ROLE` 由多签 + 自动化服务联合控制。

---

## 3. 状态变量（MVP）

```solidity
IERC20 public immutable asset;
bool public paused;

uint256 public totalDeposited;    // 统计口径（累积）
uint256 public totalLocked;       // 当前锁定总量
uint256 public totalReleased;     // 累积释放
uint256 public totalSlashed;      // 累积罚没

uint256 public minLockDelay;      // 最小锁定生效延迟（秒）

mapping(address => uint256) public availableBalance; // 用户可用余额
mapping(bytes32 => LockOrder) public lockOrders;      // requestId -> 锁单
mapping(bytes32 => bool) public consumedRequestIds;   // 防重放
```

`LockOrder`：

```solidity
struct LockOrder {
    address owner;
    uint256 amount;
    uint64  createdAt;
    uint64  unlockAt;
    Status  status; // None/Locked/Released/Slashed/Cancelled
}
```

---

## 4. 接口定义（MVP）

### 4.1 deposit

```solidity
function deposit(address beneficiary, uint256 amount) external;
```

- 行为：`transferFrom(msg.sender, this, amount)`，增加 `availableBalance[beneficiary]`。
- 校验：
  - `!paused`
  - `beneficiary != address(0)`
  - `amount > 0`
- 事件：`Deposited(sender, beneficiary, amount)`

### 4.2 lock

```solidity
function lock(bytes32 requestId, address owner, uint256 amount, uint64 unlockAt) external;
```

- 仅 `LOCKER_ROLE`。
- 行为：将 `availableBalance[owner]` 扣减并生成锁单。
- 校验：
  - `!paused`
  - `!consumedRequestIds[requestId]`
  - `amount > 0`
  - `availableBalance[owner] >= amount`
  - `unlockAt >= block.timestamp + minLockDelay`
- 状态：`consumedRequestIds[requestId] = true`，`lockOrders[requestId]=Locked`
- 事件：`Locked(requestId, owner, amount, unlockAt)`

### 4.3 release

```solidity
function release(bytes32 requestId, address to) external;
```

- 仅 `SETTLER_ROLE`。
- 行为：从锁单转出资产给 `to`。
- 校验：
  - `!paused`
  - 锁单存在且状态为 `Locked`
  - `block.timestamp >= unlockAt`（MVP 默认要求到期释放）
  - `to != address(0)`
- 状态：锁单标记 `Released`，`totalLocked -= amount`，`totalReleased += amount`
- 事件：`Released(requestId, owner, to, amount)`

### 4.4 slash

```solidity
function slash(bytes32 requestId, address treasury) external;
```

- 仅 `SETTLER_ROLE`。
- 行为：将锁单金额划转到罚没地址（`treasury`）。
- 校验：
  - `!paused`
  - 锁单存在且状态 `Locked`
  - `treasury != address(0)`
- 状态：锁单标记 `Slashed`，`totalLocked -= amount`，`totalSlashed += amount`
- 事件：`Slashed(requestId, owner, treasury, amount)`

### 4.5 emergency_pause

```solidity
function emergencyPause() external;
function unpause() external;
```

- `PAUSER_ROLE` 可 `emergencyPause`
- `DEFAULT_ADMIN_ROLE` 或 `PAUSER_ROLE`（按治理策略）可 `unpause`
- 暂停后：`deposit/lock/release/slash` 全部禁用。

---

## 5. Timelock 策略

MVP 推荐：

1. 将 `DEFAULT_ADMIN_ROLE` 交给治理 Timelock。
2. Timelock 最短延迟建议 `>= 24h`（测试网可降至 5-15 分钟）。
3. 需延迟执行的操作：
   - 角色授予/回收
   - 关键参数更新（如 `minLockDelay`）
   - 升级操作（若后续采用可升级代理）

热路径（`release/slash`）不走 timelock，但必须受限角色 + 全量事件审计。

---

## 6. 事件设计

```solidity
event Deposited(address indexed sender, address indexed beneficiary, uint256 amount);
event Locked(bytes32 indexed requestId, address indexed owner, uint256 amount, uint64 unlockAt);
event Released(bytes32 indexed requestId, address indexed owner, address indexed to, uint256 amount);
event Slashed(bytes32 indexed requestId, address indexed owner, address indexed treasury, uint256 amount);
event EmergencyPaused(address indexed by);
event Unpaused(address indexed by);
```

可选补充：`RoleGranted/RoleRevoked`（AccessControl 自带），`ParameterUpdated`。

---

## 7. 威胁模型与失败场景

### A. Reentrancy（重入）

- 风险点：`release/slash/deposit` 触发 ERC20 外部调用。
- 对策：
  - 使用 `ReentrancyGuard`。
  - Checks-Effects-Interactions 顺序（先改状态后转账）。
  - 限定资产为标准 ERC20（避免回调型 token）。

### B. Replay（重放）

- 风险点：`requestId` 被重复 lock/release。
- 对策：
  - `consumedRequestIds[requestId]` 一次性消费。
  - 锁单状态机约束：`Locked -> Released|Slashed` 单向流转。

### C. Privilege Abuse（权限滥用）

- 风险点：持有 `SETTLER_ROLE` 的主体恶意 `slash`。
- 对策：
  - 角色分离（LOCKER ≠ SETTLER ≠ PAUSER）。
  - 多签控制高权限账户。
  - 审计告警：高风险事件（slash/role change/pause）链上监控。
  - 将管理权限置于 Timelock。

### D. Pause Abuse / Liveness

- 风险点：恶意频繁 pause 影响可用性。
- 对策：
  - `PAUSER_ROLE` 最小化。
  - 约定 SLO：pause 后人工复核窗口与恢复流程。

### E. Token Compatibility

- 风险点：fee-on-transfer / rebasing 资产引发会计偏差。
- 对策：
  - MVP 限定白名单资产（标准 ERC20）。
  - 若需支持特殊 token，增加到账差额校验。

---

## 8. 最小测试计划（MVP Gate）

> 建议采用 Foundry；若环境缺失，先提交占位测试与命令脚本。

### 单元测试（必须）

1. `deposit` 正常路径：余额与事件正确。
2. `lock` 正常路径：可用余额减少、锁单创建、requestId 防重放。
3. `release` 正常路径：仅到期可释放、状态迁移正确。
4. `slash` 正常路径：仅锁定态可罚没、状态迁移正确。
5. `pause` 门禁：暂停后四个主接口全部 revert。
6. 权限测试：无角色账户调用受限函数应 revert。
7. 重入防护：恶意 token/receiver 无法重入改写状态。

### 性质测试（建议）

- 不变量：`totalLocked <= token.balanceOf(vault)`。
- 状态单调性：锁单状态不可逆回。

### 执行命令（Foundry）

```bash
cd contracts/settlement-vault
forge test -vv
```

若本地无 Foundry：

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

---

## 9. 上线路径（非本次实现）

1. 内部审阅（协议+安全）
2. 静态分析（slither/forge fmt + test + coverage）
3. 外部审计前置清单冻结
4. 测试网灰度

---

## 10. 当前交付清单（本 Lane）

- 规范文档：`docs/protocol/external-contracts/settlement-vault-mvp.md`
- 合约骨架：`contracts/settlement-vault/src/SettlementVault.sol`
- 测试占位：`contracts/settlement-vault/test/SettlementVault.t.sol`
- 说明文档：`contracts/settlement-vault/README.md`
- 本地执行脚本：`scripts/settlement_vault_mvp_test.sh`

## 11. Lane-1 收口说明（2026-03-05）

- 本次提交保持“规范 + skeleton”为主，不接入主执行路径。
- 风险策略：优先可审计接口与最小权限模型，延后升级代理与复杂资产兼容。
- 交付标准：
  - 文档必须可直接用于安全评审；
  - 合约需具备完整事件面与状态机骨架；
  - 测试计划覆盖权限、重放、暂停门禁、状态迁移。

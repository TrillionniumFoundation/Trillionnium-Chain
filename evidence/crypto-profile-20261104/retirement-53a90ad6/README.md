# 可信有效退休登记：固定53a90ad6源码证据

**状态：HOLD；六域仍全部 UNQUALIFIED。** 本目录保存固定53a90ad6的实际观察：32份有效顶层终结收据中30份退出0、2份Node重试退出101；另有两份原始0 B收据按未知状态单列，未计入32份有效收据。核心修复及所列组件、参数、互操作观察已完成，完整Node原生验收仍未完成。发布本目录不会把此前源码的结果转换为新源码验收。

## 1. 被执行的源码与交付范围

被执行提交为 **`53a90ad66b224db9d5095ba3efdadc7319ad8423`**，tree为
**`6e8ed831672296129672df51f814abba05ea3355`**。有效命令收据的执行前后身份核验覆盖8,926个tracked entries、945,979,239字节；身份核验本身不是测试。缺少终结收据的尝试另列为recording failure，不获得精确源码通过信用。后续证据／文档提交仍须与这个实际执行身份区分。

本增量补齐一个具体历史迁移缺口：原 `ProfileBinding.retirement_height` 属于不可变配置ID的编码，最初以 `None` 进入CURRENT的描述符，不能靠改成 `Some(end)` 再绑定来保留原ID。新增 `RetiredCryptoProfile` 在可信owner状态中登记独立有效截止，保留原描述符、公钥／消息绑定与配置ID；原 `from_trusted_state(Vec<BoundCryptoProfile>)` 仍支持预先声明退休高度的旧用法。

`from_trusted_state_with_retirements` 的有效截止为exclusive，必须严格晚于激活高度、不得超过已有declared end、不得晚于当前配置的激活高度。两个构造路径共享16条上限、非零generation、网络／创世／scope、重复ID和非重叠历史窗口检查。`select_historical` 使用可信有效窗口；当前选择与 `recheck_current` 继续检查当前ID、generation和高度。

新增8项控制覆盖原ID连续性、拒绝重新绑定的不同ID、exclusive end与gaps、重复／重叠／过晚结束、foreign binding／候选／容量边界、原parameters及protocol保留、候选当前授权拒绝和stale-current重验。原完整组件测试已实际执行，日志中的8条 `trusted_retirement_*` 具名终结行均为通过；它们包含在下述245项Rust通过数中，不另行重复累计。

历史结果类型没有当前effect能力，不能传给 `recheck_current`。构造器不认证输入状态，`select_historical` 也不证明来件记录已被接受。真实owner必须独立认证并持久化退休计划与已接受历史记录，在最终使用时提供新鲜可信状态，并执行业务角色、nonce、资金及撤销规则；接口实现不等于部署迁移已经完成。

本次2.1范围仍包括配置ID对算法／参数／模式、唯一编码、域隔离、按用途的哈希、网络／创世／协议／激活规则、消息／验签／累计字节限额以及历史／当前规则的绑定。ML-DSA-65保留为现有基线；新增候选65与87均不能取得当前授权，ML-DSA-87未激活。配置ID不能由来件自行降级选择。描述符规范编码、golden IDs、legacy wire、CPQ1预算及native W1挑战／ticket／完整工作关系保持不变。

这里的“完整”是明确列出的实现范围和实际执行矩阵。即使某个有限名单达到100%，也不表示全仓路径、全部owner、完整网络或整链PQ安全100%覆盖。本阶段所有native生产者已终结，但失败的Node构建和未执行控制仍阻止完整原生验收；本文不作100%验收声明。

## 2. 实际结果与未完成的验收范围

完整命令、环境、source before／after、退出码及日志身份保存在 [reproduction.json](reproduction.json) 与 [raw-observations.tar.gz](raw-observations.tar.gz)。顶层原命令收据、互操作内部命令、测试用例和参数样本采用不同计数，不相加为“测试总数”。

| 范围 | 实际终结结果及覆盖边界 |
| --- | --- |
| 顶层命令总览 | **32份有效终结收据＝30退出0＋2退出101**；另有M06首次集成、Node首次构建两份原始0 B收据为unknown，不计为有效收据或通过 |
| protocol＋crypto原 `--locked --offline --all-features --lib` | **245通过、0失败、2项原有ignored**：143 crypto＋102 protocol通过，无过滤，命令退出0 |
| 本次8项 `trusted_retirement_*` 控制 | **8项具名结果均通过**，已包含于245，不重复累计 |
| protocol doctest | **2通过、0失败**，包括历史／当前类型的compile-fail边界 |
| preflight＋16项低资源门禁、锁图、格式及Python suites | **17条命令全部成功**；其中5个Python suites共106通过（34＋4＋35＋22＋11） |
| M06 `--lib pq_accounts_v2` 单元范围 | **15通过、0失败、0ignored、105 filtered out**；只是原过滤范围，不是整个M06全部单元测试 |
| M06五组原集成目标 | 首次SIGBUS／recorder ENOSPC观察仍为**native exit未知／无通过信用**；原命令独立重试退出0，**44通过、0失败、0ignored／filtered** |
| 完整Node lib-test build、network与continuous owner | 首次构建收据0 B、native exit未知；retry1因明确ENOSPC失败101，retry2出现rustc SIGKILL并失败101，根因未定。**没有成功Node测试二进制；network／continuous-owner均未执行** |
| 原49项required controls | **49项均未执行，0项通过，batch不完整**；完整Node构建未成功，不用其他harness或旧结果替代 |
| 原设置workspace strict Clippy | **退出0、command_succeeded**；原 `--locked --offline --workspace --all-targets --all-features -- -D warnings`，完整source before／after均为53a90ad6 |
| release参数构建／运行／独立reader | **三条命令均已终结成功**；32场景、288项测量、18,432个样本值 |
| 独立65／87互操作harness | **顶层命令终结成功**；内部manifest记录121条命令、16次有效接受、64次签名拒绝；4次CLI空消息限制单列 |
| 互操作内部结果的独立只读复核 | **OBSERVATIONS_CONSISTENT_HOLD**：80项矩阵、121条内部命令、74份公开fixtures、242份stdout／stderr日志身份一致；无原生／密码学重跑 |

没有实际命名执行、只有编译完成或过滤器exit 0，不能算required selector通过。49项必须保留逐项原recorder与named reader结果及同一原Node二进制身份。发生失败、recording failure或未知状态时原样保存；不能用子进程harness或部分名单替代完整名单。Source／claim guard通过也不升级HOLD或六域UNQUALIFIED。

两项原有ignored仍为 `bulk_complete_construction_cost_observation` 和 `state_node_and_complete_root_paired_cost_observation`；它们没有运行通过，不加入245项。

16项低资源命令为 `compiler`、`cargo-version`、`locked-graph`、`fuzz-locked-graph`、`fmt`、`profile-oracle`、`inventory`、`source-pins`、`claim-guard`、`repository`、`ci-contract`，以及 `test-ci-source-integrity`、`test-record-pq-native-command`、`test-pq-research-integration`、`test-pq-chain-claim-guard`、`test-pq-authority-surface-scan`。本次独立运行的终结结果及来源记录在 `records/auxiliary/low-resource-gates-summary.json`；只复用原命令形式，不复用59f通过信用。106是上述5个suite的用例数，不再叠加为106条顶层命令。

M06原五个集成目标分别为 `pq2_authority_capacity` 2通过、`pq3_quota_authority` 8通过、`pq4_task_authority` 9通过、`pq5_task_renewal` 17通过、`pq_account_owner` 8通过，共44项。加上原过滤单元范围的15项，M06账户授权范围共有59项通过；105项单元filtered out的边界仍保留。M06重试前的 `preflight-native-retry` 及Node重试前的 `preflight-node-retry`、`preflight-node-buffer-retry` 均有成功终结收据；这些是单独记录的重复preflight，不增加新的门禁种类。

## 3. 新源码的65／87参数观测

这是本次53a90ad6重新构建并实际运行的release example，不能借用ad081或59f的性能数字。独立reader重算全部18,432个样本值并输出 `PASS`。矩阵为2种算法 × 4种消息长度（0／176／4096／65536 B）× 4种签名人数（1／2／4／8），每场景9种操作、每项64样本。

原始 [parameter-observations.jsonl](parameter-observations.jsonl) 为296,038 B，SHA-256：
`ce91124749cfb4afb0b6391a3706f07261a1ac77bae4544b70e97144eb2f1eb6`。
运行时的实际二进制为766,432 B，SHA-256：
`50c6c8a33f82a202ff6efa52c12b75a75da4918465db7fa93a2d58981f6ac70a`。
构建artifact元数据、执行前后source、原始stdout／stderr及进程记录随原命令归档。该release二进制在观测及独立回读成功后已作为任务缓存回收，本文不声称它仍保留在原路径。

下表列出两个场景；延迟是**每个签名人组**的p50，单位ms。签名列包含编码、自验与释放，验签列包含观测帧preflight，均不是单独原语的纯耗时。

| 消息／签名人数 | 参数集 | 实际观测帧 | 签名＋编码＋自验＋释放p50 | 帧preflight＋verify p50 |
| --- | --- | --- | --- | --- |
| 176 B／1 | ML-DSA-65 | 5,456 B | 0.204923 ms | 0.097845 ms |
| 176 B／1 | ML-DSA-87 | 7,414 B | 0.934493 ms | 0.141719 ms |
| 65,536 B／8 | ML-DSA-65 | 107,671 B | 11.358905 ms | 2.988531 ms |
| 65,536 B／8 | ML-DSA-87 | 123,335 B | 13.789751 ms | 3.517915 ms |

公钥／签名字节分别为65的1,952／3,309和87的2,592／4,627；参数与类别见 [FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)。NIST类别3／5不能直接换算为整条系统的量子安全位数。这里的帧是 `TRNMCPB1`，**不是CPQ1／PNQ／NPQ**；多签生产容量仍须按真实消息的metadata、payload、公钥及签名集合验证。

程序采用Pure ML-DSA、空FIPS context、确定性签名、固定重复fixture；参数／场景按固定顺序执行，没有随机交错或配对消除主机负载。每项64个样本的nearest-rank p99等于样本最大值，不能推出生产总体尾延迟。九种操作还包括keygen／key import、正确与错误签名验签、尺寸早拒绝、帧编码及单独preflight。

观测在2026-11-05 01:35:10–01:35:34 UTC完成，实际wall time为23.901917205秒，进程峰值RSS为11,136 KiB。主机为x86_64 Linux、AMD EPYC 9V74；容器可见9个逻辑CPU、CPU配额8核、内存上限8 GiB。共享负载未受控，运行前后load average和cgroup计数均随记录保存。RSS是整个观测进程的峰值，不是单次签名或每个参数集的独立峰值；本结果不提供WAN吞吐、生产p99或上线容量资格。

## 4. 有限双向互操作及CLI限制

顶层 `interop` 收据和嵌套 `records/interop/manifest.json` 是不同层次：顶层只计一条原命令，内层保留121条命令及其日志、observer与provider身份。公开fixtures用于复核；临时OpenSSL私钥目录已删除，私钥文件未归档，Rust observer的固定种子是公开测试fixture。实际crate候选API与OpenSSL 3.5.9实现进行双向观察，参数为65／87、消息长度为0／176／4096／65536 B，模式为Pure、空context。

manifest记录16次有效接受，即2参数 × 4消息长度 × 2方向；64次预期签名拒绝覆盖每个组合的wrong-message、wrong-key、语法有效的late-invalid-signature以及nonempty-context。对空消息，wrong-message变体为一个零字节，其他长度变体改变首字节；因此矩阵长度指原有效签名消息长度。

另外4次 `pkeyutl` CLI空消息签名／验签在前端拒绝，**没有计入64次密码学拒绝**。空消息的实际签名／验签由非NULL缓冲区、长度0的EVP observer完成；setup、编译、解码或CLI前端错误不得替代实际签名拒绝。

独立只读reader在相关产物回收前已核对80项完整矩阵、121条内部命令、74份公开fixtures及242份stdout／stderr的哈希，精确source证明、provider、当时的实际crate rlib与observer身份均相符，`unexpected_outcomes` 为空。`records/interop/independent-readback.json` 记录 `OBSERVATIONS_CONSISTENT_HOLD`；这是对已完成观察的回读，没有重跑原生程序、密码学操作或全源码verifier，也不是第二轮互操作执行。用于该次观察的release crate rlibs后来已回收；Rust／C两个observer ELF也在成功观察及独立回读后按既有hash核对并回收。收集时不再声称这些二进制仍在现场；helper源码、公开fixtures、原命令、日志、哈希、构建及回读元数据继续保留。

这些是有限跨实现数学观察，不是FIPS模块验证、完整FIPS一致性认证、侧信道审查、完整交易／治理／恢复业务互操作或生产激活证明。

## 5. 哈希用途、owner与共识边界

注册表ID及候选按用途commitment使用SHA-512／64 B。候选key、state、release、proof、address、Merkle与transcript helper的存在，不证明所有实际owner都已采用；legacy key、payload和PNQ policy继续保留各自原算法、长度及域隔离。按用途审查哈希不能等同于全仓替换哈希。

M15 release／recovery仍使用独立固定ML-DSA-65套件，尚未接入 `crypto_profile_id`；root identity及checkpoint仍为SHA-256／32 B，SHA-512／64 B签名消息摘要不把它变成HashML-DSA或统一注册表集成。一般role的content仍是非零32 B不透明标识；已读NodeSoftware bundle路径才明确绑定V0 SHA-256 bundle identity。

native W1挑战和ticket仍为原SHA-256／32 B，完整关系与工作配置未由本修复更改。若以后改变这些输入／哈希／关系，必须定义新的工作配置并重新做工作安全分析。配置ID、候选87及64 B commitment不能代替该分析。

后继ac240恢复admission、live journal及M15 CURRENT修复已作为本次源码基线保留；其独立历史记录中的4项Unix／daemon失败继续保持原来源和状态，不会被本目录其他组件的通过数抹去。[整链PQ声明约束](../../../docs/security/WHOLE_CHAIN_PQ_CLAIM_GUARD_20261031.md)的六域仍全部UNQUALIFIED：authorization、capacity_and_invalid_input、independent_end_to_end、migration_and_rollback、proof_pq128、quantum_mining_fork_choice。

## 6. 历史、准备失败与归档

[ad081原始证据](../README.md)和[固定59f阶段](../continuation-59f75acd/README.md)保留各自源码／运行身份。ad081的SIGKILL失败及原因未定继续保留；59f的首次fuzz离线缓存失败101与其成功147节点重试分别保存。885未归档续接收据已丢失，不根据口头进度重建通过或性能数据。这些都不加入本次53a90ad6测试统计。

本次准备阶段还发生 `git write-tree` 磁盘空间错误：退出128，外层import wrapper退出1，错误为index.lock写入时 `Out of diskspace`。该失败没有执行native测试，也没有由失败尝试移动ref；恢复记录描述了与已验证树的只读比较及精确commit导入。它按**准备失败**保留，不能误记为原生测试失败或删除；完整原命令收据不可用的限制也保留。记录源为 `publication-precommit-records/import-disk-failure.json`。

**M06首次集成的记录失败另列：** 原命令包含 `pq_account_owner`、`pq2_authority_capacity`、`pq3_quota_authority`、`pq4_task_authority`、`pq5_task_renewal` 五个集成目标。日志在链接 `pq5_task_renewal` 时记录 `ld terminated with signal 7 [Bus error]`；随后recorder写终结收据遭遇 `[Errno 28] No space left on device`。外层wrapper退出1，但原生命令的最终退出码未知，SIGBUS根因也未确认，不能推断为某个Cargo退出码或某项测试失败。

原 `m06-integrations.json` 为0 B并原样保留，未覆盖或补造。日志为3,842 B，SHA-256为 `e209c6259ec896642ded0d84c3d79373fbf57bce96724f80043df23e961b50ec`；`records/auxiliary/m06-integration-recording-failure.json` 明确记录没有完整source identity receipt、`native_exit_code=null`、`pass_credit=false`。该次作为unknown／recording failure保留，不进入有效命令通过数。重新preflight后的原命令重试使用独立 `m06-integrations-retry1` 收据，实际44项通过，执行前后均为53a90ad6的精确源码；重试成功不能覆盖首次失败观察或推定首次原生命令退出码。

**首次Node构建的记录失败也独立保留：** 原全features `--lib --no-run --message-format=json` 构建日志记录无法创建临时目录的ENOSPC诊断，Cargo `build-finished.success=false`。随后recorder也无法写终结收据，原 `node-build.json` 为0 B；外层wrapper退出1，native退出码仍未知，没有完整source identity receipt，未执行任何Node控制，不能补造成功artifact或终态。原日志113,694 B，SHA-256为 `c2654e07b3c388ec540bc6940e52b0f93184367cc7cb83152a193475d0e2b884`；`records/auxiliary/node-build-recording-failure.json` 保留该观察与 `pass_credit=false`。第一次独立重试 `node-build-retry1` 已获得完整有效原收据，执行前后均为53a90ad6，真实退出码为101。日志明确出现 `rustc-LLVM ERROR: IO failure on output stream: No space left on device`，并有 `build-finished.success=false`；日志114,831 B，SHA-256为 `1e28e4ec0e26105c5d425fd20c35e6d3e6c76f6624b1bfb562d1b402e5eeff31`。这是已知的构建失败，与首次空收据的native exit未知分别保存。第二次独立重试 `node-build-retry2` 也已获得完整有效收据，执行前后均为53a90ad6，真实退出101，`build-finished.success=false`。该次在2026-11-05T02:17:36.042363+00:00开始，elapsed_ns为920,518,172,498；日志114,768 B，SHA-256为 `8740688602da7f02ae721e1cd3f2f3774168d9bf896565c0aff13d5ba1c1f7ea`，明确记录rustc `(signal: 9, SIGKILL: kill)`。观察到共享cgroup的OOM计数增长，但不能据此把OOM归因到这个进程，因此SIGKILL根因保持未知。三次尝试分别保留为首次native exit未知、retry1明确ENOSPC／101、retry2 SIGKILL／101，没有任何一次构建成功。

没有成功的Node测试二进制，network、continuous owner及49项控制均未执行。当前没有合理的资源恢复方案，本阶段不继续同条件重试；这是尚未完成的原生验收范围，不得以缩小命令、改变预算、替代harness或借用历史通过数补齐。strict workspace Clippy随后按原完整命令成功终结；该静态检查不替代未成功的Node测试二进制构建，也不产生任何Node控制项的运行信用。

为保护后续原记录写入，已把当时330个观察文件、共3,144,613 B按原字节迁到本任务专用内存缓冲区 `/dev/shm/trnm-retirement-53a90ad6-observations`；原逻辑输出路径通过symlink指向该位置，之前的磁盘checkpoint继续保留。`records/auxiliary/observation-buffer-relocation.json` 列出每个原文件的长度／hash。迁移只改变物理存放位置，没有修改源码、原recorder、argv、预算、权限或已有记录，也没有重建测试结果；最终完整归档仍须另外持久保存。

为继续原设置的Node构建，另将本任务1,315份既有Cargo输出、共753,892,842 logical B搬到现有可执行临时空间 `/dev/shm/trnm-retirement-53a90ad6-target`。原 `CARGO_TARGET_DIR` 逻辑路径经symlink保持不变；`records/auxiliary/build-output-relocation.json` 保留每份输出的SHA-256与mode。没有改变源码、compiler profile／argv、预算、provider、共享缓存、权限／mount flags或测试TMPDIR；该移动不是构建成功证据。完成新的preflight后仍使用原全features Node命令。

为继续原预算下的验证，按记录回收了以下本任务缓存；源码、原日志／收据、共享缓存及私有provider均未修改：

| 回收范围 | 数量／logical bytes | 保留的辅助记录 |
| --- | --- | --- |
| 已终结的两份组件test executable | 86,073,832 B | `completed-component-cache-retirement.json`，包含各hash及成功收据身份 |
| 已完成完整fuzz locked graph后的任务临时Cargo cache | 10,943文件，284,317,505 B | `completed-fuzz-cache-retirement.json`，图解析及准备哈希保留 |
| 已终结的M06单元test executable | 76,283,640 B | `completed-m06-unit-cache-retirement.json`，成功收据及二进制hash保留 |
| 已完成release观测／互操作缓存、74份旧任务依赖变体及1份失败链接临时输出 | 607文件，284,078,139 B | `completed-release-and-old-variants-retirement.json`，保留实际链接依赖范围及文件身份 |
| 已成功终结的5份M06集成test executables | 324,457,744 B | `completed-m06-integration-cache-retirement.json`，重试成功收据及各二进制hash保留 |
| Node retry1失败后、buffer迁移前的35份旧变体／失败输出 | 174,150,164 B | `pre-buffer-target-cache-retirement.json`，保留有效失败收据及受保护Cargo输出范围 |
| Node retry2终结失败后产生的4份自身Node对象 | 188,958,752 B | `failed-node-retry2-object-retirement.json`，各对象身份及失败记录保留 |
| 互操作及独立读回完成后的两个Rust／C observer ELF | 10,988,992 B | `completed-interop-observer-cache-retirement.json`，既有程序hash及全部helper／日志／命令／公开fixtures保留 |
| 所有native生产者终结、strict Clippy成功后的本任务剩余Cargo输出 | 4,337文件，872,300,932 B | `completed-native-target-cache-retirement.json`，32份终结收据身份及当时输出文件身份保留 |

这些辅助记录位于归档的 `records/auxiliary/`。logical bytes不等同于真实回收的物理块数。本文不声称已回收的test executables、release benchmark二进制、release crate rlibs或互操作observer ELF仍存在；原始证据及精确构建来源继续保留，后续需要时由原锁定命令重建。

最终collector已完成，状态仍为HOLD。`reproduction.json` 列出32份有效顶层收据，两个已知失败标签为 `node-build-retry1`、`node-build-retry2`；另两份0 B原收据列在 `unreadable_json_observations`，native execution status均为unknown。required controls记录 `executed=0`、`passed=0`、`not_observed=49`、`complete=false`，没有成功Node二进制；`native_acceptance_complete` 和 `full_node_regression_claimed` 均为false。

| 文件 | 字节数 | SHA-256 |
| --- | --- | --- |
| [reproduction.json](reproduction.json) | 231,447 | `890b3c7cc03f6e027453127e94c82f9ba5f181f029f0171335287778b1b2fc3e` |
| [raw-observations.tar.gz](raw-observations.tar.gz) | 830,679 | `65d95ac910ae19748f13a66d0d152e2c0bb60b71c1d8db64a36100be2f210ced` |
| [parameter-observations.jsonl](parameter-observations.jsonl) | 296,038 | `ce91124749cfb4afb0b6391a3706f07261a1ac77bae4544b70e97144eb2f1eb6` |

以上三个结果文件的长度与SHA-256已核对。[归档独立复核](archive-review.json)为110,297 B，SHA-256为 `c3c2c7a74708692cd0c02d76adf982bd88c856e32a2672553b18181ca28269ca`，结果为 **ARCHIVE_INTEGRITY_CONSISTENT_HOLD**。复核确认375个唯一常规成员，374项payload逐项匹配manifest的长度及SHA-256；manifest自身由整个归档的SHA-256覆盖。没有重复、越界成员、编译二进制或私钥header。三份结果文件在复核前后保持一致。

该只读复核还核对32份有效收据的源码／日志绑定、两份0 B原文的unknown状态、49项未执行状态以及互操作的121条命令、80项唯一矩阵、242份日志和74份公开fixtures。互操作内部命令不会再计成121份顶层源码收据。复核没有重跑native、密码学操作、旧reader或全源码verifier；归档一致性成功不构成新一轮native测试或整链资格。

最终清理只回收本任务派生Cargo输出；源码、原日志与收据、provider、共享Cargo／Rustup缓存和其他任务输出未删除。程序运行时及成功读回时的身份继续保留，收集时不声称已回收的二进制仍在现场。本目录由后续文档／证据提交发布，该提交不冒充重新执行过的native源码；所有执行结论仍固定归属于53a90ad6。

后续工程顺序仍由[唯一开发计划](../../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)管理。任何上线、CURRENT／FinalUse owner集成、完整单调恢复、独立原生端到端及共识安全结论，都必须由相应真实owner和原预算下的证据单独建立。

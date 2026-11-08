# 新 system-scope CPU 隔离探针

本记录只覆盖 2026-11-08 的一个新短任务，未运行昂贵证明、未重派历史任务、未改写历史 M12 数据或资源 cap。旧任务的 `gpu_ns` 仍为 `null`，完整资源结算与 provider 付款仍不成立。

## 实际执行

现有操作员权限的只读检查确认合法的非交互系统服务权限；未修改 sudo、polkit 或内核策略。旧 user-scope 单元的 `218/CAPABILITIES` 不能推广为 system-scope 也不支持隔离。

`attempt-01` 的 systemd 255 transient-service 设置在创建阶段返回 `Invalid argument`，没有工作负载启动。分组与单项诊断明确定位到 `RestrictAddressFamilies=none`；同版本的静态 unit 验证通过并不证明 transient DBus 属性可用。失败原件和诊断全部保留。

`attempt-02` 使用 `RestrictAddressFamilies=AF_UNIX` 并以 seccomp 明确拒绝 `socket` / `socketpair`，保留独立网络、设备、IPC 和进程视图、动态 UID、空 capability 集及 `NoNewPrivileges`。实际父进程收到 exit 0，12 个预定条件全部为真。所有计时来自该次实际父进程及同机单调时钟。

- 主机发现 7 个 GPU 字符设备。每个既检查原路径，也通过只读 bind 的备用路径检查相同设备号；28 次 read / read-write open 全部被拒绝。权限为 666 的 NVIDIA 节点返回 `EPERM`，因此不只是原路径不存在或普通文件权限造成拒绝。
- `AF_UNIX`、`AF_INET`、`AF_INET6` 的 socket 创建均失败；没有继承 GPU 或 socket 描述符，初始描述符只有 0、1、2 的管道或 `/dev/null`。
- 动态非特权 UID、空 capabilities、seccomp、不可见外部 `/proc/1/root` 和自身 `ptrace` 拒绝均实际读回或实测。
- `/dev/null` 写入和 `/dev/zero` 读取作为正向控制实际成功。
- cgroup 的 CPU、内存、swap、pids 限制与观察值保留在原件。探针使用 0.25 CPU、256 MiB、0 swap、16 pids；这不是原业务的完整资源实验。

该结果建立了新短任务的 GPU 设备及套接字拒绝能力。尚未证明完整 zkVM 工作负载在此隔离配置下可以运行，也未形成覆盖所有后代、所有原始计费维度的结算收据。不能据此回填旧运行的 GPU 使用量为零。

## 原件

[文件哈希清单](manifest.json)、[首轮失败](attempt-01/result.json)、[实际通过](attempt-02/result.json)、[通过的配置与探针代码](attempt-02/intent.json)、[原始 stdout](attempt-02/stdout.json)。两版 runner 均保留；它们是本次观测的复现代码，不是默认生产沙箱。

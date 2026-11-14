# SSH 用户证书 CA 运维手册

本文档配套 `ca-ssh/` 工具链，说明如何把分散在一百多台机器上的
`~/.ssh/authorized_keys` 迁移到集中签发、按组授权、可即时吊销的 SSH 证书模型，
同时保留独立的紧急（break-glass）通道。

## 1. 架构与信任模型

### 1.1 为什么用证书而不是继续堆 authorized_keys

- 公钥散落在每台机器，员工离职需要逐台删除，极易遗漏。
- 证书由 CA 集中签发，机器只信任 CA 公钥，不再认识任何个人公钥。
- 证书带短有效期（默认 12h，紧急通道 4h），到期自动失效，天然限制离职影响面。
- 需要立即踢人时，把序列号写入 KRL（Key Revocation List）并下发，秒级全网生效。

### 1.2 两个独立 CA（关键设计）

| CA | 私钥 | 信任的 principal | 用途 |
|----|------|------------------|------|
| `user-ca` | 离线保管 | `group:<组名>` + 个人登录名 | 日常运维/研发登录 |
| `breakglass-ca` | 离线、分片保管、审计更严 | 仅 `breakglass` | 紧急通道专用 |

两个 CA 的私钥互相独立，机器端通过 `Match User breakglass` 块只信任
`breakglass-ca`。因此：

- 日常 CA 即使被滥用，也无法登录紧急账号。
- 紧急证书不能用于普通账号（普通账号的 principal 文件里没有 `breakglass`）。
- 紧急通道的开关、轮换、审计可以独立于日常体系进行。

### 1.3 授权如何按组落地

证书里的 principal 与机器上的 principal 文件双向匹配：

- 签发时（`10-sign-cert.sh`）：组成员写成 `group:web,group:sre`，再附个人登录名。
- 机器端（`AuthorizedPrincipalsFile /etc/ssh/ca/principals/%u`）：
  每个账号一个文件，列出该机器允许的 principal。
- 只有证书携带的某个 principal 出现在目标机器对应账号的文件里，才允许登录。

`group:` 前缀保证组名永远不会和真实登录名冲突。机器允许哪些组由
`inventory/hosts.csv` 单一事实源决定，`30-render-principals.sh` 渲染成文件，
`40-deploy.sh` 下发，`50-audit.sh` 持续核对是否漂移。

## 2. 目录与产物

```
ca-ssh/
  bin/
    lib/common.sh            公共函数、路径、序列号、台账
    00-init-ca.sh            初始化两个 CA 和空 KRL
    10-sign-cert.sh          签发用户/紧急证书，写台账
    20-revoke.sh             按证书/序列号/用户吊销，重建 KRL
    30-render-principals.sh  从 inventory 渲染每台机器的 principal 文件
    40-deploy.sh             下发 CA/KRL/principal/sshd 配置，校验+回滚
    50-audit.sh              审计线上配置与本地清单/台账一致性
  etc/sshd_config.d/10-ssh-ca.conf   服务器端配置模板
  inventory/hosts.csv       主机清单（授权事实源）
  tests/e2e.sh              端到端认证矩阵测试
  docs/runbook.md           本文档
```

CA 主机上的运行时目录（`CA_ROOT`，默认 `/etc/ssh-ca`）：

```
ca/           两个 CA 的公/私钥（私钥 600，离线）
krl/          user-ca.krl / breakglass-ca.krl
ledger/       每张证书的签发台账（CSV，含序列号、principal、指纹）
state/        单调序列号、持久化吊销记录
staging/      渲染好的、待下发的 per-host principal 文件
```

## 3. 首次上线（灰度，不要一次性全量）

### 3.1 在离线 CA 主机初始化

```bash
export CA_ROOT=/etc/ssh-ca
ca-ssh/bin/00-init-ca.sh
```

产出两个 CA。私钥立即离线备份（建议加密 + 分片托管，如双人各持一半），
公钥才允许进入下发流程。

### 3.2 维护主机清单

编辑 `inventory/hosts.csv`，为每台机器声明允许的组、个人例外、是否开紧急通道。
渲染并检查产物：

```bash
export CA_INVENTORY=/etc/ssh-ca/inventory/hosts.csv SSH_LOGIN_USER=ops
ca-ssh/bin/30-render-principals.sh
```

### 3.3 先灰度一台，保留旧通道

首次下发时**不要**加 `--purge-authorized-keys`，让新旧机制并行：

```bash
ca-ssh/bin/40-deploy.sh --host web-01
```

部署脚本在每台机器上：先把文件放到 `.new`，合并 principal，再 `sshd -t` 校验，
通过后才 reload；失败自动回滚备份。验证证书登录、组隔离、紧急通道都正常后，
再逐批推广。

### 3.4 验证通过后再关闭旧通道

确认一批机器证书登录稳定后，下发时清理历史 authorized_keys：

```bash
ca-ssh/bin/40-deploy.sh --host web-01 --purge-authorized-keys
```

配置模板里 `AuthorizedKeysFile none` 让 sshd 根本不再读取个人公钥文件，
因此即使有遗漏的 authorized_keys 也不会被信任。`--purge` 只是清理磁盘残留。

### 3.5 跳板机本身

跳板机（bastion）也作为 inventory 中的一台主机处理，登录账号同样只接受
`user-ca` 签发的证书。若用户需要经跳板机二次跳转，可在跳板机证书上按需
开放 agent forwarding（默认签发关闭，按需用 `-O` 调整），或对目标主机同样
部署本方案，实现端到端证书认证。

## 4. 日常操作

### 4.1 给员工签发（短期、按需）

```bash
# 研发，属于 web 组，12 小时有效
ca-ssh/bin/10-sign-cert.sh --user alice --key /path/alice.pub --groups web --ttl 12h

# SRE，同时属于 web 和 sre
ca-ssh/bin/10-sign-cert.sh --user bob --key /path/bob.pub --groups web,sre

# 限制只能从公司出口 IP 发起
ca-ssh/bin/10-sign-cert.sh --user carol --key carol.pub --groups db \
    --source 203.0.113.10/32
```

员工把返回的 `*-cert.pub` 与私钥放一起，`ssh` 会自动出示证书。

### 4.2 员工离职 / 密钥泄露：立即吊销

```bash
# 按用户：吊销台账中该用户所有序列号
ca-ssh/bin/20-revoke.sh --user alice

# 或精确到某个序列号 / 某张证书
ca-ssh/bin/20-revoke.sh --serial 1001
ca-ssh/bin/20-revoke.sh --cert /path/alice-cert.pub

# 只刷新 KRL，快速全网下发
ca-ssh/bin/40-deploy.sh --only-krl
```

即使不下发，短 TTL 证书也会在几小时内全部过期；KRL 是“立即生效”的开关。
吊销记录持久化在 `state/*.revocations`，KRL 可随时从该文件确定性重建。

### 4.3 紧急通道（break-glass）

紧急账号 `breakglass` 在每台标记 `breakglass=yes` 的机器上存在，且：

- 只信任 `breakglass-ca`，与日常 CA 物理隔离。
- principal 文件只有一行 `breakglass`。
- 模板里关闭 agent/tcp/X11 转发、隧道、网关端口，缩小滥用面。

签发紧急证书（短时、建议绑定来源 IP、走双人审批）：

```bash
ca-ssh/bin/10-sign-cert.sh --ca breakglass --user oncall-pager \
    --key bg.pub --groups breakglass --ttl 2h --source 203.0.113.10/32
ssh -i bg -o CertificateFile=bg-cert.pub breakglass@<host>
```

紧急证书的 principal 固定为裸 `breakglass`，无法用于任何普通账号。
紧急 CA 的每次签发都进入独立台账，便于事后审计。

## 5. CA 轮换

1. `00-init-ca.sh` 不会覆盖已有 CA；轮换时先在新目录生成新 CA 对。
2. 机器端 `TrustedUserCAKeys` 支持列出多个公钥（文件里多行）。
   先把新 CA 公钥追加下发，进入“新旧 CA 同时受信”的过渡期。
3. 用新 CA 重新签发，观察台账确认线上不再使用旧 CA 证书。
4. 从信任文件移除旧 CA 公钥并重新下发，归档（不要立即销毁）旧私钥。
5. breakglass CA 轮换流程相同，但应单独安排窗口并做一次真实登录演练。

## 6. 持续审计

```bash
ca-ssh/bin/50-audit.sh
```

核对每台机器：CA 指纹、KRL 校验和、principal 文件内容、`AuthorizedKeysFile none`
是否生效、紧急通道块是否只存在于授权主机，以及吊销状态与 KRL 是否一致。
任何一项不符即返回非零，适合接 CI 或定时告警。

## 7. 测试

`tests/e2e.sh` 用仓库自带源码编译的 `sshd` 在本地回环起两个实例，
覆盖：合法组登录、跨组拒绝、过期拒绝、裸公钥拒绝、紧急通道双向隔离、
KRL 吊销即时生效、source-address 约束。共 19 个断言。

```bash
make sshd ssh sshd-auth sshd-session sftp-server
ca-ssh/tests/e2e.sh
```

## 8. 关键安全注意

- CA 私钥是整个体系的根，必须离线、最小授权、加密备份、分片托管。
- 证书 TTL 要短；长期证书会抵消“离职自动失效”的核心价值。
- 不要给日常证书加 `breakglass` principal，也不要把两个 CA 混在同一信任块。
- `inventory/hosts.csv` 的改动要走代码评审，它等价于授权变更。
- 每次 `sshd -t` 失败都会自动回滚，但仍建议先 `--dry-run`、先灰度再全量。

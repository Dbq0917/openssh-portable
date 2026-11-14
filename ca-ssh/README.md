# ca-ssh — SSH 用户证书认证工具链

把跳板机/服务器上分散维护的 `authorized_keys` 换成 **SSH CA 集中签发的证书**：
按组（principal）控制能登录哪台机器，员工离职通过短 TTL + KRL 吊销收敛，
并保留一条与日常体系物理隔离的紧急（break-glass）通道。

本目录与 OpenSSH 源码同级，但**不修改 OpenSSH 本身**，只用其标准能力：
`TrustedUserCAKeys`、`AuthorizedPrincipalsFile`、`RevokedKeys`、证书 `principals`
与 `source-address` 选项、KRL。

## 一分钟理解

- 两台离线 CA：`user-ca`（日常）与 `breakglass-ca`（紧急），私钥独立。
- 员工证书携带 `group:<组名>` 和个人登录名，短期有效（默认 12h）。
- 每台机器的 `principals/<账号>` 文件声明本机接受哪些组，由 inventory 渲染下发。
- `AuthorizedKeysFile none` 让裸公钥彻底失效，只认证书。
- 离职 = 序列号进 KRL 并 `--only-krl` 下发，秒级全网封禁；证书本身也会很快过期。
- 紧急账号只信任 `breakglass-ca`，证书 principal 固定为 `breakglass`，双向隔离。

## 目录

| 路径 | 作用 |
|------|------|
| `bin/00-init-ca.sh` | 初始化两个 CA 与空 KRL |
| `bin/10-sign-cert.sh` | 签发证书（组、TTL、来源 IP、紧急通道） |
| `bin/20-revoke.sh` | 按用户/序列号/证书吊销并重建 KRL |
| `bin/30-render-principals.sh` | 从主机清单渲染每台机器的授权文件 |
| `bin/40-deploy.sh` | 下发信任材料，`sshd -t` 校验、失败自动回滚 |
| `bin/50-audit.sh` | 审计线上配置与清单/台账一致性 |
| `etc/sshd_config.d/10-ssh-ca.conf` | 服务器端配置模板 |
| `inventory/hosts.csv` | 主机与组授权的单一事实源 |
| `tests/e2e.sh` | 本地端到端认证矩阵测试（19 项断言） |
| `docs/runbook.md` | 架构、迁移、轮换、离职、紧急通道手册 |

## 快速上手（离线 CA 主机）

```bash
export CA_ROOT=/etc/ssh-ca
export CA_INVENTORY=$CA_ROOT/inventory/hosts.csv SSH_LOGIN_USER=ops

ca-ssh/bin/00-init-ca.sh                     # 1. 建 CA
$EDITOR ca-ssh/inventory/hosts.csv           # 2. 维护机器-组映射
ca-ssh/bin/30-render-principals.sh           # 3. 渲染授权
ca-ssh/bin/40-deploy.sh --host web-01        # 4. 灰度下发（先不删旧 key）
#    验证 OK 后：
ca-ssh/bin/40-deploy.sh --host web-01 --purge-authorized-keys
```

签发与吊销：

```bash
ca-ssh/bin/10-sign-cert.sh --user alice --key alice.pub --groups web --ttl 12h
ca-ssh/bin/20-revoke.sh --user alice
ca-ssh/bin/40-deploy.sh --only-krl
```

## 客户端（员工侧）

拿到 `alice`（私钥）和 `alice-cert.pub`（证书）后放入 `~/.ssh/`，
证书与私钥同名时 `ssh` 自动携带。也可在 `~/.ssh/config` 显式指定：

```
Host *.internal
    IdentityFile ~/.ssh/alice
    CertificateFile ~/.ssh/alice-cert.pub
    IdentitiesOnly yes
```

## 跑测试

```bash
make sshd ssh sshd-auth sshd-session sftp-server   # 用仓库源码编译本地 sshd
ca-ssh/tests/e2e.sh
```

预期输出 `passed: 19 failed: 0 / E2E OK`。测试使用非特权回环端口，
不需要 root，也不影响系统 sshd。

## 设计要点

- **双 CA 物理隔离**：日常证书无法登录紧急账号，紧急证书无法登录普通账号。
- **组名命名空间**：组成员统一写成 `group:<name>`，杜绝与真实登录名冲突。
- **确定性吊销**：KRL 从 `state/*.revocations` + 台账重建，可重复、可审计。
- **安全下发**：先 `.new` 暂存、`sshd -t` 校验、原子替换、失败自动回滚。
- **短 TTL 优先**：吊销是即时开关，过期是兜底，二者结合覆盖离职场景。

# 遗留 SSH 设备隔离接入方案

目标：让只支持 `diffie-hellman-group1-sha1` 和 `ssh-rsa` 的固定来源设备继续连接，
同时保证普通客户端只会看到现代算法，并让弱算法只存在于一个受网络 ACL 限制的
独立 `sshd` 实例中。

## 为什么不能只写一个 Match

OpenSSH 的 `KexAlgorithms`、`Ciphers`、`MACs` 和 `HostKeyAlgorithms` 是
`SSHCFG_GLOBAL`，不能在 `Match Address` 中覆盖；而且 KEX 和主机密钥算法在
用户认证前就已经协商完成。因此下面这种配置不会达到目的：

```text
Match Address 10.10.0.0/16
    KexAlgorithms +diffie-hellman-group1-sha1
```

必须把旧算法放进单独的 `sshd` 进程，再在网络层把白名单来源分流过去。

## 拓扑

```text
旧设备(固定源地址) --\
                      >-- 10.20.30.40:22 -- nftables DNAT --> 10.255.255.1:2222
新客户端 ------------/                                      legacy sshd
                                                            (仅 group1 + ssh-rsa)

新客户端 ------------------------------------------------> 10.20.30.40:22
                                                            modern sshd
                                                            (仅现代算法)
```

设备端仍然连接原来的 `10.20.30.40:22`，不需要改配置。只有
`legacy_src` 集合中的源地址会被 DNAT 到隔离实例。

## 文件

- `etc/ssh/sshd_config.d/10-modern-crypto.conf`：主 `sshd` 的现代算法白名单。
- `etc/ssh/sshd_config.legacy`：隔离实例配置，只允许旧设备所需算法。
- `etc/systemd/system/sshd-legacy.service`：隔离实例的 systemd 单元。
- `etc/nftables.d/ssh-legacy-split.nft`：按来源地址分流和旧端口防护。

模板中的以下值必须替换：

- `10.20.30.40`：服务器现有 SSH VIP。
- `eth0`：接收 SSH 连接的网卡。
- `10.255.255.1`：仅用于本机隔离实例的未使用地址。
- `10.10.0.0/16`：旧设备来源网段，越窄越好，优先按设备 IP 列集合。
- `legacy-collect`：旧设备登录账号。

如果旧设备使用 IPv6，需要为 `legacy_src` 增加 `ipv6_addr` 类型，并复制对应的
DNAT/filter 规则；不能把 IPv6 地址直接放进当前 IPv4 集合。

## 上线前确认

1. 用一台旧设备或同版本测试机执行 `ssh -vvv`，记录它实际协商的 KEX、主机密钥、
   cipher、MAC 和认证方式。只把真正需要的算法放进 legacy 配置。
2. 确认 `sshd -Q kex` 和 `sshd -Q key` 中包含所需算法。本方案的 group1 和
   `ssh-rsa` 需要 OpenSSL 支持，但默认不启用。
3. 继续使用服务器现有的 RSA 主机密钥，不要为了这次变更重建主机密钥，否则旧设备
   可能因 `known_hosts` 不匹配而拒绝连接。
4. 旧账号只允许公钥认证；如果设备只能密码认证，需单独评估并改用受控的 PAM
   策略，不能直接复用普通运维账号。
5. 在上游交换机/安全组同时限制旧设备网段只能访问该 SSH VIP，防止源地址伪造。

## 部署顺序

1. 安装新 `sshd` 和配置文件，先执行语法检查：

   ```bash
   sshd -t -f /etc/ssh/sshd_config.legacy
   sshd -t -f /etc/ssh/sshd_config
   ```

2. 给本机增加隔离地址：

   ```bash
   ip addr add 10.255.255.1/32 dev lo
   ```

   该地址应固化到网络配置中，不要依赖手工命令。

3. 启动隔离实例：

   ```bash
   systemctl daemon-reload
   systemctl enable --now sshd-legacy
   ss -ltnp | grep -E ':(22|2222)\b'
   ```

   可以用下面的命令确认实际生效的算法，而不是只看配置文件：

   ```bash
   sshd -T -f /etc/ssh/sshd_config.legacy |
       grep -E '^(kexalgorithms|hostkeyalgorithms|pubkeyacceptedalgorithms|ciphers|macs) '
   ```

4. 先只把一台测试设备 IP 加入 `legacy_src`，加载 nftables 规则，验证新连接会落到
   legacy 实例，而普通客户端仍然只看到现代算法。

5. 按设备批次扩大 `legacy_src`。不要周期性重启设备；设备下一次自然重连时会走新
   路径。

6. 旧设备不再从主 `sshd` 建立新连接后，从主配置移除任何临时弱算法，然后执行：

   ```bash
   systemctl reload ssh
   ```

   必须使用 `reload`，不要 `restart` 或重启机器。

## 长连接如何处理

- `sshd` 的 `SIGHUP`/`systemctl reload` 只影响监听进程和后续新连接，已经建立的
  session 子进程不会被杀掉。
- nftables 的 NAT 只对连接首包生效。新增 DNAT 规则不会改写已有 conntrack 会话，
  因此旧的长连接会继续留在原进程上。
- 已经建立在主 `sshd` 上的旧会话不会被强制迁移；它们会在原有进程上继续运行并
  使用原协商参数完成后续 rekey，直到自然断开。新连接则全部进入 legacy 实例。
- 因此可以在不断开现有采集连接的前提下，先把主 `sshd` 的新连接入口切走，再用
  `reload` 收紧主配置。若要求“立即把所有活动会话迁走”，SSH 协议本身无法做到，
  只能安排现场维护窗口重连。
- 不要执行 `conntrack -F`、重启整机或 `systemctl restart ssh`，这些会使现有会话
  立即中断。

## 审计口径

建议把 legacy 实例定义为“隔离 enclave”，而不是主 SSH 服务的一部分：

- 主 `sshd` 使用显式现代算法白名单，新客户端不会看到旧算法。
- legacy 实例只监听内部地址，入口仅允许固定设备网段，且只能由指定账号公钥登录。
- 使用独立日志、独立 pid、独立 systemd 单元和独立监听端口；资源上限可单独设置。
- 记录设备清单、来源网段、负责人和退役日期；每季度复核 `legacy_src`。
- 旧设备退役后删除对应 IP、账号、nftables 集合成员，最后停止 legacy 实例。

如果安全基线要求“任何进程都不得提供旧算法”，则该要求与“固件不可升级的旧设备
仍要连接”在技术上互斥。此时唯一的选择是更换设备，或增加一个专门做协议终止的
隔离网关；后者仍然在网关内保留旧算法，只是把风险范围缩到最小。

如果同一台生产机上的隔离实例仍不能过审，把 `sshd-legacy` 放到独立的小型 VM 或
容器中，nftables 的 DNAT 目标改为该 VM/容器地址；主机的现代 `sshd` 和业务数据
面不需要出现任何旧算法。

## 回滚

1. 从 `legacy_src` 删除测试网段，或删除 DNAT 规则。
2. `systemctl stop sshd-legacy`。
3. 主 `sshd` 的现代算法配置不需要回滚；旧设备在回滚后会暂时无法连接。

回滚不会恢复已经断开的旧会话。

# Komari Agent Installer
- **主要功能**：自动准备依赖、自动守护更新、写入配置、启用 systemd 或 cron 监管，并支持远程配置的自动定时同步。
- **适用环境**：支持 systemd、OpenRC/cron，CPU 架构覆盖 `x86_64` 与 `arm64`。
- **支持系统**：Ubuntu/Debian/CentOS/AlmaLinux/Rocky/Fedora/Alpine

## 使用方法

* 确保当前用户具备 `root` 权限
* 使用配置文件：
   - `bash <(curl -sL komari.app) -c config.json`
   - `bash <(curl -sL komari.app) -c <URL>`
* 使用自动发现或者指定TOKEN：
   - `bash <(curl -sL komari.app) -e <URL> -a <KEY>`
   - `bash <(curl -sL komari.app) -e <URL> -t <TOKEN>`
* 使用远程配置文件 + 自动同步（每 10 分钟）：
   - `bash <(curl -sL komari.app) -e <URL> --auto 10`

## 参数说明

| 参数 | 说明 |
| --- | --- |
| `-c <path\|url>` | 本地配置文件路径或远程配置文件链接 |
| `-a <value>` | 自动发现 KEY |
| `-t <value>` | 指定节点 TOKEN |
| `-e <url>` | 指定 `endpoint`，需为可访问 URL |
| `--auto [min\|d]` | 启用/禁用自动配置同步，`d` 代表关闭|
| `--debug` | 输出调试信息 |
| `-log` | 服务状态和最近日志|
| `-u` | 卸载脚本生成的所有内容 |

### 安装目录结构

```
/opt/komari-agent/
├── bin/komari-agent          # 二进制 (root:komari 750)
├── config.json               # 配置文件 (komari:komari 600)
├── logs/komari-agent.log     # 运行日志
└── run/
    ├── komari-wrapper.sh     # 进程管理包装脚本
    └── auto-update.conf      # 自动同步配置
```
### 常用操作

```bash
# 服务状态（systemd 系统）
sudo systemctl status komari-agent

# 服务状态（Alpine）
sudo rc-service komari-agent status

# 查看实时日志
sudo bash kai.sh -log

# 卸载所有内容
sudo bash kai.sh -u
```

## 默认配置文件说明

| 配置文件 Key (`json`) | 类型 | 说明 |
| :--- | :--- | :--- |
| `endpoint` | `string` | **必填**。面板连接地址 (格式 `host:port`，如 `dashboard.example.com:5555`) |
| `token` | `string` | **必填**。Agent 通信密钥 |
| `auto_discovery_key` | `string` | 自动发现密钥（用于未在面板手动添加服务器时自动注册） |
| `ignore_unsafe_cert` | `bool` | 是否忽略 SSL/TLS 证书验证（用于自签名证书） |
| `max_retries` | `int` | 连接断开后的最大重试次数 |
| `reconnect_interval` | `int` | 重连等待间隔（秒） |
| `interval` | `float64` | 性能数据（CPU/内存等）采集上报间隔（秒） |
| `info_report_interval` | `int` | 基础主机信息（系统版本/IP）上报间隔（分钟） |
| `enable_gpu` | `bool` | 启用 GPU 状态监控（支持 NVIDIA 等显卡） |
| `host_proc` | `string` | 宿主机 `/proc` 挂载路径（Docker 模式下设置为 `/host/proc` 以获取宿主机真实负载） |
| `memory_include_cache` | `bool` | 统计内存占用时是否包含 Cache/Buffer |
| `memory_report_raw_used` | `bool` | 使用原始公式计算内存 (`Total - Free - Buffers - Cached`) |
| `disable_web_ssh` | `bool` | **重要**。禁用 Web SSH 终端和远程命令执行功能 |
| `disable_auto_update` | `bool` | 禁用 Agent 自动更新功能 |
| `cf_access_client_id` | `string` | Cloudflare Access ID（用于穿透 Cloudflare Zero Trust 防护） |
| `cf_access_client_secret` | `string` | Cloudflare Access Secret |
| `include_nics` | `string` | 网卡**白名单**。仅统计此列表中的网卡（逗号分隔，支持通配符 `*`） |
| `exclude_nics` | `string` | 网卡**黑名单**。统计时排除此列表中的网卡（逗号分隔，支持通配符 `*`） |
| `month_rotate` | `int` | 流量统计的月度重置日期（1-31），设置为 `0` 表示禁用自动重置 |
| `custom_dns` | `string` | 强制指定 DNS 服务器（格式 `IP:Port`，如 `1.1.1.1:53`） |
| `custom_ipv4` | `string` | 自定义上报的 IPv4 地址（覆盖自动探测结果） |
| `custom_ipv6` | `string` | 自定义上报的 IPv6 地址 |
| `get_ip_addr_from_nic` | `bool` | 是否直接从网卡接口获取 IP，而不是通过外部 API 探测 |
| `include_mountpoints` | `string` | 磁盘统计的包含挂载点列表，使用分号分隔 |

## 来源

https://github.com/komari-monitor/komari-agent/

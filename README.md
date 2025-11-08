# Komari Agent Install

- **主要功能**：自动准备依赖、下载最新二进制、写入配置、启用 systemd 用户服务或 cron 监管，并支持远程配置的自动定时同步。
- **适用环境**：Linux 用户态安装，支持 systemd、OpenRC/cron，CPU 架构覆盖 `x86_64` 与 `aarch64`。

## 使用方法

* 确保当前用户具备 `sudo` 权限（安装缺失依赖时会提示输入密码）。
* 使用配置文件：
   - `bash <(curl -sL komari.app) -c config.json`
   - `bash <(curl -sL komari.app) -c <URL>`
* 使用自动发现或者指定TOKEN：
   - `bash <(curl -sL komari.app) -e <URL> -a <KEY>`
   - `bash <(curl -sL komari.app) -e <URL> -t <TOKEN>`

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

## 常见操作
- **更新配置后重启**：脚本会在配置变更后自动重启，无需手动操作。
- **查看服务状态**：`systemctl --user status komari-agent`
- **查看日志**：`bash kai.sh -log`
- **卸载**：`bash kai.sh -u`

> 提示：在非 systemd 环境（如 Alpine）下，脚本会自动写入定时任务并启动 `crond`，请确保系统允许用户级 cron 运行。

# NetTool

NetTool 是一个多功能网络监控和转发工具，用于跟踪和管理网络事件，例如 TCP 状态变化、RTT 统计、连接延迟、UDP 带宽、UDP拥塞事件、套接字重定向和 XDP 规则转发。它基于 eBPF 提供高性能、低开销的网络监控和管理。

## 功能

- **TCP 状态变化**：跟踪 TCP 状态转换。
- **TCP RTT 统计**：监控 TCP 往返时间 (RTT)，支持扩展统计。
- **TCP 连接延迟**：测量 TCP 连接的延迟。
- **UDP 带宽**：跟踪 UDP 带宽使用情况。
- **UDP 拥塞**：检测和分析 UDP 拥塞事件。
- **套接字重定向**：在套接字之间重定向流量。
- **XDP 转发**：使用 XDP 规则管理和转发流量。

## 安装

### 先决条件

- Linux 内核版本 5.4 或更高，支持 eBPF。
- 用于编译 eBPF 程序的 `clang` 和 `llvm`。
- 已安装 `libbpf` 库。
- 加载 eBPF 程序需要 root 权限。

### 构建步骤

1. 克隆仓库：
   ```bash
   git clone https://github.com/zzxscodes/nettool.git
   cd nettool-main
   ```

2. 构建项目：
   ```bash
   sudo make #or root
   ```

## 使用方法

### 命令行选项

使用以下选项运行 `nettool`：

```bash
nettool [--mode=MODE] [OPTIONS]
```

#### 模式

- `tcpstates`：跟踪 TCP 状态变化。
- `tcprtt`：跟踪 TCP RTT 统计。
- `tcpconnlat`：跟踪 TCP 连接延迟。
- `udpbandwidth`：跟踪 UDP 带宽使用情况。
- `udpcongest`：跟踪 UDP 拥塞事件。
- `sockredirect`：在套接字之间重定向流量。
- `xdpforward`：使用 XDP 规则管理和转发流量。

#### 选项

| 选项                     | 描述                                                                         |
|--------------------------|------------------------------------------------------------------------------|
| `-m, --mode=MODE`        | 设置工具模式（例如 `tcpstates`、`tcprtt` 等）。                              |
| `-v, --verbose`          | 启用详细调试输出。                                                           |
| `-T, --timestamp`        | 在输出中包含时间戳（适用于 `tcpstates` 模式）。                              |
| `-4, --ipv4`             | 仅跟踪 IPv4 家族（适用于 `tcpstates` 模式）。                                |
| `-6, --ipv6`             | 仅跟踪 IPv6 家族（适用于 `tcpstates` 模式）。                                |
| `-L, --localport=LPORT`  | 跟踪特定本地端口（适用于 `tcpstates` 模式）。                                |
| `-D, --remoteport=DPORT` | 跟踪特定远程端口（适用于 `tcpstates` 模式）。                                |
| `--ms`                   | 以毫秒显示 RTT（适用于 `tcprtt` 模式）。                                     |
| `--ext`                  | 显示扩展统计信息（适用于 `tcprtt` 模式）。                                   |
| `--min=MINUS`            | 最小延迟（以微秒为单位，适用于 `tcpconnlat` 模式）。                         |
| `--pid=PID`              | 跟踪特定 PID（适用于 `tcpconnlat` 模式）。                                   |
| `--udpport=PORT`         | 跟踪特定 UDP 端口（适用于 `udpbandwidth` 和 `udpcongest` 模式）。             |
| `-c, --conf=FILE`        | `xdpforward` 模式的配置文件路径（默认：`./conf/rules.conf`）。                |

### 示例

#### 跟踪 TCP 状态变化
```bash
sudo nettool --mode=tcpstates -v
```

#### 使用扩展统计监控 TCP RTT
```bash
sudo nettool --mode=tcprtt --ms --ext
```

#### 测量特定 PID 的 TCP 连接延迟
```bash
sudo nettool --mode=tcpconnlat --pid=1234
```

#### 跟踪特定端口的 UDP 带宽
```bash
sudo nettool --mode=udpbandwidth --udpport=8080
```

#### 管理 XDP 转发规则
```bash
sudo nettool --mode=xdpforward -c /path/to/rules.conf
```

## XDP 转发的配置文件

`xdpforward` 模式的配置文件应包含以下格式的规则：

```
<source_ip> <destination_ip> <source_port> <destination_port> <protocol> <priority> <action>
```

- `<source_ip>` 和 `<destination_ip>`：IP 地址（使用 `*` 表示通配符）。
- `<source_port>` 和 `<destination_port>`：端口号（使用 `*` 表示通配符）。
- `<protocol>`：`tcp`、`udp` 或 `*` 表示通配符。
- `<priority>`：规则优先级（值越高优先级越高）。
- `<action>`：`0` 表示丢弃，`1` 表示转发。

示例：
```
192.168.1.1 192.168.1.2 80 443 tcp 10 1
* * * * udp 5 0
```

## 支持

如有问题或功能请求，请在 [GitHub](https://github.com/zzxscodes/nettool) 上提交 Issue。


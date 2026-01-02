sendpkt  — Interactive Raw Packet Generator & Sender

sendpkt 是一个基于 Linux + C 语言 + Raw Socket 的交互式网络报文构造与发送工具。
它通过 JSON preset 配置文件 描述一个完整的网络帧（Ethernet → VLAN → IPv4 → TCP/UDP → Payload），允许用户在交互过程中逐字段修改，最终将报文：

通过 AF_PACKET（二层，指定目的 MAC）

或 AF_INET + IP_HDRINCL（三层）

真实发送到网络，
或在 dry-run 模式 下导出为 pcap 文件，供 Wireshark 离线分析。

一、核心能力概览
1. 协议层支持

L2

Ethernet II

可选 VLAN（802.1Q）

L3

IPv4

DSCP / ECN

Flags（DF / MF）

Fragment Offset

自动分片（按 MTU）

IP Options（NOP / EOL / RR / TS 等）

L4

UDP

TCP

Seq / Ack

Flags（SYN / ACK / FIN / RST / PSH / URG）

TCP Options（MSS / WS / SACK_PERM / TS / NOP / EOL）

Payload

任意字符串或二进制数据（当前为字符串）

2. 发送能力

AF_PACKET（L2 原始发送）

使用 sockaddr_ll

自动将 目的 MAC 写入 sll_addr

sendto 时显式指定目标 MAC

AF_INET（L3 原始发送）

IP_HDRINCL

发送控制

发送次数

发送间隔（秒）

自动重发

3. 自动 IP 分片

当启用：

"layers.fragment.fields.auto_fragment.default": true


按 MTU 自动切分 payload

Fragment Offset 单位为 8 字节

MF 位自动设置

第一个分片包含 L4 Header

后续分片仅包含 IP Header + Data

自动重新计算 IP / UDP / TCP 校验和

4. Dry-run / PCAP 导出
"layers.send.fields.dry_run.default": true


不发送任何报文

生成 sendpkt_out.pcap

可直接用 Wireshark 打开验证：

Ethernet / VLAN

IP Header & Options

Fragment

TCP / UDP / Options

二、工程结构
sendpkt_v2/
├── Makefile
├── README.md
├── preset_full.json      # 完整网络帧 preset（核心）
├── main.c                # 程序入口（交互 + 流程控制）
├── builder.c             # 报文构造（含 options / fragment）
├── builder.h
├── sender.c              # 报文发送（AF_PACKET / AF_INET / pcap）
├── sender.h
├── json_util.c           # JSON 路径访问封装
├── json_util.h
├── utils.c               # checksum / MAC 解析等工具
├── utils.h
├── cJSON.c               
└── cJSON.h               

并修改 Makefile 使用系统库。

三、编译与运行
1. 编译
make


生成：

sendpkt

2. 运行（需要 root）
dry-run（推荐先用）
sudo ./sendpkt preset_full.json


生成：

sendpkt_out.pcap


用 Wireshark 打开验证。

实际发送

确保：

"layers.send.fields.dry_run.default": false


并选择后端：

"layers.send.fields.backend.default": "af_packet"


然后：

sudo ./sendpkt preset_full.json

四、JSON preset 设计理念
1. preset 的职责

唯一真实来源

描述：

每一层是否存在

字段格式说明

默认值

CLI 交互 仅修改内存中的 frame

不回写 JSON（符合你的需求）

2. JSON 访问方式

统一通过：

json_get_string(config, "layers.ip.fields.src_ip.default", "x.x.x.x");
json_get_int(...)
json_get_bool(...)
json_get_node_by_path(...)


支持任意层级扩展，不影响现有代码。

五、关键实现说明（设计重点）
1. AF_PACKET + 目标 MAC
addr.sll_family  = AF_PACKET;
addr.sll_ifindex = if_nametoindex(iface);
addr.sll_halen   = ETH_ALEN;
memcpy(addr.sll_addr, eth_hdr->ether_dhost, 6);

sendto(sock, packet, len, 0,
       (struct sockaddr *)&addr, sizeof(addr));


✔ 不依赖 kernel 自动 ARP
✔ 明确二层语义
✔ 可用于测试交换机 / 网卡行为

2. IP / TCP Options 编码

JSON → 字节流

自动 4 字节对齐

自动更新：

ip->ihl

tcp->doff

3. Fragment Buffer 内部格式（设计约定）
[ uint32_t fragment_count ]
[ uint32_t len_0 ][ packet_0 bytes ]
[ uint32_t len_1 ][ packet_1 bytes ]
...


优点：

builder 与 sender 解耦

sender 不关心“是否分片”

同一接口支持单包 / 多包

六、适用场景

协议栈 / 网络设备测试

防火墙 / IDS / IPS 行为验证

TCP/IP 选项、分片边界条件测试

教学 / 学习 TCP/IP 协议

抓包工具或发包工具的底层引擎

七、测试方法：

见test.md

八、后续可扩展方向

IPv6

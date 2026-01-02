sendpkt  — Interactive Raw Packet Generator & Sender

sendpkt 是一个基于 Linux + C 语言 + Raw Socket 的交互式网络报文构造与发送工具。

它通过 JSON preset 配置文件 描述一个完整的网络帧（Ethernet → VLAN → IPv4 → TCP/UDP → Payload），允许用户在交互过程中逐字段修改，最终将报文：
通过 AF_PACKET（二层，指定目的 MAC）或 AF_INET + IP_HDRINCL（三层）真实发送到网络，或在 dry-run 模式 下导出为 pcap 文件，供 Wireshark 离线分析。

工程结构
sendpkt/
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

详细介绍：
README_1

测试方法：
test

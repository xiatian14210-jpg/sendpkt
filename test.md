1. 创建一个测试接口（推荐：dummy 接口，易于观察且不影响真实网卡）

在 Linux 上我们可以创建一个 dummy0 虚拟网卡并给它一个测试 IP，用于发送与抓包。

# 以 root 执行：
sudo ip link add dummy0 type dummy
sudo ip addr add 192.168.100.1/24 dev dummy0
sudo ip link set dummy0 up

# 验证
ip addr show dev dummy0
# 你应当看到 dummy0 上有 192.168.100.1


解释：dummy0 是虚拟网卡，能接收与发送帧，但不会影响真实网络，适合造包/抓包实验。

2. 打开抓包窗口，准备捕获报文

在一个独立终端窗口运行 tcpdump（或你喜欢的 Wireshark）。我演示用 tcpdump 将数据写到 capture.pcap，也可实时查看。

# 在另一个终端（也要 root）
sudo tcpdump -i dummy0 -s 0 -w capture.pcap
# 这个命令会阻塞在终端，保持运行以捕获发送的包。
# -s 0 保证抓取完整包，-w 写 pcap 文件。


解释：tcpdump -w capture.pcap 会捕获所有到 dummy0 的帧并写入文件，之后可以用 wireshark/tshark/tcpdump -r 查看。

3. 启动 sendpkt（REPL）并做第一次 dry-run（仅生成 pcap，不发送到网络）

我们先以 dry-run 模式验证构造的帧（包括 L2/L3/L4、options、分片方案等），程序会把结果写入 sendpkt_out.pcap（或在控制台中提示路径）。

# 在项目目录下（假设二进制为 ./sendpkt）
sudo ./sendpkt preset_full.json


程序启动后会进入交互命令行（sendpkt>）。下面我给出一个从头到尾的、逐项的示例操作（你可以直接复制粘贴命令到 REPL）：

（A）将后端设置为 AF_PACKET，这样我们可以控制与观察 MAC

在 REPL 中：

sendpkt> set layers.send.fields.backend.default af_packet


（提示：这条 set 把 JSON 中 layers.send.fields.backend.default 字符串改为 "af_packet"。）

（B）设置接口为 dummy0
sendpkt> set layers.send.fields.iface.default dummy0

（C）设置目标 MAC 与源 MAC（示例）
sendpkt> set layers.ethernet.fields.dst_mac.default aa:bb:cc:dd:ee:ff
sendpkt> set layers.ethernet.fields.src_mac.default 00:11:22:33:44:55

（D）设置 IP（src/dst）与传输层（举例用 UDP）
sendpkt> set layers.ip.fields.src_ip.default 192.168.100.2
sendpkt> set layers.ip.fields.dst_ip.default 192.168.100.3
sendpkt> set layers.transport_choice.default udp


说明：即使 dummy0 在主机上只有 192.168.100.1，我们仍然可以发送任意 src IP — 这是造包工具的常见用法，实际发送时 L2 层会被注入到接口上，不会影响 host 路由。（但在一些系统或网络策略下，内核可能有额外过滤）

（E）设置 payload 和次数，并开启 dry-run
sendpkt> set layers.payload.fields.data.default "Hello_from_test"
sendpkt> set layers.send.fields.count.default 1
sendpkt> set layers.send.fields.dry_run.default true

（F）执行 send（dry-run）
sendpkt> send


预期行为：程序不会实际 sendto() 网络接口，而是把构造的包（或多个分片）写成 sendpkt_out.pcap（在项目目录）。程序会打印 Wrote pcap: sendpkt_out.pcap 或类似提示。

4. 验证 dry-run 输出（pcap 文件）

在终端中用 tshark 或 tcpdump 查看 pcap 内容（更直观使用 Wireshark 打开 GUI）：

# 使用 tcpdump 快速查看
tcpdump -nn -r sendpkt_out.pcap -vv

# 或用 tshark 显示详细解析
tshark -r sendpkt_out.pcap -V


你应该看到：

如果使用 af_packet：PCAP 中会包含以太网帧，字段显示 Ethernet II, Src: 00:11:22:33:44:55, Dst: aa:bb:cc:dd:ee:ff。

IP 层：源/目的 IP 与你设定的一致（192.168.100.2 -> 192.168.100.3）。

传输层：如果 UDP，看到 UDP header；如果 TCP 有 options，tshark 会列出 TCP options（MSS/WS/TS 等）。

如果 fragment.auto_fragment = false，则只有一个 IP 包；如果 auto fragment = true（下面讲如何测试），pcap 中会看到多个 IP 分片（tshark 会标记“[Fragments]”或者显示 MF flag 与 fragment offset）。

如果你在 Wireshark 中打开 sendpkt_out.pcap，也可以用 GUI 检查 IP options 和 TCP options 的字节编码是否正确。

5. 实际发送（非 dry-run）：用 AF_PACKET 发帧并在 tcpdump 中捕获

先回到之前专门运行 tcpdump 捕获 dummy0 的终端（如果你刚才没有开启，请打开一个新终端运行 sudo tcpdump -i dummy0 -s 0 -w capture.pcap）

在 sendpkt REPL 中把 dry_run 设为 false 并 send：

sendpkt> set layers.send.fields.dry_run.default false
sendpkt> send


程序会调用 AF_PACKET 并把帧逐个发到 dummy0。发送完成，停止 tcpdump（Ctrl+C），然后分析 capture.pcap：

# 使用 tshark
tshark -r capture.pcap -V
# 或
tcpdump -nn -r capture.pcap -vv


检查点：

L2: 目标 MAC 与你在 JSON 中设置的 aa:bb:cc:dd:ee:ff 一致（这证明 sockaddr_ll.sll_addr 被正确填充）。
L3/L4: IP 和 UDP/TCP 字段正确（src/dst、ports、checksums 等）。
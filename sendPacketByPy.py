import socket
import struct
import os
import argparse

# 版本+IHL(1字节), DSCP(1字节), 总长度(2字节), 标识(2字节), 标志+片偏移(2字节),
# 生存时间(1字节), 协议(1字节), 头校验和(2字节), 源IP(4字节), 目标IP(4字节)
IP_HEADER_FMT = '!BBHHHBBH4s4s'
# 版本+DSCP+流标签(4字节), 载荷长度(2字节), next_header(1字节), 跳数限制(1字节)
# 源ip(16字节), 目的ip(16字节)
IP6_HEADER_FMT = '!4sHBB16s16s'
# 源端口(2字节), 目标端口(2字节), 长度(2字节), 校验和(2字节)
UDP_HEADER_FMT = '!HHHH'
# 源端口(2字节), 目的端口(2字节), 序列号(4字节), 确认号(4字节), 头部长度+标志(2字节)
# 窗口大小(2字节), 校验和(2字节), 紧急指针(2字节)
TCP_HEADER_FMT = '!HH4s4sHHHH'


def checksum(source_string):
    """
    计算校验和，这是IP和UDP头中必要的字段。
    这个实现是简化的，并不完全符合RFC的规范。
    """
    check_sum = 0
    max_count = (len(source_string) // 2) * 2
    for count in range(0, max_count, 2):
        this_val = source_string[count + 1] * 256 + source_string[count]
        check_sum = check_sum + this_val
        check_sum = check_sum & 0xffffffff
    if max_count < len(source_string):
        check_sum = check_sum + source_string[len(source_string) - 1]
        check_sum = check_sum & 0xffffffff
    check_sum = (check_sum >> 16) + (check_sum & 0xffff)
    check_sum = check_sum + (check_sum >> 16)
    answer = ~check_sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def create_udp_packet(cus_version, cus_src_ip, cus_dst_ip, cus_src_port, cus_dst_port, cus_data):
    four_header_len = 8
    four_proto_num = 17
    ip_header = struct.Struct('')
    if cus_version == 4:
        ip_header = struct.pack(IP_HEADER_FMT,
                                0x45,  # 版本+IHL(1字节)
                                0x00,  # DSCP(1字节)
                                20 + four_header_len + len(cus_data),  # 总长度（IP头+四层头+数据）
                                54321,  # 标识(用于标识数据包被分片后是否是同一个数据包)
                                0,  # 标志
                                64,  # 生存时间
                                four_proto_num,  # 协议（UDP）
                                0,  # 头校验和（稍后计算）
                                socket.inet_aton(cus_src_ip),  # 源IP
                                socket.inet_aton(cus_dst_ip)  # 目的IP
                                )
        ip_checksum = checksum(ip_header)
        ip_header = struct.pack(IP_HEADER_FMT,
                                0x45,  # 版本+IHL(1字节)
                                0x00,  # DSCP(1字节)
                                20 + four_header_len + len(cus_data),  # 总长度（IP头+四层头+数据）
                                54321,  # 标识(用于标识数据包被分片后是否是同一个数据包)
                                0,  # 标志
                                64,  # 生存时间
                                four_proto_num,  # 协议（UDP）
                                ip_checksum,  # 头校验和（稍后计算）
                                socket.inet_aton(cus_src_ip),  # 源IP
                                socket.inet_aton(cus_dst_ip)  # 目的IP
                                )
    udp_len = 8 + len(cus_data)
    # udp头部
    four_header = struct.pack(UDP_HEADER_FMT,
                              cus_src_port,
                              cus_dst_port,
                              udp_len,  # 长度（UDP头+数据）
                              0  # 校验和（稍后计算）
                              )
    # 合并IP头和UDP头（不包括UDP的校验和数据部分）
    pseudo_header = (socket.inet_aton(cus_src_ip) + socket.inet_aton(cus_dst_ip) +
                     int.to_bytes(four_proto_num, 2, 'big') +
                     int.to_bytes(udp_len, 2, 'big') + four_header)

    # 计算UDP校验和
    udp_checksum = checksum(pseudo_header + cus_data.encode())
    four_header = struct.pack(UDP_HEADER_FMT,
                              cus_src_port,
                              cus_dst_port,
                              udp_len,  # 长度（UDP头+数据）
                              udp_checksum  # 校验和（稍后计算）
                              )
    # 合并IP头和UDP头+数据
    cus_packet = ip_header + four_header + cus_data.encode()
    return cus_packet


def create_tcp_packet(cus_version, cus_src_ip, cus_dst_ip, cus_src_port, cus_dst_port, cus_data):
    four_header_len = 20
    four_proto_num = 6
    ip_header = struct.Struct('')
    if cus_version == 4:
        ip_header = struct.pack(IP_HEADER_FMT,
                                0x45,  # 版本+IHL(1字节)
                                0x00,  # DSCP(1字节)
                                20 + four_header_len + len(cus_data),  # 总长度（IP头+四层头+数据）
                                54321,  # 标识(用于标识数据包被分片后是否是同一个数据包)
                                0,  # 标志
                                64,  # 生存时间
                                four_proto_num,  # 协议（TCP）
                                0,  # 头校验和（稍后计算）
                                socket.inet_aton(cus_src_ip),  # 源IP
                                socket.inet_aton(cus_dst_ip)  # 目的IP
                                )
        ip_checksum = checksum(ip_header)
        ip_header = struct.pack(IP_HEADER_FMT,
                                0x45,  # 版本+IHL(1字节)
                                0x00,  # DSCP(1字节)
                                20 + four_header_len + len(cus_data),  # 总长度（IP头+四层头+数据）
                                54321,  # 标识(用于标识数据包被分片后是否是同一个数据包)
                                0,  # 标志
                                64,  # 生存时间
                                four_proto_num,  # 协议（UDP）
                                ip_checksum,  # 头校验和（稍后计算）
                                socket.inet_aton(cus_src_ip),  # 源IP
                                socket.inet_aton(cus_dst_ip)  # 目的IP
                                )
    # tcp头部  0010 1000
    four_header = struct.pack(TCP_HEADER_FMT,
                              cus_src_port,
                              cus_dst_port,
                              int.to_bytes(1, 4, 'big'),  # 序列号
                              int.to_bytes(1, 4, 'big'),  # 确认号
                              0x5002,  # 头部长度+标志
                              3000,  # 窗口大小
                              0,  # 校验和（稍后计算）
                              0  # 紧急指针
                              )
    tcp_len = four_header_len + len(cus_data)
    # 合并IP头和UDP头（不包括UDP的校验和数据部分）
    pseudo_header = (socket.inet_aton(cus_src_ip) + socket.inet_aton(cus_dst_ip) +
                     int.to_bytes(four_proto_num, 2, 'big') +
                     int.to_bytes(tcp_len, 2, 'big') + four_header)
    # 计算TCP校验和
    tcp_checksum = checksum(pseudo_header + cus_data.encode())
    four_header = struct.pack(TCP_HEADER_FMT,
                              cus_src_port,
                              cus_dst_port,
                              int.to_bytes(1, 4, 'big'),  # 序列号
                              int.to_bytes(1, 4, 'big'),  # 确认号
                              0x5002,  # 头部长度+标志
                              3000,  # 窗口大小
                              tcp_checksum,  # 校验和（稍后计算）
                              0  # 紧急指针
                              )
    # 合并IP头和TCP头+数据
    cus_packet = ip_header + four_header + cus_data.encode()
    return cus_packet


def create_packet(cus_version, cus_four_proto, cus_src_ip, cus_dst_ip, cus_src_port, cus_dst_port, cus_data):
    if cus_four_proto == "udp":
        return create_udp_packet(cus_version, cus_src_ip, cus_dst_ip,
                                 cus_src_port, cus_dst_port, cus_data)
    elif cus_four_proto == "tcp":
        return create_tcp_packet(cus_version, cus_src_ip, cus_dst_ip,
                                 cus_src_port, cus_dst_port, cus_data)


def send_packet(cus_packet, cus_dst_ip):
    # 创建一个原始套接字
    try:
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except PermissionError:
        print("你需要管理员权限来发送原始套接字报文。")
        return

    try:
        # 发送报文
        raw_socket.sendto(cus_packet, (cus_dst_ip, 0))  # 端口号对于原始套接字来说不重要
        print("报文已发送。")
    except Exception as e:
        print(f"发送报文时出错：{e}")
    finally:
        raw_socket.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser("sendPacketByPy: python sendPacketByPy.py")
    parser.add_argument("-version", type=int, nargs='+', required=True, default=4,
                        help="版本IPV4/IPV6")
    parser.add_argument("-four_proto", type=str, nargs='+', required=True, default='udp',
                        help="传输层协议UDP/TCP")
    arges = parser.parse_args()
    version = arges.version[0]
    four_proto = arges.four_proto[0]
    src_ip = "192.168.1.100"  # 源IP地址（需要根据你的实际情况修改）
    dst_ip = "192.168.147.1"  # 目标IP地址
    src_port = 12345  # 源端口
    dst_port = 54321  # 目标端口
    data = "Hello, UDP!"  # 要发送的数据
    packet = create_packet(version, four_proto, src_ip, dst_ip, src_port, dst_port, data)
    send_packet(packet, dst_ip)

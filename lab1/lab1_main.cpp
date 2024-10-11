#include <iostream>
#include <pcap.h>
#include <cstring>
#include <cstdlib>
#include <iomanip>
#include <ctime>

using namespace std;

#define _WINSOCK_DEPRECATED_NO_WARNINGS // 禁止编译器显示与 Winsock / WIN API 相关的特定警告信息
#define _CRT_SECURE_NO_WARNINGS         // 禁止编译器在编译过程中发出关于可能存在安全风险的函数警告

// 定义帧头结构
struct EthernetHeader {
    u_char dest_mac[6];
    u_char src_mac[6];
    u_short ether_type;
};

// 定义IP头结构
struct ip_header {
    uint8_t ip_header_length : 4,          // 头部长度（Header Length）：指示IP头部的长度。
            ip_version : 4;                // 版本（Version）：指示IP协议的版本（IPv4或IPv6）。

    uint8_t ip_tos;                        // 服务类型（Type of Service, ToS）：指示数据包的优先级和服务质量。
    uint16_t total_len;                    // 总长度（Total Length）：指示整个IP数据包的长度，包括头部和数据部分。
    uint16_t ip_id;                        // 标识（Identification）：用于唯一标识数据包，特别是在数据包分片时。
    uint16_t ip_off;                       // 片偏移（Fragment Offset）：指示数据包分片的位置。
    uint8_t ip_ttl;                        // 生存时间（Time to Live, TTL）：指示数据包在网络中的生存时间，防止数据包无限循环。
    uint8_t ip_protocol;                   // 协议（Protocol）：指示数据包携带的上层协议（如TCP、UDP）。
    uint16_t ip_checksum;                  // 头部校验和（Header Checksum）：用于校验IP头部的完整性。
    struct in_addr ip_source_address;      // 源IP地址
    struct in_addr ip_destination_address; // 目的IP地址
};

// 打印 MAC 地址
void print_mac_address(const u_char* mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02x", mac[i]);
        if (i < 5)
            cout << ":";
    }
    cout << endl;
}

// 打印IP头部信息
void print_ip_header(const ip_header* iph) {
    //cout << "IP Version: " << (int)iph->ip_version << endl;
    cout << "IP Version: " << (int)iph->ip_version << "(";
    switch ((int)iph->ip_version) {
    case 4:
        cout << "IPv4";
        break;
    case 6:
        cout << "IPv6";
        break;
    default:
        break;
    }
    cout << ")" << endl;
    cout << "IP Header Length: " << (int)iph->ip_header_length * 4 << " bytes" << endl;
    cout << "Type of Service: " << (int)iph->ip_tos << endl;
    cout << "Total Length: " << ntohs(iph->total_len) << " bytes" << endl;
    cout << "Identification: " << ntohs(iph->ip_id) << endl;
    cout << "Fragment Offset: " << ntohs(iph->ip_off) << endl;
    cout << "Time to Live: " << (int)iph->ip_ttl << endl;
    //cout << "Protocol: " << (int)iph->ip_protocol << endl;
    cout << "Protocol: " << (int)iph->ip_protocol << "(";
    switch ((int)iph->ip_protocol) {
    case 6:
        cout << "TCP";
        break;
    case 17:
        cout << "UDP";
        break;
    case 1:
        cout << "ICMP";
        break;
    case 2:
        cout << "IGMP";
        break;
    default:
        break;
    }
    cout << ")" << endl;
    cout << "Header Checksum: " << ntohs(iph->ip_checksum) << endl;
    cout << "Source IP: " << inet_ntoa(iph->ip_source_address) << endl;
    cout << "Destination IP: " << inet_ntoa(iph->ip_destination_address) << endl;
}

// 数据包信息
void print_packet_details(const struct pcap_pkthdr* header) {
    time_t packet_time = header->ts.tv_sec;
    cout << endl;
    cout << "Packet capture time: " << ctime(&packet_time);
    cout << "Packet length: " << header->len << " bytes" << endl;
}

// 数据包内容
void print_packet_content(const u_char* packet, int length) {
    cout << "Packet content (hex):" << endl;
    for (int i = 0; i < length; ++i) {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0) {
            cout << endl;
        }
    }
    cout << endl << "--------------------------------------" << endl;
}

// 数据包处理函数
void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    print_packet_details(header);
    print_packet_content(packet, header->len);

    // 获取以太网帧头
    const EthernetHeader* eth_header = (EthernetHeader*)packet;

    cout << "Source MAC: ";
    print_mac_address(eth_header->src_mac);
    cout << "Destination MAC: ";
    print_mac_address(eth_header->dest_mac);

    cout << "Type: 0x" << hex << ntohs(eth_header->ether_type) << dec << "(";
    switch (ntohs(eth_header->ether_type)) {
    case 0x0800:
        cout << "IPv4"; 
        break;
    case 0x0806:
        cout << "ARP"; 
        break;
    case 0x8035:
        cout << "RARP"; 
        break;
    default: 
        break;
    }
    cout << ")" << endl;
    // 判断是否为IP数据包 (以太网协议类型为0x0800)
    if (ntohs(eth_header->ether_type) == 0x0800) {
        const ip_header* iph = (ip_header*)(packet + sizeof(EthernetHeader));
        print_ip_header(iph);  // 打印IP头部信息
    }

    cout << "--------------------------------------" << endl;
}

int main() {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t* all_devices;
    pcap_t* handle;
    int device_count = 0;
    int device_choice;
    int pockets_num;

    // 查找设备列表
    if (pcap_findalldevs(&all_devices, error_buffer) == -1) {
        cerr << "Error finding devices: " << error_buffer << endl;
        return -1;
    }

    // 列出所有设备并编号
    pcap_if_t* device;
    cout << "Available network devices:" << endl;
    for (device = all_devices; device; device = device->next) {
        cout << ++device_count << ". " << device->name;
        if (device->description) {
            cout << " (" << device->description << ")";
        }
        cout << endl;
    }

    if (device_count == 0) {
        cerr << "No devices found!" << endl;
        return -1;
    }

    cout << "Select a device to capture packets (1-" << device_count << "): ";
    cin >> device_choice;

    if (device_choice < 1 || device_choice > device_count) {
        cerr << "Invalid choice!" << endl;
        pcap_freealldevs(all_devices);
        return -1;
    }

    cout << "Select the number of captured packets: ";
    cin >> pockets_num;

    if (pockets_num < 1) {
        cerr << "Invalid count!" << endl;
        pcap_freealldevs(all_devices);
        return -1;
    }

    // 找到用户选择的设备
    device = all_devices;
    for (int i = 1; i < device_choice; ++i) {
        device = device->next;
    }

    cout << "Using device: " << device->name << endl;

    // 打开设备进行数据包捕获
    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, error_buffer);
    if (handle == nullptr) {
        cerr << "Could not open device: " << error_buffer << endl;
        pcap_freealldevs(all_devices);
        return -1;
    }

    // 开始捕获
    pcap_loop(handle, pockets_num, packet_handler, nullptr);

    pcap_freealldevs(all_devices);
    pcap_close(handle);
    return 0;
}

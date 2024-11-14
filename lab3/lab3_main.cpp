#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <stdio.h>
#include <pcap.h>
#include <winsock2.h>
#include <Windows.h>
#include <cstdint>
#include <iomanip>
using namespace std;
#define cout std::cout
#define cin std::cin

#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "WS2_32.lib")

#define ETH_ARP 0x0806
#define ARP_HARDWARE 1 // 硬件类型字段值为表示以太网地址
#define ETH_IP 0x0800
#define ARP_REQUEST 1
#define ARP_RESPONSE 2

// 以太网首部
typedef struct EthernetHeader {
	u_char dest_mac[6];
	u_char src_mac[6];
	u_short ether_type;
}EthernetHeader;

// ARP结构
typedef struct ArpHeader {
	unsigned short HdType;    // 硬件类型
	unsigned short ProType;   // 协议类型
	unsigned char HdSize;     // 硬件地址长度
	unsigned char ProSize;    // 协议地址长度
	unsigned short OP;        // ARP请求1 ARP应答2 RARP请求3 RARP应答4
	u_char SrcMac[6];
	u_char SrcIp[4];
	u_char DestMac[6];
	u_char DestIp[4];
}ArpHeader;

// ARP报文包
struct ArpPacket {
	EthernetHeader* ed;
	ArpHeader* ah;
};

void PrintIp(u_char* Ip) {
	for (int i = 0; i < 4; ++i) {
		printf("%u", Ip[i]);
		if (i < 3) {
			cout << ".";
		}
	}
	cout << endl;
}

void PrintMac(u_char* Mac) {
	for (int i = 0; i < 6; ++i) {
		printf("%02X", Mac[i]);
		if (i < 5) {
			cout << ":";
		}
	}
	cout << endl;
}

void PrintHeader(const u_char* packetData) {
	struct EthernetHeader* eth_protocol;
	eth_protocol = (struct EthernetHeader*)packetData;

	if (ntohs(eth_protocol->ether_type) == 0x0806) {
		struct ArpHeader* arp_protocol;
		arp_protocol = (struct ArpHeader*)(packetData + sizeof(struct EthernetHeader));

		cout << "ARP type:";
		if (ntohs(arp_protocol->OP) == 1)
			cout << "ARP request";
		else if (ntohs(arp_protocol->OP) == 2)
			cout << "ARP response";
		else
			cout << "Unknown Type";
		cout << endl;

		printf("Source Mac Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
			arp_protocol->SrcMac[0], arp_protocol->SrcMac[1], arp_protocol->SrcMac[2],
			arp_protocol->SrcMac[3], arp_protocol->SrcMac[4], arp_protocol->SrcMac[5]);

		printf("Source Ip Address: %u.%u.%u.%u\n",
			arp_protocol->SrcIp[0], arp_protocol->SrcIp[1], arp_protocol->SrcIp[2], arp_protocol->SrcIp[3]);

		printf("Target Mac Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
			arp_protocol->DestMac[0], arp_protocol->DestMac[1], arp_protocol->DestMac[2],
			arp_protocol->DestMac[3], arp_protocol->DestMac[4], arp_protocol->DestMac[5]);

		printf("Target Ip Address: %u.%u.%u.%u\n",
			arp_protocol->DestIp[0], arp_protocol->DestIp[1], arp_protocol->DestIp[2], arp_protocol->DestIp[3]);
	}
}

bool Compare(const u_char* ip1, const u_char* ip2) {
	for (int i = 0; i < 4; ++i) {
		if (ip1[i] != ip2[i])
			return false;
	}
	return true;
}

bool CapPacket(pcap_t* handle, const u_char* src_ip, const u_char* dest_ip, u_char* SendIp = nullptr, u_char* SendMac = nullptr) {
	pcap_pkthdr* Packet_Header;
	const u_char* Packet_Data;
	char errbuf[256];

	while (true) {
		int n = pcap_next_ex(handle, &Packet_Header, &Packet_Data);
		if (n == -1) {
			cout << "Error: " << errbuf << endl;
			return false;
		}
		else if (n != 0) {
			ArpPacket* IPPacket = (ArpPacket*)Packet_Data;
			PrintHeader(Packet_Data);
			struct ArpHeader* arp_protocol = (struct ArpHeader*)(Packet_Data + sizeof(struct EthernetHeader));

			if (Compare(arp_protocol->DestIp, src_ip) && Compare(arp_protocol->SrcIp, dest_ip)) {
				cout << "Captured ARP packet with matching IP and MAC address:" << endl;
				cout << "IP: "; PrintIp(arp_protocol->SrcIp);
				cout << "MAC: "; PrintMac(arp_protocol->SrcMac);

				if (SendIp != nullptr && SendMac != nullptr) {
					// arp_protocol->SrcIp -> SendIp
					for (int j = 0; j < 4; ++j)
						SendIp[j] = arp_protocol->SrcIp[j];
					// arp_protocol->SrcMac -> SendMac
					for (int j = 0; j < 6; ++j)
						SendMac[j] = arp_protocol->SrcMac[j];
				}
				break;
			}
		}
	}
	return true;
}

void BuildRequest(EthernetHeader* eh, ArpHeader* ah, u_char* sendbuf, const u_char* src_mac, const u_char* src_ip, const u_char* dest_ip) {
	memset(eh->dest_mac, 0xff, 6);
	if (src_mac != nullptr) {
		memcpy(eh->src_mac, src_mac, 6);
		memcpy(ah->SrcMac, src_mac, 6);
	}
	else {
		memset(eh->src_mac, 0x0f, 6);
		memset(ah->SrcMac, 0x0f, 6);
	}

	memset(ah->DestMac, 0xff, 6);
	memcpy(ah->SrcIp, src_ip, 4);
	memcpy(ah->DestIp, dest_ip, 4);

	eh->ether_type = htons(ETH_ARP);
	ah->HdType = htons(ARP_HARDWARE);
	ah->ProType = htons(ETH_IP);
	ah->HdSize = 6;
	ah->ProSize = 4;
	ah->OP = htons(ARP_REQUEST);

	memset(sendbuf, 0, 42);
	memcpy(sendbuf, eh, sizeof(*eh)); 
	memcpy(sendbuf + sizeof(*eh), ah, sizeof(*ah));
}

int main() {
	char error_buffer[256];
	pcap_if_t* all_devices;
	pcap_t* handle;
	int device_count = 0;
	int device_choice;

	EthernetHeader eh;
	ArpHeader ah;

	u_char sendbuf[42];
	u_char SendIp[4] = { 0x00, 0x00, 0x00, 0x00 };
	u_char SendMac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	u_char RevIp[4] = { 0x00, 0x00, 0x00, 0x00 };
	u_char RevMac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	u_char MyIp[4] = { 0x00, 0x00, 0x00, 0x00 };
	u_char MyMac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

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

	// 找到用户选择的设备
	device = all_devices;
	for (int i = 1; i < device_choice; ++i) {
		device = device->next;
	}
	handle = pcap_open(device->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, error_buffer);
	if (handle == NULL) {
		cerr << "Error opening device: " << error_buffer << endl;
		pcap_freealldevs(all_devices);
		return -1;
	}
	cout << "Open successful!" << endl;

	pcap_addr_t* a;
	int i = 0;
	for (a = device->addresses; a != NULL; a = a->next) {
		if (a->addr->sa_family == AF_INET) {
			struct sockaddr_in* sa = (struct sockaddr_in*)(a->addr);
			uint32_t ipAddress = sa->sin_addr.s_addr;

			for (int j = 0; j < 4; ++j) {
				RevIp[i++] = (ipAddress >> (j * 8)) & 0xFF;
			}
			break;
		}
	}
	cout << "Get Host Ip:"; PrintIp(RevIp);

	BuildRequest(&eh, &ah, sendbuf, MyMac, MyIp, RevIp);
	if (pcap_sendpacket(handle, sendbuf, 42) == 0)
		cout << "Send ARP request successfully." << endl;

	if (!CapPacket(handle, SendIp, RevIp, MyIp, MyMac)) {
		cout << "Failed to capture ARP." << endl;
		pcap_freealldevs(all_devices);
		return -1;
	}

	// Target IP -> MAC
	cout << "Target Ip Address:";
	char str[16] = "000.000.000.000";
	cin >> str;

	if (inet_pton(AF_INET, str, &RevIp) != 1) {
		cout << "Invalid IP address.";
		return 1;
	}

	cout << "Input RevIp:"; PrintIp(RevIp);

	BuildRequest(&eh, &ah, sendbuf, MyMac, MyIp, RevIp);
	if (pcap_sendpacket(handle, sendbuf, 42) == 0) {
		cout << "Send ARP successfully." << endl;
		CapPacket(handle, MyIp, RevIp);
	}
	else
		cout << "Send ARP failed." << endl;

	pcap_freealldevs(all_devices);
	return 0;
}
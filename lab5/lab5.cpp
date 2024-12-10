#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "pcap.h"
#include <WinSock2.h>
#include <string>
#include <ctime>
#include <stdio.h>

#pragma comment(lib,"ws2_32.lib")

HANDLE hThread;
DWORD dwThreadId;
char myip[2][100];
char mymask[2][100];
BYTE mymac[6];
int arpnum = 0;

pcap_t* point;
#pragma pack(1)

struct Frame_Header {
	BYTE DesMAC[6];
	BYTE SrcMAC[6];
	WORD FrameType;
};

struct ARP_Frame {
	Frame_Header FrameHeader;
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HLen;
	BYTE PLen;
	WORD op;
	BYTE SrcMAC[6];
	DWORD SrcIP;
	BYTE DesMAC[6];
	DWORD DesIP;
};

struct IP_Header {
	BYTE Version;
	BYTE TOS;
	WORD TotLen;
	WORD ID;
	WORD Flagoffset;
	BYTE TTL;
	BYTE Protocol;
	WORD Checksum;
	ULONG SrcIP;
	ULONG DstIP;
};

struct Data {
	Frame_Header FrameHeader;
	IP_Header IPHeader;
	char buf[0x80];
};

struct Send_Packet {
	BYTE PktData[2000];
	ULONG DestIP;
	bool flag = 1; // 是否有效，如果已经被转发或者超时，则置0
	clock_t time;
};
Send_Packet Buffer[50];
int bufsize = 0;

class RouteTableEntry {
public:
	DWORD netmask;
	DWORD destnet;
	DWORD nextip;
	int type;//0为直接连接，1为用户添加
	RouteTableEntry* nextitem;

	RouteTableEntry() { memset(this, 0, sizeof(*this)); };
	RouteTableEntry(DWORD netmask, DWORD dstnet, int type, DWORD nextip = 0) {
		this->netmask = netmask;
		this->destnet = dstnet;
		this->nextip = nextip;
		this->type = type;
	}

	void print();
};
void RouteTableEntry::print() {
	in_addr addr;
	memcpy(&addr, &netmask, sizeof(netmask));
	printf("MASK：%s\n", inet_ntoa(addr));
	memcpy(&addr, &destnet, sizeof(destnet));
	printf("Tar-Net：%s\n", inet_ntoa(addr));
	memcpy(&addr, &nextip, sizeof(nextip));
	printf("Next-IP：%s\n", inet_ntoa(addr));
}

class RouteTable {
public:
	RouteTableEntry* head;
	RouteTableEntry* tail;
	int num;//路由表项数
	RouteTable() {
		num = 0;
		head = new RouteTableEntry(inet_addr(mymask[0]), (inet_addr(myip[0])) & (inet_addr(mymask[0])), 0);
		tail = new RouteTableEntry;
		head->nextitem = tail;

		RouteTableEntry* temp = new RouteTableEntry;
		temp->destnet = (inet_addr(myip[1])) & (inet_addr(mymask[1]));;
		temp->netmask = inet_addr(mymask[1]);
		temp->type = 0;
		add(temp);

	}

	void add(RouteTableEntry* newt);
	void Delete(int index);
	void print();
	DWORD find(DWORD destip);//查找
};
void RouteTable::add(RouteTableEntry* newt) {
	num++;
	//直接投递
	if (newt->type == 0) {
		newt->nextitem = head->nextitem;//插入在head后
		head->nextitem = newt;
		return;
	}
	//根据掩码的大小插入
	RouteTableEntry* cur = head;
	while (cur->nextitem != tail) {
		if (cur->nextitem->type != 0 && cur->nextitem->netmask <= newt->netmask) {
			break;
		}
		cur = cur->nextitem;
	}
	//插入在 cur 和 cur->next 之间
	newt->nextitem = cur->nextitem;
	cur->nextitem = newt;
}
void RouteTable::Delete(int index) {
	if (index > num) {
		printf("Routing-Table Entries %d beyond the scope.\n", index);
		return;
	}
	if (index == 0) {
		if (head->type == 0) {
			printf("Delete failed!\n");
		}
		else {
			head = head->nextitem;
		}
		return;
	}
	RouteTableEntry* cur = head;
	int i = 0;
	while (i < index - 1 && cur->nextitem != tail) {
		i++;
		cur = cur->nextitem;
	}
	if (cur->nextitem->type == 0) {
		printf("Delete failed!\n");
	}
	else {
		cur->nextitem = cur->nextitem->nextitem;
	}

}
void RouteTable::print() {
	RouteTableEntry* cur = head;
	int i = 1;
	while (cur != tail) {
		printf("%d Routing-Table Entry\n", i);
		cur->print();
		cur = cur->nextitem;
		i++;
	}
}
DWORD RouteTable::find(DWORD destip) {
	DWORD result;
	RouteTableEntry* cur = head;
	while (cur != tail) {
		result = destip & cur->netmask;
		if (result == cur->destnet) {
			if (cur->type == 1) {
				return cur->nextip;//转发
			}
			else if (cur->type == 0) {
				return destip;//直接投递
			}
		}
		cur = cur->nextitem;
	}
	printf("No Routing-Table Entry.\n");
	return -1;
}

class ARPTable {
public:
	int arpnum = 0;
	DWORD IP;
	BYTE mac[6];

	void add(DWORD ip, BYTE mac[6]);
	int find(DWORD ip, BYTE mac[6]);
};
ARPTable arp_table[50];
void ARPTable::add(DWORD ip, BYTE mac[6]) {
	extern ARPTable arp_table[50];
	arp_table[arpnum].IP = ip;
	for (int i = 0; i < 6; i++) {
		arp_table[arpnum].mac[i] = mac[i];
	}

	arpnum++;
}
int ARPTable::find(DWORD ip, BYTE mac[6]) {
	extern ARPTable arp_table[50];
	for (int i = 0; i < arpnum; i++) {
		if (ip == arp_table[i].IP) {
			for (int j = 0; j < 6; j++) {
				mac[j] = arp_table[i].mac[j];
			}
			return 1;
		}
	}
	return 0;
}


//设置检验校验和
void SetChecksum(Data* temp) {
	temp->IPHeader.Checksum = 0;
	unsigned long sum = 0;
	WORD* buffer = (WORD*)&temp->IPHeader;
	int size = sizeof(IP_Header);
	while (size > 1) {
		sum += *buffer++;
		size -= sizeof(unsigned short);
	}
	if (size)
		sum += *(unsigned char*)buffer;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	temp->IPHeader.Checksum = ~sum;
}
bool Check(Data* temp) {
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IP_Header) / 2; i++) {
		sum += t[i];
		while (sum >= 0x10000) {
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	if (sum == 65535)//全1
		return 1;
	return 0;
}

bool Compare(BYTE a[], BYTE b[]) {
	for (int i = 0; i < 6; i++) {
		if (a[i] != b[i])
			return false;
	}
	return true;
}

//转发数据包
void SendPacket(Data data, BYTE nextmac[]) {
	//拷贝数据包
	Data* temp = (Data*)&data;
	memcpy(temp->FrameHeader.SrcMAC, temp->FrameHeader.DesMAC, 6);//源MAC为本机MAC
	memcpy(temp->FrameHeader.DesMAC, nextmac, 6);//目的MAC为下一跳MAC
	temp->IPHeader.TTL -= 1;
	if (temp->IPHeader.TTL < 0)
		return;
	SetChecksum(temp);

	//打印IP数据包
	printf("Host-MAC Add: \t ");
	for (int i = 0; i < 5; i++) {
		printf("%02X-", temp->FrameHeader.SrcMAC[i]);
	}
	printf("%02X\n", temp->FrameHeader.SrcMAC[5]);

	printf("Tar-MAC Add: \t");
	for (int i = 0; i < 5; i++) {
		printf("%02X-", temp->FrameHeader.DesMAC[i]);
	}
	printf("%02X\n", temp->FrameHeader.DesMAC[5]);
	printf("Host-IP Add: \t ");
	in_addr addr;
	memcpy(&addr, &temp->IPHeader.SrcIP, sizeof(temp->IPHeader.SrcIP));
	printf("%s  ", inet_ntoa(addr));
	printf("\n");
	printf("Tar-IP Add:\t ");
	memcpy(&addr, &temp->IPHeader.DstIP, sizeof(temp->IPHeader.DstIP));
	printf("%s  ", inet_ntoa(addr));
	printf("\n");
	printf("TTL: %d\n", temp->IPHeader.TTL);
	pcap_sendpacket(point, (const u_char*)temp, 74);//发送数据报
}

//获取目的主机MAC地址
void GetTarMac(DWORD ip, BYTE mac[]) {
	//初始化ARP数据包
	ARP_Frame rev_ARPFrame;
	/*获取目的主机的MAC地址*/
	for (int i = 0; i < 6; i++) {
		rev_ARPFrame.FrameHeader.DesMAC[i] = 0xff; //广播地址
		rev_ARPFrame.FrameHeader.SrcMAC[i] = mac[i]; //MAC地址
		rev_ARPFrame.DesMAC[i] = 0x00; //设置为0
		rev_ARPFrame.SrcMAC[i] = mymac[i]; //本机MAC地址
	}
	rev_ARPFrame.FrameHeader.FrameType = htons(0x0806);//帧类型为ARP
	rev_ARPFrame.HardwareType = htons(0x0001); //硬件类型为以太网
	rev_ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
	rev_ARPFrame.HLen = 6;//硬件地址长度为6
	rev_ARPFrame.PLen = 4;//协议类型长度为4
	rev_ARPFrame.op = htons(0x0001);//操作为ARP请求	
	rev_ARPFrame.SrcIP = inet_addr(myip[0]);//设置发送方ip地址
	rev_ARPFrame.DesIP = ip;
	//发送数据包
	pcap_sendpacket(point, (u_char*)&rev_ARPFrame, sizeof(ARP_Frame));
}

DWORD WINAPI receive(LPVOID lparam) {
	ARPTable arptable;
	RouteTable rtable = *(RouteTable*)(LPVOID)lparam;
	while (1) {
		pcap_pkthdr* pkt_header;
		const u_char* packetData;

		while (1) {
			int result = pcap_next_ex(point, &pkt_header, &packetData);
			if (result)
				break;
		}

		Frame_Header* header = (Frame_Header*)packetData;
		//数据包是ARP格式
		if (ntohs(header->FrameType) == 0x806) {
			ARP_Frame* data = (ARP_Frame*)packetData;

			printf("Host-MAC Add: \t ");
			for (int i = 0; i < 5; i++) {
				printf("%02X-", data->FrameHeader.SrcMAC[i]);
			}
			printf("%02X\n", data->FrameHeader.SrcMAC[5]);

			printf("Tar-MAC Add: \t");
			for (int i = 0; i < 5; i++) {
				printf("%02X-", data->FrameHeader.DesMAC[i]);
			}
			printf("%02X\n", data->FrameHeader.DesMAC[5]);
			printf("Host-IP Add: \t ");
			in_addr addr;
			memcpy(&addr, &data->SrcIP, sizeof(data->SrcIP));
			printf("%s  ", inet_ntoa(addr));
			printf("\n");
			printf("Tar-IP Add: \t ");
			memcpy(&addr, &data->DesIP, sizeof(data->DesIP));
			printf("%s  ", inet_ntoa(addr));
			printf("\n");
			//收到ARP响应包
			if (data->op == ntohs(0x0002)) {
				BYTE tempmac[6];
				//该映射关系已经存到arp表中，不做处理
				if (arptable.find(data->SrcIP, tempmac));
				//不在arp表中，插入
				else
					arptable.add(data->SrcIP, data->SrcMAC);

				//遍历缓冲区，看是否有可以转发的包
				for (int i = 0; i < bufsize; i++)
				{
					if (Buffer[i].flag == 0)
						continue;
					if (clock() - Buffer[i].time >= 6000) {
						Buffer[i].flag = 0;
						continue;
					}
					if (Buffer[i].DestIP == data->SrcIP) {
						Data* data_send = (Data*)Buffer[i].PktData;
						Data temp = *data_send;
						SendPacket(temp, data->SrcMAC);
						Buffer[i].flag = 0;
						break;
					}
				}
			}
		}
		//目的mac是自己的mac且数据包是IP格式
		if (Compare(header->DesMAC, mymac) && ntohs(header->FrameType) == 0x800) {
			Data* data = (Data*)packetData; //格式化收到的包
			//如果校验和不正确，则直接丢弃不进行处理
			if (!Check(data)) {
				printf("Checknum Error.\n");
				continue;
			}

			//打印IP数据包
			printf("Host-MAC Add: \t ");
			for (int i = 6; i < 12; ++i) {
				printf("%02X", packetData[i]);
				if (i < 11) printf("-");
			}
			printf("\n");
			printf("Tar-MAC Add:\t");
			for (int i = 0; i < 6; ++i) {
				printf("%02X", packetData[i]);
				if (i < 5) printf("-");
			}
			printf("\n");
			printf("Host-IP Add: \t ");
			for (int i = 26; i < 30; ++i) {
				printf("%d", packetData[i]);
				if (i < 29) printf(".");
			}
			printf("\n");
			printf("Tar-IP Add: \t ");
			for (int i = 30; i < 34; ++i) {
				printf("%d", packetData[i]);
				if (i < 33) printf(".");
			}
			printf("\n");
			printf("TTL: %d\n", data->IPHeader.TTL);
			if (data->IPHeader.DstIP == inet_addr(myip[0]) 
				|| data->IPHeader.DstIP == inet_addr(myip[1])) { //路由器两个网卡都可以接受
				printf("Selfcheck\n");
				continue;
			}
			DWORD destip = data->IPHeader.DstIP; //目的IP地址
			DWORD nextdestip = rtable.find(destip);//查找下一跳IP地址

			if (nextdestip == -1) {
				printf("Routing-Table Entries！\n");
				continue;//如果没有则直接丢弃或直接递交至上层
			}
			else {
				in_addr next;
				next.s_addr = nextdestip;
				printf("Next-IP: %s\n", inet_ntoa(next));

				Data* temp2 = (Data*)packetData;
				Data temp = *temp2;
				BYTE mac[6];
				//直接投递
				if (nextdestip == destip) {
					//如果ARP表中没有所需内容，则需要获取ARP
					if (!arptable.find(destip, mac)) {
						int flag2 = 0;
						for (int i = 0; i < bufsize; i++) {
							//如果缓冲区中有已经被转发的，将数据包复制到该转发完成的数据包（覆盖用过的地方，节省空间）
							if (Buffer[i].flag == 0) {
								flag2 = 1;
								memcpy(Buffer[i].PktData, packetData, pkt_header->len);
								Buffer[i].flag = 1;
								Buffer[i].time = clock();
								Buffer[i].DestIP = destip;
								GetTarMac(destip, mac);
								break;
							}
						}
						//缓冲区上限50
						if (flag2 == 0 && bufsize < 50) {
							memcpy(Buffer[bufsize].PktData, packetData, pkt_header->len);
							Buffer[bufsize].flag = 1;
							Buffer[bufsize].time = clock();
							Buffer[bufsize].DestIP = destip;
							bufsize++;
							GetTarMac(destip, mac);
						}
						else 
							printf("Buffer full.\n");
					}
					else if (arptable.find(destip, mac))
						SendPacket(temp, mac);//转发

				}
				else {
					if (!arptable.find(nextdestip, mac)) {
						int flag3 = 0;
						for (int i = 0; i < bufsize; i++) {
							if (Buffer[i].flag == 0) {
								flag3 = 1;
								memcpy(Buffer[i].PktData, packetData, pkt_header->len);
								Buffer[i].flag = 1;
								Buffer[i].time = clock();
								Buffer[i].DestIP = nextdestip;
								GetTarMac(nextdestip, mac);
								break;
							}
						}
						if (flag3 == 0 && bufsize < 50) {
							memcpy(Buffer[bufsize].PktData, packetData, pkt_header->len);
							Buffer[bufsize].flag = 1;
							Buffer[bufsize].time = clock();
							Buffer[bufsize].DestIP = nextdestip;
							bufsize++;
							GetTarMac(nextdestip, mac);
						}
						else if (arptable.find(destip, mac))
							SendPacket(temp, mac);//转发
					}
					else if (arptable.find(nextdestip, mac))
						SendPacket(temp, mac);
				}
			}
		}
	}
}

int main() {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_addr_t* a;
	pcap_if_t* devices;
	int i = 0;

	if (pcap_findalldevs(&devices, errbuf) == -1){
		printf("No decides: %s\n", errbuf);
		return 0;
	}

	pcap_if_t* count;
	for (count = devices; count; count = count->next)
	{
		printf("%d. %s", ++i, count->name);
		if (count->description)
			printf("(%s)\n", count->description);

		for (a = count->addresses; a != NULL; a = a->next) {
			if (a->addr->sa_family == AF_INET) {
				char str[100];
				strcpy(str, inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				printf("IP: %s\n", str);
				strcpy(str, inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
				printf("Mask: %s\n", str);
				strcpy(str, inet_ntoa(((struct sockaddr_in*)a->broadaddr)->sin_addr));
			}
		}
	}

	if (i == 0) {
		printf("No Decides.");
		return 0;
	}

	pcap_if_t* count2;
	int num = 0;
	printf("Select a device (1-%d): ", i);
	scanf("%d", &num);

	while (num < 1 || num > 2) {
		printf("Select a device again (1-%d): ", i);
		scanf("%d", &num);
	}
	count2 = devices;
	for (int i = 1; i < num; i++)
		count2 = count2->next;

	int k = 0;
	//储存ip和子网掩码
	for (a = count2->addresses; a != NULL; a = a->next) {
		if (a->addr->sa_family == AF_INET) {
			printf("(%s)", count2->name);
			printf("(%s)\n", count2->description);
			strcpy(myip[k], inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
			printf("IP: %s\n", myip);
			strcpy(mymask[k], inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
			printf("MASK: %s\n", mymask);
			k++;
		}
	}

	//指定获取数据包最大长度为65536,可以确保程序可以抓到整个数据包，指定时间范围为200ms
	point = pcap_open(count2->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 200, NULL, errbuf);
	if (point == NULL) {
		printf("Error");
		return 0;
	}

	pcap_freealldevs(devices);

	//组装报文
	ARP_Frame send_ARPFrame;
	for (int i = 0; i < 6; i++) {
		send_ARPFrame.FrameHeader.DesMAC[i] = 0xFF; //DesMAC设置为广播地址
		send_ARPFrame.DesMAC[i] = 0x00; //DesMAC设置为0
	}
	send_ARPFrame.FrameHeader.FrameType = htons(0x0806); //帧类型为ARP
	send_ARPFrame.HardwareType = htons(0x0001); //硬件类型为以太网
	send_ARPFrame.ProtocolType = htons(0x0800); //协议类型为IPv4
	send_ARPFrame.HLen = 6; //硬件地址长度为6
	send_ARPFrame.PLen = 4; //协议地址长度为4
	send_ARPFrame.op = htons(0x0001); //操作为ARP请求
	send_ARPFrame.DesIP = inet_addr(myip[0]); //设置为本机IP地址
	pcap_sendpacket(point, (u_char*)&send_ARPFrame, sizeof(ARP_Frame));

	struct pcap_pkthdr* pkt_header;
	const u_char* packetData;
	int ret;

	//判断获取报文
	while ((ret = pcap_next_ex(point, &pkt_header, &packetData)) >= 0) {
		if (ret == 0)
			continue;

		//通过报文内容比对判断是否是要发打印的ARP数据包内容
		else if (*(unsigned short*)(packetData + 12) == htons(0x0806)
			&& *(unsigned short*)(packetData + 20) == htons(0x0002)
			&& *(unsigned long*)(packetData + 28) == send_ARPFrame.DesIP) {
			printf("\n");
			//用mac数组记录本机的MAC地址
			for (int i = 0; i < 6; i++) {
				mymac[i] = *(unsigned char*)(packetData + 22 + i);
			}
			printf("MAC: \t ");
			for (int i = 6; i < 12; ++i) {
				printf("%02X", packetData[i]);
				if (i < 11) printf("-");
			}
			printf("\n");
			break;
		}
	}

	if (ret == -1) {
		printf("Packet Error\n");
		pcap_freealldevs(devices);
		return 0;
	}

	struct bpf_program fcode;

	//通过绑定过滤器，设置只捕获IP和ARP数据报
	if (pcap_compile(point, &fcode, "ip or arp", 1, bpf_u_int32(inet_addr(mymask[0]))) < 0) {
		fprintf(stderr, "Set filter failed.\n");
		system("pause");
		return 0;
	}
	if (pcap_setfilter(point, &fcode) < 0) {
		fprintf(stderr, "Bind filter failed.\n");
		system("pause");
		return 0;
	}

	RouteTable rtable;
	rtable.print();
	hThread = CreateThread(NULL, 0, receive, LPVOID(&rtable), 0, &dwThreadId);

	while (1) {
		printf("1.Add Routing-Table Entries\n2.Delete Routing-Table Entries\n3.Print Routing-Table\n");
		int num;
		scanf("%d", &num);

		if (num == 1) {
			RouteTableEntry* rtableitem = new RouteTableEntry;
			rtableitem->type = 1;
			char buf[INET_ADDRSTRLEN];
			printf("Mask: ");
			scanf("%s", &buf);
			rtableitem->netmask = inet_addr(buf);
			printf("Tar-Net: ");
			scanf("%s", &buf);
			rtableitem->destnet = inet_addr(buf);
			printf("Next-IP: ");
			scanf("%s", &buf);
			rtableitem->nextip = inet_addr(buf);
			rtable.add(rtableitem);
		}
		else if (num == 2) {
			printf("Delete Num: ");
			int index;
			scanf("%d", &index);

			rtable.Delete(index - 1);
		}
		else if (num == 3)
			rtable.print();
		else
			printf("Input again.\n");
	}
	return 0;
}

#include "util.h"
#ifdef DEBUG_INFO
static void DbgPrint(int level, void *header)
{
	ethII_header* eth_headerp = (ethII_header*)header;
	ip_header* ip_headerp = (ip_header*)header;
	udp_header* udp_headerp = (udp_header*)header;
	tcp_header* tcp_headerp = (tcp_header*)header;
	in_addr srcip, dstip;
	char srcip_dot[32] = { 0 }, dstip_dot[32] = { 0 };
	if(!(level & DEBUG_INFO))
	{
		return;
	}
	switch (level & DEBUG_INFO)
	{
	case eth_info:
		
		printf("EthII");
		for (int i = 0; i < sizeof(eth_headerp->destination); i++)
		{
			if (i == 0) printf("\tdst:");
			printf("%0.2X", eth_headerp->destination[i]);
			if (i < (sizeof(eth_headerp->destination) - 1)) printf(":");
		}
		for (int i = 0; i < sizeof(eth_headerp->source); i++)
		{
			if (i == 0) printf("\tsrc:");
			printf("%0.2X", eth_headerp->source[i]);
			if (i < (sizeof(eth_headerp->source) - 1)) printf(":");
		}
		printf("\ttype:%0.4X\n", eth_headerp->type);
		break;
	case tcp_info:
		printf("TCP");
		printf("\t Source Port:%d,Dest Port:%d,Length:%d\n", tcp_headerp->sport, tcp_headerp->dport, 4 * ((tcp_headerp->tcpHeader_reserve & 0xF0)>>4));
		break;
	case udp_info:
		printf("UDP");
		printf("\tSource Port:%d,Dest Port:%d,Length:%d\n", udp_headerp->sport, udp_headerp->dport, udp_headerp->len);
		break;
	case ip_info:
		printf("IP");
                #ifdef _WIN32
		srcip.S_un.S_addr = ip_headerp->saddr;
		dstip.S_un.S_addr = ip_headerp->daddr;
                #else
                srcip.s_addr = ip_headerp->saddr;
		dstip.s_addr = ip_headerp->daddr;
		#endif

		sprintf(srcip_dot, "%s", inet_ntoa(srcip));
		sprintf(dstip_dot, "%s", inet_ntoa(dstip));
		printf("\theader length:%d(bytes) , procotol:%X ,source:%s,dest:%s \n", 4*(ip_headerp->ver_ihl & 0x0F), ip_headerp->proto, srcip_dot,dstip_dot);
		break;
	default:
		break;
	}
}


void display(unsigned char * pkt_data, int len, int nextline)
{
	if (!(DEBUG_INFO & raw_packet_info))
		//没有打开打印报文的选项
	{
		return;
	}
	for (int i = 0; i < len;)
	{
		printf("%.2X ", pkt_data[i]);
		i += 1;
		if (i % nextline == 0)
		{
			printf("\n");
		}
	}
	printf("\n");
}
#else
#define DEBUG_INFO (0)
#define DbgPrint(int,const char *,...)     ;
#define display(unsigned char *,int,int)   ;
#endif
pcap_gather::pcap_gather(char *pcapfilename)
{
	this->pcapt = pcap_open_offline(pcapfilename, this->errBuf);
	if (this->pcapt == NULL)
	{
		printf("Error when open pcap file.\n");
		system("pause");
		exit(-1);
	}
}

void pcap_gather::set_filter(char *FilterString, pcap_t * pt)
//设置过滤器
{
	if (pt == NULL)
	{
		pt = this->pcapt;
	}
	bpf_program *fprog = new bpf_program();

	if (pcap_compile(pt, fprog, FilterString, 1, 0) == -1)
	{
		printf("compile filter error.\n");
	}

	if (pcap_setfilter(pt, fprog) == -1)
	{
		printf("set filter error.\n");
	}
}

vector< _packet> pcap_gather::get_packets(pcap_t * pt)
//获取全部报文,主要用于通过文件获取报文
{
	if (pt == NULL)
	{
		pt = this->pcapt;
	}
	vector< _packet> rst;
	while (true)
	{
		_packet pkt;
		get_next_packet(&pkt);
		if (pkt.data)
		{
			rst.push_back(pkt);
		}
		else
		{
			break;
		}
	}
	return rst;
}
void pcap_gather::get_next_packet(_packet * packet, pcap_t * pt)
//一个一个的获取报文
{
	if (pt == NULL)
	{
		pt = this->pcapt;
	}
	pcap_pkthdr pktheader;
	const u_char *pktdata = pcap_next(pt, &pktheader);
	if (pktdata != NULL)
	{
		packet->len = pktheader.caplen;
		packet->timestamp = pktheader.ts.tv_sec;
		packet->data = (unsigned char *)malloc(sizeof(unsigned char)*pktheader.caplen);
		memcpy(packet->data, pktdata, packet->len);
	}
}

ethII_header eth_parser(const unsigned char * pkt_data)
//以太网的解析,生成一个以太网的header
{
	ethII_header header = { 0 };
	ethII_header * data = (ethII_header*)pkt_data;
	memcpy(&header, data, sizeof(ethII_header));
	header.type = ntohs(header.type);
	DbgPrint(eth_info, &header);
	return header;
}
ip_header ip_parser(const unsigned char *  ip_data)
//ip报文的解析
{
	ip_header header = { 0 };
	ip_header * data = (ip_header*)ip_data;
	memcpy(&header, data, sizeof(ip_header));
	header.tlen = ntohs(header.tlen);
	header.identification = ntohs(header.identification);
	header.flags_fo = ntohs(header.flags_fo);
	header.crc = ntohs(header.crc);
	//header.saddr = ntohl(header.saddr);
	//header.daddr = ntohl(header.daddr);
	DbgPrint(ip_info, &header);
	return header;
}


udp_header udp_parser(const unsigned char * udp_data)
//udp报文的解析
{
	udp_header header = { 0 };
	udp_header * data = (udp_header *)udp_data;
	memcpy(&header, data, sizeof(udp_header));
	header.sport = ntohs(header.sport);
	header.dport = ntohs(header.dport);
	header.len = ntohs(header.len);
	header.crc = ntohs(header.crc);
	DbgPrint(udp_info, &header);
	return header;
}

tcp_header tcp_parser(const unsigned char * tcp_data)
//tcp报文的解析
{
	tcp_header header = { 0 };
	tcp_header * data = (tcp_header*)tcp_data;
	memcpy(&header, data, sizeof(tcp_header));
	header.sport = ntohs(header.sport);
	header.dport = ntohs(header.dport);
	header.sequence = ntohl(header.sequence);
	header.acknum = ntohl(header.acknum);
	header.crc = ntohs(header.crc);
	DbgPrint(tcp_info, &header);
	return header;
}

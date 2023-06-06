#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <vector>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef _WIN32
#include <pcap-stdinc.h>
#endif

#include <pcap.h>
#include <vector>
#include <set>
#include <map>
#include <string.h>

#include <util.h>

#define DLT_NFLOG 239
#define DLT_ETH 1
#define _MOD (1000003)
#define _E (1993)


using namespace std;

typedef struct __flow_tuple{
	unsigned int src_ip = 0;
	unsigned int dst_ip = 0;
	unsigned short src_port = 0;
	unsigned short dst_port = 0;
	unsigned char protocol=0;
	int _hash = 1;
	__flow_tuple(unsigned int& _src_ip, unsigned int& _dst_ip, unsigned short& _src_port, unsigned short& _dst_port, unsigned char & _protocol)
	{
		char tuples[64] = { 0 };
		if (_src_ip > _dst_ip)
		//确保C->S和S->C的元组信息是一致的
		{
			swap(_src_ip, _dst_ip);
			swap(_src_port, _dst_port);
		}
		src_ip = _src_ip;
		dst_ip = _dst_ip;
		src_port = _src_port;
		dst_port = _dst_port;
		protocol = _protocol;
		sprintf(tuples, "%u%u%u%u%c", _src_ip, _dst_ip, _src_port, _dst_port, protocol);
		for (int i = 0; i < 64; i++){
			_hash = (_hash * _E + tuples[i]) % _MOD;
		}
	}
	__flow_tuple();
} flow_tuple;
flow_tuple gather_flow_tuple( const unsigned char * data){
	
	ethII_header eth = eth_parser(data);

	unsigned int src_ip = 0;
	unsigned int dst_ip = 0;
	unsigned short src_port = 0;
	unsigned short dst_port = 0;
	unsigned char protocol = 0;

	if (eth.type == 0x0800)
		//ip 协议
	{
		ip_header ip = ip_parser(data + sizeof(ethII_header));
		src_ip = ip.saddr;
		dst_ip = ip.daddr;
		protocol = ip.proto;

		if (ip.proto == 0x11)
			//udp
		{
			udp_header udp = udp_parser(data + sizeof(ethII_header)+4 * (ip.ver_ihl & 0xF));
			src_port = udp.sport;
			dst_port = udp.dport;
		}
		else if (ip.proto == 0x06)
			//tcp
		{
			tcp_header tcp = tcp_parser(data + sizeof(ethII_header)+4 * (ip.ver_ihl & 0xF));
			src_port = tcp.sport;
			dst_port = tcp.dport;
		}
	}
	else{
		//非IP协议; 把MAC地址高4位作为IP
		src_ip = * ((unsigned int *) eth.source);
		dst_ip = *((unsigned int *) eth.destination);
	}
	flow_tuple rst(src_ip, dst_ip, src_port, dst_port, protocol);
	return rst;
}
int splitpcaps(char *pcapname, char * dst_dir, int piece_num=10)
{

	pcap_t * rdpcap;//打开pcap的指针
	
	char errBUF[4096] = { 0 };
	rdpcap = pcap_open_offline(pcapname,errBUF);
	if (rdpcap == NULL)
	{
		printf("Error when open pcap file. error is :%s\n", errBUF);
		return -1;
	}

	//创建目录
	char mkdir_cmd[256] = { 0 };
	sprintf(mkdir_cmd, "mkdir %s", dst_dir);
	system(mkdir_cmd);

	//依次创建 //写pcap的指针
	vector<pcap_dumper_t *> wtpcap_dumps;	
	vector<pcap_t *> _wtpcaps;

	for (int i = 0; i < piece_num; i++)
	{
		char dstfile[256] = { 0 };
		sprintf(dstfile, "%s/%d.pcap", dst_dir, i);
		pcap_t * wtpcap = pcap_open_dead(DLT_ETH, 65535);//第一个参数是 linktype,以太网的linktype是1;
		pcap_dumper_t * wtpcap_dump = pcap_dump_open(wtpcap, dstfile);
		_wtpcaps.push_back(wtpcap);
		wtpcap_dumps.push_back(wtpcap_dump);
		
		//检查是否打开成功
		if (wtpcap == NULL || wtpcap_dump == NULL)
		{
			printf("Error when create dst file:%s\n", dstfile);
			return -2;
		}

	}

	int nb_transfer = 0;
	while (1)
	{
		pcap_pkthdr pktheader;
		const u_char *pktdata = pcap_next(rdpcap, &pktheader);
		if (pktdata != NULL)
			//pcap存在pcapket未处理
		{
			//printf("Packet :%d\n", nb_transfer);

			//拷贝packet所有内容
			display((unsigned char *)pktdata, pktheader.len);
			pcap_pkthdr new_pkthdr = pktheader;
			u_char new_data[2000] = { 0};
			memcpy(new_data, pktdata, new_pkthdr.len);
			//获取五元组信息,并对五元组进行哈希
			flow_tuple tuple = gather_flow_tuple(pktdata);

			//写入对应的小pcap中
			pcap_dumper_t * wtpcap_dump = wtpcap_dumps[tuple._hash % piece_num];
			pcap_dump((u_char*) wtpcap_dump, &new_pkthdr, new_data);
			nb_transfer++;
			if (nb_transfer % 100 == 0)
			{
				for (int i = 0; i < wtpcap_dumps.size(); i++){
					pcap_dump_flush(wtpcap_dumps[i]);
				}
			}
		}
		else
		{
			break;
		}
	}
	//关闭pcap句柄
	for (int i = 0; i < wtpcap_dumps.size(); i++){
		pcap_dump_flush(wtpcap_dumps[i]);
		if (wtpcap_dumps[i])
		{
			pcap_dump_close(wtpcap_dumps[i]);
		}
		if (_wtpcaps[i]){
			pcap_close(_wtpcaps[i]);
		}
	}
	if (rdpcap)
	{
		pcap_close(rdpcap);
	}
	return nb_transfer;
}
int main(int argc,char *argv[])
{
	//splitpcaps("C:\\Users\\dk\\splitpcap\\vsrc\\Debug\\nat.pcap","nat",10);
	//system("pause");
	//return 0;

	if (argc != 4)
	{
		printf("Split large PCAP file into multi smaller PCAP pieces.\n");
		printf("Usage:\n\t splitpcap src_pcapname dst_dir piece_num\n"\
			"\t\t src_pcapname: The src pcap to be splitted.\n"\
			"\t\t dst_dir: The dst directory to save the PCAP pieces\n"\
			"\t\t piece_num: The number of pieces pcaps.\n\n");
		exit(-1);
	}
	
	char * pcapname = argv[1];
	char * dst_dir = argv[2];
	int piece_num = atoi(argv[3]);

	if (splitpcaps(pcapname, dst_dir,piece_num) <0 )
	{
			printf("Error!!!!%s\n", pcapname);
	}

	//system("pause");
	return 0;
}

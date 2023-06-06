#include <util.h>
#define PCAPDIR "C:\\Users\\jmh081701\\Documents\\apcap\\pcap"
int main()
{
	char pcapname[] = PCAPDIR"\\gs\\wenz\\wenz3.pcap";
	pcap_gather gather = pcap_gather(pcapname);
	//gather.set_filter("not nbns and not llmnr and not ssdp");
	pcapname[strlen(pcapname) - 4] = 't';
	pcapname[strlen(pcapname) - 3] = 'x';
	pcapname[strlen(pcapname) - 2] = 't';
	pcapname[strlen(pcapname) - 1] = 0;
	freopen(pcapname,"w", stdout);
	int packetno = 1;
	while (true)
	{
		_packet packet;
		gather.get_next_packet(&packet);
		//gather.display(packet.data, packet.len);
		
		//if (packetno == 451)
		//{
		//	printf("attention...\n");
		//}
		//printf("Packet Number:%d\n", packetno++);
		if (packet.data && packet.len)
		{
			ethII_header eth = eth_parser(packet.data);

			if (eth.type == 0x0800)
				//ip Ð­Òé
			{
				ip_header ip = ip_parser(packet.data + sizeof(ethII_header));
				if (ip.proto == 0x11)
					//udp
				{
					udp_header udp = udp_parser(packet.data + sizeof(ethII_header)+4 * (ip.ver_ihl & 0xF));
				}
				else if (ip.proto == 0x06)
					//tcp
				{
					tcp_header tcp = tcp_parser(packet.data + sizeof(ethII_header)+4 * (ip.ver_ihl & 0xF));
					if (tcp.sport == 80 || tcp.dport == 80)
						//½âÎöhttp
					{
						http_header http = http_parser(packet.data + sizeof(ethII_header)+4 * (ip.ver_ihl & 0xF) + 4 * ((tcp.tcpHeader_reserve & 0xF0) >> 4), packet.data + packet.len);
						if (http.ContentType)
						{
							free(http.ContentType);
						}
						if (http.Host)
						{
							free(http.Host);
						}
						if (http.UA)
						{
							free(http.UA);
						}
						if (http.URL)
						{
							free(http.URL);
						}
					}
					if (tcp.sport == 443 || tcp.dport == 443)
					{
						
						https_header https = https_parser_rough(packet.data + sizeof(ethII_header)+4 * (ip.ver_ihl & 0xF) + 4 * ((tcp.tcpHeader_reserve & 0xF0) >> 4), packet.data + packet.len, ip.saddr, tcp.sport, ip.daddr, tcp.dport, tcp.sequence);
						if (https.sever_name)
						{
							free(https.sever_name);
						}
						for (int i=0; i<https.certs.size(); i++)
						{
							if (https.certs[i].issuer)
							{
								free(https.certs[i].issuer);
							}
							if (https.certs[i].subj)
							{
								free(https.certs[i].subj);
							}
							if (https.certs[i].not_after)
							{
								free(https.certs[i].not_after);
							}
							if (https.certs[i].not_before)
							{
								free(https.certs[i].not_before);
							}
						}
					}
				}
			}
			if (packet.data)
			{
				free(packet.data);
			}
		}
		else
		{
			printf("Analyse Over...\n");
			break;
		}
	}
	//system("pause");
	return 0;
}
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "pcap-test.h"

void usage()
{
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct
{
	char *dev_;
} Param;

Param param = {
	.dev_ = NULL};

bool parse(Param *param, int argc, char *argv[])
{
	if (argc != 2)
	{
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char *argv[])
{
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL)
	{
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true)
	{
		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0)
			continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		// printf("%u bytes captured\n", header->caplen);
		//  Ethernet Header
		struct libnet_ethernet_hdr *eth = (struct libnet_ethernet_hdr *)packet;

		if (ntohs(eth->ether_type) != ETHERTYPE_IP)
		{
			// printf("[-] Not an IP packet\n");
			continue;
		}

		// IP Header
		struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));

		if (ip->ip_p != IPPROTO_TCP)
		{
			//	printf("[-] Not a TCP packet\n");
			continue;
		}

		// IP 헤더 길이는 4비트 필드 × 4byte
		int ip_header_len = ip->ip_hl * 4;

		// TCP Header
		struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *)((u_char *)ip + ip_header_len);

		// 출력
		printf("Ethernet: Src MAC: %02x:%02x:%02x:%02x:%02x:%02x, Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
			   eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
			   eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5],
			   eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
			   eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

		printf("IP: %s ->",
			   inet_ntoa(ip->ip_src));
		printf("%s\n", inet_ntoa(ip->ip_dst));
		printf("TCP Port: %d -> %d\n",
			   ntohs(tcp->th_sport), ntohs(tcp->th_dport));
		int tcp_header_len = tcp->th_off * 4;
		const u_char *payload = (u_char *)tcp + tcp_header_len;
		int payload_len = header->caplen - (payload - packet);
		// printf("%d",payload_len);
		if (payload_len > 20)
			payload_len = 20;

		printf("Payload (max 20 bytes): ");
		for (int i = 0; i < payload_len; i++)
			printf("%02x ", payload[i]);
		printf("\n\n\n");
	}

	pcap_close(pcap);
}

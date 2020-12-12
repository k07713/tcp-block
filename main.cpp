#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <libnet.h>

#define SIZE_ETHERNET 14
#define IP_HL(ip) (((ip)->ip_hl) & 0x0f)
#define TH_OFF(th) (((th)->th_off & 0xf0) >> 4)

void usage(){
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block enp0s5 \"Host: test.gilgil.net\"\n");
}

bool check(const u_char *packet, char *pattern){
	struct libnet_ethernet_hdr *ethernet = (struct libnet_ethernet_hdr*)packet;
    struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr*)(packet + SIZE_ETHERNET);
    struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr*)(packet + SIZE_ETHERNET + IP_HL(ip)*4);

    if(ethernet->ether_type != 0x0008) return false;
    if(ip->ip_p != 0x06) return false;

	char *payload = (char *)(packet + SIZE_ETHERNET + IP_HL(ip)*4 + TH_OFF(tcp)*4);
	int payload_len = ntohs(ip->ip_len) - (IP_HL(ip)*4 + TH_OFF(tcp)*4);
    int pattern_size = strlen(pattern);

    for(int i=0; i<payload_len; i++){
        if(!strncmp(payload+i, pattern, pattern_size)) return true;
    }
    return false;
}

uint32_t sum_(uint32_t x, uint32_t y)
{
    uint32_t ans = x+y;
    if(ans > 0xffff) ans += 1;
    ans &= 0xffff;
    return ans;
}

void TcpChecksum(const u_char *packet){
    struct libnet_ethernet_hdr *ethernet = (struct libnet_ethernet_hdr*)packet;
    struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr*)(packet + SIZE_ETHERNET);
    struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr*)(packet + SIZE_ETHERNET + IP_HL(ip)*4);

	char *payload = (char *)(packet + SIZE_ETHERNET + IP_HL(ip)*4 + TH_OFF(tcp)*4);
	int payload_len = ntohs(ip->ip_len) - (IP_HL(ip)*4 + TH_OFF(tcp)*4);

    uint32_t sum = 0;
    sum = sum_(sum, ip->ip_src.s_addr >> 16);
    sum = sum_(sum, ip->ip_src.s_addr & 0xffff);
    sum = sum_(sum, ip->ip_dst.s_addr >> 16);
    sum = sum_(sum, ip->ip_dst.s_addr & 0xffff);
    sum = sum_(sum, ip->ip_p << 8);
    sum = sum_(sum, htons(TH_OFF(tcp)*4 + payload_len));

    uint32_t sum1 = 0;
    u_char *data = (u_char *)tcp;
    for(int i = 0; i < TH_OFF(tcp)*4 + payload_len; i += 2){
        sum1 = sum_(sum1, (data[i]) + (data[i+1] << 8));
    }
    tcp->th_sum = sum_(sum, sum1) ^ 0xffff;
}

void IpChecksum(const u_char *packet){
	struct libnet_ethernet_hdr *ethernet = (struct libnet_ethernet_hdr*)packet;
    struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr*)(packet + SIZE_ETHERNET);
    struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr*)(packet + SIZE_ETHERNET + IP_HL(ip)*4);

	char *payload = (char *)(packet + SIZE_ETHERNET + IP_HL(ip)*4 + TH_OFF(tcp)*4);
	int payload_len = ntohs(ip->ip_len) - (IP_HL(ip)*4 + TH_OFF(tcp)*4);

    uint32_t sum = 0;
    u_char *data = (u_char *)ip;
    for(int i=0; i<IP_HL(ip)*4; i+=2){
        sum = sum_(sum, (data[i]) + (data[i+1]<<8));
    }
    ip->ip_sum = sum ^ 0xffff;
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return -1;
	}

    char *dev = argv[1];
    char *pattern = argv[2];
    
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    while(1){
		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0) continue;
		if(res == -1 || res == -2) break;
        if(check(packet, pattern)){
            
            struct libnet_ethernet_hdr *ethernet = (struct libnet_ethernet_hdr*)packet;
            struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr*)(packet + SIZE_ETHERNET);
            struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr*)(packet + SIZE_ETHERNET + IP_HL(ip)*4);

            char *payload = (char *)(packet + SIZE_ETHERNET + IP_HL(ip)*4 + TH_OFF(tcp)*4);
            int payload_len = ntohs(ip->ip_len) - (IP_HL(ip)*4 + TH_OFF(tcp)*4);

            tcp->th_flags |= 4;
            int DataSize = payload_len;
            payload[0] = '\0';
            payload_len = strlen(payload);

            ip->ip_len = htons(IP_HL(ip)*4 + TH_OFF(tcp)*4 + payload_len);
            header->caplen = 14 + IP_HL(ip)*4 + TH_OFF(tcp)*4 + payload_len;
            tcp->th_seq = ntohl(htonl(tcp->th_seq) + DataSize);

            IpChecksum(packet);
            TcpChecksum(packet);

            int res = pcap_sendpacket(handle, packet, header->caplen);
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                continue;
            }

            tcp->th_flags &= tcp->th_flags^4;
            tcp->th_flags |= 1;

            strcpy(payload, "blocked!!!");
            payload_len = 10;
            ip->ip_len = htons(IP_HL(ip)*4 + TH_OFF(tcp)*4 + payload_len);
            header->caplen = 14 + IP_HL(ip)*4 + TH_OFF(tcp)*4 + payload_len;
            
            tcp_seq tmp = tcp->th_seq;
            tcp->th_seq = tcp->th_ack;
            tcp->th_ack = tmp;
            
            for(int i=0; i< 6 ; i++){
                u_char tmp1 = ethernet->ether_dhost[i];
                ethernet->ether_dhost[i] = ethernet->ether_shost[i];
                ethernet->ether_shost[i] = tmp1;
            }   
            
        	struct in_addr tmp2 = ip->ip_dst;
            ip->ip_dst = ip->ip_src;
            ip->ip_src = tmp2;

        	uint16_t tmp3 = tcp->th_dport;
            tcp->th_dport = tcp->th_sport;
            tcp->th_sport = tmp3;

            IpChecksum(packet);
            TcpChecksum(packet);

            res = pcap_sendpacket(handle, packet, header->caplen);
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                continue;
            }
        }
    }
    return 0;
}
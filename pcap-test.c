#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>

#define ethernet_header_size 14
#define ip_header_common_size 20
#define tcp_header_common_size 20

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
	
	//+++++
	typedef struct ethernet_header{
		uint8_t ethernet_arr[ethernet_header_size];
	}ethernet_hdr;
	
	typedef struct ip_header{
		uint8_t ip_arr[ip_header_common_size];
	}ip_hdr;

	typedef struct tcp_header{
		uint8_t tcp_arr[tcp_header_common_size];
	}tcp_hdr;

	typedef struct Payload{
		uint8_t payload_arr[20];
	}payload_hdr;
	//+++++
	
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;

		//+++++
		ethernet_hdr* ethernet;
		ip_hdr* ip;
		tcp_hdr* tcp;
		payload_hdr* payload;
		//+++++

		int res = pcap_next_ex(pcap, &header, &packet);
		//About pcap_next_ex()'s 2nd parameter..
		//"struct pcap_pkthdr" has packet's Time Stamp and Length Values
		//"header" is saving the address of packet's Time Stamp and Length Values
		//So "header" can point(->) packet's Time Stamp and Length Values directly
		//And "&header" is the address of "header"
		//
		//About pcap_next_ex()'s 3rd parameter..
		//"packet" is saving the address of packet's first byte
		//And "&packet" is the address of "packet"

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		//+++++
		ethernet = (ethernet_hdr*) packet;
		//Change the form of pointer("packet"): u_char* -> ethernet_hdr*
		//No matter at all. Because it is "pointer".
		
		printf("\n\n\n<Ethernet Header>\n");
		printf("src mac: ");
		for(uint32_t i=6; i<12; i++){
		printf("%02X ", ethernet->ethernet_arr[i]);
		}
		printf("\ndst mac: ");
		for(uint32_t i=0; i<6; i++){
		printf("%02X ", ethernet->ethernet_arr[i]);
		}


		ip = (ip_hdr*) (packet+ethernet_header_size);
		//Change the form of pointer("packet"): u_char* -> id_hdr*
		//No matter at all. Because it is "pointer".

		if(ip->ip_arr[9] != 6){
			printf("\nNah..this is not a TCP packet..");
			continue;
		}

		uint32_t ip_header_real_size = (ip->ip_arr[0]&0x0f)*4;

		printf("\n\n<IP Header>\n");
		printf("src ip: ");
		for(uint32_t i=12; i<16; i++){
		printf("%02X ", ip->ip_arr[i]);
		}
		printf("\ndst ip: ");
		for(uint32_t i=16; i<20; i++){
		printf("%02X ", ip->ip_arr[i]);
		}


		tcp = (tcp_hdr*) (packet+ethernet_header_size+ip_header_real_size);
		//Change the form of pointer("packet"): u_char* -> tcp_hdr*
		//No matter at all. Because it is "pointer".

		printf("\n\n<TCP Header>\n");
		printf("src port: ");

		uint32_t tcp_header_real_size = ((tcp->tcp_arr[12]>>4)&0x0f)*4;

		for(uint32_t i=0; i<2; i++){
		printf("%02X ", tcp->tcp_arr[i]);
		}
		printf("\ndst port: ");
		for(uint32_t i=2; i<4; i++){
		printf("%02X ", tcp->tcp_arr[i]);
		}

		uint32_t data_length = (header->caplen) - (ethernet_header_size+ip_header_real_size+tcp_header_real_size);

		if(data_length > 0 && data_length < 21){
		payload = (payload_hdr*) (packet+ethernet_header_size+ip_header_real_size+tcp_header_real_size);
		printf("\n\n<Payload>\n");
		printf("data: ");
		for(uint32_t i=0; i<data_length; i++){
			printf("%02X ", payload->payload_arr[i]);
		}
		}

		else if(data_length > 20){
		payload = (payload_hdr*) (packet+ethernet_header_size+ip_header_real_size+tcp_header_real_size);
		printf("\n\n<Payload>\n");
		printf("data: ");
		for(uint32_t i=0; i<20; i++){
			printf("%02X ", payload->payload_arr[i]);
		}
		}

		else{
			printf("\n\n<Payload>\n");
			printf("No data!");
		}


		printf("\n");
		//+++++
	}
	pcap_close(pcap);
}

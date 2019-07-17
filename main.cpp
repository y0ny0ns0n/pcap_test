#include <pcap.h>
#include <stdio.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

typedef struct frame_h {
    u_char dst_mac[6];
    u_char src_mac[6];
    u_short type;
    u_char reserved2;    // Header Length
    u_char reserved3;    // Differentiated Services Codepoint
    u_char reserved4;    // Explicit Congestion Notification
    u_char reserved5;    // Total Length
    u_short reserved6;   // Identification
    u_short reserved7;   // Flags
    u_char TTL;
    u_char proto;
    u_short reserved10;  // Header checksum
    u_char src_ip[4];
    u_char dst_ip[4];
    u_short src_port;
    u_short dst_port;
    u_char reserved11[4]; // etc1
    u_char reserved12[4]; // etc2
    u_char reserved13;    // etc3
    u_char reserved14;    // etc4
    u_short reserved15;   // Window size value
    u_short reserved16;   // Checksum
    u_short reserved17;   // Urgent Pointer
} frame_h;

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  puts("=================================================================");
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    frame_h* frm;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    frm = (frame_h *)packet;

    printf("Total length = %d\n", header->caplen);
    printf("eth.smac = %02x:%02x:%02x:%02x:%02x:%02x\n", frm->src_mac[0], frm->src_mac[1], frm->src_mac[2], frm->src_mac[3], frm->src_mac[4], frm->src_mac[5]);
    printf("eth.dmac = %02x:%02x:%02x:%02x:%02x:%02x\n", frm->dst_mac[0], frm->dst_mac[1], frm->dst_mac[2], frm->dst_mac[3], frm->dst_mac[4], frm->dst_mac[5]);
    if(frm->type == 0x0008) // IPV4
	{
	    printf("ip.sip = %d.%d.%d.%d\n", frm->src_ip[0], frm->src_ip[1], frm->src_ip[2], frm->src_ip[3]);
	    printf("ip.dip = %d.%d.%d.%d\n", frm->dst_ip[0], frm->dst_ip[1], frm->dst_ip[2], frm->dst_ip[3]);
        if(frm->proto == 0x06) // TCP
        {
		    printf("tcp.sport = %d\n", frm->src_port);
		    printf("tcp.dport = %d\n", frm->dst_port);
		
		    if(header->caplen <= sizeof(frame_h))
            {
		        puts("[!] No TCP data!");
            }
		    else {
                for(int i = 0; (i < (header->caplen - sizeof(frame_h))) && (i < 10); i++) {
                    printf("%02x ", *(unsigned char *)(&packet+sizeof(frame_h)+i));
                }
                putchar('\n');
		    }
        }
        else {
            printf("[!] 0x%02x is not TCP packet\n", frm->proto);
        }
    }
    else {
        printf("[!] 0x%04x is not IPv4\n", frm->type);
    }

    puts("=================================================================");
  }

  pcap_close(handle);
  return 0;
}

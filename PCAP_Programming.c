#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

/* Ethernet 헤더 */
struct ethheader {
  u_char  ether_dhost[6]; /* 목적지 호스트 주소 */
  u_char  ether_shost[6]; /* 출발지 호스트 주소 */
  u_short ether_type;     /* 프로토콜 타입 (IP, ARP, RARP 등) */
};

/* IP 헤더 */
struct ipheader {
  unsigned char      iph_ihl:4, //IP 헤더 길이
                     iph_ver:4; //IP 버전
  unsigned char      iph_tos; //서비스 타입
  unsigned short int iph_len; //IP 패킷 길이 (데이터 + 헤더)
  unsigned short int iph_ident; //식별자
  unsigned short int iph_flag:3, //프래그먼트 플래그
                     iph_offset:13; //플래그 오프셋
  unsigned char      iph_ttl; //TTL
  unsigned char      iph_protocol; //프로토콜 타입
  unsigned short int iph_chksum; //IP 데이터그램 체크섬
  struct  in_addr    iph_sourceip; //출발지 IP 주소
  struct  in_addr    iph_destip;   //목적지 IP 주소
};

/* TCP 헤더 */
struct tcpheader {
  unsigned short int tcp_sport; //출발지 포트
  unsigned short int tcp_dport; //목적지 포트
  unsigned int       tcp_seq;   //시퀀스 번호
  unsigned int       tcp_ack;   //승인 번호
  unsigned char      tcp_reserved:4, //예약 공간 중 4비트
                     tcp_offset:4;    //TCP 데이터 오프셋 (리틀 엔디언)
  unsigned char      tcp_flags;      //TCP 플래그 (그리고 예약 공간 중 2비트)
  unsigned short int tcp_window;     //TCP 윈도우 크기
  unsigned short int tcp_checksum;   //TCP 체크섬
  unsigned short int tcp_urgentptr;  //TCP 긴급 포인터
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800은 IP 타입
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    if (ip->iph_protocol == IPPROTO_TCP) { // 프로토콜이 TCP인지 확인
      struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4));

      printf("Ethernet 헤더:\n");
      printf("   출발지 MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
      printf("   목적지 MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

      printf("IP 헤더:\n");
      printf("   출발지 IP: %s\n", inet_ntoa(ip->iph_sourceip));
      printf("   목적지 IP: %s\n", inet_ntoa(ip->iph_destip));

      printf("TCP 헤더:\n");
      printf("   출발지 포트: %d\n", ntohs(tcp->tcp_sport));
      printf("   목적지 포트: %d\n", ntohs(tcp->tcp_dport));

      // TCP 메시지의 일부를 출력
      printf("메시지:\n");
      int data_len = ntohs(ip->iph_len) - (ip->iph_ihl * 4) - (tcp->tcp_offset * 4);
      int max_data_len = data_len < 10 ? data_len : 10; // 최대 10바이트의 데이터 출력
      printf("   \n");
      for (int i = 0; i < max_data_len; ++i) {
        printf("%02x ", packet[sizeof(struct ethheader) + (ip->iph_ihl * 4) + (tcp->tcp_offset * 4) + i]);
      }
      printf("\n");
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: enp0s3와 같은 이름의 NIC에서 라이브 pcap 세션 열기
  handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

  // Step 2: filter_exp를 BPF 의사 코드로 컴파일
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: 패킷 캡처
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   // 핸들 닫기
  return 0;
}

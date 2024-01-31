// 비콘프레임 생성 및 전송모듈
#include "beacon_frame.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib> 
#include <pcap.h>
#include <chrono>
#include <unistd.h>
// 비콘프레임 추출

bool Distinguish_Beacon(const uint8_t *packet) {
    radiotap_header *radio_hdr = (radiotap_header *)packet;
    uint16_t radiotap_header_length = radio_hdr->len;
    uint8_t type_subtype = packet[radiotap_header_length];
    uint8_t type = (type_subtype & 0x0C) >> 2;    // 타입 필드
    uint8_t subtype = (type_subtype & 0xF0) >> 4; // 서브타입 필드
    if (type == 0 && subtype == 8) {
        printf("Beacon Frame Captured\n");
        return true;
    }
    else{
        return false;
    }
}

uint8_t find_beacon_channel(const struct pcap_pkthdr *header, const u_char *packet) 
{
    radiotap_header *radio_hdr = (radiotap_header *)packet;
    int offset = radio_hdr->len;

    uint8_t *wireless_tagged_frame = (uint8_t *)(packet + offset + 24 + 12);
    Tag_SSID * ssid = (Tag_SSID *)wireless_tagged_frame;
    wireless_tagged_frame += (2 + ssid->tag_length);

    Tag_Supported_Rates * rates = (Tag_Supported_Rates *)wireless_tagged_frame;
    wireless_tagged_frame += (2 + rates->tag_length);

    Tag_DS * ds = (Tag_DS *)wireless_tagged_frame;
    uint8_t channel = ds->channel;
    printf("channel: %d\n", channel);
    return channel;
}


uint8_t find_csa_insertion_location(const struct pcap_pkthdr *header, const u_char *packet) {
    radiotap_header *radio_hdr = (radiotap_header *)packet;
    int offset = radio_hdr->len;

    uint8_t basement = offset + 24 + 12;

    while(1)
    {
        uint8_t num = *(packet + basement);
        printf("현재번호:%d\n", num);

        if(num > 37)
        {
            return basement; 
        }

        uint8_t length = *(packet + basement + 1);
        basement += (2+ length);

    }
    return basement;
}

// SSID 위치 찾기
int find_destination_mac(const uint8_t *packet, int packet_len) {

    radiotap_header *radio_hdr = (radiotap_header *)packet;
    int radio_len = radio_hdr->len;

    int offset = radio_len + 4;
    return offset;
}

int find_source_mac(const uint8_t *packet, int packet_len) {

    radiotap_header *radio_hdr = (radiotap_header *)packet;
    int radio_len = radio_hdr->len;

    int offset = radio_len + 4 + 6;
    return offset;
}


uint8_t* insert_broadcast_csa_tag(const uint8_t *packet, int packet_len, const uint8_t* ap_mac, uint8_t target_location, uint8_t new_channel_num ) {
    
    // 패킷 복사
    int new_packet_len = packet_len + 5;
    uint8_t *new_packet = (uint8_t *)malloc(new_packet_len);
    if (!new_packet) return NULL;


    memcpy(new_packet, packet, packet_len);

    // 맥주소 위치찾기 + 삽입
    int source_mac_loc = find_source_mac(new_packet, packet_len);
    int destination_mac_loc = find_destination_mac(new_packet, packet_len);
    
    const uint8_t station_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    memcpy(new_packet + source_mac_loc, ap_mac, 6);
    memcpy(new_packet + destination_mac_loc, station_mac, 6);



    // csa 정보 위치찾기 + 삽입
    const uint8_t csa_info[] = {0x25, 0x03, 0x01, new_channel_num, 0x03};
    
    //넣으면서 올바르게 이동시켜줌
    memmove(new_packet + target_location + 5, new_packet + target_location, packet_len - target_location);
    memcpy(new_packet + target_location, csa_info, 5);

    return new_packet;
}

uint8_t* insert_unicast_csa_tag(const uint8_t *packet, int packet_len, const uint8_t* ap_mac, const uint8_t* station_mac, uint8_t target_location, uint8_t new_channel_num ) {
    
    // 패킷 복사
    int new_packet_len = packet_len + 5;
    uint8_t *new_packet = (uint8_t *)malloc(new_packet_len);
    if (!new_packet) return NULL;

    memcpy(new_packet, packet, packet_len);

    // 맥주소 위치찾기 + 삽입
    int source_mac_loc = find_source_mac(new_packet, packet_len);
    int destination_mac_loc = find_destination_mac(new_packet, packet_len);
    
    memcpy(new_packet + source_mac_loc, ap_mac, 6);
    memcpy(new_packet + destination_mac_loc, station_mac, 6);

    // csa 정보 위치찾기 + 삽입
    const uint8_t csa_info[] = {0x25, 0x03, 0x01, new_channel_num, 0x03};
    
    //넣으면서 올바르게 이동시켜줌
    memmove(new_packet + target_location + 5, new_packet + target_location, packet_len - target_location);
    memcpy(new_packet + target_location, csa_info, 5);

    return new_packet;
}

void send_csa_packet(uint8_t * csa_packet, pcap_t *handle, int length)
{
    printf("%d\n", sizeof(csa_packet));
    while(1)
    {
        pcap_sendpacket(handle, csa_packet, length);
        sleep(0.5); 

    }
    pcap_close(handle);
}
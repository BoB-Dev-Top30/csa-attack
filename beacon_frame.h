#include <cstdint>
#include <cstdio>
#include <vector>
#include <pcap.h>
#include <chrono>

#include <mutex>
#include <condition_variable>

extern std::mutex mtx;
extern std::condition_variable cv;
extern bool ready;





///////////////////////////// 라디오헤더 ////////////////////////
// radio 헤더 구조체
typedef struct {
    uint8_t version;
    uint8_t pad;
    uint16_t len;
}radiotap_header;


///////////////////////////비콘 프레임////////////////////////////
// beacon 프레임 구조체
typedef struct{
    uint8_t beacon_frame;
    uint8_t flags;
    uint16_t duration;
    uint8_t destination_address[6];
    uint8_t source_address[6];
    uint8_t bss_id[6];
    uint16_t fragment_sequence_number; // 한꺼번에(no need)
}beacon_frame;


///////////////////////////Wireless Management/////////////////////////
// SSID 구조체

#define SSID_MAX_LEN 32 //ssid의 최대길이
typedef struct{
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t ssid[SSID_MAX_LEN];

} Tag_SSID;

// Supported rates(MB) 구조체
typedef struct{
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t *rates;
    // supported rates가 가변길이여서 뒤는 length 보고 결정된다. 여기랑 extended에서 최댓값 구해야함 

} Tag_Supported_Rates;

// DS파트구조체
typedef struct{
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t channel;

} Tag_DS;

//RSN파트 구조체(security)
// 전반부, 중반부, 후반부를 나눈 이유는 가변길이가 중간에 하나 섞이기 때문이다.
typedef struct{
    uint8_t tag_number;
    uint8_t tag_length;
    uint16_t rsn_version;
    uint32_t group_cipher; // 그룹 암호화 알고리즘
    uint16_t pairwise_cipher_count; // 페어와이즈 암호화 알고리즘의 수
}Tag_RSN_Information_Front;

typedef struct{
    uint32_t * pairwise_cipher_list; // 페어와이즈 암호화 알고리즘 리스트(가변길이)
    uint16_t auth_key_mngt_count; // 인증 방법의 수
} Tag_RSN_Information_Middle;

typedef struct{
    uint32_t * auth_key_mngt_list; // 인증 방법 리스트(가변길이)
    uint16_t rsn_capabilities; // RSN 능력
} Tag_RSN_Information_Back;

// Extended_Supported_Rates (MB)
typedef struct{
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t * rates;
    // supported rates가 가변길이여서 뒤는 length 보고 결정된다. 여기랑 extended에서 최댓값 구해야함 

} Tag_Extended_Supported_Rates;

// Traffic_Indication_Map
typedef struct{
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t DTIM_count;
    uint8_t DTIM_period;
    uint8_t bitmap;
    uint8_t * virtual_bitmap; // 가변
} Tag_Traffic_Indication_Map;

//ERP Information
typedef struct{
    uint8_t tag_number;
    uint8_t tag_length;
    uint8_t erp_information;
} Tag_ERP_Information;

// wireless management 구조체
struct wireless_management{
    uint8_t fixed_parameter[12];
    Tag_SSID SSID;
    Tag_Supported_Rates Rates;
    Tag_DS DS;
    Tag_Traffic_Indication_Map TIM;
    Tag_ERP_Information ERP_INFO;
    Tag_Extended_Supported_Rates E_Rates;
    uint8_t ht_capabilities[28]; //고정
    uint8_t ht_information[24]; //고정
    Tag_RSN_Information_Front r_f;
    Tag_RSN_Information_Middle r_m;
    Tag_RSN_Information_Back r_b;

};

/////////////////////////최종 비콘 프레임//////////////////////////
// 출력용 비콘 프레임 구조체
struct airodump_beacon{
    uint8_t BSSID [6];
    int PWR;
    int BEACONS;
    uint8_t CH;
    uint8_t *ESSID; //가변
};

//함수 선언//
bool Distinguish_Beacon(const uint8_t *packet);
uint8_t find_beacon_channel(const struct pcap_pkthdr *header, const u_char *packet);
uint8_t find_csa_insertion_location(const struct pcap_pkthdr *header, const u_char *packet);
uint8_t* insert_broadcast_csa_tag(const uint8_t *packet, int packet_len, const uint8_t* ap_mac, uint8_t target_location, uint8_t new_channel_num);
void send_csa_packet(uint8_t * csa_packet, pcap_t *handle, int length);

/*
int find_ssid_position(const uint8_t *packet, int packet_len);
uint8_t* find_wireless_static(const uint8_t *packet, int *ssid_length);
uint8_t* modify_beacon_ssid(const uint8_t *packet, int packet_len, const char* new_ssid);
void send_packet(pcap_t* handle, const uint8_t* packet, int length);
*/
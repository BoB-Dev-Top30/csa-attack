#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

int choose_csa(int argc, char * argv[])
{
    switch(argc) {

        // 입력값 부족
        case 2:
            fprintf(stderr, "Usage: %s or <interface> or <ap_mac>\n", argv[0]);
            return 1;

        //올바른 맥값 넣었는지 검증필요(추후구현)

        // 브로드캐스트
        case 3:
            printf("---------CSA-Attack---------\n");
            printf("<Broadcast>\n");
            return 2;

        
        case 4:

            // 양쪽 전송
            printf("---------CSA-Attack---------\n");
            printf("<ap_mac>: %s -> <station_mac>: %s \n", argv[2], argv[3]);
            printf("<station_mac>: %s -> <ap_mac>: %s \n", argv[3], argv[2]);
            return 3;
        
        // 초과 입력
        default:
            fprintf(stderr, "Less Input Please!\n");
            return 4;
    }
}

uint8_t find_attack_channel(int channel_num)
{
     switch(channel_num) {

        // 입력값 부족
        case 1: return 0x0D;
        case 2: return 0x0D;
        case 3: return 0x0D;
        case 4: return 0x0D;
        case 5: return 0x0D;
        case 6: return 0x0D;
        case 7: return 0x0D;
        case 8: return 0x01;
        case 9: return 0x01;
        case 10: return 0x01;
        case 11: return 0x01;
        case 12: return 0x01;
        case 13: return 0x01;
        default: return 0;
     }

}

void convert_mac_address(const char *mac_str, uint8_t *mac_array) {
    sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
           &mac_array[0], &mac_array[1], &mac_array[2], 
           &mac_array[3], &mac_array[4], &mac_array[5]);
}

// 모니터 모드 자동 실행
void start_monitor_mode(char *interface) {
    char command[100];
    sprintf(command, "sudo gmon %s", interface);
    system(command);
}

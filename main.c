#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>
#include <pcap.h>

#include "main.h"

// bob11 $IN$A

radiotap_header * radiotap;
ieee80211_header * ieee80211;

int channel = 1;
long long time_count = 0;
int elapsed =  0;

void usage() {
    printf("syntax : signal-strength <interface> <mac>\n");
    printf("sample : signal-strength mon0 00:11:22:33:44:55\n");
}

typedef struct { // skeleton
    char * dev_;
    char * AP_MAC_Addr_;
} Param;

Param param = { // skeleton
    .dev_ = NULL,
    .AP_MAC_Addr_ = NULL
};

bool parse(Param * param, int argc, char * argv[]) { // skeleton
    
    if (argc != 3) {
        usage();
        return false;
    }
    param->dev_ = argv[1]; // NIC 담기
    param->AP_MAC_Addr_ = argv[2]; // mac addr 담기
    return true;
}

void print_mac(uint8_t * MAC_address) {
    if (!memcmp(MAC_address, "\x00\x00\x00\x00\x00\x00", 6)) {
        printf(" (not associated)  ");
    }
    else {
        printf(" %02X:%02X:%02X:%02X:%02X:%02X ", MAC_address[0], MAC_address[1], MAC_address[2], MAC_address[3], MAC_address[4], MAC_address[5]);
    }
}

long long tickCount()
{
    struct timeval te; 
    gettimeofday(&te, NULL);
    long long milliseconds = te.tv_sec*1000LL + te.tv_usec/1000;
    return milliseconds;
}



void * timer(void * dev) {
    while(1) {
        char cmd[255];
        if (tickCount() - time_count > 1000) {    // Every Second
            time_count = tickCount();
            elapsed++;

            /* channel hopping */
            snprintf(cmd, sizeof(cmd), "iwconfig %s channel %d", (char *)dev, channel);
            system(cmd);

            //display();

            if (channel <= 13) channel++;
            else channel = 0;
        }
    }
}



int main(int argc, char * argv[]) {

    struct pcap_pkthdr * header;
    const u_char * packet;
    int res;
    
    pthread_t p_thread;
    int thr_id;
    int pwr = -1;
    int tmp = -1;
    uint8_t AP_MAC[6];
    uint8_t Src_Addr[6];
    uint8_t Dst_Addr[6];
    uint8_t Trans_Addr[6];
    uint8_t Recv_Addr[6];

    // skeleton
    if (!parse(&param, argc, argv))
        return -1;

    // skeleton
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t * pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf); // exception
        return -1;
    };

    thr_id = pthread_create(&p_thread, NULL, timer, (void *)argv[argc-2]);

    //결국 frame1이든 frame2든 ta는 BSSID와 동일하다.

    printf("\n\nPWR     BSSID\n\n");

    while(true) {

        res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        else if (res == -1 || res == -2) break;

        radiotap = (radiotap_header *)packet;
        ieee80211 = (ieee80211_header *)(packet + radiotap->length);
        
        //:는 포맷
        sscanf(param.AP_MAC_Addr_, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &AP_MAC[0], &AP_MAC[1], &AP_MAC[2], &AP_MAC[3], &AP_MAC[4], &AP_MAC[5]);

        //printf("Ok\n");
        //printf("%hhn\n", ieee80211->bssid_addr);
        //print_mac()
        if(!memcmp(AP_MAC, ieee80211->bssid_addr, sizeof(AP_MAC))) {

            if(tmp > pwr) {
                printf("down\n");
            }
            else if (tmp == pwr) {
                printf("-\n");
            }
            else {
                printf("up\n");
            }
            tmp = pwr;

            //printf("ok\n");

            /*
            // ta가 sa랑 같은 경우 -> frame 1 , sa - AA, da - CC, ta - AA, ra - BB ; ra = ap addr
            if (!memcmp(ieee80211->source_addr, ieee80211->bssid_addr, sizeof(ieee80211->bssid_addr))) {
                memcpy(Src_Addr, ieee80211->bssid_addr, sizeof(Src_Addr));
                memcpy(Dst_Addr, ieee80211->destination_addr, sizeof(Dst_Addr));
                memcpy(Trans_Addr, ieee80211->bssid_addr, sizeof(Trans_Addr));
                memcpy(Recv_Addr, ieee80211->destination_addr, sizeof(Recv_Addr)); //어케나타냄;

                
                //print_mac(Src_Addr);
            }
            else {  // ta가 sa랑 다른 경우 -> frame2 sa - AA, da - CC, ta - BB, ra - CC
                memcpy(Src_Addr, ieee80211->source_addr, sizeof(Src_Addr));
                memcpy(Dst_Addr, ieee80211->destination_addr, sizeof(Dst_Addr));
                memcpy(Trans_Addr, ieee80211->bssid_addr, sizeof(Trans_Addr));
                memcpy(Recv_Addr, ieee80211->destination_addr, sizeof(Recv_Addr));
                
            }
            */

            int p_cnt = 1;
            
            // radiotap present flag의 ext(extension)이 설정되어 있다면 p_cnt 증가
            if ((radiotap->present_flag & (1 << 31)) >> 31) {
                p_cnt = 2;
            }
            

            uint8_t * flag_ptr = (uint8_t *)&(radiotap->present_flag) + (4 * p_cnt); // present_flag offset을 계산해줄 flag_ptr
            uint8_t data_rate = 0;

            // data_rate와 pwr을 가져오기 위해선 활성화 되어 있는 필드들을 건너 뛰어 주는 것이 필요
            // present flag로 rate, pwr 계산
            for (uint32_t pflag = 0; pflag < 32; pflag++) {
                if (radiotap->present_flag & (1 << pflag)) {    // bit mask
                    switch(pflag) {
                        case RADIOTAP_TSFT:
                            flag_ptr += 8; // uint64 mactimestamp length 8
                            break;
                        case RADIOTAP_FLAGS:
                            flag_ptr++; // uint8 flag
                            break;
                        case RADIOTAP_RATE:
                            //data_rate = *(uint8_t *)flag_ptr / 2; // Data_rate : 1.0 Mb/s -> 0x02 고정이라 /2 로 1 을 표현
                            flag_ptr++; // uint8
                            break;
                        case RADIOTAP_CHANNEL:
                            flag_ptr += 4; // uint16 frequency, uint16 flags
                            break;
                        case RADIOTAP_FHSS:
                            flag_ptr += 2; // uint8 hop set, uint8 hop pattern
                            break;
                        case RADIOTAP_DBM_ANTSIGNAL:
                            pwr = *(char *)flag_ptr; // 신호 세기
                            flag_ptr++; // s8
                            break;
                        default:
                            break;
                    }
                }
            }
            printf("%d", pwr);
            //printf("\t Src");
            //print_mac(Src_Addr);
            //printf("\t Dst");
            //print_mac(Dst_Addr);
            printf("\t TA(BSSID):");
            print_mac(ieee80211->bssid_addr);
            //printf("\t Recv");
            //print_mac(Recv_Addr);
        } // cmp



    } // while end

    
    pcap_close(pcap);

    return 0;
}
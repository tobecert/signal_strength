#ifndef SIGNAL_H
#define SIGNAL_H

#include <stdint.h>

#pragma pack(push, 1)

typedef struct _radiotap_header {
    uint8_t version;
    uint8_t pad;
    uint16_t length;
    uint32_t present_flag;
} radiotap_header;

enum radiotap_present_flag {
    RADIOTAP_TSFT = 0,
    RADIOTAP_FLAGS = 1,
    RADIOTAP_RATE = 2,
    RADIOTAP_CHANNEL = 3,
    RADIOTAP_FHSS = 4,
    RADIOTAP_DBM_ANTSIGNAL = 5,
    RADIOTAP_DBM_ANTNOISE = 6,
    RADIOTAP_LOCK_QUALITY = 7,
    RADIOTAP_TX_ATTENUATION = 8,
    RADIOTAP_DB_TX_ATTENUATION = 9,
    RADIOTAP_DBM_TX_POWER = 10,
    RADIOTAP_ANTENNA = 11,
    RADIOTAP_DB_ANTSIGNAL = 12,
    RADIOTAP_DB_ANTNOISE = 13,
    RADIOTAP_RX_FLAGS = 14,
    RADIOTAP_TX_FLAGS = 15,
    RADIOTAP_RTS_RETRIES = 16,
    RADIOTAP_DATA_RETRIES = 17,
    RADIOTAP_MCS = 19,
    RADIOTAP_AMPDU_STATUS = 20,
    RADIOTAP_VHT = 21,
    RADIOTAP_TIMESTAMP = 22,
    RADIOTAP_RADIOTAP_NAMESPACE = 29,
    RADIOTAP_VENDOR_NAMESPACE = 30,
    RADIOTAP_EXT = 31
};

typedef struct _ieee80211_header {
    uint8_t frame_control_version : 2;
    uint8_t frame_control_type : 2;
    uint8_t frame_control_subtype : 4;
    uint8_t flags; 
    uint16_t duration;
    uint8_t destination_addr[6];
    uint8_t source_addr[6];
    uint8_t bssid_addr[6];
    uint16_t fragment_number : 4;
    uint16_t sequence_number : 12;
} ieee80211_header;

enum ieee80211_flags {
    TO_DS = 0,
    FROM_DS = 1,
    MORE_FRAGEMENTS = 2,
    RETRY = 3,
    PWR_MAG = 4,
    MORE_DATA = 5,
    PROTECTED_FLAG = 7,
    ORDER_FLAG = 8
};

#pragma pack(pop)

#endif
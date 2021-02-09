#include <stdint.h>
#include "net-address.h"

#pragma pack(push, 1)
struct Dot11HeaderCommon {
    uint8_t version:2;
    uint8_t type:2;
    uint8_t subtype:4;
    uint8_t flags;

    uint16_t duration;

    uint16_t getTypes() {
        return type << 4 + subtype;
    }
    void setTypes(uint16_t types) {
        type = (types & 0x0030) >> 4;
        subtype = types & 0x000F;
    }
};
#pragma pack(pop)

enum Dot11Types {
    BEACON_FRAME = 0x0008,
    DEAUTH = 0x000c,
    ACKNOWLEDGEMENT = 0x001d,
    DATA = 0x0020,
    NULL_FUNC = 0x0024
};

#pragma pack(push, 1)
struct Dot11Beacon {
    MacAddr receiver_addr;
    MacAddr transmitter_addr;
    MacAddr bssid;
    uint8_t fragment_num:4;
    uint16_t sequence_num:12;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Dot11Management {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities_info;

    // Please insert into Beacon structure
    enum TagNumber {
        SSID_PARAMETER_SET = 0,
        SUPPORTED_RATES = 1,
        DS_PARAMETER_SET = 3,
        TRAFFIC_INDICATION_MAP = 5,
        QBSS_LOAD_ELEMENT = 11,
        ERP_INFORMATION = 42,
        HT_CAPABILITIES_80211N_D110 = 45,
        RSN_INFORMATION = 48,
        EXTENDED_SUPPORTED_RATES = 50,
        AP_CHANNEL_REPORT = 51,
        HT_INFORMATION_80211N_D110 = 61,
        OVERLAPPING_BSS_SCAN_PARAMETERS = 74,
        EXTENDED_CAPABILITIES = 127,
        VENDOR_SPECIFIC = 221
    };
};
#pragma pack(pop)

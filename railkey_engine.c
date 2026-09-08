#include "railkey_engine.h"
#include <string.h>

uint32_t railkey_gray(uint32_t n) {
    return n ^ (n >> 1);
}

typedef struct {
    RailKeyProto proto;
    uint8_t data[5];
    uint8_t len;
} RailKeyDictEntry;

// Generic factory/test credentials only - the same class of default values
// every fuzzer ships. Not real facility credentials. Fast first pass before
// falling back to a structured sweep.
static const RailKeyDictEntry k_dict[] = {
    // EM4100 (5-byte decoded id)
    {RailKeyProtoEm4100, {0x00, 0x00, 0x00, 0x00, 0x00}, 5},
    {RailKeyProtoEm4100, {0x00, 0x00, 0x00, 0x00, 0x01}, 5},
    {RailKeyProtoEm4100, {0x00, 0x00, 0x00, 0x00, 0x02}, 5},
    {RailKeyProtoEm4100, {0x00, 0x00, 0x12, 0x34, 0x56}, 5},
    {RailKeyProtoEm4100, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 5},
    // HID H10301 (3-byte decoded id: facility, card_hi, card_lo)
    {RailKeyProtoH10301, {0x00, 0x00, 0x00, 0, 0}, 3},
    {RailKeyProtoH10301, {0x00, 0x00, 0x01, 0, 0}, 3},
    {RailKeyProtoH10301, {0x01, 0x00, 0x01, 0, 0}, 3},
    {RailKeyProtoH10301, {0x0B, 0x04, 0xD2, 0, 0}, 3}, // fc 11, card 1234
    {RailKeyProtoH10301, {0xFF, 0xFF, 0xFF, 0, 0}, 3},
    // Indala26 (3-byte decoded id)
    {RailKeyProtoIndala26, {0x00, 0x00, 0x00, 0, 0}, 3},
    {RailKeyProtoIndala26, {0x01, 0x00, 0x01, 0, 0}, 3},
};
#define K_DICT_LEN (sizeof(k_dict) / sizeof(k_dict[0]))

// Bounded spans keep the finite modes usable in a single session.
#define RAILKEY_MULTI_SPAN 4096u // logical ids per protocol in multi mode

uint32_t railkey_job_total(const RailKeyJob* job) {
    const RailKeySettings* s = job->s;
    switch(job->mode) {
    case RailKeyModeDictionary:
        return (uint32_t)K_DICT_LEN;
    case RailKeyModeHidSmart:
        return s->hid_facility_sweep ? (256u * 65536u) : 65536u;
    case RailKeyModeEmGray:
        return 65536u;
    case RailKeyModeMulti:
        return 3u * RAILKEY_MULTI_SPAN;
    case RailKeyModeNeighborhood:
        return 1u + 2u * (uint32_t)s->neighbor_radius + 24u;
    default:
        return 0;
    }
}

void railkey_job_init(RailKeyJob* job, const RailKeySettings* s, RailKeyMode mode) {
    memset(job, 0, sizeof(*job));
    job->mode = mode;
    job->s = s;
    job->total = railkey_job_total(job);
}

static void em4100_pack(const RailKeySettings* s, uint16_t card, uint8_t* data) {
    data[0] = s->em_prefix[0];
    data[1] = s->em_prefix[1];
    data[2] = s->em_prefix[2];
    data[3] = (uint8_t)(card >> 8);
    data[4] = (uint8_t)(card & 0xFF);
}

static void hid_pack(uint8_t facility, uint16_t card, uint8_t* data) {
    data[0] = facility;
    data[1] = (uint8_t)(card >> 8);
    data[2] = (uint8_t)(card & 0xFF);
}

bool railkey_job_next(RailKeyJob* job, RailKeyProto* proto, uint8_t* data, size_t* out_len) {
    const RailKeySettings* s = job->s;
    if(job->total && job->index >= job->total) return false;

    const uint32_t idx = job->index;

    switch(job->mode) {
    case RailKeyModeDictionary: {
        const RailKeyDictEntry* e = &k_dict[idx];
        *proto = e->proto;
        memcpy(data, e->data, e->len);
        *out_len = e->len;
        break;
    }
    case RailKeyModeEmGray: {
        uint16_t card = (uint16_t)railkey_gray((uint16_t)(s->em_card_start + idx));
        *proto = RailKeyProtoEm4100;
        em4100_pack(s, card, data);
        *out_len = 5;
        break;
    }
    case RailKeyModeHidSmart: {
        uint16_t card = (uint16_t)railkey_gray((uint16_t)(idx & 0xFFFF));
        uint8_t facility = s->hid_facility_sweep ? (uint8_t)((idx >> 16) & 0xFF) : s->hid_facility;
        *proto = RailKeyProtoH10301;
        hid_pack(facility, card, data);
        *out_len = 3;
        break;
    }
    case RailKeyModeMulti: {
        static const RailKeyProto order[3] = {
            RailKeyProtoEm4100, RailKeyProtoH10301, RailKeyProtoIndala26};
        RailKeyProto p = order[idx % 3];
        uint16_t card = (uint16_t)railkey_gray((uint16_t)(idx / 3));
        *proto = p;
        if(p == RailKeyProtoEm4100) {
            em4100_pack(s, card, data);
            *out_len = 5;
        } else {
            hid_pack(s->hid_facility, card, data);
            *out_len = 3;
        }
        break;
    }
    case RailKeyModeNeighborhood: {
        uint32_t center = ((uint32_t)s->hid_facility << 16) | s->seed_card;
        uint32_t val;
        if(idx == 0) {
            // known-good seed first
            val = center;
        } else if(idx <= 2u * (uint32_t)s->neighbor_radius) {
            // adjacent card numbers, alternating +/-: sequential badge issuance
            // means the neighbours of a valid card are the likeliest hits.
            uint32_t k = (idx + 1u) / 2u;    // 1,1,2,2,3,3,...
            int32_t delta = (idx & 1u) ? (int32_t)k : -(int32_t)k;
            uint16_t card = (uint16_t)((int32_t)s->seed_card + delta);
            val = ((uint32_t)s->hid_facility << 16) | card;
        } else {
            // single-bit flips across the 24-bit facility+card payload
            uint32_t bit = idx - 1u - 2u * (uint32_t)s->neighbor_radius; // 0..23
            val = center ^ (1u << bit);
        }
        *proto = RailKeyProtoH10301;
        data[0] = (uint8_t)((val >> 16) & 0xFF);
        data[1] = (uint8_t)((val >> 8) & 0xFF);
        data[2] = (uint8_t)(val & 0xFF);
        *out_len = 3;
        break;
    }
    default:
        return false;
    }

    job->index++;
    return true;
}

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

// ============================================================================
// Dictionaries.
//
// Every value below is a generic factory-default, published sample, or a
// low-issuance seed - the same class of "default values" every RFID fuzzer
// ships. NONE of these are real facility credentials, and none are tied to any
// specific site. They exist so an authorized tester can quickly rule out the
// obvious defaults before falling back to a structured sweep (HID smart / EM
// gray / neighborhood). Use only on readers you own or are authorized to test.
//
// Grouped one list per 125 kHz format, ordered by how commonly the format shows
// up so the "All" pass tries the likeliest classes first.
// ============================================================================

// ---- HID Prox 26-bit (H10301) --------------------------------------------
// Decoded id: [facility, card_hi, card_lo]. The most common LF format on
// commercial/office access readers. Seeds: unprogrammed defaults, low facility
// codes at start-of-batch card numbers, and published sample cards.
static const RailKeyDictEntry k_dict_hid[] = {
    // Unprogrammed / factory-test (facility 0)
    {RailKeyProtoH10301, {0x00, 0x00, 0x00, 0, 0}, 3}, // fc 0,  card 0
    {RailKeyProtoH10301, {0x00, 0x00, 0x01, 0, 0}, 3}, // fc 0,  card 1
    {RailKeyProtoH10301, {0x00, 0x00, 0x02, 0, 0}, 3},
    {RailKeyProtoH10301, {0x00, 0x00, 0x03, 0, 0}, 3},
    {RailKeyProtoH10301, {0x00, 0x00, 0x0A, 0, 0}, 3}, // fc 0,  card 10
    {RailKeyProtoH10301, {0x00, 0x00, 0x64, 0, 0}, 3}, // fc 0,  card 100
    {RailKeyProtoH10301, {0x00, 0x04, 0xD2, 0, 0}, 3}, // fc 0,  card 1234
    // Low facility codes at card 1 (installers often number batches from 1)
    {RailKeyProtoH10301, {0x01, 0x00, 0x01, 0, 0}, 3}, // fc 1
    {RailKeyProtoH10301, {0x02, 0x00, 0x01, 0, 0}, 3}, // fc 2
    {RailKeyProtoH10301, {0x03, 0x00, 0x01, 0, 0}, 3}, // fc 3
    {RailKeyProtoH10301, {0x05, 0x00, 0x01, 0, 0}, 3}, // fc 5
    {RailKeyProtoH10301, {0x07, 0x00, 0x01, 0, 0}, 3}, // fc 7
    {RailKeyProtoH10301, {0x0A, 0x00, 0x01, 0, 0}, 3}, // fc 10
    {RailKeyProtoH10301, {0x0B, 0x00, 0x01, 0, 0}, 3}, // fc 11
    {RailKeyProtoH10301, {0x0C, 0x00, 0x01, 0, 0}, 3}, // fc 12
    {RailKeyProtoH10301, {0x0D, 0x00, 0x01, 0, 0}, 3}, // fc 13
    {RailKeyProtoH10301, {0x0F, 0x00, 0x01, 0, 0}, 3}, // fc 15
    {RailKeyProtoH10301, {0x14, 0x00, 0x01, 0, 0}, 3}, // fc 20
    {RailKeyProtoH10301, {0x1E, 0x00, 0x01, 0, 0}, 3}, // fc 30
    {RailKeyProtoH10301, {0x2A, 0x00, 0x01, 0, 0}, 3}, // fc 42
    {RailKeyProtoH10301, {0x64, 0x00, 0x01, 0, 0}, 3}, // fc 100
    {RailKeyProtoH10301, {0xC8, 0x00, 0x01, 0, 0}, 3}, // fc 200
    // Facility 1, low card spread (a very common default facility)
    {RailKeyProtoH10301, {0x01, 0x00, 0x02, 0, 0}, 3}, // fc 1,  card 2
    {RailKeyProtoH10301, {0x01, 0x00, 0x03, 0, 0}, 3},
    {RailKeyProtoH10301, {0x01, 0x00, 0x0A, 0, 0}, 3}, // fc 1,  card 10
    {RailKeyProtoH10301, {0x01, 0x00, 0x64, 0, 0}, 3}, // fc 1,  card 100
    {RailKeyProtoH10301, {0x01, 0x03, 0xE8, 0, 0}, 3}, // fc 1,  card 1000
    // Published sample cards
    {RailKeyProtoH10301, {0x0B, 0x04, 0xD2, 0, 0}, 3}, // fc 11, card 1234 (classic sample)
    // All-ones
    {RailKeyProtoH10301, {0xFF, 0xFF, 0xFF, 0, 0}, 3},
};

// ---- EM4100 (EM410x) ------------------------------------------------------
// Decoded id: the 5-byte (40-bit) tag id. The most common LF format on
// residential fobs, intercoms, gyms and amenity readers. Seeds: zeros/ones,
// small sequential ids, common batch prefixes, and published samples.
static const RailKeyDictEntry k_dict_em[] = {
    {RailKeyProtoEm4100, {0x00, 0x00, 0x00, 0x00, 0x00}, 5},
    {RailKeyProtoEm4100, {0x00, 0x00, 0x00, 0x00, 0x01}, 5},
    {RailKeyProtoEm4100, {0x00, 0x00, 0x00, 0x00, 0x02}, 5},
    {RailKeyProtoEm4100, {0x00, 0x00, 0x00, 0x00, 0x0A}, 5}, // 10
    {RailKeyProtoEm4100, {0x00, 0x00, 0x00, 0x00, 0x64}, 5}, // 100
    {RailKeyProtoEm4100, {0x00, 0x00, 0x00, 0x03, 0xE8}, 5}, // 1000
    {RailKeyProtoEm4100, {0x00, 0x00, 0x00, 0x27, 0x10}, 5}, // 10000
    {RailKeyProtoEm4100, {0x00, 0x00, 0x00, 0x12, 0x34}, 5},
    {RailKeyProtoEm4100, {0x00, 0x00, 0x12, 0x34, 0x56}, 5}, // published sample
    {RailKeyProtoEm4100, {0x01, 0x00, 0x00, 0x00, 0x01}, 5}, // nonzero batch prefix
    {RailKeyProtoEm4100, {0x02, 0x00, 0x00, 0x00, 0x01}, 5},
    {RailKeyProtoEm4100, {0x11, 0x22, 0x33, 0x44, 0x55}, 5}, // published sample
    {RailKeyProtoEm4100, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 5},
};

// ---- Indala 26-bit --------------------------------------------------------
// Decoded id: [facility, card_hi, card_lo]. Legacy Motorola/Indala installs.
static const RailKeyDictEntry k_dict_indala[] = {
    {RailKeyProtoIndala26, {0x00, 0x00, 0x00, 0, 0}, 3},
    {RailKeyProtoIndala26, {0x00, 0x00, 0x01, 0, 0}, 3},
    {RailKeyProtoIndala26, {0x01, 0x00, 0x01, 0, 0}, 3},
    {RailKeyProtoIndala26, {0x0B, 0x04, 0xD2, 0, 0}, 3}, // fc 11, card 1234
    {RailKeyProtoIndala26, {0x64, 0x00, 0x01, 0, 0}, 3}, // fc 100
    {RailKeyProtoIndala26, {0xFF, 0xFF, 0xFF, 0, 0}, 3},
};

typedef struct {
    const char* name;
    const RailKeyDictEntry* entries;
    uint16_t count;
} RailKeyDict;

// Priority order (also the order "All" walks): HID Prox first (most common on
// the commercial readers this is used against), then EM4100, then Indala.
static const RailKeyDict k_dicts[] = {
    {"HID Prox 26", k_dict_hid, sizeof(k_dict_hid) / sizeof(k_dict_hid[0])},
    {"EM4100 fob", k_dict_em, sizeof(k_dict_em) / sizeof(k_dict_em[0])},
    {"Indala 26", k_dict_indala, sizeof(k_dict_indala) / sizeof(k_dict_indala[0])},
};
#define K_DICTS_N (sizeof(k_dicts) / sizeof(k_dicts[0]))

// Map a dict_id to the concrete dictionary (ids 1..K_DICTS_N). Returns NULL for
// "All" or an out-of-range id.
static const RailKeyDict* dict_by_id(uint8_t dict_id) {
    if(dict_id >= 1 && dict_id <= K_DICTS_N) return &k_dicts[dict_id - 1];
    return NULL;
}

const char* railkey_dict_name(uint8_t dict_id) {
    if(dict_id == RailKeyDictAll) return "All formats";
    const RailKeyDict* d = dict_by_id(dict_id);
    return d ? d->name : "?";
}

uint32_t railkey_dict_size(uint8_t dict_id) {
    if(dict_id == RailKeyDictAll) {
        uint32_t total = 0;
        for(size_t i = 0; i < K_DICTS_N; i++) total += k_dicts[i].count;
        return total;
    }
    const RailKeyDict* d = dict_by_id(dict_id);
    return d ? d->count : 0;
}

// Resolve a global dictionary index to its entry, honoring the selected
// dictionary (or the concatenation of all of them for "All").
static const RailKeyDictEntry* dict_entry_at(uint8_t dict_id, uint32_t idx) {
    if(dict_id == RailKeyDictAll) {
        uint32_t rem = idx;
        for(size_t i = 0; i < K_DICTS_N; i++) {
            if(rem < k_dicts[i].count) return &k_dicts[i].entries[rem];
            rem -= k_dicts[i].count;
        }
        return NULL;
    }
    const RailKeyDict* d = dict_by_id(dict_id);
    if(!d || idx >= d->count) return NULL;
    return &d->entries[idx];
}

// Bounded spans keep the finite modes usable in a single session.
#define RAILKEY_MULTI_SPAN 4096u // logical ids per protocol in multi mode

uint32_t railkey_job_total(const RailKeyJob* job) {
    const RailKeySettings* s = job->s;
    switch(job->mode) {
    case RailKeyModeDictionary:
        return railkey_dict_size(s->dict_id);
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
        const RailKeyDictEntry* e = dict_entry_at(s->dict_id, idx);
        if(!e) return false;
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

// RailKey fuzz engine - pure logic, no Flipper dependencies.
// Kept free of firmware headers so the sequence generators can be reasoned
// about (and, if desired, unit-tested) off-device.
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Protocols the engine knows how to shape data for. Mapped to the firmware's
// LFRFIDProtocol enum by the caller.
typedef enum {
    RailKeyProtoEm4100,
    RailKeyProtoH10301, // HID Prox 26-bit (H10301)
    RailKeyProtoIndala26,
} RailKeyProto;

typedef enum {
    RailKeyModeDictionary,   // curated default/test values from the selected dictionary
    RailKeyModeHidSmart,     // structure-aware HID: facility x card, Gray-ordered
    RailKeyModeEmGray,       // EM4100 card counter in Gray-code order
    RailKeyModeMulti,        // interleave EM4100 / HID / Indala per logical id
    RailKeyModeNeighborhood, // seed one HID card, sweep neighbours + Hamming-1
} RailKeyMode;

// Dictionary selection for RailKeyModeDictionary. One curated list per 125 kHz
// format, grouped by where each is common so an operator can pick the reader
// class they are authorized to test. All entries are generic factory/test/
// low-issuance seed values - NOT real facility credentials.
typedef enum {
    RailKeyDictAll = 0,   // every dictionary, in priority order
    RailKeyDictHidProx,   // HID Prox 26-bit (H10301) - common in commercial/office readers
    RailKeyDictEm4100,    // EM4100 fobs - common in residential/intercom/amenity readers
    RailKeyDictIndala,    // Indala 26-bit - legacy installs
    RailKeyDictCount,     // number of selectable options (used for UI sizing)
} RailKeyDictId;

typedef struct {
    uint16_t dwell_ms;         // emulate time per id
    uint8_t  hid_facility;     // facility used when not sweeping
    bool     hid_facility_sweep;
    uint8_t  em_prefix[3];     // fixed high 3 bytes of the 5-byte EM4100 id
    uint16_t em_card_start;    // starting EM4100 card number (pre-Gray)
    uint8_t  neighbor_radius;  // +/- card numbers explored around the seed
    uint16_t seed_card;        // HID card number seed for neighborhood mode
    uint8_t  dict_id;          // RailKeyDictId selecting the dictionary to run
} RailKeySettings;

typedef struct {
    RailKeyMode mode;
    const RailKeySettings* s; // borrowed, must outlive the job
    uint32_t index;          // steps emitted so far
    uint32_t total;          // planned count (0 = unbounded)
} RailKeyJob;

// Minimal-change binary-reflected Gray code: gray(i) and gray(i+1) differ by
// exactly one bit, so consecutive emitted ids reshape the modulation buffer as
// little as possible.
uint32_t railkey_gray(uint32_t n);

void railkey_job_init(RailKeyJob* job, const RailKeySettings* s, RailKeyMode mode);
uint32_t railkey_job_total(const RailKeyJob* job);

// Fill *proto and up to 5 bytes of decoded data (Flipper's decoded layout for
// the protocol), setting *out_len to that protocol's data length. Returns false
// once the job is exhausted.
bool railkey_job_next(RailKeyJob* job, RailKeyProto* proto, uint8_t* data, size_t* out_len);

// Human-readable name for a dictionary id, and the number of entries it holds.
const char* railkey_dict_name(uint8_t dict_id);
uint32_t railkey_dict_size(uint8_t dict_id);

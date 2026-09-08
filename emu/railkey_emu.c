/* RailKey — browser-emulator build.
 *
 * The real RailKey FAP (railkey.c) drives the Flipper LFRFID worker through the
 * GUI module framework, none of which the datarail.org/flipperzero API shim
 * provides. This file is a shim-compatible front end that renders RailKey on the
 * 128x64 canvas using only view_port / canvas / input / furi — and drives the
 * *same* sequence generator the hardware app uses (railkey_engine.c), so what
 * you watch in the browser is the real Gray-code / structure-aware ordering, not
 * a mock-up. No RF is transmitted here; the emulator has no radio.
 *
 * Built by datarail-site/flipper/build.sh with entry point railkey_emu_app.
 */

#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>

#include "railkey_engine.h"

typedef enum {
    ScreenMenu,
    ScreenRun,
} EmuScreen;

#define MENU_COUNT 5

static const RailKeyMode MENU_MODES[MENU_COUNT] = {
    RailKeyModeDictionary,
    RailKeyModeHidSmart,
    RailKeyModeEmGray,
    RailKeyModeMulti,
    RailKeyModeNeighborhood,
};

static const char* MENU_LABELS[MENU_COUNT] = {
    "Dictionary sweep",
    "HID smart sweep",
    "EM4100 gray",
    "Multi-protocol",
    "Neighborhood",
};

typedef struct {
    FuriMutex* mutex;
    bool running; // app alive
    EmuScreen screen;
    int8_t sel; // menu selection

    RailKeySettings settings;
    RailKeyJob job;
    bool sweeping;
    bool finished;

    RailKeyProto cur_proto;
    uint8_t cur_data[5];
    size_t cur_len;
    uint32_t attempts;
    uint32_t total;
    uint32_t start_ms;
} Emu;

static const char* mode_name(RailKeyMode m) {
    switch(m) {
    case RailKeyModeDictionary:
        return "Dictionary sweep";
    case RailKeyModeHidSmart:
        return "HID smart sweep";
    case RailKeyModeEmGray:
        return "EM4100 gray sweep";
    case RailKeyModeMulti:
        return "Multi-protocol";
    case RailKeyModeNeighborhood:
        return "Neighborhood";
    default:
        return "RailKey";
    }
}

static const char* proto_name(RailKeyProto p) {
    switch(p) {
    case RailKeyProtoEm4100:
        return "EM4100";
    case RailKeyProtoH10301:
        return "HID26";
    case RailKeyProtoIndala26:
        return "Indala";
    default:
        return "?";
    }
}

static void emu_start(Emu* e, RailKeyMode mode) {
    railkey_job_init(&e->job, &e->settings, mode);
    e->total = e->job.total;
    e->attempts = 0;
    e->finished = false;
    e->sweeping = true;
    e->cur_len = 0;
    e->start_ms = furi_get_tick();
    e->screen = ScreenRun;
}

static void emu_draw(Canvas* canvas, void* ctx) {
    Emu* e = ctx;
    char line[48];

    canvas_clear(canvas);

    if(e->screen == ScreenMenu) {
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 2, 10, "RailKey");
        canvas_set_font(canvas, FontSecondary);

        for(int i = 0; i < MENU_COUNT; i++) {
            int y = 21 + i * 8;
            if(i == e->sel) {
                canvas_draw_box(canvas, 0, y - 7, 128, 8);
                canvas_set_color(canvas, ColorWhite);
            }
            canvas_draw_str(canvas, 4, y, MENU_LABELS[i]);
            if(i == e->sel) canvas_set_color(canvas, ColorBlack);
        }

        canvas_draw_str(canvas, 2, 63, "OK run   Back exit");
        return;
    }

    // Run screen
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 10, mode_name(MENU_MODES[e->sel]));

    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 23, proto_name(e->cur_proto));

    char hex[16];
    size_t hp = 0;
    for(size_t i = 0; i < e->cur_len && i < 5 && hp + 2 < sizeof(hex); i++) {
        hp += (size_t)snprintf(hex + hp, sizeof(hex) - hp, "%02X", e->cur_data[i]);
    }
    hex[hp] = '\0';
    canvas_draw_str(canvas, 46, 23, hex);

    if(e->total) {
        snprintf(
            line, sizeof(line), "%lu / %lu", (unsigned long)e->attempts, (unsigned long)e->total);
    } else {
        snprintf(line, sizeof(line), "%lu", (unsigned long)e->attempts);
    }
    canvas_draw_str(canvas, 2, 35, line);

    uint32_t elapsed = furi_get_tick() - e->start_ms;
    uint32_t secs = elapsed / 1000;
    uint32_t rate = secs ? (e->attempts / secs) : e->attempts;
    snprintf(line, sizeof(line), "%lu/s  %lus", (unsigned long)rate, (unsigned long)secs);
    canvas_draw_str(canvas, 2, 46, line);

    if(e->total) {
        int w = (int)(((uint64_t)e->attempts * 124u) / e->total);
        if(w > 124) w = 124;
        canvas_draw_frame(canvas, 2, 50, 124, 6);
        if(w > 0) canvas_draw_box(canvas, 2, 50, w, 6);
    }

    canvas_draw_str(canvas, 2, 63, e->finished ? "Done   Back: menu" : "Back: menu");
}

static void emu_input(InputEvent* ev, void* ctx) {
    Emu* e = ctx;
    if(ev->type != InputTypeShort) return;

    furi_mutex_acquire(e->mutex, FuriWaitForever);

    if(e->screen == ScreenMenu) {
        switch(ev->key) {
        case InputKeyUp:
            e->sel = (int8_t)((e->sel + MENU_COUNT - 1) % MENU_COUNT);
            break;
        case InputKeyDown:
            e->sel = (int8_t)((e->sel + 1) % MENU_COUNT);
            break;
        case InputKeyOk:
            emu_start(e, MENU_MODES[e->sel]);
            break;
        case InputKeyBack:
            e->running = false;
            break;
        default:
            break;
        }
    } else { // ScreenRun
        switch(ev->key) {
        case InputKeyBack:
            e->screen = ScreenMenu;
            e->sweeping = false;
            break;
        case InputKeyOk:
            if(!e->finished) e->sweeping = !e->sweeping; // pause / resume
            break;
        default:
            break;
        }
    }

    furi_mutex_release(e->mutex);
}

int32_t railkey_emu_app(void* p) {
    UNUSED(p);

    Emu* e = malloc(sizeof(Emu));
    if(!e) return 255;
    memset(e, 0, sizeof(Emu));

    e->running = true;
    e->screen = ScreenMenu;
    e->sel = 0;

    // Defaults picked to make the ordering legible: a nonzero HID seed so
    // neighborhood mode visibly sweeps around a real-looking card.
    e->settings.dwell_ms = 120;
    e->settings.hid_facility = 11;
    e->settings.hid_facility_sweep = false;
    e->settings.neighbor_radius = 25;
    e->settings.em_card_start = 0;
    e->settings.seed_card = 1234;

    e->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    if(!e->mutex) {
        free(e);
        return 255;
    }

    ViewPort* view_port = view_port_alloc();
    view_port_draw_callback_set(view_port, emu_draw, e);
    view_port_input_callback_set(view_port, emu_input, e);

    Gui* gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(gui, view_port, GuiLayerFullscreen);

    while(e->running) {
        furi_mutex_acquire(e->mutex, FuriWaitForever);
        if(e->screen == ScreenRun && e->sweeping && !e->finished) {
            RailKeyProto pr;
            uint8_t d[5];
            size_t l;
            if(railkey_job_next(&e->job, &pr, d, &l)) {
                e->cur_proto = pr;
                memcpy(e->cur_data, d, l);
                e->cur_len = l;
                e->attempts++;
            } else {
                e->finished = true;
                e->sweeping = false;
            }
        }
        furi_mutex_release(e->mutex);

        view_port_update(view_port);
        furi_delay_ms(90);
    }

    gui_remove_view_port(gui, view_port);
    view_port_free(view_port);
    furi_record_close(RECORD_GUI);
    furi_mutex_free(e->mutex);
    free(e);
    return 0;
}

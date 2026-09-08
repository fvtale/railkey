#include "railkey.h"

#include <toolbox/protocols/protocol_dict.h>
#include <lfrfid/protocols/lfrfid_protocols.h>
#include <lfrfid/lfrfid_worker.h>

#include <string.h>
#include <stdio.h>

// ---- main menu indices ----
typedef enum {
    MenuDictionary,
    MenuHidSmart,
    MenuEmGray,
    MenuMulti,
    MenuNeighborhood,
    MenuSettings,
    MenuAbout,
} MenuIndex;

// ---- run view model (a snapshot the draw callback reads) ----
typedef struct {
    bool running;
    bool finished;
    RailKeyMode mode;
    uint32_t attempts;
    uint32_t total;
    uint32_t elapsed_ms;
    RailKeyProto proto;
    uint8_t data[5];
    size_t len;
} RailKeyRunModel;

static const char* railkey_mode_name(RailKeyMode m) {
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

static const char* railkey_proto_name(RailKeyProto p) {
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

static LFRFIDProtocol railkey_map_proto(RailKeyProto p) {
    switch(p) {
    case RailKeyProtoEm4100:
        return LFRFIDProtocolEM4100;
    case RailKeyProtoH10301:
        return LFRFIDProtocolH10301;
    case RailKeyProtoIndala26:
        return LFRFIDProtocolIndala26;
    default:
        return LFRFIDProtocolEM4100;
    }
}

// ---- fuzz worker thread ----
static int32_t railkey_worker_thread(void* ctx) {
    RailKey* app = ctx;

    ProtocolDict* dict = protocol_dict_alloc(lfrfid_protocols, LFRFIDProtocolMax);
    LFRFIDWorker* worker = lfrfid_worker_alloc(dict);
    lfrfid_worker_start_thread(worker);

    RailKeyJob job;
    railkey_job_init(&job, &app->settings, app->run.mode);

    furi_mutex_acquire(app->run.mutex, FuriWaitForever);
    app->run.total = railkey_job_total(&job);
    app->run.attempts = 0;
    app->run.start_ms = furi_get_tick();
    app->run.finished = false;
    furi_mutex_release(app->run.mutex);

    uint8_t data[5];
    size_t len = 0;
    RailKeyProto rproto = RailKeyProtoEm4100;

    for(;;) {
        furi_mutex_acquire(app->run.mutex, FuriWaitForever);
        bool keep = app->run.running;
        uint16_t dwell = app->settings.dwell_ms;
        furi_mutex_release(app->run.mutex);
        if(!keep) break;

        if(!railkey_job_next(&job, &rproto, data, &len)) break;

        LFRFIDProtocol proto = railkey_map_proto(rproto);
        size_t ds = protocol_dict_get_data_size(dict, proto);
        if(ds > len) {
            memset(data + len, 0, ds - len);
        }
        protocol_dict_set_data(dict, proto, data, ds);
        lfrfid_worker_emulate_start(worker, proto);

        furi_mutex_acquire(app->run.mutex, FuriWaitForever);
        app->run.cur_proto = rproto;
        memcpy(app->run.cur_data, data, len);
        app->run.cur_len = len;
        app->run.attempts++;
        furi_mutex_release(app->run.mutex);

        // Dwell in short slices so a stop request is honored quickly.
        uint16_t waited = 0;
        while(waited < dwell) {
            uint16_t slice = (uint16_t)((dwell - waited) > 20 ? 20 : (dwell - waited));
            furi_delay_ms(slice);
            waited = (uint16_t)(waited + slice);
            furi_mutex_acquire(app->run.mutex, FuriWaitForever);
            bool stop = !app->run.running;
            furi_mutex_release(app->run.mutex);
            if(stop) break;
        }

        lfrfid_worker_stop(worker);
    }

    lfrfid_worker_stop_thread(worker);
    lfrfid_worker_free(worker);
    protocol_dict_free(dict);

    furi_mutex_acquire(app->run.mutex, FuriWaitForever);
    app->run.running = false;
    app->run.finished = true;
    furi_mutex_release(app->run.mutex);
    return 0;
}

static void railkey_stop_worker(RailKey* app) {
    if(app->worker) {
        furi_mutex_acquire(app->run.mutex, FuriWaitForever);
        app->run.running = false;
        furi_mutex_release(app->run.mutex);
        furi_thread_join(app->worker);
        furi_thread_free(app->worker);
        app->worker = NULL;
    }
}

// ---- run view ----
static void railkey_run_draw(Canvas* canvas, void* model) {
    RailKeyRunModel* m = model;
    char line[48];

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 10, railkey_mode_name(m->mode));

    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 22, railkey_proto_name(m->proto));

    char hex[16];
    size_t hp = 0;
    for(size_t i = 0; i < m->len && i < 5 && hp + 2 < sizeof(hex); i++) {
        hp += (size_t)snprintf(hex + hp, sizeof(hex) - hp, "%02X", m->data[i]);
    }
    hex[hp] = '\0';
    canvas_draw_str(canvas, 44, 22, hex);

    if(m->total) {
        snprintf(
            line, sizeof(line), "%lu / %lu", (unsigned long)m->attempts, (unsigned long)m->total);
    } else {
        snprintf(line, sizeof(line), "%lu", (unsigned long)m->attempts);
    }
    canvas_draw_str(canvas, 2, 34, line);

    uint32_t secs = m->elapsed_ms / 1000;
    uint32_t rate = secs ? (m->attempts / secs) : m->attempts;
    snprintf(line, sizeof(line), "%lu/s  %lus", (unsigned long)rate, (unsigned long)secs);
    canvas_draw_str(canvas, 2, 45, line);

    if(m->total) {
        uint8_t w = (uint8_t)(((uint64_t)m->attempts * 124u) / m->total);
        if(w > 124) w = 124;
        canvas_draw_frame(canvas, 2, 49, 124, 6);
        canvas_draw_box(canvas, 2, 49, w, 6);
    }

    canvas_draw_str(canvas, 2, 63, m->finished ? "Done - Back to exit" : "Back to stop");
}

static void railkey_run_timer(void* ctx) {
    RailKey* app = ctx;

    RailKeyRun snap;
    furi_mutex_acquire(app->run.mutex, FuriWaitForever);
    snap = app->run;
    furi_mutex_release(app->run.mutex);

    uint32_t elapsed = furi_get_tick() - snap.start_ms;

    with_view_model(
        app->run_view,
        RailKeyRunModel * m,
        {
            m->running = snap.running;
            m->finished = snap.finished;
            m->mode = snap.mode;
            m->attempts = snap.attempts;
            m->total = snap.total;
            m->elapsed_ms = elapsed;
            m->proto = snap.cur_proto;
            memcpy(m->data, snap.cur_data, sizeof(m->data));
            m->len = snap.cur_len;
        },
        true);
}

static void railkey_run_enter(void* ctx) {
    RailKey* app = ctx;

    furi_mutex_acquire(app->run.mutex, FuriWaitForever);
    app->run.mode = app->pending_mode;
    app->run.running = true;
    app->run.finished = false;
    app->run.attempts = 0;
    app->run.total = 0;
    app->run.start_ms = furi_get_tick();
    app->run.cur_len = 0;
    furi_mutex_release(app->run.mutex);

    with_view_model(
        app->run_view,
        RailKeyRunModel * m,
        {
            memset(m, 0, sizeof(*m));
            m->running = true;
            m->mode = app->pending_mode;
        },
        true);

    app->worker = furi_thread_alloc_ex("RailKeyWorker", 2048, railkey_worker_thread, app);
    furi_thread_start(app->worker);

    app->run_timer = furi_timer_alloc(railkey_run_timer, FuriTimerTypePeriodic, app);
    furi_timer_start(app->run_timer, 150);

    notification_message(app->notifications, &sequence_display_backlight_enforce_on);
}

static void railkey_run_exit(void* ctx) {
    RailKey* app = ctx;

    if(app->run_timer) {
        furi_timer_stop(app->run_timer);
        furi_timer_free(app->run_timer);
        app->run_timer = NULL;
    }
    railkey_stop_worker(app);
    notification_message(app->notifications, &sequence_display_backlight_enforce_auto);
}

static uint32_t railkey_prev_submenu(void* ctx) {
    UNUSED(ctx);
    return RailKeyViewSubmenu;
}

// ---- submenu ----
static void railkey_submenu_cb(void* ctx, uint32_t index) {
    RailKey* app = ctx;
    switch(index) {
    case MenuDictionary:
        app->pending_mode = RailKeyModeDictionary;
        view_dispatcher_switch_to_view(app->view_dispatcher, RailKeyViewRun);
        break;
    case MenuHidSmart:
        app->pending_mode = RailKeyModeHidSmart;
        view_dispatcher_switch_to_view(app->view_dispatcher, RailKeyViewRun);
        break;
    case MenuEmGray:
        app->pending_mode = RailKeyModeEmGray;
        view_dispatcher_switch_to_view(app->view_dispatcher, RailKeyViewRun);
        break;
    case MenuMulti:
        app->pending_mode = RailKeyModeMulti;
        view_dispatcher_switch_to_view(app->view_dispatcher, RailKeyViewRun);
        break;
    case MenuNeighborhood:
        view_dispatcher_switch_to_view(app->view_dispatcher, RailKeyViewSeed);
        break;
    case MenuSettings:
        view_dispatcher_switch_to_view(app->view_dispatcher, RailKeyViewSettings);
        break;
    case MenuAbout:
        view_dispatcher_switch_to_view(app->view_dispatcher, RailKeyViewAbout);
        break;
    default:
        break;
    }
}

// ---- seed (byte input) ----
static void railkey_seed_done(void* ctx) {
    RailKey* app = ctx;
    app->settings.seed_card = (uint16_t)((app->seed_bytes[0] << 8) | app->seed_bytes[1]);
    app->pending_mode = RailKeyModeNeighborhood;
    view_dispatcher_switch_to_view(app->view_dispatcher, RailKeyViewRun);
}

// ---- settings ----
static const uint16_t k_dwell_vals[] = {40, 60, 80, 100, 120, 160, 200, 300};
#define K_DWELL_LEN (sizeof(k_dwell_vals) / sizeof(k_dwell_vals[0]))

static const uint8_t k_radius_vals[] = {5, 10, 25, 50, 100, 200};
#define K_RADIUS_LEN (sizeof(k_radius_vals) / sizeof(k_radius_vals[0]))

static void railkey_setting_dwell(VariableItem* item) {
    RailKey* app = variable_item_get_context(item);
    uint8_t i = variable_item_get_current_value_index(item);
    app->settings.dwell_ms = k_dwell_vals[i];
    char t[8];
    snprintf(t, sizeof(t), "%u", (unsigned)k_dwell_vals[i]);
    variable_item_set_current_value_text(item, t);
}

static void railkey_setting_facility(VariableItem* item) {
    RailKey* app = variable_item_get_context(item);
    uint8_t i = variable_item_get_current_value_index(item);
    app->settings.hid_facility = i;
    char t[8];
    snprintf(t, sizeof(t), "%u", (unsigned)i);
    variable_item_set_current_value_text(item, t);
}

static void railkey_setting_fac_sweep(VariableItem* item) {
    RailKey* app = variable_item_get_context(item);
    uint8_t i = variable_item_get_current_value_index(item);
    app->settings.hid_facility_sweep = (i != 0);
    variable_item_set_current_value_text(item, i ? "On" : "Off");
}

static void railkey_setting_radius(VariableItem* item) {
    RailKey* app = variable_item_get_context(item);
    uint8_t i = variable_item_get_current_value_index(item);
    app->settings.neighbor_radius = k_radius_vals[i];
    char t[8];
    snprintf(t, sizeof(t), "%u", (unsigned)k_radius_vals[i]);
    variable_item_set_current_value_text(item, t);
}

static void railkey_build_settings(RailKey* app) {
    VariableItem* item;

    item = variable_item_list_add(
        app->settings_list, "Dwell (ms)", K_DWELL_LEN, railkey_setting_dwell, app);
    uint8_t di = 4; // default 120ms
    for(uint8_t i = 0; i < K_DWELL_LEN; i++) {
        if(k_dwell_vals[i] == app->settings.dwell_ms) di = i;
    }
    variable_item_set_current_value_index(item, di);
    {
        char t[8];
        snprintf(t, sizeof(t), "%u", (unsigned)k_dwell_vals[di]);
        variable_item_set_current_value_text(item, t);
    }

    // VariableItemList counts are uint8_t, so facility here covers 0..254;
    // facility 255 is still reachable via "HID fac sweep".
    item =
        variable_item_list_add(app->settings_list, "HID facility", 255, railkey_setting_facility, app);
    if(app->settings.hid_facility > 254) app->settings.hid_facility = 254;
    variable_item_set_current_value_index(item, app->settings.hid_facility);
    {
        char t[8];
        snprintf(t, sizeof(t), "%u", (unsigned)app->settings.hid_facility);
        variable_item_set_current_value_text(item, t);
    }

    item = variable_item_list_add(
        app->settings_list, "HID fac sweep", 2, railkey_setting_fac_sweep, app);
    variable_item_set_current_value_index(item, app->settings.hid_facility_sweep ? 1 : 0);
    variable_item_set_current_value_text(item, app->settings.hid_facility_sweep ? "On" : "Off");

    item = variable_item_list_add(
        app->settings_list, "Neighbor +/-", K_RADIUS_LEN, railkey_setting_radius, app);
    uint8_t ri = 2; // default 25
    for(uint8_t i = 0; i < K_RADIUS_LEN; i++) {
        if(k_radius_vals[i] == app->settings.neighbor_radius) ri = i;
    }
    variable_item_set_current_value_index(item, ri);
    {
        char t[8];
        snprintf(t, sizeof(t), "%u", (unsigned)k_radius_vals[ri]);
        variable_item_set_current_value_text(item, t);
    }
}

static bool railkey_nav_exit(void* ctx) {
    UNUSED(ctx);
    return false; // nothing left to pop -> exit the app
}

// ---- app lifecycle ----
static RailKey* railkey_alloc(void) {
    RailKey* app = malloc(sizeof(RailKey));
    memset(app, 0, sizeof(RailKey));

    app->settings.dwell_ms = 120;
    app->settings.hid_facility = 0;
    app->settings.hid_facility_sweep = false;
    app->settings.neighbor_radius = 25;
    app->settings.em_card_start = 0;
    app->settings.seed_card = 0;
    memset(app->settings.em_prefix, 0, sizeof(app->settings.em_prefix));

    app->run.mutex = furi_mutex_alloc(FuriMutexTypeNormal);

    app->gui = furi_record_open(RECORD_GUI);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);

    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_navigation_event_callback(app->view_dispatcher, railkey_nav_exit);

    // Submenu (root)
    app->submenu = submenu_alloc();
    submenu_add_item(app->submenu, "Dictionary sweep", MenuDictionary, railkey_submenu_cb, app);
    submenu_add_item(app->submenu, "HID smart sweep", MenuHidSmart, railkey_submenu_cb, app);
    submenu_add_item(app->submenu, "EM4100 gray sweep", MenuEmGray, railkey_submenu_cb, app);
    submenu_add_item(app->submenu, "Multi-protocol", MenuMulti, railkey_submenu_cb, app);
    submenu_add_item(app->submenu, "Neighborhood (HID)", MenuNeighborhood, railkey_submenu_cb, app);
    submenu_add_item(app->submenu, "Settings", MenuSettings, railkey_submenu_cb, app);
    submenu_add_item(app->submenu, "About / Legal", MenuAbout, railkey_submenu_cb, app);
    view_dispatcher_add_view(
        app->view_dispatcher, RailKeyViewSubmenu, submenu_get_view(app->submenu));

    // Settings
    app->settings_list = variable_item_list_alloc();
    railkey_build_settings(app);
    view_set_previous_callback(
        variable_item_list_get_view(app->settings_list), railkey_prev_submenu);
    view_dispatcher_add_view(
        app->view_dispatcher, RailKeyViewSettings, variable_item_list_get_view(app->settings_list));

    // Seed byte input
    app->byte_input = byte_input_alloc();
    byte_input_set_header_text(app->byte_input, "HID card number (2 bytes hex)");
    byte_input_set_result_callback(
        app->byte_input, railkey_seed_done, NULL, app, app->seed_bytes, 2);
    view_set_previous_callback(byte_input_get_view(app->byte_input), railkey_prev_submenu);
    view_dispatcher_add_view(
        app->view_dispatcher, RailKeyViewSeed, byte_input_get_view(app->byte_input));

    // Run view
    app->run_view = view_alloc();
    view_set_context(app->run_view, app);
    view_allocate_model(app->run_view, ViewModelTypeLocking, sizeof(RailKeyRunModel));
    view_set_draw_callback(app->run_view, railkey_run_draw);
    view_set_enter_callback(app->run_view, railkey_run_enter);
    view_set_exit_callback(app->run_view, railkey_run_exit);
    view_set_previous_callback(app->run_view, railkey_prev_submenu);
    view_dispatcher_add_view(app->view_dispatcher, RailKeyViewRun, app->run_view);

    // About / Legal
    app->popup = popup_alloc();
    popup_set_header(app->popup, "RailKey", 64, 6, AlignCenter, AlignTop);
    popup_set_text(
        app->popup,
        "Authorized testing only.\n"
        "Use only on readers you\n"
        "own or may test in\n"
        "writing.",
        64,
        20,
        AlignCenter,
        AlignTop);
    view_set_previous_callback(popup_get_view(app->popup), railkey_prev_submenu);
    view_dispatcher_add_view(app->view_dispatcher, RailKeyViewAbout, popup_get_view(app->popup));

    return app;
}

static void railkey_free(RailKey* app) {
    railkey_stop_worker(app);

    view_dispatcher_remove_view(app->view_dispatcher, RailKeyViewSubmenu);
    view_dispatcher_remove_view(app->view_dispatcher, RailKeyViewSettings);
    view_dispatcher_remove_view(app->view_dispatcher, RailKeyViewSeed);
    view_dispatcher_remove_view(app->view_dispatcher, RailKeyViewRun);
    view_dispatcher_remove_view(app->view_dispatcher, RailKeyViewAbout);

    submenu_free(app->submenu);
    variable_item_list_free(app->settings_list);
    byte_input_free(app->byte_input);
    popup_free(app->popup);
    view_free(app->run_view);

    view_dispatcher_free(app->view_dispatcher);

    furi_record_close(RECORD_NOTIFICATION);
    furi_record_close(RECORD_GUI);

    furi_mutex_free(app->run.mutex);
    free(app);
}

int32_t railkey_app(void* p) {
    UNUSED(p);
    RailKey* app = railkey_alloc();

    view_dispatcher_switch_to_view(app->view_dispatcher, RailKeyViewSubmenu);
    view_dispatcher_run(app->view_dispatcher);

    railkey_free(app);
    return 0;
}

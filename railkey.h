#pragma once

#include <furi.h>
#include <gui/gui.h>
#include <gui/view.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/variable_item_list.h>
#include <gui/modules/byte_input.h>
#include <gui/modules/popup.h>
#include <notification/notification.h>
#include <notification/notification_messages.h>

#include "railkey_engine.h"

typedef enum {
    RailKeyViewSubmenu,
    RailKeyViewSettings,
    RailKeyViewSeed,
    RailKeyViewRun,
    RailKeyViewAbout,
} RailKeyViewId;

// Shared state written by the fuzz worker thread and read by the GUI timer.
// All access is guarded by `mutex`.
typedef struct {
    FuriMutex* mutex;
    volatile bool running;
    bool finished;
    RailKeyMode mode;
    uint32_t attempts;
    uint32_t total;
    uint32_t start_ms;
    RailKeyProto cur_proto;
    uint8_t cur_data[5];
    size_t cur_len;
} RailKeyRun;

typedef struct {
    Gui* gui;
    ViewDispatcher* view_dispatcher;
    NotificationApp* notifications;
    Submenu* submenu;
    VariableItemList* settings_list;
    ByteInput* byte_input;
    Popup* popup;
    View* run_view;
    FuriTimer* run_timer;

    RailKeySettings settings;
    RailKeyMode pending_mode;

    FuriThread* worker;
    RailKeyRun run;

    uint8_t seed_bytes[2]; // HID card number entry for neighborhood mode
} RailKey;

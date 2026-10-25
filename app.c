#include <furi.h>
#include <gui/gui.h>
#include <furi_hal.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_input.h>
#include <gui/modules/widget.h>
#include <gui/view.h>
#include <bt/bt_service/bt.h>
#include <lib/ble_profile/extra_profiles/hid_profile.h>
#include <storage/storage.h>
#include <flipper_format/flipper_format.h>

#define FAPP_NAME "FPass"
#define FPASS_MAX_PASSWORDS 20
#define FPASS_PASSWORD_SIZE 64
#define FPASS_LABEL_SIZE 32
#define FPASS_PASSWORDS_PATH APP_DATA_PATH("passwords.txt")
#define FPASS_METADATA_FILE "labels.txt"
#define FPASS_PASSWORDS_FILE_SIZE \
    (FPASS_MAX_PASSWORDS * (FPASS_LABEL_SIZE + FPASS_PASSWORD_SIZE + 2))
#define FPASS_METADATA_FILE_SIZE (FPASS_MAX_PASSWORDS * (11 + FPASS_LABEL_SIZE))

static const char fpass_password_file_prefix[] = "STRING ";

typedef enum {
    FPassSubmenuIndexCreatePassword,
    FPassSubmenuIndexSavedPasswords,
    FPassSubmenuIndexAbout,
} FPassSubmenuIndex;

typedef enum {
    FPassCreateIndexLabel,
    FPassCreateIndexPassword,
    FPassCreateIndexSave,
} FPassCreateIndex;

typedef enum {
    FPassEntryIndexShowPassword,
    FPassEntryIndexTypePassword,
    FPassEntryIndexChangeLabel,
    FPassEntryIndexDelete,
} FPassEntryIndex;

typedef enum {
    FPassTypingTransportUsb,
    FPassTypingTransportBle,
} FPassTypingTransport;

typedef enum {
    FPassTypingStateConnecting,
    FPassTypingStateWaiting,
    FPassTypingStateTyping,
    FPassTypingStateDone,
    FPassTypingStateError,
    FPassTypingStateCancelled,
} FPassTypingState;

typedef enum {
    FPassViewSubmenu,
    FPassViewCreatePassword,
    FPassViewTextInput,
    FPassViewSavedPasswords,
    FPassViewEntryActions,
    FPassViewTypingTransport,
    FPassViewTyping,
    FPassViewScreen,
} FPassView;

typedef struct {
    FPassTypingTransport transport;
    FPassTypingState state;
    uint32_t progress;
    uint32_t total;
    char label[FPASS_LABEL_SIZE];
    char message[48];
} FPassTypingModel;

typedef struct {
    ViewDispatcher* view_dispatcher;
    Submenu* submenu;
    Submenu* create_password_submenu;
    Submenu* saved_passwords_submenu;
    Submenu* entry_actions_submenu;
    Submenu* typing_transport_submenu;
    TextInput* text_input;
    View* typing_view;
    Widget* screen;
    Storage* storage;
    FuriString* passwords_path;
    FuriString* data_directory;
    char labels[FPASS_MAX_PASSWORDS][FPASS_LABEL_SIZE];
    char passwords[FPASS_MAX_PASSWORDS][FPASS_PASSWORD_SIZE];
    uint32_t password_ids[FPASS_MAX_PASSWORDS];
    uint32_t password_count;
    uint32_t selected_password;
    char temp_label[FPASS_LABEL_SIZE];
    char temp_password[FPASS_PASSWORD_SIZE];
    FuriThread* typing_thread;
    Bt* typing_bt;
    FuriHalBleProfileBase* ble_profile;
    FPassTypingTransport typing_transport;
    volatile bool typing_cancel_requested;
    volatile bool ble_connected;
} FPassApp;

static void fpass_create_password_callback(void* context, uint32_t index);
static void fpass_saved_password_callback(void* context, uint32_t index);
static void fpass_entry_action_callback(void* context, uint32_t index);
static void fpass_typing_transport_callback(void* context, uint32_t index);

static uint32_t fpass_navigation_exit_callback(void* context) {
    UNUSED(context);
    return VIEW_NONE;
}

static uint32_t fpass_navigation_to_submenu_callback(void* context) {
    UNUSED(context);
    return FPassViewSubmenu;
}

static uint32_t fpass_navigation_to_saved_passwords_callback(void* context) {
    UNUSED(context);
    return FPassViewSavedPasswords;
}

static uint32_t fpass_navigation_to_create_password_callback(void* context) {
    UNUSED(context);
    return FPassViewCreatePassword;
}

static uint32_t fpass_navigation_to_entry_actions_callback(void* context) {
    UNUSED(context);
    return FPassViewEntryActions;
}

static void fpass_update_create_password_menu(FPassApp* app) {
    char label[FPASS_LABEL_SIZE];
    snprintf(label, sizeof(label), "Label: %.20s", app->temp_label);
    submenu_change_item_label(
        app->create_password_submenu, FPassCreateIndexLabel, label);
    submenu_change_item_label(
        app->create_password_submenu,
        FPassCreateIndexPassword,
        app->temp_password[0] == '\0' ? "Enter password" : "Password: set");
}

static bool fpass_legacy_passwords_load(FPassApp* app) {
    const char* path = furi_string_get_cstr(app->passwords_path);
    if(!storage_file_exists(app->storage, path)) {
        return true;
    }

    File* file = storage_file_alloc(app->storage);
    if(!storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        FURI_LOG_E(FAPP_NAME, "Could not open password file: %s", path);
        storage_file_close(file);
        storage_file_free(file);
        return false;
    }

    char contents[FPASS_PASSWORDS_FILE_SIZE + 1];
    size_t contents_size = 0;
    while(!storage_file_eof(file) && contents_size < sizeof(contents)) {
        size_t bytes_read = storage_file_read(
            file, contents + contents_size, sizeof(contents) - contents_size);
        if(bytes_read == 0) break;
        contents_size += bytes_read;
    }

    bool read_ok = storage_file_eof(file) && storage_file_get_error(file) == FSE_OK;
    bool close_ok = storage_file_close(file);
    storage_file_free(file);
    if(!read_ok || !close_ok || contents_size > FPASS_PASSWORDS_FILE_SIZE) {
        FURI_LOG_E(FAPP_NAME, "Could not read password file");
        return false;
    }

    char line[FPASS_LABEL_SIZE + FPASS_PASSWORD_SIZE + 1];
    uint32_t line_length = 0;
    for(size_t i = 0; i < contents_size; i++) {
        char character = contents[i];
        if(character == '\r') {
            continue;
        }
        if(character == '\n') {
            if(line_length > 0) {
                if(app->password_count >= FPASS_MAX_PASSWORDS) {
                    FURI_LOG_E(FAPP_NAME, "Password file contains too many entries");
                    return false;
                }
                line[line_length] = '\0';
                char* separator = strchr(line, '\t');
                if(separator) {
                    *separator = '\0';
                    size_t label_length = strlen(line);
                    size_t password_length = strlen(separator + 1);
                    if(label_length == 0 || label_length >= FPASS_LABEL_SIZE ||
                       password_length == 0 || password_length >= FPASS_PASSWORD_SIZE) {
                        FURI_LOG_E(FAPP_NAME, "Password file contains an invalid entry");
                        return false;
                    }
                    memcpy(app->labels[app->password_count], line, label_length + 1);
                    memcpy(
                        app->passwords[app->password_count],
                        separator + 1,
                        password_length + 1);
                } else {
                    size_t password_length = strlen(line);
                    if(password_length >= FPASS_PASSWORD_SIZE) {
                        FURI_LOG_E(FAPP_NAME, "Password file contains an invalid entry");
                        return false;
                    }
                    snprintf(
                        app->labels[app->password_count],
                        FPASS_LABEL_SIZE,
                        "Password %lu",
                        (unsigned long)(app->password_count + 1));
                    memcpy(
                        app->passwords[app->password_count],
                        line,
                        password_length + 1);
                }
                app->password_count++;
                line_length = 0;
            }
        } else {
            if(character == '\0' || line_length >= sizeof(line) - 1) {
                FURI_LOG_E(FAPP_NAME, "Password file contains an invalid entry");
                return false;
            }
            line[line_length++] = character;
        }
    }

    if(line_length > 0) {
        if(app->password_count >= FPASS_MAX_PASSWORDS) {
            FURI_LOG_E(FAPP_NAME, "Password file contains too many entries");
            return false;
        }
        line[line_length] = '\0';
        char* separator = strchr(line, '\t');
        if(separator) {
            *separator = '\0';
            size_t label_length = strlen(line);
            size_t password_length = strlen(separator + 1);
            if(label_length == 0 || label_length >= FPASS_LABEL_SIZE ||
               password_length == 0 || password_length >= FPASS_PASSWORD_SIZE) {
                FURI_LOG_E(FAPP_NAME, "Password file contains an invalid entry");
                return false;
            }
            memcpy(app->labels[app->password_count], line, label_length + 1);
            memcpy(
                app->passwords[app->password_count],
                separator + 1,
                password_length + 1);
        } else {
            size_t password_length = strlen(line);
            if(password_length >= FPASS_PASSWORD_SIZE) {
                FURI_LOG_E(FAPP_NAME, "Password file contains an invalid entry");
                return false;
            }
            snprintf(
                app->labels[app->password_count],
                FPASS_LABEL_SIZE,
                "Password %lu",
                (unsigned long)(app->password_count + 1));
            memcpy(
                app->passwords[app->password_count],
                line,
                password_length + 1);
        }
        app->password_count++;
    }

    return true;
}

static void fpass_password_file_path(FPassApp* app, uint32_t id, FuriString* path) {
    furi_string_printf(
        path,
        "%s/password_%lu.txt",
        furi_string_get_cstr(app->data_directory),
        (unsigned long)id);
}

static void fpass_metadata_file_path(FPassApp* app, FuriString* path) {
    furi_string_printf(
        path,
        "%s/%s",
        furi_string_get_cstr(app->data_directory),
        FPASS_METADATA_FILE);
}

static bool fpass_file_write(Storage* storage, const char* path, const char* contents, size_t size) {
    File* file = storage_file_alloc(storage);
    if(!storage_file_open(file, path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        FURI_LOG_E(FAPP_NAME, "Could not open file for writing: %s", path);
        storage_file_close(file);
        storage_file_free(file);
        return false;
    }
    bool write_ok = storage_file_write(file, contents, size) == size;
    bool close_ok = storage_file_close(file);
    storage_file_free(file);
    if(!write_ok || !close_ok) {
        FURI_LOG_E(FAPP_NAME, "Could not write file: %s", path);
        return false;
    }
    return true;
}

static bool fpass_file_read(
    Storage* storage, const char* path, char* contents, size_t capacity, size_t* size) {
    File* file = storage_file_alloc(storage);
    if(!storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        FURI_LOG_E(FAPP_NAME, "Could not open file for reading: %s", path);
        storage_file_close(file);
        storage_file_free(file);
        return false;
    }

    *size = 0;
    while(!storage_file_eof(file) && *size < capacity) {
        size_t bytes_read = storage_file_read(file, contents + *size, capacity - *size);
        if(bytes_read == 0) break;
        *size += bytes_read;
    }
    bool read_ok = storage_file_eof(file) && storage_file_get_error(file) == FSE_OK;
    bool close_ok = storage_file_close(file);
    storage_file_free(file);
    if(!read_ok || !close_ok) {
        FURI_LOG_E(FAPP_NAME, "Could not read file: %s", path);
        return false;
    }
    return true;
}

static bool fpass_password_file_save(FPassApp* app, uint32_t id, const char* password) {
    FuriString* path = furi_string_alloc();
    fpass_password_file_path(app, id, path);
    char file_contents[sizeof(fpass_password_file_prefix) + FPASS_PASSWORD_SIZE - 1];
    size_t prefix_size = sizeof(fpass_password_file_prefix) - 1;
    size_t password_size = strlen(password);
    memcpy(file_contents, fpass_password_file_prefix, prefix_size);
    memcpy(file_contents + prefix_size, password, password_size);
    bool saved = fpass_file_write(
        app->storage,
        furi_string_get_cstr(path),
        file_contents,
        prefix_size + password_size);
    furi_string_free(path);
    return saved;
}

static bool fpass_password_file_load(FPassApp* app, uint32_t id, char* password) {
    FuriString* path = furi_string_alloc();
    fpass_password_file_path(app, id, path);
    char file_contents[sizeof(fpass_password_file_prefix) + FPASS_PASSWORD_SIZE - 1];
    size_t size = 0;
    bool loaded = fpass_file_read(
        app->storage,
        furi_string_get_cstr(path),
        file_contents,
        sizeof(file_contents),
        &size);
    furi_string_free(path);
    if(!loaded) return false;

    size_t prefix_size = sizeof(fpass_password_file_prefix) - 1;
    if(size >= prefix_size &&
       memcmp(file_contents, fpass_password_file_prefix, prefix_size) == 0) {
        memmove(file_contents, file_contents + prefix_size, size - prefix_size);
        size -= prefix_size;
    }
    if(size == 0 || size >= FPASS_PASSWORD_SIZE) {
        FURI_LOG_E(FAPP_NAME, "Password file is empty or too large");
        return false;
    }
    memcpy(password, file_contents, size);
    password[size] = '\0';
    return true;
}

static bool fpass_metadata_save(
    FPassApp* app,
    const uint32_t ids[FPASS_MAX_PASSWORDS],
    const char labels[FPASS_MAX_PASSWORDS][FPASS_LABEL_SIZE],
    uint32_t password_count) {
    char metadata[FPASS_METADATA_FILE_SIZE];
    size_t metadata_size = 0;
    for(uint32_t i = 0; i < password_count; i++) {
        if(ids[i] == UINT32_MAX) {
            FURI_LOG_E(FAPP_NAME, "Password identifier is invalid");
            return false;
        }
        size_t label_length = strlen(labels[i]);
        if(label_length == 0 || label_length >= FPASS_LABEL_SIZE ||
           strchr(labels[i], '\n') != NULL || strchr(labels[i], '\r') != NULL ||
           strchr(labels[i], '\t') != NULL) {
            FURI_LOG_E(FAPP_NAME, "Password label is invalid");
            return false;
        }
        int written = snprintf(
            metadata + metadata_size,
            sizeof(metadata) - metadata_size,
            "%lu\t%s\n",
            (unsigned long)ids[i],
            labels[i]);
        if(written < 0 || (size_t)written >= sizeof(metadata) - metadata_size) {
            FURI_LOG_E(FAPP_NAME, "Password metadata is too large");
            return false;
        }
        metadata_size += (size_t)written;
    }

    FuriString* path = furi_string_alloc();
    fpass_metadata_file_path(app, path);
    bool saved = fpass_file_write(
        app->storage, furi_string_get_cstr(path), metadata, metadata_size);
    furi_string_free(path);
    return saved;
}

static bool fpass_passwords_load(FPassApp* app) {
    FuriString* metadata_path = furi_string_alloc();
    fpass_metadata_file_path(app, metadata_path);
    const char* metadata_path_cstr = furi_string_get_cstr(metadata_path);

    if(storage_file_exists(app->storage, metadata_path_cstr)) {
        char metadata[FPASS_METADATA_FILE_SIZE];
        size_t metadata_size = 0;
        bool read_ok = fpass_file_read(
            app->storage,
            metadata_path_cstr,
            metadata,
            sizeof(metadata),
            &metadata_size);
        furi_string_free(metadata_path);
        if(!read_ok) return false;

        char line[FPASS_LABEL_SIZE + 12];
        size_t line_length = 0;
        for(size_t i = 0; i <= metadata_size; i++) {
            char character = i < metadata_size ? metadata[i] : '\n';
            if(character == '\r') continue;
            if(character != '\n') {
                if(line_length >= sizeof(line) - 1 || character == '\0') {
                    FURI_LOG_E(FAPP_NAME, "Password metadata is invalid");
                    return false;
                }
                line[line_length++] = character;
                continue;
            }
            if(line_length == 0) continue;
            if(app->password_count >= FPASS_MAX_PASSWORDS) {
                FURI_LOG_E(FAPP_NAME, "Too many saved passwords");
                return false;
            }
            line[line_length] = '\0';
            char* separator = strchr(line, '\t');
            if(separator == NULL || separator == line || separator[1] == '\0') {
                FURI_LOG_E(FAPP_NAME, "Password metadata entry is invalid");
                return false;
            }

            uint32_t id = 0;
            for(char* digit = line; digit < separator; digit++) {
                if(*digit < '0' || *digit > '9' ||
                   id > (UINT32_MAX - (uint32_t)(*digit - '0')) / 10) {
                    FURI_LOG_E(FAPP_NAME, "Password identifier is invalid");
                    return false;
                }
                id = id * 10 + (uint32_t)(*digit - '0');
            }
            if(id == UINT32_MAX) {
                FURI_LOG_E(FAPP_NAME, "Password identifier is invalid");
                return false;
            }
            *separator = '\0';
            size_t label_length = strlen(separator + 1);
            if(label_length >= FPASS_LABEL_SIZE || strchr(separator + 1, '\t') != NULL) {
                FURI_LOG_E(FAPP_NAME, "Password label is invalid");
                return false;
            }
            for(uint32_t entry = 0; entry < app->password_count; entry++) {
                if(app->password_ids[entry] == id) {
                    FURI_LOG_E(FAPP_NAME, "Duplicate password identifier");
                    return false;
                }
            }

            uint32_t entry = app->password_count;
            app->password_ids[entry] = id;
            memcpy(app->labels[entry], separator + 1, label_length + 1);
            if(!fpass_password_file_load(app, id, app->passwords[entry])) return false;
            app->password_count++;
            line_length = 0;
        }
        return true;
    }

    furi_string_free(metadata_path);
    if(!storage_file_exists(app->storage, furi_string_get_cstr(app->passwords_path))) {
        return true;
    }

    if(!fpass_legacy_passwords_load(app)) return false;
    for(uint32_t i = 0; i < app->password_count; i++) {
        app->password_ids[i] = i;
        if(!fpass_password_file_save(app, app->password_ids[i], app->passwords[i])) {
            return false;
        }
    }
    if(!fpass_metadata_save(app, app->password_ids, app->labels, app->password_count)) {
        return false;
    }
    FS_Error remove_error =
        storage_common_remove(app->storage, furi_string_get_cstr(app->passwords_path));
    if(remove_error != FSE_OK) {
        FURI_LOG_E(FAPP_NAME, "Could not remove migrated password file");
        return false;
    }
    return true;
}

static void fpass_show_message(FPassApp* app, const char* message, uint32_t return_view) {
    widget_reset(app->screen);
    widget_add_text_scroll_element(app->screen, 0, 0, 128, 64, message);
    view_set_previous_callback(
        widget_get_view(app->screen),
        return_view == FPassViewSavedPasswords ?
            fpass_navigation_to_saved_passwords_callback :
        return_view == FPassViewEntryActions ? fpass_navigation_to_entry_actions_callback :
        return_view == FPassViewCreatePassword ? fpass_navigation_to_create_password_callback :
                                                 fpass_navigation_to_submenu_callback);
    view_dispatcher_switch_to_view(app->view_dispatcher, FPassViewScreen);
}

static void fpass_build_saved_passwords_menu(FPassApp* app) {
    submenu_reset(app->saved_passwords_submenu);
    submenu_set_header(app->saved_passwords_submenu, "Saved Passwords");
    for(uint32_t i = 0; i < app->password_count; i++) {
        submenu_add_item(
            app->saved_passwords_submenu,
            app->labels[i],
            i,
            fpass_saved_password_callback,
            app);
    }
}

static void fpass_show_password(FPassApp* app, uint32_t index) {
    app->selected_password = index;
    widget_reset(app->screen);
    char details[FPASS_LABEL_SIZE + FPASS_PASSWORD_SIZE + 4];
    snprintf(
        details,
        sizeof(details),
        "\e#%s\n\n%s",
        app->labels[index],
        app->passwords[index]);
    widget_add_text_scroll_element(app->screen, 0, 0, 128, 64, details);
    view_set_previous_callback(
        widget_get_view(app->screen), fpass_navigation_to_entry_actions_callback);
    view_dispatcher_switch_to_view(app->view_dispatcher, FPassViewScreen);
}

static bool fpass_hid_send_key(uint16_t key) {
    bool pressed = false;
    for(uint32_t attempt = 0; attempt < 4; attempt++) {
        if(furi_hal_hid_kb_press(key)) {
            pressed = true;
            break;
        }
        furi_delay_ms(10);
    }
    if(!pressed) return false;

    furi_delay_ms(20);
    bool released = false;
    for(uint32_t attempt = 0; attempt < 4; attempt++) {
        if(furi_hal_hid_kb_release(key)) {
            released = true;
            break;
        }
        furi_delay_ms(10);
    }
    furi_delay_ms(10);
    return released;
}

static bool fpass_hid_release_all(void) {
    for(uint32_t attempt = 0; attempt < 50; attempt++) {
        if(furi_hal_hid_kb_release_all()) return true;
        furi_delay_ms(20);
    }
    return false;
}

static bool fpass_ble_send_key(FuriHalBleProfileBase* profile, uint16_t key) {
    bool pressed = false;
    for(uint32_t attempt = 0; attempt < 4; attempt++) {
        if(ble_profile_hid_kb_press(profile, key)) {
            pressed = true;
            break;
        }
        furi_delay_ms(50);
    }
    if(!pressed) return false;

    furi_delay_ms(50);
    bool released = false;
    for(uint32_t attempt = 0; attempt < 4; attempt++) {
        if(ble_profile_hid_kb_release(profile, key)) {
            released = true;
            break;
        }
        furi_delay_ms(50);
    }
    furi_delay_ms(30);
    return released;
}

static void fpass_ble_session_stop(FPassApp* app) {
    if(app->typing_bt == NULL) return;

    bt_set_status_changed_callback(app->typing_bt, NULL, NULL);
    bt_disconnect(app->typing_bt);
    furi_delay_ms(200);
    bt_keys_storage_set_default_path(app->typing_bt);
    if(!bt_profile_restore_default(app->typing_bt)) {
        FURI_LOG_E(FAPP_NAME, "Could not restore previous BLE profile");
    }
    furi_record_close(RECORD_BT);
    app->typing_bt = NULL;
    app->ble_profile = NULL;
    app->ble_connected = false;
}

static void fpass_typing_update(
    FPassApp* app,
    FPassTypingState state,
    uint32_t progress,
    const char* message) {
    FPassTypingModel* model = view_get_model(app->typing_view);
    model->state = state;
    model->progress = progress;
    snprintf(model->message, sizeof(model->message), "%s", message);
    view_commit_model(app->typing_view, true);
}

static void fpass_typing_draw(Canvas* canvas, void* model_context) {
    const FPassTypingModel* model = model_context;
    canvas_clear(canvas);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 8, "FPass");
    canvas_draw_line(canvas, 2, 11, 126, 11);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 26, model->label);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(
        canvas,
        2,
        37,
        model->transport == FPassTypingTransportUsb ? "USB keyboard" : "BLE keyboard");
    canvas_draw_str(canvas, 2, 48, model->message);
    if(model->state == FPassTypingStateTyping && model->total > 0) {
        canvas_draw_frame(canvas, 4, 52, 120, 7);
        uint32_t width = model->progress * 116 / model->total;
        if(width > 0) canvas_draw_box(canvas, 6, 54, width, 3);
    } else if(model->state == FPassTypingStateConnecting ||
              model->state == FPassTypingStateWaiting) {
        canvas_draw_str(canvas, 2, 61, "BACK: cancel");
    } else if(model->state == FPassTypingStateDone ||
              model->state == FPassTypingStateError ||
              model->state == FPassTypingStateCancelled) {
        canvas_draw_str(canvas, 2, 61, "OK: retry  BACK: return");
    } else {
        canvas_draw_str(canvas, 2, 61, "BACK: return");
    }
}

static void fpass_start_typing(FPassApp* app, FPassTypingTransport transport);

static bool fpass_typing_input(InputEvent* event, void* context) {
    FPassApp* app = context;
    if(event->type != InputTypeShort ||
       (event->key != InputKeyOk && event->key != InputKeyBack)) {
        return false;
    }

    FPassTypingModel* model = view_get_model(app->typing_view);
    FPassTypingState state = model->state;
    FPassTypingTransport transport = model->transport;
    if(event->key == InputKeyOk &&
       (state == FPassTypingStateDone || state == FPassTypingStateError ||
        state == FPassTypingStateCancelled)) {
        view_commit_model(app->typing_view, false);
        fpass_start_typing(app, transport);
        return true;
    }

    bool active = state == FPassTypingStateConnecting ||
                  state == FPassTypingStateWaiting ||
                  state == FPassTypingStateTyping;
    if(active) {
        app->typing_cancel_requested = true;
        snprintf(model->message, sizeof(model->message), "Canceling...");
        view_commit_model(app->typing_view, true);
        return true;
    }
    view_commit_model(app->typing_view, false);
    return false;
}

static void fpass_ble_status_changed(BtStatus status, void* context) {
    FPassApp* app = context;
    app->ble_connected = status == BtStatusConnected;
}

static bool fpass_delay_with_cancel(FPassApp* app, uint32_t milliseconds) {
    while(milliseconds > 0) {
        if(app->typing_cancel_requested) return false;
        uint32_t delay = milliseconds > 20 ? 20 : milliseconds;
        furi_delay_ms(delay);
        milliseconds -= delay;
    }
    return !app->typing_cancel_requested;
}

static int32_t fpass_typing_worker(void* context) {
    FPassApp* app = context;
    const char* password = app->passwords[app->selected_password];
    uint32_t password_length = strlen(password);
    uint32_t progress = 0;
    bool connected = false;
    bool ready = false;
    bool typed = true;
    bool keys_released = true;
    bool cancelled = false;
    uint32_t failed_character = 0;
    FuriHalUsbInterface* previous_usb_mode = NULL;
    bool usb_was_locked = false;
    bool usb_mode_changed = false;
    bool transport_restored = true;
    FuriHalBleProfileBase* ble_profile = NULL;

    fpass_typing_update(
        app,
        FPassTypingStateConnecting,
        0,
        app->typing_transport == FPassTypingTransportUsb ? "Switching USB..." : "Starting BLE...");

    if(app->typing_transport == FPassTypingTransportUsb) {
        usb_was_locked = furi_hal_usb_is_locked();
        previous_usb_mode = furi_hal_usb_get_config();
        if(usb_was_locked) furi_hal_usb_unlock();

        bool disconnected = furi_hal_usb_set_config(NULL, NULL);
        usb_mode_changed = disconnected;
        bool hid_started = disconnected && furi_hal_usb_set_config(&usb_hid, NULL);
        if(!hid_started) {
            bool restored = !disconnected || furi_hal_usb_set_config(previous_usb_mode, NULL);
            if(!restored) FURI_LOG_E(FAPP_NAME, "Could not restore USB mode after reconnect failure");
            if(usb_was_locked) furi_hal_usb_lock();
            fpass_typing_update(
                app,
                FPassTypingStateError,
                0,
                restored ? "Could not start USB HID." : "USB restore failed.");
            return 0;
        }

        fpass_typing_update(
            app, FPassTypingStateWaiting, 0, "Connect USB host...");
        for(uint32_t attempt = 0; attempt < 100; attempt++) {
            if(app->typing_cancel_requested) break;
            if(furi_hal_hid_is_connected()) {
                connected = true;
                break;
            }
            furi_delay_ms(50);
        }
        if(connected && fpass_delay_with_cancel(app, 500)) {
            ready = fpass_hid_release_all();
        }
    } else {
        if(app->typing_bt == NULL) {
            app->typing_bt = furi_record_open(RECORD_BT);
            bt_disconnect(app->typing_bt);
            furi_delay_ms(200);
            FuriString* keys_path = furi_string_alloc();
            furi_string_printf(
                keys_path,
                "%s/fpass_ble.keys",
                furi_string_get_cstr(app->data_directory));
            bt_keys_storage_set_storage_path(
                app->typing_bt, furi_string_get_cstr(keys_path));
            furi_string_free(keys_path);

            BleProfileHidParams params = {
                .device_name_prefix = "FPass",
                .mac_xor = 0x0004,
            };
            app->ble_profile = bt_profile_start(app->typing_bt, ble_profile_hid, &params);
            if(app->ble_profile == NULL) {
                fpass_ble_session_stop(app);
                fpass_typing_update(
                    app, FPassTypingStateError, 0, "Could not start BLE keyboard.");
                return 0;
            }

            app->ble_connected = false;
            bt_set_status_changed_callback(
                app->typing_bt, fpass_ble_status_changed, app);
        }
        ble_profile = app->ble_profile;
        furi_hal_bt_start_advertising();
        fpass_typing_update(app, FPassTypingStateWaiting, 0, "Pair with FPass keyboard...");
        for(uint32_t attempt = 0; attempt < 600; attempt++) {
            if(app->typing_cancel_requested) break;
            if(app->ble_connected) {
                connected = true;
                break;
            }
            furi_delay_ms(100);
        }
        if(connected && fpass_delay_with_cancel(app, 300)) {
            ready = ble_profile_hid_kb_release_all(ble_profile);
        }
    }

    if(app->typing_cancel_requested) {
        cancelled = true;
    } else if(!connected) {
        typed = false;
    } else if(!ready) {
        typed = false;
    } else {
        fpass_typing_update(app, FPassTypingStateTyping, 0, "Typing password...");
        uint32_t position = 1;
        for(const char* character = password; *character != '\0'; character++, position++) {
            if(app->typing_cancel_requested) {
                cancelled = true;
                break;
            }
            uint16_t key = HID_ASCII_TO_KEY((uint8_t)*character);
            bool key_sent;
            if(app->typing_transport == FPassTypingTransportUsb) {
                key_sent = fpass_hid_send_key(key);
            } else {
                key_sent = fpass_ble_send_key(ble_profile, key);
            }
            if(!key_sent) {
                typed = false;
                failed_character = position;
                break;
            }
            progress++;
            fpass_typing_update(app, FPassTypingStateTyping, progress, "Typing password...");
        }
    }

    if(connected && ready) {
        if(app->typing_transport == FPassTypingTransportUsb) {
            keys_released = fpass_hid_release_all();
        } else if(ble_profile) {
            keys_released = ble_profile_hid_kb_release_all(ble_profile);
        }
    }

    if(app->typing_transport == FPassTypingTransportUsb && usb_mode_changed) {
        bool restored = furi_hal_usb_set_config(previous_usb_mode, NULL);
        transport_restored = restored;
        if(!restored) {
            FURI_LOG_E(FAPP_NAME, "Could not restore previous USB mode");
            typed = false;
        }
        if(usb_was_locked) furi_hal_usb_lock();
    }

    if(cancelled) {
        fpass_typing_update(app, FPassTypingStateCancelled, progress, "Typing canceled.");
    } else if(!transport_restored) {
        fpass_typing_update(app, FPassTypingStateError, progress, "Could not restore connection.");
    } else if(!connected) {
        fpass_typing_update(
            app,
            FPassTypingStateError,
            progress,
            app->typing_transport == FPassTypingTransportUsb ? "No USB host found." :
                                                               "No BLE device connected.");
    } else if(!ready) {
        fpass_typing_update(app, FPassTypingStateError, progress, "Keyboard not ready.");
    } else if(!typed) {
        char message[48];
        snprintf(
            message,
            sizeof(message),
            "Typing failed at character %lu.",
            (unsigned long)failed_character);
        fpass_typing_update(app, FPassTypingStateError, progress, message);
    } else if(!keys_released) {
        fpass_typing_update(app, FPassTypingStateError, progress, "Could not reset keyboard.");
    } else {
        fpass_typing_update(app, FPassTypingStateDone, password_length, "Password typed.");
    }
    return 0;
}

static void fpass_start_typing(FPassApp* app, FPassTypingTransport transport) {
    uint32_t index = app->selected_password;
    if(index >= app->password_count) return;

    const char* password = app->passwords[index];
    for(const char* character = password; *character != '\0'; character++) {
        uint8_t ascii = (uint8_t)*character;
        if(ascii < 0x20 || ascii > 0x7e ||
           HID_ASCII_TO_KEY(ascii) == HID_KEYBOARD_NONE) {
            fpass_show_message(
                app, "Password contains unsupported characters.", FPassViewEntryActions);
            return;
        }
    }

    if(app->typing_thread) {
        furi_thread_join(app->typing_thread);
        furi_thread_free(app->typing_thread);
        app->typing_thread = NULL;
    }

    app->typing_transport = transport;
    app->typing_cancel_requested = false;
    FPassTypingModel* model = view_get_model(app->typing_view);
    model->transport = transport;
    model->state = FPassTypingStateConnecting;
    model->progress = 0;
    model->total = strlen(password);
    snprintf(model->label, sizeof(model->label), "%.24s", app->labels[index]);
    snprintf(model->message, sizeof(model->message), "Starting...");
    view_commit_model(app->typing_view, true);

    app->typing_thread = furi_thread_alloc_ex(
        transport == FPassTypingTransportUsb ? "FPassUsbTyping" : "FPassBleTyping",
        4096,
        fpass_typing_worker,
        app);
    furi_thread_start(app->typing_thread);
    view_dispatcher_switch_to_view(app->view_dispatcher, FPassViewTyping);
}

static void fpass_delete_password(FPassApp* app) {
    uint32_t index = app->selected_password;
    if(index >= app->password_count) return;

    uint32_t deleted_id = app->password_ids[index];
    uint32_t updated_ids[FPASS_MAX_PASSWORDS] = {0};
    char updated_labels[FPASS_MAX_PASSWORDS][FPASS_LABEL_SIZE] = {{0}};
    char updated_passwords[FPASS_MAX_PASSWORDS][FPASS_PASSWORD_SIZE] = {{0}};
    uint32_t updated_count = app->password_count - 1;
    for(uint32_t source = 0, destination = 0; source < app->password_count; source++) {
        if(source != index) {
            updated_ids[destination] = app->password_ids[source];
            memcpy(
                updated_labels[destination],
                app->labels[source],
                sizeof(updated_labels[destination]));
            memcpy(
                updated_passwords[destination],
                app->passwords[source],
                sizeof(updated_passwords[destination]));
            destination++;
        }
    }

    if(!fpass_metadata_save(app, updated_ids, updated_labels, updated_count)) {
        fpass_show_message(app, "Could not save changes.", FPassViewEntryActions);
        return;
    }

    FuriString* password_path = furi_string_alloc();
    fpass_password_file_path(app, deleted_id, password_path);
    FS_Error remove_error =
        storage_common_remove(app->storage, furi_string_get_cstr(password_path));
    furi_string_free(password_path);
    if(remove_error != FSE_OK) {
        if(!fpass_metadata_save(app, app->password_ids, app->labels, app->password_count)) {
            FURI_LOG_E(FAPP_NAME, "Could not restore password metadata after delete failure");
        }
        FURI_LOG_E(FAPP_NAME, "Could not delete password file");
        fpass_show_message(app, "Could not delete password file.", FPassViewEntryActions);
        return;
    }

    memset(app->password_ids, 0, sizeof(app->password_ids));
    memcpy(app->labels, updated_labels, sizeof(app->labels));
    memcpy(app->passwords, updated_passwords, sizeof(app->passwords));
    memcpy(app->password_ids, updated_ids, sizeof(app->password_ids));
    app->password_count = updated_count;
    fpass_build_saved_passwords_menu(app);
    view_dispatcher_switch_to_view(app->view_dispatcher, FPassViewSavedPasswords);
}

static void fpass_saved_password_callback(void* context, uint32_t index) {
    FPassApp* app = context;
    if(index >= app->password_count) return;
    app->selected_password = index;
    submenu_set_header(app->entry_actions_submenu, app->labels[index]);
    view_dispatcher_switch_to_view(app->view_dispatcher, FPassViewEntryActions);
}

static void fpass_change_saved_label_result_callback(void* context) {
    FPassApp* app = context;
    uint32_t index = app->selected_password;
    if(index >= app->password_count) return;
    if(app->temp_label[0] == '\0' || strchr(app->temp_label, '\t') != NULL ||
       strchr(app->temp_label, '\n') != NULL || strchr(app->temp_label, '\r') != NULL) {
        fpass_show_message(app, "Enter a valid label.", FPassViewEntryActions);
        return;
    }

    char updated_labels[FPASS_MAX_PASSWORDS][FPASS_LABEL_SIZE] = {{0}};
    memcpy(updated_labels, app->labels, sizeof(app->labels));
    memcpy(updated_labels[index], app->temp_label, sizeof(app->temp_label));
    if(!fpass_metadata_save(
           app, app->password_ids, updated_labels, app->password_count)) {
        fpass_show_message(app, "Could not save label.", FPassViewEntryActions);
        return;
    }

    memcpy(app->labels, updated_labels, sizeof(app->labels));
    fpass_build_saved_passwords_menu(app);
    view_dispatcher_switch_to_view(app->view_dispatcher, FPassViewSavedPasswords);
}

static void fpass_entry_action_callback(void* context, uint32_t index) {
    FPassApp* app = context;
    if(app->selected_password >= app->password_count) return;

    switch(index) {
    case FPassEntryIndexShowPassword:
        fpass_show_password(app, app->selected_password);
        break;
    case FPassEntryIndexTypePassword:
        submenu_set_header(app->typing_transport_submenu, "Type password");
        view_dispatcher_switch_to_view(
            app->view_dispatcher, FPassViewTypingTransport);
        break;
    case FPassEntryIndexChangeLabel:
        memcpy(
            app->temp_label,
            app->labels[app->selected_password],
            sizeof(app->temp_label));
        text_input_set_header_text(app->text_input, "Change label");
        text_input_set_result_callback(
            app->text_input,
            fpass_change_saved_label_result_callback,
            app,
            app->temp_label,
            sizeof(app->temp_label),
            false);
        view_set_previous_callback(
            text_input_get_view(app->text_input),
            fpass_navigation_to_entry_actions_callback);
        view_dispatcher_switch_to_view(app->view_dispatcher, FPassViewTextInput);
        break;
    case FPassEntryIndexDelete:
        fpass_delete_password(app);
        break;
    default:
        break;
    }
}

static void fpass_typing_transport_callback(void* context, uint32_t index) {
    FPassApp* app = context;
    if(app->selected_password >= app->password_count) return;

    switch(index) {
    case FPassTypingTransportUsb:
        fpass_start_typing(app, FPassTypingTransportUsb);
        break;
    case FPassTypingTransportBle:
        fpass_start_typing(app, FPassTypingTransportBle);
        break;
    default:
        break;
    }
}

static void fpass_label_result_callback(void* context) {
    FPassApp* app = context;
    if(app->temp_label[0] == '\0' || strchr(app->temp_label, '\t') != NULL ||
       strchr(app->temp_label, '\n') != NULL || strchr(app->temp_label, '\r') != NULL) {
        fpass_show_message(app, "Enter a valid label.", FPassViewCreatePassword);
        return;
    }
    fpass_update_create_password_menu(app);
    view_dispatcher_switch_to_view(app->view_dispatcher, FPassViewCreatePassword);
}

static void fpass_password_result_callback(void* context) {
    FPassApp* app = context;
    if(app->temp_password[0] == '\0') {
        fpass_show_message(app, "Password cannot be empty.", FPassViewCreatePassword);
        return;
    }
    fpass_update_create_password_menu(app);
    view_dispatcher_switch_to_view(app->view_dispatcher, FPassViewCreatePassword);
}

static void fpass_save_new_password(FPassApp* app) {
    if(app->temp_label[0] == '\0' || app->temp_password[0] == '\0') {
        fpass_show_message(
            app, "Set a label and password first.", FPassViewCreatePassword);
        return;
    }
    if(app->password_count >= FPASS_MAX_PASSWORDS) {
        fpass_show_message(app, "Password list is full.", FPassViewCreatePassword);
        return;
    }

    char updated_labels[FPASS_MAX_PASSWORDS][FPASS_LABEL_SIZE] = {{0}};
    uint32_t updated_ids[FPASS_MAX_PASSWORDS] = {0};
    memcpy(updated_labels, app->labels, sizeof(app->labels));
    memcpy(updated_ids, app->password_ids, sizeof(app->password_ids));
    memcpy(updated_labels[app->password_count], app->temp_label, sizeof(app->temp_label));
    uint32_t new_id = 0;
    for(;;) {
        bool id_used = false;
        for(uint32_t i = 0; i < app->password_count; i++) {
            if(app->password_ids[i] == new_id) {
                id_used = true;
                break;
            }
        }
        if(!id_used) break;
        if(new_id == UINT32_MAX - 1) {
            fpass_show_message(app, "No available password file ID.", FPassViewCreatePassword);
            return;
        }
        new_id++;
    }
    updated_ids[app->password_count] = new_id;
    if(!fpass_password_file_save(app, new_id, app->temp_password)) {
        fpass_show_message(app, "Could not save password file.", FPassViewCreatePassword);
        return;
    }
    uint32_t updated_count = app->password_count + 1;
    if(!fpass_metadata_save(app, updated_ids, updated_labels, updated_count)) {
        FuriString* password_path = furi_string_alloc();
        fpass_password_file_path(app, new_id, password_path);
        if(storage_common_remove(app->storage, furi_string_get_cstr(password_path)) != FSE_OK) {
            FURI_LOG_E(FAPP_NAME, "Could not remove unsaved password file");
        }
        furi_string_free(password_path);
        fpass_show_message(app, "Could not save password.", FPassViewCreatePassword);
        return;
    }

    memcpy(app->labels, updated_labels, sizeof(app->labels));
    memcpy(app->password_ids, updated_ids, sizeof(app->password_ids));
    memcpy(app->passwords[app->password_count], app->temp_password, sizeof(app->temp_password));
    app->password_count = updated_count;
    memset(app->temp_label, 0, sizeof(app->temp_label));
    memset(app->temp_password, 0, sizeof(app->temp_password));
    view_dispatcher_switch_to_view(app->view_dispatcher, FPassViewSubmenu);
}

static void fpass_create_password_callback(void* context, uint32_t index) {
    FPassApp* app = context;
    switch(index) {
    case FPassCreateIndexLabel:
        text_input_set_header_text(app->text_input, "Set label");
        text_input_set_result_callback(
            app->text_input,
            fpass_label_result_callback,
            app,
            app->temp_label,
            sizeof(app->temp_label),
            false);
        view_set_previous_callback(
            text_input_get_view(app->text_input),
            fpass_navigation_to_create_password_callback);
        view_dispatcher_switch_to_view(app->view_dispatcher, FPassViewTextInput);
        break;
    case FPassCreateIndexPassword:
        text_input_set_header_text(app->text_input, "Enter password");
        text_input_set_result_callback(
            app->text_input,
            fpass_password_result_callback,
            app,
            app->temp_password,
            sizeof(app->temp_password),
            false);
        view_set_previous_callback(
            text_input_get_view(app->text_input),
            fpass_navigation_to_create_password_callback);
        view_dispatcher_switch_to_view(app->view_dispatcher, FPassViewTextInput);
        break;
    case FPassCreateIndexSave:
        fpass_save_new_password(app);
        break;
    default:
        break;
    }
}

static void fpass_submenu_callback(void* context, uint32_t index) {
    FPassApp* app = context;

    switch(index) {
    case FPassSubmenuIndexCreatePassword:
        memset(app->temp_label, 0, sizeof(app->temp_label));
        memset(app->temp_password, 0, sizeof(app->temp_password));
        snprintf(
            app->temp_label,
            sizeof(app->temp_label),
            "Password %lu",
            (unsigned long)(app->password_count + 1));
        submenu_set_header(app->create_password_submenu, "Create Password");
        fpass_update_create_password_menu(app);
        view_set_previous_callback(
            submenu_get_view(app->create_password_submenu),
            fpass_navigation_to_submenu_callback);
        view_dispatcher_switch_to_view(app->view_dispatcher, FPassViewCreatePassword);
        break;
    case FPassSubmenuIndexSavedPasswords:
        if(app->password_count == 0) {
            fpass_show_message(app, "No saved passwords yet.", FPassViewSubmenu);
        } else {
            fpass_build_saved_passwords_menu(app);
            view_dispatcher_switch_to_view(
                app->view_dispatcher, FPassViewSavedPasswords);
        }
        break;
    case FPassSubmenuIndexAbout:
        fpass_show_message(
            app,
            "FPass\n\nPasswords are stored in plaintext. Do not use for real credentials.",
            FPassViewSubmenu);
        break;
    default:
        break;
    }
}

static FPassApp* fpass_app_alloc(void) {
    FPassApp* app = malloc(sizeof(FPassApp));
    memset(app, 0, sizeof(FPassApp));

    app->storage = furi_record_open(RECORD_STORAGE);
    app->passwords_path = furi_string_alloc_set(FPASS_PASSWORDS_PATH);
    storage_common_resolve_path_and_ensure_app_directory(app->storage, app->passwords_path);
    const char* passwords_path = furi_string_get_cstr(app->passwords_path);
    const char* path_separator = strrchr(passwords_path, '/');
    if(path_separator == NULL) {
        FURI_LOG_E(FAPP_NAME, "Could not resolve app data directory");
        furi_crash("Invalid app data path");
    }
    app->data_directory = furi_string_alloc();
    furi_string_set_strn(
        app->data_directory, passwords_path, (size_t)(path_separator - passwords_path));
    bool passwords_loaded = fpass_passwords_load(app);

    Gui* gui = furi_record_open(RECORD_GUI);
    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_attach_to_gui(app->view_dispatcher, gui, ViewDispatcherTypeFullscreen);
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);

    app->submenu = submenu_alloc();
    submenu_add_item(
        app->submenu,
        "Create password",
        FPassSubmenuIndexCreatePassword,
        fpass_submenu_callback,
        app);
    submenu_add_item(
        app->submenu,
        "Saved Passwords",
        FPassSubmenuIndexSavedPasswords,
        fpass_submenu_callback,
        app);
    submenu_add_item(
        app->submenu,
        "About",
        FPassSubmenuIndexAbout,
        fpass_submenu_callback,
        app);
    view_set_previous_callback(submenu_get_view(app->submenu), fpass_navigation_exit_callback);
    view_dispatcher_add_view(
        app->view_dispatcher, FPassViewSubmenu, submenu_get_view(app->submenu));

    app->create_password_submenu = submenu_alloc();
    submenu_add_item(
        app->create_password_submenu,
        "Change label",
        FPassCreateIndexLabel,
        fpass_create_password_callback,
        app);
    submenu_add_item(
        app->create_password_submenu,
        "Enter password",
        FPassCreateIndexPassword,
        fpass_create_password_callback,
        app);
    submenu_add_item(
        app->create_password_submenu,
        "Save password",
        FPassCreateIndexSave,
        fpass_create_password_callback,
        app);
    view_dispatcher_add_view(
        app->view_dispatcher,
        FPassViewCreatePassword,
        submenu_get_view(app->create_password_submenu));

    app->text_input = text_input_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, FPassViewTextInput, text_input_get_view(app->text_input));

    app->saved_passwords_submenu = submenu_alloc();
    view_set_previous_callback(
        submenu_get_view(app->saved_passwords_submenu), fpass_navigation_to_submenu_callback);
    view_dispatcher_add_view(
        app->view_dispatcher,
        FPassViewSavedPasswords,
        submenu_get_view(app->saved_passwords_submenu));

    app->entry_actions_submenu = submenu_alloc();
    submenu_add_item(
        app->entry_actions_submenu,
        "Show password",
        FPassEntryIndexShowPassword,
        fpass_entry_action_callback,
        app);
    submenu_add_item(
        app->entry_actions_submenu,
        "Type password",
        FPassEntryIndexTypePassword,
        fpass_entry_action_callback,
        app);
    submenu_add_item(
        app->entry_actions_submenu,
        "Change label",
        FPassEntryIndexChangeLabel,
        fpass_entry_action_callback,
        app);
    submenu_add_item(
        app->entry_actions_submenu,
        "Delete",
        FPassEntryIndexDelete,
        fpass_entry_action_callback,
        app);
    view_set_previous_callback(
        submenu_get_view(app->entry_actions_submenu),
        fpass_navigation_to_saved_passwords_callback);
    view_dispatcher_add_view(
        app->view_dispatcher,
        FPassViewEntryActions,
        submenu_get_view(app->entry_actions_submenu));

    app->typing_transport_submenu = submenu_alloc();
    submenu_add_item(
        app->typing_transport_submenu,
        "USB keyboard",
        FPassTypingTransportUsb,
        fpass_typing_transport_callback,
        app);
    submenu_add_item(
        app->typing_transport_submenu,
        "Bluetooth keyboard",
        FPassTypingTransportBle,
        fpass_typing_transport_callback,
        app);
    view_set_previous_callback(
        submenu_get_view(app->typing_transport_submenu),
        fpass_navigation_to_entry_actions_callback);
    view_dispatcher_add_view(
        app->view_dispatcher,
        FPassViewTypingTransport,
        submenu_get_view(app->typing_transport_submenu));

    app->typing_view = view_alloc();
    view_allocate_model(app->typing_view, ViewModelTypeLocking, sizeof(FPassTypingModel));
    view_set_context(app->typing_view, app);
    view_set_draw_callback(app->typing_view, fpass_typing_draw);
    view_set_input_callback(app->typing_view, fpass_typing_input);
    view_set_previous_callback(
        app->typing_view, fpass_navigation_to_entry_actions_callback);
    view_dispatcher_add_view(
        app->view_dispatcher, FPassViewTyping, app->typing_view);

    app->screen = widget_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, FPassViewScreen, widget_get_view(app->screen));

    if(passwords_loaded) {
        view_dispatcher_switch_to_view(app->view_dispatcher, FPassViewSubmenu);
    } else {
        fpass_show_message(app, "Could not load saved passwords.", FPassViewSubmenu);
    }

    return app;
}

static void fpass_app_free(FPassApp* app) {
    if(app->typing_thread) {
        app->typing_cancel_requested = true;
        furi_thread_join(app->typing_thread);
        furi_thread_free(app->typing_thread);
    }
    fpass_ble_session_stop(app);

    view_dispatcher_remove_view(app->view_dispatcher, FPassViewScreen);
    widget_free(app->screen);

    view_dispatcher_remove_view(app->view_dispatcher, FPassViewTyping);
    view_free(app->typing_view);

    view_dispatcher_remove_view(app->view_dispatcher, FPassViewTypingTransport);
    submenu_free(app->typing_transport_submenu);

    view_dispatcher_remove_view(app->view_dispatcher, FPassViewSavedPasswords);
    submenu_free(app->saved_passwords_submenu);

    view_dispatcher_remove_view(app->view_dispatcher, FPassViewEntryActions);
    submenu_free(app->entry_actions_submenu);

    view_dispatcher_remove_view(app->view_dispatcher, FPassViewTextInput);
    text_input_free(app->text_input);

    view_dispatcher_remove_view(app->view_dispatcher, FPassViewCreatePassword);
    submenu_free(app->create_password_submenu);

    view_dispatcher_remove_view(app->view_dispatcher, FPassViewSubmenu);
    submenu_free(app->submenu);
    view_dispatcher_free(app->view_dispatcher);
    furi_record_close(RECORD_GUI);
    furi_string_free(app->data_directory);
    furi_string_free(app->passwords_path);
    furi_record_close(RECORD_STORAGE);
    free(app);
}

int32_t main_fpass_app(void* _p) {
    UNUSED(_p);

    FPassApp* app = fpass_app_alloc();
    view_dispatcher_run(app->view_dispatcher);
    fpass_app_free(app);

    return 0;
}

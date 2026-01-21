//! Xiaomi Air Purifier Filter Reset - Flipper Zero Application
//!
//! This application reads the NFC tag on Xiaomi air purifier filters,
//! derives the password from the UID, and resets the filter counter
//! by writing zeros to Block 8.
//!
//! # References
//!
//! - <https://unethical.info/2024/01/24/hacking-my-air-purifier/>

#![no_main]
#![no_std]

extern crate flipperzero_rt;

mod password;

use core::ffi::CStr;
use core::ptr;

use flipperzero::println;
use flipperzero_rt::{entry, manifest};
use flipperzero_sys as sys;

use password::derive_password;

// =============================================================================
// FAP Manifest & Entry Point
// =============================================================================

manifest!(
    name = "Xiaomi Filter Reset",
    app_version = 1,
    has_icon = true,
    // See https://github.com/flipperzero-rs/flipperzero/blob/v0.11.0/docs/icons.md for icon format
    icon = "rustacean-10x10.icon",
);

entry!(main);

// =============================================================================
// Constants
// =============================================================================

/// Block 8 is the filter status page on Xiaomi filter NTAG tags
const NTAG_BLOCK_FILTER_STATUS: u8 = 0x08;

// Screen layout (Flipper Zero has 128x64 display)
const SCREEN_CENTER_X: u8 = 64;
const HEADER_Y: u8 = 0;
const DIALOG_TEXT_Y: u8 = 32;
const POPUP_HEADER_Y: u8 = 20;
const POPUP_TEXT_Y: u8 = 40;
const TAG_INFO_TEXT_Y: u8 = 28;

// Timeouts
const SCAN_TIMEOUT_MS: u32 = 30_000;
const WRITE_TIMEOUT_MS: u32 = 10_000;
const POLL_INTERVAL_MS: u32 = 100;
const SUCCESS_DISPLAY_MS: u32 = 3000;

// View IDs
const VIEW_DIALOG: u32 = 0;
const VIEW_POPUP: u32 = 1;

// UI Strings
const STR_TITLE: &CStr = c"Xiaomi Filter Reset";
const STR_START_SCAN: &CStr = c"Start scan?";
const STR_YES: &CStr = c"Yes";
const STR_ABORT: &CStr = c"Abort";
const STR_SCANNING: &CStr = c"Scanning...";
const STR_PLACE_TAG: &CStr = c"Place filter tag near Flipper";
const STR_TAG_FOUND: &CStr = c"Tag Found";
const STR_WRITE: &CStr = c"Write";
const STR_WRITING: &CStr = c"Writing...";
const STR_KEEP_TAG: &CStr = c"Keep tag in place";
const STR_SUCCESS: &CStr = c"Success!";
const STR_RESET_100: &CStr = c"Filter reset to 100%";
const STR_FAILURE: &CStr = c"Failure";
const STR_OK: &CStr = c"OK";
const STR_SCAN_TIMEOUT: &CStr = c"Scan timeout";
const STR_AUTH_FAILED: &CStr = c"Auth failed";
const STR_WRITE_FAILED: &CStr = c"Write failed";
const STR_NFC_ERROR: &CStr = c"NFC error";
const STR_GUI: &CStr = c"gui";

// =============================================================================
// Types
// =============================================================================

/// Application states
#[derive(Clone, Copy, PartialEq, Eq)]
enum AppState {
    StartPrompt,
    Scanning,
    TagInfo,
    Writing,
    Success,
    Failure,
}

/// Dialog button result from callback
#[derive(Clone, Copy, PartialEq, Eq)]
enum DialogResult {
    None,
    Left,
    Center,
    Right,
}

/// Result of state handling
enum StateAction {
    Continue,
    Exit(i32),
}

/// Tag information collected during scan
struct TagData {
    uid: [u8; 7],
    uid_len: usize,
    password: [u8; 4],
}

impl TagData {
    const fn new() -> Self {
        Self {
            uid: [0u8; 7],
            uid_len: 0,
            password: [0u8; 4],
        }
    }
}

/// Context for ISO14443-3A scan callback
struct ScanContext {
    got_uid: bool,
    uid: [u8; 7],
    uid_len: usize,
    error: bool,
}

impl ScanContext {
    const fn new() -> Self {
        Self {
            got_uid: false,
            uid: [0u8; 7],
            uid_len: 0,
            error: false,
        }
    }
}

/// Context for ISO14443-3A write callback
struct WriteContext {
    password: [u8; 4],
    auth_done: bool,
    write_done: bool,
    error: bool,
}

impl WriteContext {
    const fn new(password: [u8; 4]) -> Self {
        Self {
            password,
            auth_done: false,
            write_done: false,
            error: false,
        }
    }
}

// =============================================================================
// Global State (required for C callbacks)
// =============================================================================

static mut DIALOG_RESULT: DialogResult = DialogResult::None;

// =============================================================================
// Utility Functions
// =============================================================================

/// Format bytes as hex string into buffer.
/// 
/// - `separator`: If `Some(b':')`, produces "AA:BB:CC". If `None`, produces "AABBCC".
/// - Returns number of bytes written.
fn format_hex_bytes(bytes: &[u8], buf: &mut [u8], separator: Option<u8>) -> usize {
    const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";
    let mut pos = 0;

    for (i, &byte) in bytes.iter().enumerate() {
        // Add separator between bytes (not before first)
        if let Some(sep) = separator {
            if i > 0 && pos < buf.len() {
                buf[pos] = sep;
                pos += 1;
            }
        }
        // Write two hex chars
        if pos + 1 < buf.len() {
            buf[pos] = HEX_CHARS[(byte >> 4) as usize];
            buf[pos + 1] = HEX_CHARS[(byte & 0x0F) as usize];
            pos += 2;
        }
    }
    pos
}

// =============================================================================
// NFC Callbacks
// =============================================================================

/// Dialog result callback (sets global state)
unsafe extern "C" fn dialog_callback(
    result: sys::DialogExResult,
    _context: *mut core::ffi::c_void,
) {
    unsafe {
        DIALOG_RESULT = match result {
            sys::DialogExResultLeft => DialogResult::Left,
            sys::DialogExResultCenter => DialogResult::Center,
            sys::DialogExResultRight => DialogResult::Right,
            _ => DialogResult::None,
        };
    }
}

/// Popup timeout callback (no-op, timeout handled in main loop)
unsafe extern "C" fn popup_callback(_context: *mut core::ffi::c_void) {}

/// ISO14443-3A poller callback for scanning (getting UID)
unsafe extern "C" fn iso14443_3a_scan_callback(
    event: sys::NfcGenericEvent,
    context: *mut core::ffi::c_void,
) -> sys::NfcCommand {
    if context.is_null() {
        return sys::NfcCommandStop;
    }

    let ctx = unsafe { &mut *(context as *mut ScanContext) };
    let iso_event = unsafe { &*(event.event_data as *const sys::Iso14443_3aPollerEvent) };

    match iso_event.type_ {
        sys::Iso14443_3aPollerEventTypeReady => {
            let instance = event.instance as *mut sys::Iso14443_3aPoller;
            
            // Allocate and activate to get UID
            let iso_data = unsafe { sys::iso14443_3a_alloc() };
            if iso_data.is_null() {
                ctx.error = true;
                return sys::NfcCommandStop;
            }

            let result = unsafe { sys::iso14443_3a_poller_activate(instance, iso_data) };
            
            if result == sys::Iso14443_3aErrorNone {
                let data = unsafe { &*iso_data };
                let uid_len = (data.uid_len as usize).min(7);
                ctx.uid[..uid_len].copy_from_slice(&data.uid[..uid_len]);
                ctx.uid_len = uid_len;
                ctx.got_uid = true;
            } else {
                ctx.error = true;
            }

            unsafe { sys::iso14443_3a_free(iso_data) };
            sys::NfcCommandStop
        }
        sys::Iso14443_3aPollerEventTypeError => {
            ctx.error = true;
            sys::NfcCommandStop
        }
        _ => sys::NfcCommandContinue,
    }
}

/// ISO14443-3A poller callback for write operations (auth + write)
unsafe extern "C" fn iso14443_3a_write_callback(
    event: sys::NfcGenericEvent,
    context: *mut core::ffi::c_void,
) -> sys::NfcCommand {
    if context.is_null() {
        return sys::NfcCommandStop;
    }

    let ctx = unsafe { &mut *(context as *mut WriteContext) };
    let iso_event = unsafe { &*(event.event_data as *const sys::Iso14443_3aPollerEvent) };

    match iso_event.type_ {
        sys::Iso14443_3aPollerEventTypeReady => {
            let instance = event.instance as *mut sys::Iso14443_3aPoller;

            // Allocate TX/RX buffers
            let tx_buffer = unsafe { sys::bit_buffer_alloc(16) };
            let rx_buffer = unsafe { sys::bit_buffer_alloc(16) };

            if tx_buffer.is_null() || rx_buffer.is_null() {
                if !tx_buffer.is_null() { unsafe { sys::bit_buffer_free(tx_buffer) }; }
                if !rx_buffer.is_null() { unsafe { sys::bit_buffer_free(rx_buffer) }; }
                ctx.error = true;
                return sys::NfcCommandStop;
            }

            // PWD_AUTH command: 0x1B + 4-byte password
            let auth_cmd = [0x1B, ctx.password[0], ctx.password[1], ctx.password[2], ctx.password[3]];
            unsafe {
                sys::bit_buffer_reset(tx_buffer);
                sys::bit_buffer_copy_bytes(tx_buffer, auth_cmd.as_ptr(), auth_cmd.len());
            }

            let auth_result = unsafe {
                sys::iso14443_3a_poller_send_standard_frame(instance, tx_buffer, rx_buffer, 5000)
            };

            if auth_result != sys::Iso14443_3aErrorNone {
                unsafe { sys::bit_buffer_free(tx_buffer); sys::bit_buffer_free(rx_buffer); }
                ctx.error = true;
                return sys::NfcCommandStop;
            }
            ctx.auth_done = true;

            // WRITE command: 0xA2 + page + 4 zero bytes
            let write_cmd = [0xA2, NTAG_BLOCK_FILTER_STATUS, 0x00, 0x00, 0x00, 0x00];
            unsafe {
                sys::bit_buffer_reset(tx_buffer);
                sys::bit_buffer_copy_bytes(tx_buffer, write_cmd.as_ptr(), write_cmd.len());
            }

            let write_result = unsafe {
                sys::iso14443_3a_poller_send_standard_frame(instance, tx_buffer, rx_buffer, 5000)
            };

            unsafe { sys::bit_buffer_free(tx_buffer); sys::bit_buffer_free(rx_buffer); }

            if write_result != sys::Iso14443_3aErrorNone {
                ctx.error = true;
                return sys::NfcCommandStop;
            }

            ctx.write_done = true;
            sys::NfcCommandStop
        }
        sys::Iso14443_3aPollerEventTypeError => {
            ctx.error = true;
            sys::NfcCommandStop
        }
        _ => sys::NfcCommandContinue,
    }
}

// =============================================================================
// Application
// =============================================================================

/// Main application structure
struct App {
    state: AppState,
    tag_data: TagData,
    error_msg: &'static CStr,
    view_dispatcher: *mut sys::ViewDispatcher,
    dialog: *mut sys::DialogEx,
    popup: *mut sys::Popup,
    nfc: *mut sys::Nfc,
    info_text: [u8; 128],
}

impl App {
    // -------------------------------------------------------------------------
    // Initialization
    // -------------------------------------------------------------------------

    /// Create a new application instance. Returns None if allocation fails.
    fn new() -> Option<Self> {
        // SAFETY: All FFI calls for GUI and NFC resource allocation
        unsafe {
            let gui = sys::furi_record_open(STR_GUI.as_ptr() as *const u8) as *mut sys::Gui;
            if gui.is_null() { return None; }

            let view_dispatcher = sys::view_dispatcher_alloc();
            if view_dispatcher.is_null() {
                sys::furi_record_close(STR_GUI.as_ptr() as *const u8);
                return None;
            }

            let dialog = sys::dialog_ex_alloc();
            let popup = sys::popup_alloc();
            let nfc = sys::nfc_alloc();

            // Cleanup on partial failure
            if dialog.is_null() || popup.is_null() || nfc.is_null() {
                if !dialog.is_null() { sys::dialog_ex_free(dialog); }
                if !popup.is_null() { sys::popup_free(popup); }
                if !nfc.is_null() { sys::nfc_free(nfc); }
                sys::view_dispatcher_free(view_dispatcher);
                sys::furi_record_close(STR_GUI.as_ptr() as *const u8);
                return None;
            }

            // Configure view dispatcher
            sys::view_dispatcher_enable_queue(view_dispatcher);
            sys::view_dispatcher_attach_to_gui(view_dispatcher, gui, sys::ViewDispatcherTypeFullscreen);
            sys::view_dispatcher_add_view(view_dispatcher, VIEW_DIALOG, sys::dialog_ex_get_view(dialog));
            sys::view_dispatcher_add_view(view_dispatcher, VIEW_POPUP, sys::popup_get_view(popup));

            // Set up callbacks
            sys::dialog_ex_set_context(dialog, ptr::null_mut());
            sys::dialog_ex_set_result_callback(dialog, Some(dialog_callback));
            sys::popup_set_context(popup, ptr::null_mut());
            sys::popup_set_callback(popup, Some(popup_callback));

            Some(Self {
                state: AppState::StartPrompt,
                tag_data: TagData::new(),
                error_msg: STR_NFC_ERROR,
                view_dispatcher,
                dialog,
                popup,
                nfc,
                info_text: [0u8; 128],
            })
        }
    }

    /// Clean up all allocated resources
    fn cleanup(&mut self) {
        // SAFETY: Freeing all allocated FFI resources
        unsafe {
            sys::view_dispatcher_remove_view(self.view_dispatcher, VIEW_DIALOG);
            sys::view_dispatcher_remove_view(self.view_dispatcher, VIEW_POPUP);
            sys::nfc_free(self.nfc);
            sys::dialog_ex_free(self.dialog);
            sys::popup_free(self.popup);
            sys::view_dispatcher_free(self.view_dispatcher);
            sys::furi_record_close(STR_GUI.as_ptr() as *const u8);
        }
    }

    // -------------------------------------------------------------------------
    // Main Loop
    // -------------------------------------------------------------------------

    /// Run the application main loop
    fn run(&mut self) -> i32 {
        self.show_start_prompt();

        loop {
            let result = self.wait_for_input();
            match self.handle_state(result) {
                StateAction::Continue => continue,
                StateAction::Exit(code) => return code,
            }
        }
    }

    /// Wait for user input via view dispatcher
    fn wait_for_input(&self) -> DialogResult {
        unsafe {
            DIALOG_RESULT = DialogResult::None;
            sys::view_dispatcher_run(self.view_dispatcher);
            DIALOG_RESULT
        }
    }

    /// Handle current state based on user input, returns next action
    fn handle_state(&mut self, result: DialogResult) -> StateAction {
        match self.state {
            AppState::StartPrompt => match result {
                DialogResult::Left => StateAction::Exit(0),
                DialogResult::Right => {
                    self.state = AppState::Scanning;
                    self.show_scanning();
                    // self.do_scan();
                    StateAction::Continue
                }
                _ => StateAction::Continue,
            },
            AppState::Scanning => StateAction::Exit(0), // Back pressed
            AppState::TagInfo => match result {
                DialogResult::Right => {
                    self.state = AppState::Writing;
                    self.show_writing();
                    // self.do_write();
                    StateAction::Continue
                }
                DialogResult::Left => StateAction::Exit(0),
                _ => StateAction::Continue,
            },
            AppState::Writing => StateAction::Continue,
            AppState::Success => StateAction::Exit(0),
            AppState::Failure => match result {
                DialogResult::Center => StateAction::Exit(0),
                _ => StateAction::Continue,
            },
        }
    }

    // -------------------------------------------------------------------------
    // UI Helpers
    // -------------------------------------------------------------------------

    /// Configure and show a dialog with header, text, and up to 3 buttons
    fn setup_dialog(
        &self,
        header: &CStr,
        text: &[u8],
        text_y: u8,
        left: Option<&CStr>,
        center: Option<&CStr>,
        right: Option<&CStr>,
    ) {
        // SAFETY: FFI calls to configure dialog
        unsafe {
            sys::dialog_ex_reset(self.dialog);
            sys::dialog_ex_set_header(
                self.dialog, header.as_ptr() as *const u8,
                SCREEN_CENTER_X, HEADER_Y, sys::AlignCenter, sys::AlignTop,
            );
            sys::dialog_ex_set_text(
                self.dialog, text.as_ptr(),
                SCREEN_CENTER_X, text_y, sys::AlignCenter, sys::AlignCenter,
            );
            if let Some(btn) = left {
                sys::dialog_ex_set_left_button_text(self.dialog, btn.as_ptr() as *const u8);
            }
            if let Some(btn) = center {
                sys::dialog_ex_set_center_button_text(self.dialog, btn.as_ptr() as *const u8);
            }
            if let Some(btn) = right {
                sys::dialog_ex_set_right_button_text(self.dialog, btn.as_ptr() as *const u8);
            }
            sys::view_dispatcher_switch_to_view(self.view_dispatcher, VIEW_DIALOG);
        }
    }

    /// Configure and show a popup with header and text
    fn setup_popup(&self, header: &CStr, text: &CStr, timeout_ms: Option<u32>) {
        // SAFETY: FFI calls to configure popup
        unsafe {
            sys::popup_reset(self.popup);
            sys::popup_set_header(
                self.popup, header.as_ptr() as *const u8,
                SCREEN_CENTER_X, POPUP_HEADER_Y, sys::AlignCenter, sys::AlignCenter,
            );
            sys::popup_set_text(
                self.popup, text.as_ptr() as *const u8,
                SCREEN_CENTER_X, POPUP_TEXT_Y, sys::AlignCenter, sys::AlignCenter,
            );
            if let Some(ms) = timeout_ms {
                sys::popup_set_timeout(self.popup, ms);
                sys::popup_enable_timeout(self.popup);
            }
            sys::view_dispatcher_switch_to_view(self.view_dispatcher, VIEW_POPUP);
        }
    }

    // -------------------------------------------------------------------------
    // UI Screens
    // -------------------------------------------------------------------------

    fn show_start_prompt(&self) {
        self.setup_dialog(
            STR_TITLE, STR_START_SCAN.to_bytes_with_nul(), DIALOG_TEXT_Y,
            Some(STR_ABORT), None, Some(STR_YES),
        );
    }

    fn show_scanning(&self) {
        self.setup_popup(STR_SCANNING, STR_PLACE_TAG, None);
    }

    fn show_tag_info(&mut self) {
        self.build_info_text();
        self.setup_dialog(
            STR_TAG_FOUND, &self.info_text, TAG_INFO_TEXT_Y,
            Some(STR_ABORT), None, Some(STR_WRITE),
        );
    }

    fn show_writing(&self) {
        self.setup_popup(STR_WRITING, STR_KEEP_TAG, None);
    }

    fn show_success(&self) {
        self.setup_popup(STR_SUCCESS, STR_RESET_100, Some(SUCCESS_DISPLAY_MS));
    }

    fn show_failure(&self) {
        self.setup_dialog(
            STR_FAILURE, self.error_msg.to_bytes_with_nul(), DIALOG_TEXT_Y,
            None, Some(STR_OK), None,
        );
    }

    /// Build tag info text: "UID:XX:XX:...\nPWD:XXXXXXXX"
    fn build_info_text(&mut self) {
        let mut pos = 0;

        // "UID:"
        self.info_text[pos..pos + 4].copy_from_slice(b"UID:");
        pos += 4;

        // UID with colons
        pos += format_hex_bytes(
            &self.tag_data.uid[..self.tag_data.uid_len],
            &mut self.info_text[pos..],
            Some(b':'),
        );

        // "\nPWD:"
        self.info_text[pos..pos + 5].copy_from_slice(b"\nPWD:");
        pos += 5;

        // Password without separator
        pos += format_hex_bytes(&self.tag_data.password, &mut self.info_text[pos..], None);

        // Null terminate
        self.info_text[pos] = 0;
    }

    // -------------------------------------------------------------------------
    // NFC Operations
    // -------------------------------------------------------------------------

    /// Perform NFC scan to get UID
    fn do_scan(&mut self) {
        println!("Starting NFC scan...");

        let mut ctx = ScanContext::new();

        // SAFETY: NFC poller allocation, start, polling, stop, and free
        let scan_result = unsafe {
            let poller = sys::nfc_poller_alloc(self.nfc, sys::NfcProtocolIso14443_3a);
            if poller.is_null() {
                return self.fail_with(STR_NFC_ERROR);
            }

            sys::nfc_poller_start(
                poller, Some(iso14443_3a_scan_callback),
                &mut ctx as *mut ScanContext as *mut core::ffi::c_void,
            );

            // Poll until complete or timeout
            let mut elapsed = 0u32;
            while elapsed < SCAN_TIMEOUT_MS && !ctx.got_uid && !ctx.error {
                sys::furi_delay_ms(POLL_INTERVAL_MS);
                elapsed += POLL_INTERVAL_MS;
            }

            sys::nfc_poller_stop(poller);
            sys::nfc_poller_free(poller);

            if ctx.error { Err(STR_NFC_ERROR) }
            else if !ctx.got_uid { Err(STR_SCAN_TIMEOUT) }
            else { Ok(()) }
        };

        if let Err(msg) = scan_result {
            return self.fail_with(msg);
        }

        // Store UID and derive password
        self.tag_data.uid = ctx.uid;
        self.tag_data.uid_len = ctx.uid_len;
        if ctx.uid_len == 7 {
            self.tag_data.password = derive_password(&self.tag_data.uid);
        }

        println!("Tag found, UID len: {}", self.tag_data.uid_len);
        self.state = AppState::TagInfo;
        self.show_tag_info();
    }

    /// Perform write operation (auth + write zeros to filter block)
    fn do_write(&mut self) {
        println!("Starting write operation...");

        let mut ctx = WriteContext::new(self.tag_data.password);

        // SAFETY: NFC poller allocation, start, polling, stop, and free
        let write_result = unsafe {
            let poller = sys::nfc_poller_alloc(self.nfc, sys::NfcProtocolIso14443_3a);
            if poller.is_null() {
                return self.fail_with(STR_NFC_ERROR);
            }

            sys::nfc_poller_start(
                poller, Some(iso14443_3a_write_callback),
                &mut ctx as *mut WriteContext as *mut core::ffi::c_void,
            );

            // Poll until complete or timeout
            let mut elapsed = 0u32;
            while elapsed < WRITE_TIMEOUT_MS && !ctx.write_done && !ctx.error {
                sys::furi_delay_ms(POLL_INTERVAL_MS);
                elapsed += POLL_INTERVAL_MS;
            }

            sys::nfc_poller_stop(poller);
            sys::nfc_poller_free(poller);

            if ctx.error {
                Err(if ctx.auth_done { STR_WRITE_FAILED } else { STR_AUTH_FAILED })
            } else if !ctx.write_done {
                Err(STR_WRITE_FAILED)
            } else {
                Ok(())
            }
        };

        if let Err(msg) = write_result {
            return self.fail_with(msg);
        }

        println!("Write successful!");
        self.state = AppState::Success;
        self.show_success();
    }

    /// Transition to failure state with given message
    fn fail_with(&mut self, msg: &'static CStr) {
        self.error_msg = msg;
        self.state = AppState::Failure;
        self.show_failure();
    }
}

// =============================================================================
// Entry Point
// =============================================================================

fn main(_args: Option<&CStr>) -> i32 {
    println!("Xiaomi Filter Reset starting...");

    match App::new() {
        Some(mut app) => {
            let result = app.run();
            app.cleanup();
            result
        }
        None => {
            println!("Failed to initialize app");
            1
        }
    }
}

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

use flipperzero::{
    dialogs::{DialogMessage, DialogMessageButton, DialogsApp},
    gui::canvas::Align,
    println,
};
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

// Timeouts
const SCAN_TIMEOUT_MS: u32 = 30_000;
const WRITE_TIMEOUT_MS: u32 = 10_000;
const POLL_INTERVAL_MS: u32 = 100;

// UI Strings
const STR_TITLE: &CStr = c"Xiaomi Filter Reset";
const STR_START_SCAN: &CStr = c"Start scan?";
const STR_YES: &CStr = c"Yes";
const STR_ABORT: &CStr = c"Abort";
const STR_TAG_FOUND: &CStr = c"Tag Found";
const STR_WRITE: &CStr = c"Write";
const STR_SUCCESS: &CStr = c"Success!";
const STR_RESET_100: &CStr = c"Filter reset to 100%";
const STR_FAILURE: &CStr = c"Failure";
const STR_OK: &CStr = c"OK";
const STR_RETRY: &CStr = c"Retry";
const STR_SCAN_TIMEOUT: &CStr = c"Scan timeout";
const STR_AUTH_FAILED: &CStr = c"Auth failed";
const STR_WRITE_FAILED: &CStr = c"Write failed";
const STR_NFC_ERROR: &CStr = c"NFC error";
const STR_SCANNING: &CStr = c"Scanning...";

// =============================================================================
// Types
// =============================================================================

/// Application states
#[derive(Clone, Copy, PartialEq, Eq)]
enum AppState {
    StartPrompt,
    ScanDialog,
    ScanRunning,
    TagInfo,
    Writing,
    Success,
    Failure,
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
                if !tx_buffer.is_null() {
                    unsafe { sys::bit_buffer_free(tx_buffer) };
                }
                if !rx_buffer.is_null() {
                    unsafe { sys::bit_buffer_free(rx_buffer) };
                }
                ctx.error = true;
                return sys::NfcCommandStop;
            }

            // PWD_AUTH command: 0x1B + 4-byte password
            let auth_cmd = [
                0x1B,
                ctx.password[0],
                ctx.password[1],
                ctx.password[2],
                ctx.password[3],
            ];
            unsafe {
                sys::bit_buffer_reset(tx_buffer);
                sys::bit_buffer_copy_bytes(tx_buffer, auth_cmd.as_ptr(), auth_cmd.len());
            }

            let auth_result = unsafe {
                sys::iso14443_3a_poller_send_standard_frame(instance, tx_buffer, rx_buffer, 5000)
            };

            if auth_result != sys::Iso14443_3aErrorNone {
                unsafe {
                    sys::bit_buffer_free(tx_buffer);
                    sys::bit_buffer_free(rx_buffer);
                }
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

            unsafe {
                sys::bit_buffer_free(tx_buffer);
                sys::bit_buffer_free(rx_buffer);
            }

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
    nfc: *mut sys::Nfc,
    info_text: [u8; 128],
    scan_ctx: Option<ScanContext>,
    scan_poller: Option<*mut sys::NfcPoller>,
    scan_elapsed_ms: u32,
}

impl App {
    // -------------------------------------------------------------------------
    // Initialization
    // -------------------------------------------------------------------------

    /// Create a new application instance. Returns None if allocation fails.
    fn new() -> Option<Self> {
        // SAFETY: NFC resource allocation
        unsafe {
            let nfc = sys::nfc_alloc();
            if nfc.is_null() {
                return None;
            }

            Some(Self {
                state: AppState::StartPrompt,
                tag_data: TagData::new(),
                error_msg: STR_NFC_ERROR,
                nfc,
                info_text: [0u8; 128],
                scan_ctx: None,
                scan_poller: None,
                scan_elapsed_ms: 0,
            })
        }
    }

    /// Clean up all allocated resources
    fn cleanup(&mut self) {
        if let Some(poller) = self.scan_poller.take() {
            unsafe {
                sys::nfc_poller_stop(poller);
                sys::nfc_poller_free(poller);
            }
        }

        unsafe {
            sys::nfc_free(self.nfc);
        }
    }

    // -------------------------------------------------------------------------
    // Main Loop
    // -------------------------------------------------------------------------

    /// Run the application main loop
    fn run(&mut self) -> i32 {
        loop {
            match self.state {
                AppState::StartPrompt => match self.show_start_prompt() {
                    DialogMessageButton::Right => {
                        // Only change state, don't scan yet
                        self.state = AppState::ScanDialog;
                    }
                    DialogMessageButton::Left | DialogMessageButton::Back => {
                        return 0;
                    }
                    _ => {}
                },
                AppState::ScanDialog => {
                    // Show dialog and start async scan
                    self.show_scanning_dialog();
                    self.start_async_scan();
                    self.state = AppState::ScanRunning;
                }
                AppState::ScanRunning => {
                    // Poll scan progress, check if complete
                    unsafe { sys::furi_delay_ms(POLL_INTERVAL_MS) };
                    self.scan_elapsed_ms += POLL_INTERVAL_MS;

                    if self.scan_elapsed_ms >= SCAN_TIMEOUT_MS {
                        self.stop_scan();
                        self.fail_with(STR_SCAN_TIMEOUT);
                    } else {
                        if self.is_scan_complete() {
                            self.finalize_scan();
                        }
                    }
                }
                AppState::TagInfo => match self.show_tag_info() {
                    DialogMessageButton::Right => {
                        self.state = AppState::Writing;
                        self.do_write();
                    }
                    DialogMessageButton::Left | DialogMessageButton::Back => {
                        return 0;
                    }
                    _ => {}
                },
                AppState::Writing => {
                    // Writing is handled in do_write(), which transitions to Success or Failure
                    return 0;
                }
                AppState::Success => match self.show_success() {
                    DialogMessageButton::Center | DialogMessageButton::Back => {
                        return 0;
                    }
                    _ => {}
                },
                AppState::Failure => {
                    match self.show_failure() {
                        DialogMessageButton::Left
                        | DialogMessageButton::Center
                        | DialogMessageButton::Back => {
                            return 0;
                        }
                        DialogMessageButton::Right => {
                            // Retry - go back to scanning dialog
                            self.state = AppState::ScanDialog;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // UI Screens
    // -------------------------------------------------------------------------

    /// Show start prompt dialog and return button pressed
    fn show_start_prompt(&self) -> DialogMessageButton {
        let mut dialogs = DialogsApp::open();
        let mut message = DialogMessage::new();

        message.set_header(STR_TITLE, 5, 8, Align::Left, Align::Top);
        message.set_text(STR_START_SCAN, 5, 25, Align::Left, Align::Top);
        message.set_buttons(Some(STR_ABORT), None, Some(STR_YES));

        dialogs.show_message(&message)
    }

    /// Show scanning dialog (non-blocking, just displays text)
    fn show_scanning_dialog(&self) {
        let mut dialogs = DialogsApp::open();
        let mut message = DialogMessage::new();

        message.set_header(STR_TITLE, 5, 8, Align::Left, Align::Top);
        message.set_text(STR_SCANNING, 5, 25, Align::Left, Align::Top);
        message.set_buttons(None, None, None);

        dialogs.show_message(&message);
    }

    /// Show tag info dialog and return button pressed
    fn show_tag_info(&mut self) -> DialogMessageButton {
        let info_text = self.build_info_text();
        let mut dialogs = DialogsApp::open();
        let mut message = DialogMessage::new();

        message.set_header(STR_TAG_FOUND, 5, 8, Align::Left, Align::Top);
        message.set_text(&info_text, 5, 22, Align::Left, Align::Top);
        message.set_buttons(Some(STR_ABORT), None, Some(STR_WRITE));

        dialogs.show_message(&message)
    }

    /// Show success message
    fn show_success(&self) -> DialogMessageButton {
        let mut dialogs = DialogsApp::open();
        let mut message = DialogMessage::new();

        message.set_header(STR_SUCCESS, 5, 8, Align::Left, Align::Top);
        message.set_text(STR_RESET_100, 5, 25, Align::Left, Align::Top);
        message.set_buttons(None, Some(STR_OK), None);

        dialogs.show_message(&message)
    }

    /// Show failure dialog and return button pressed
    fn show_failure(&self) -> DialogMessageButton {
        let mut dialogs = DialogsApp::open();
        let mut message = DialogMessage::new();

        message.set_header(STR_FAILURE, 5, 8, Align::Left, Align::Top);
        message.set_text(self.error_msg, 5, 25, Align::Left, Align::Top);
        message.set_buttons(Some(STR_ABORT), Some(STR_OK), Some(STR_RETRY));

        dialogs.show_message(&message)
    }

    /// Build tag info text: "UID:XX:XX:...\nPWD:XXXXXXXX"
    /// Returns a CStr reference to the formatted text
    fn build_info_text(&mut self) -> &CStr {
        let mut pos = 0;

        // "UID: " (with trailing space)
        self.info_text[pos..pos + 5].copy_from_slice(b"UID: ");
        pos += 5;

        // UID with colons
        pos += format_hex_bytes(
            &self.tag_data.uid[..self.tag_data.uid_len],
            &mut self.info_text[pos..],
            Some(b':'),
        );

        // "\nPWD: " (with trailing space)
        self.info_text[pos..pos + 6].copy_from_slice(b"\nPWD: ");
        pos += 6;

        // Password without separator
        pos += format_hex_bytes(&self.tag_data.password, &mut self.info_text[pos..], None);

        // Null terminate
        self.info_text[pos] = 0;

        // Create CStr with bounds checking
        CStr::from_bytes_with_nul(&self.info_text[..=pos])
            .expect("Info text contains invalid null byte")
    }

    // -------------------------------------------------------------------------
    // NFC Operations
    // -------------------------------------------------------------------------

    /// Start asynchronous NFC scan
    fn start_async_scan(&mut self) {
        println!("Starting NFC scan...");

        self.scan_ctx = Some(ScanContext::new());

        let poller = unsafe {
            let p = sys::nfc_poller_alloc(self.nfc, sys::NfcProtocolIso14443_3a);
            if p.is_null() {
                self.scan_ctx = None;
                self.fail_with(STR_NFC_ERROR);
                return;
            }

            let ctx_ptr = match &mut self.scan_ctx {
                Some(ctx) => ctx as *mut ScanContext,
                None => return,
            };

            sys::nfc_poller_start(
                p,
                Some(iso14443_3a_scan_callback),
                ctx_ptr as *mut core::ffi::c_void,
            );
            p
        };

        self.scan_poller = Some(poller);
        self.scan_elapsed_ms = 0;
    }

    /// Check if scan is complete (success or error)
    fn is_scan_complete(&self) -> bool {
        match &self.scan_ctx {
            Some(ctx) => ctx.got_uid || ctx.error || false,
            None => false,
        }
    }

    /// Finalize scan operation and handle results
    fn finalize_scan(&mut self) {
        self.stop_scan();

        if let Some(ctx) = self.scan_ctx.take() {
            if ctx.error {
                self.fail_with(STR_NFC_ERROR);
            } else if !ctx.got_uid {
                self.fail_with(STR_SCAN_TIMEOUT);
            } else {
                self.tag_data.uid = ctx.uid;
                self.tag_data.uid_len = ctx.uid_len;
                if ctx.uid_len == 7 {
                    self.tag_data.password = derive_password(&self.tag_data.uid);
                }

                println!("Tag found, UID len: {}", self.tag_data.uid_len);
                self.state = AppState::TagInfo;
            }
        }
    }

    /// Stop the current scan and clean up resources
    fn stop_scan(&mut self) {
        if let Some(poller) = self.scan_poller.take() {
            unsafe {
                sys::nfc_poller_stop(poller);
                sys::nfc_poller_free(poller);
            }
        }
    }

    /// Perform write operation (auth + write zeros to filter block)
    fn do_write(&mut self) {
        println!("Starting write operation...");

        /*
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
        */

        // Mock success for UI testing
        println!("Write successful!");
        self.state = AppState::Success;
    }

    /// Transition to failure state with given message
    fn fail_with(&mut self, msg: &'static CStr) {
        self.error_msg = msg;
        self.state = AppState::Failure;
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

//! Session and power event watcher.
//!
//! A hidden message-only window receives `WM_WTSSESSION_CHANGE` (session lock,
//! logoff, RDP disconnect) and `WM_POWERBROADCAST` (suspend). Each event is
//! forwarded to the app, which wipes the vault keys.
//!
//! This is best effort: a process killed by the OS gets no callback, and the
//! vault is still encrypted on disk in that case.

use std::sync::OnceLock;

use windows::core::w;
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::RemoteDesktop::{
    WTSRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW,
    TranslateMessage, HWND_MESSAGE, MSG, WINDOW_EX_STYLE, WINDOW_STYLE, WM_ENDSESSION,
    WM_POWERBROADCAST, WM_QUERYENDSESSION, WM_WTSSESSION_CHANGE, WNDCLASSW,
};

use super::PlatformError;

/// Why the watcher fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    Lock,
    Logoff,
    Disconnect,
    Suspend,
    Shutdown,
}

const WTS_SESSION_LOCK: u32 = 0x7;
const WTS_SESSION_LOGOFF: u32 = 0x6;
const WTS_REMOTE_DISCONNECT: u32 = 0x3;
const PBT_APMSUSPEND: u32 = 0x4;

static CALLBACK: OnceLock<Box<dyn Fn(SessionEvent) + Send + Sync>> = OnceLock::new();

fn dispatch(event: SessionEvent) {
    if let Some(callback) = CALLBACK.get() {
        callback(event);
    }
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_WTSSESSION_CHANGE => match wparam.0 as u32 {
            WTS_SESSION_LOCK => dispatch(SessionEvent::Lock),
            WTS_REMOTE_DISCONNECT => dispatch(SessionEvent::Disconnect),
            WTS_SESSION_LOGOFF => dispatch(SessionEvent::Logoff),
            _ => {}
        },
        WM_POWERBROADCAST => {
            if wparam.0 as u32 == PBT_APMSUSPEND {
                dispatch(SessionEvent::Suspend);
            }
        }
        WM_QUERYENDSESSION => {
            dispatch(SessionEvent::Shutdown);
            return LRESULT(1);
        }
        WM_ENDSESSION if wparam.0 != 0 => dispatch(SessionEvent::Shutdown),
        _ => {}
    }
    // SAFETY: forwarding an unhandled message with the original parameters is
    // the documented contract of DefWindowProcW.
    unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
}

/// Start the watcher thread. The callback runs on that thread and must not
/// block (Vaultly's callback only takes a mutex and drops the vault).
pub fn start<F>(callback: F) -> Result<(), PlatformError>
where
    F: Fn(SessionEvent) + Send + Sync + 'static,
{
    let _ = CALLBACK.set(Box::new(callback));
    std::thread::Builder::new()
        .name("vaultly-session-watch".into())
        .spawn(|| {
            // SAFETY: message-only window creation on a dedicated thread; all
            // handles are local and freed when the thread exits.
            unsafe {
                let class = WNDCLASSW {
                    lpfnWndProc: Some(window_proc),
                    lpszClassName: w!("Vaultly.SessionWatcher"),
                    ..Default::default()
                };
                if RegisterClassW(&class) == 0 {
                    return;
                }
                let Ok(hwnd) = CreateWindowExW(
                    WINDOW_EX_STYLE(0),
                    class.lpszClassName,
                    w!("Vaultly Session Watcher"),
                    WINDOW_STYLE(0),
                    0,
                    0,
                    0,
                    0,
                    Some(HWND_MESSAGE),
                    None,
                    None,
                    None,
                ) else {
                    return;
                };
                if WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION).is_err() {
                    return;
                }

                let mut message = MSG::default();
                while GetMessageW(&mut message, None, 0, 0).as_bool() {
                    let _ = TranslateMessage(&message);
                    DispatchMessageW(&message);
                }
            }
        })
        .map_err(|_| PlatformError::new("spawn session watcher"))?;
    Ok(())
}

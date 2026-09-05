// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(target_os = "macos")]
    if ripley_terminal_lib::vpn_macos::run_helper_from_args() {
        return;
    }
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    log::info!("Ripley Terminal v2 starting...");
    ripley_terminal_lib::run();
    log::info!("Ripley Terminal v2 exited.");
}

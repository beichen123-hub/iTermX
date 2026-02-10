use tauri::{AppHandle};
use crate::models::SshConfig;

pub async fn establish_base_session_async(_config: &SshConfig) -> Result<(), String> {
    Ok(())
}

pub async fn create_shell_channel(_config: &SshConfig) -> Result<(), String> {
    Ok(())
}

pub fn spawn_shell_reader(_app: AppHandle, _id: String) {
    // 暂时留空
}

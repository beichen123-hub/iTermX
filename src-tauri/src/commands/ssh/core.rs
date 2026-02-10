use std::sync::{Arc};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tauri::{AppHandle, Emitter};
use russh::{client, Channel, client::Msg};
use russh_keys::*;
use crate::models::SshConfig;

// 定义 Client 处理器，用于处理 SSH 协议层事件
struct ClientHandler;

impl client::Handler for ClientHandler {
    type Error = russh::Error;
    // 可以在这里处理服务器主动发来的消息（如心跳、断开连接通知等）
}

/// 建立基础异步连接
/// 这是一个通用辅助函数，用于建立会话并完成鉴权
pub async fn establish_base_session_async(config: &SshConfig) -> Result<client::Handle<ClientHandler>, String> {
    let addr = format!("{}:{}", config.host, config.port);
    
    // 1. 配置 client
    let russh_config = Arc::new(client::Config {
        connection_timeout: Some(Duration::from_secs(config.connect_timeout.unwrap_or(10) as u64)),
        ..Default::default()
    });

    // 2. 建立连接 (不带鉴权)
    let mut session = client::connect(russh_config, addr, ClientHandler)
        .await
        .map_err(|e| format!("Connection Error: {}", e))?;

    // 3. 鉴权逻辑
    // A. 优先尝试私钥认证 (russh 直接支持内存字符串，不需要写临时文件)
    if let Some(key_content) = &config.private_key {
        if !key_content.trim().is_empty() {
            // 解析私钥
            let key_pair = decode_secret_key(key_content, config.passphrase.as_deref())
                .map_err(|e| format!("Invalid Private Key: {}", e))?;
            
            if session.authenticate_publickey(&config.username, Arc::new(key_pair)).await.map_err(|e| e.to_string())? {
                return Ok(session);
            }
        }
    }

    // B. 尝试密码认证
    if let Some(pwd) = &config.password {
        if session.authenticate_password(&config.username, pwd).await.map_err(|e| e.to_string())? {
            return Ok(session);
        }
    }

    Err("Auth failed: Invalid credentials".to_string())
}

/// 建立 Shell 通道
pub async fn create_shell_channel(config: &SshConfig) -> Result<client::Channel<Msg>, String> {
    let session = establish_base_session_async(config).await?;
    
    // 打开一个会话通道
    let mut channel = session.channel_open_session().await
        .map_err(|e| format!("Channel Open Error: {}", e))?;
    
    // 请求 PTY (伪终端)
    channel.request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .map_err(|e| format!("PTY Request Error: {}", e))?;
    
    // 请求 Shell
    channel.request_shell(true)
        .await
        .map_err(|e| format!("Shell Request Error: {}", e))?;

    Ok(channel)
}

/// 建立监控会话 (移动端建议合并连接或保持单连接)
pub async fn create_monitor_session_async(config: &SshConfig) -> Option<client::Handle<ClientHandler>> {
    establish_base_session_async(config).await.ok()
}

/// 建立 SFTP 会话 (注：russh 需要配合专用库或手动处理 SFTP 协议)
pub async fn create_sftp_session_async(config: &SshConfig) -> Option<client::Handle<ClientHandler>> {
    establish_base_session_async(config).await.ok()
}

/// 启动读取循环 (异步版)
/// 代替原来的读取线程，使用 tokio::spawn
pub fn spawn_shell_reader(app: AppHandle, mut channel: client::Channel<Msg>, id: String) {
    tokio::spawn(async move {
        // russh 的 channel 本身就是异步流
        while let Some(msg) = channel.wait().await {
            match msg {
                Msg::Data { ref data } => {
                    let text = String::from_utf8_lossy(&data).to_string();
                    let _ = app.emit(&format!("term-data-{}", id), text);
                }
                Msg::Eof => {
                    println!("[SSH] EOF received for session: {}", id);
                    break;
                }
                _ => {}
            }
        }
        
        println!("[SSH] Shell reader exited for {}", id);
        let _ = app.emit(&format!("term-exit-{}", id), ());
    });
}

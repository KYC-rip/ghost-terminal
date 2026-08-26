//! Path-locked KV for RipleyOS (`ripleyos:*` keys) under `$APPDATA/ros-kv/`.
//!
//! This is NOT general filesystem access and must stay off `fs:*` capabilities.
//! Compromised ROS JS can already read/write OS state in webview localStorage;
//! these commands persist that same namespaced map on disk so WKWebView quota
//! cannot drop settings. Vault ciphertext is still whatever RosSecure wrote —
//! the backend does not encrypt.
//!
//! Per-key files (atomic tmp+rename), not one JSON map: a ~2.5 MB currency
//! catalog must not rewrite every window-position save.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager};

const DIR_NAME: &str = "ros-kv";
const MAX_VALUE_BYTES: usize = 32 * 1024 * 1024;
const KEY_PREFIX: &str = "ripleyos:";

fn kv_dir_from(app_data: &Path) -> PathBuf {
    app_data.join(DIR_NAME)
}

fn kv_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let d = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("no app data dir: {e}"))?;
    let dir = kv_dir_from(&d);
    fs::create_dir_all(&dir).map_err(|e| format!("mkdir: {e}"))?;
    Ok(dir)
}

fn assert_kv_dir(dir: &Path) -> Result<(), String> {
    match dir.file_name().and_then(|n| n.to_str()) {
        Some(DIR_NAME) => Ok(()),
        _ => Err("refuse to operate outside ros-kv".into()),
    }
}

/// Percent-encode so the filename mapping is injective. Unreserved: A-Za-z0-9._-
/// (`:` → `%3A`, `~` → `%7E`, `%` → `%25`). Reject path separators and NUL.
pub fn encode_key(key: &str) -> Result<String, String> {
    if !key.starts_with(KEY_PREFIX) {
        return Err("key must start with ripleyos:".into());
    }
    if key.contains('\0') || key.contains('/') || key.contains('\\') {
        return Err("key contains illegal path characters".into());
    }
    let mut out = String::with_capacity(key.len() + 8);
    for b in key.bytes() {
        if b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    Ok(out)
}

pub fn decode_key(stem: &str) -> Result<String, String> {
    if stem.is_empty() || stem == "." || stem == ".." {
        return Err("illegal stem".into());
    }
    let bytes = stem.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err("truncated percent-encoding".into());
            }
            let h = std::str::from_utf8(&bytes[i + 1..i + 3]).map_err(|_| "bad percent")?;
            let v = u8::from_str_radix(h, 16).map_err(|_| "bad percent")?;
            out.push(v);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    let key = String::from_utf8(out).map_err(|_| "filename is not utf-8")?;
    if !key.starts_with(KEY_PREFIX) {
        return Err("decoded key missing ripleyos: prefix".into());
    }
    Ok(key)
}

pub fn put(dir: &Path, key: &str, value: &str) -> Result<(), String> {
    assert_kv_dir(dir)?;
    if value.len() > MAX_VALUE_BYTES {
        return Err("value exceeds the 32 MiB limit".into());
    }
    fs::create_dir_all(dir).map_err(|e| format!("mkdir: {e}"))?;
    let stem = encode_key(key)?;
    let path = dir.join(&stem);
    let tmp = dir.join(format!("{stem}.tmp"));
    fs::write(&tmp, value.as_bytes()).map_err(|e| format!("write: {e}"))?;
    if path.exists() {
        let _ = fs::remove_file(&path);
    }
    fs::rename(&tmp, &path).map_err(|e| format!("rename: {e}"))?;
    Ok(())
}

pub fn load(dir: &Path) -> Result<HashMap<String, String>, String> {
    assert_kv_dir(dir)?;
    let mut out = HashMap::new();
    if !dir.is_dir() {
        return Ok(out);
    }
    for entry in fs::read_dir(dir).map_err(|e| format!("read_dir: {e}"))? {
        let entry = entry.map_err(|e| format!("read_dir: {e}"))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".tmp") {
            continue;
        }
        let Ok(key) = decode_key(&name) else { continue };
        // One unreadable/corrupt file must not fail the whole map — otherwise the
        // probe returns null and ROS boots on a webview that prior migrations emptied.
        let Ok(val) = fs::read_to_string(entry.path()) else { continue };
        out.insert(key, val);
    }
    Ok(out)
}

pub fn remove_key(dir: &Path, key: &str) -> Result<(), String> {
    assert_kv_dir(dir)?;
    let stem = encode_key(key)?;
    let path = dir.join(stem);
    if path.exists() {
        fs::remove_file(&path).map_err(|e| format!("remove: {e}"))?;
    }
    Ok(())
}

/// Delete only decoded `ripleyos:*` files inside ros-kv/. Never touches siblings
/// (wallpapers/, wallets, ghost_trades.json).
pub fn clear(dir: &Path) -> Result<(), String> {
    assert_kv_dir(dir)?;
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(dir).map_err(|e| format!("read_dir: {e}"))? {
        let entry = entry.map_err(|e| format!("read_dir: {e}"))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".tmp") {
            let _ = fs::remove_file(entry.path());
            continue;
        }
        if decode_key(&name).is_ok() {
            let _ = fs::remove_file(entry.path());
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn ros_kv_load(app: AppHandle) -> Result<HashMap<String, String>, String> {
    load(&kv_dir(&app)?)
}

#[tauri::command]
pub async fn ros_kv_set(app: AppHandle, key: String, value: String) -> Result<(), String> {
    put(&kv_dir(&app)?, &key, &value)
}

#[tauri::command]
pub async fn ros_kv_remove(app: AppHandle, key: String) -> Result<(), String> {
    remove_key(&kv_dir(&app)?, &key)
}

#[tauri::command]
pub async fn ros_kv_clear(app: AppHandle) -> Result<(), String> {
    clear(&kv_dir(&app)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch() -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir()
            .join(format!("ros-kv-test-{n}"))
            .join("ros-kv");
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn kv_dir_is_app_data_join_ros_kv() {
        let app_data = PathBuf::from("/tmp/Application Support/run.ripley.terminal");
        assert_eq!(kv_dir_from(&app_data), app_data.join("ros-kv"));
        let win = PathBuf::from(r"C:\Users\a\AppData\Roaming\run.ripley.terminal");
        assert_eq!(kv_dir_from(&win), win.join("ros-kv"));
        let xdg = PathBuf::from("/home/a/.local/share/run.ripley.terminal");
        assert_eq!(kv_dir_from(&xdg), xdg.join("ros-kv"));
    }

    #[test]
    fn encode_is_injective_and_round_trips_adversarial_names() {
        let keys = [
            "ripleyos:foo:bar",
            "ripleyos:foo~bar",
            "ripleyos:foo_bar",
            "ripleyos:foo%bar",
            "ripleyos:swap:currencies:cache:v4",
            "ripleyos:__native_migrated",
        ];
        let mut stems = std::collections::HashSet::new();
        for k in keys {
            let stem = encode_key(k).unwrap();
            assert!(stems.insert(stem.clone()), "collision on {k}");
            assert_eq!(decode_key(&stem).unwrap(), k);
        }
        assert_ne!(encode_key("ripleyos:foo:bar").unwrap(), encode_key("ripleyos:foo~bar").unwrap());
    }

    #[test]
    fn encode_rejects_bad_keys() {
        assert!(encode_key("not-namespaced").is_err());
        assert!(encode_key("ripleyos:foo/bar").is_err());
        assert!(encode_key("ripleyos:foo\\bar").is_err());
        assert!(encode_key("ripleyos:foo\0bar").is_err());
    }

    #[test]
    fn put_load_remove_round_trip() {
        let dir = scratch();
        put(&dir, "ripleyos:a", "one").unwrap();
        put(&dir, "ripleyos:b", "two").unwrap();
        let map = load(&dir).unwrap();
        assert_eq!(map.get("ripleyos:a").unwrap(), "one");
        assert_eq!(map.get("ripleyos:b").unwrap(), "two");
        remove_key(&dir, "ripleyos:a").unwrap();
        let map = load(&dir).unwrap();
        assert!(map.get("ripleyos:a").is_none());
        assert_eq!(map.get("ripleyos:b").unwrap(), "two");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn skips_tmp_and_refuses_to_operate_outside_ros_kv() {
        let dir = scratch();
        fs::write(dir.join("orphan.tmp"), "x").unwrap();
        put(&dir, "ripleyos:ok", "v").unwrap();
        let map = load(&dir).unwrap();
        assert_eq!(map.len(), 1);
        let elsewhere = std::env::temp_dir().join(format!("not-kv-{}", dir.file_name().unwrap().to_string_lossy()));
        fs::create_dir_all(&elsewhere).unwrap();
        assert!(put(&elsewhere, "ripleyos:x", "y").is_err());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&elsewhere);
    }

    #[test]
    fn clear_does_not_touch_sibling_wallpapers() {
        let parent = scratch().parent().unwrap().join(format!(
            "ros-kv-parent-{}",
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        let kv = parent.join("ros-kv");
        let walls = parent.join("wallpapers");
        fs::create_dir_all(&kv).unwrap();
        fs::create_dir_all(&walls).unwrap();
        put(&kv, "ripleyos:a", "1").unwrap();
        fs::write(walls.join("keep.img"), b"img").unwrap();
        clear(&kv).unwrap();
        assert!(load(&kv).unwrap().is_empty());
        assert!(walls.join("keep.img").is_file());
        let _ = fs::remove_dir_all(&parent);
    }

    #[test]
    fn load_skips_unreadable_entries_and_keeps_the_rest() {
        let dir = scratch();
        put(&dir, "ripleyos:good", "ok").unwrap();
        let stem = encode_key("ripleyos:bin").unwrap();
        fs::write(dir.join(stem), [0xff, 0xfe]).unwrap();
        let map = load(&dir).unwrap();
        assert_eq!(map.get("ripleyos:good").unwrap(), "ok");
        assert!(map.get("ripleyos:bin").is_none());
        let _ = fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn value_cap() {
        let dir = scratch();
        let too_big = "x".repeat(MAX_VALUE_BYTES + 1);
        assert!(put(&dir, "ripleyos:big", &too_big).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}

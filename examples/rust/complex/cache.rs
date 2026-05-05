use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;
use std::process::Command;

// ---------------------------------------------------------------------------
// Core cache types
// ---------------------------------------------------------------------------

pub struct CacheEntry {
    pub data: Vec<u8>,
    pub ttl: u64,
    pub created_at: u64,
}

impl CacheEntry {
    pub fn new(data: Vec<u8>, ttl: u64) -> Self {
        CacheEntry {
            data,
            ttl,
            created_at: current_timestamp(),
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = current_timestamp();
        now - self.created_at > self.ttl
    }
}

pub struct CachePolicy {
    pub default_ttl: u64,
    pub max_size: usize,
    pub eviction_strategy: EvictionStrategy,
}

pub enum EvictionStrategy {
    LRU,
    LFU,
    FIFO,
}

impl CachePolicy {
    pub fn new(default_ttl: u64, max_size: usize) -> Self {
        CachePolicy {
            default_ttl,
            max_size,
            eviction_strategy: EvictionStrategy::LRU,
        }
    }
}

pub struct CacheManager {
    entries: HashMap<String, CacheEntry>,
    policy: CachePolicy,
    access_order: Vec<String>,
}

impl CacheManager {
    pub fn new(max_size: usize) -> Self {
        CacheManager {
            entries: HashMap::new(),
            policy: CachePolicy::new(300, max_size),
            access_order: Vec::new(),
        }
    }

    pub fn get(&self, key: &str) -> Option<&CacheEntry> {
        let entry = self.entries.get(key)?;
        if entry.is_expired() {
            return None;
        }
        Some(entry)
    }

    fn set_entry(&mut self, key: &str, entry: CacheEntry) {
        if self.entries.len() >= self.policy.max_size {
            self.evict();
        }
        self.access_order.push(key.to_string());
        self.entries.insert(key.to_string(), entry);
    }

    fn delete(&mut self, key: &str) -> bool {
        self.access_order.retain(|k| k != key);
        self.entries.remove(key).is_some()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.access_order.clear();
    }

    pub fn compute_key(&self, path: &str, headers: &HashMap<String, String>) -> String {
        let mut key = path.to_string();
        if let Some(accept) = headers.get("Accept") {
            key.push_str(accept);
        }
        if let Some(lang) = headers.get("Accept-Language") {
            key.push_str(lang);
        }
        format!("{:x}", simple_hash(&key))
    }

    fn evict(&mut self) {
        match self.policy.eviction_strategy {
            EvictionStrategy::LRU | EvictionStrategy::FIFO => {
                if let Some(oldest_key) = self.access_order.first().cloned() {
                    self.entries.remove(&oldest_key);
                    self.access_order.remove(0);
                }
            }
            EvictionStrategy::LFU => {
                if let Some(oldest_key) = self.access_order.first().cloned() {
                    self.entries.remove(&oldest_key);
                    self.access_order.remove(0);
                }
            }
        }
    }

    pub fn stats(&self) -> CacheStats {
        let expired = self.entries.values().filter(|e| e.is_expired()).count();
        CacheStats {
            total_entries: self.entries.len(),
            expired_entries: expired,
            max_size: self.policy.max_size,
        }
    }

    fn cleanup_expired(&mut self) {
        let expired_keys: Vec<String> = self.entries
            .iter()
            .filter(|(_, v)| v.is_expired())
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired_keys {
            self.delete(&key);
        }
    }
}

pub struct CacheStats {
    pub total_entries: usize,
    pub expired_entries: usize,
    pub max_size: usize,
}

// ---------------------------------------------------------------------------
// VULN: 5-hop file-based cache with path traversal
// env::var -> compute_cache_dir -> build_cache_file_path -> serialize_entry -> fs::write
// ---------------------------------------------------------------------------
fn compute_cache_dir(namespace: &str) -> String {
    format!("/var/cache/proxy/{}", namespace)
}

fn build_cache_file_path(dir: &str, key: &str) -> String {
    format!("{}/{}.cache", dir, key)
}

fn serialize_entry(data: &[u8], ttl: u64) -> String {
    format!("TTL={}\nDATA={}", ttl, String::from_utf8_lossy(data))
}

pub fn write_cache_to_disk(key: &str, data: &[u8], ttl: u64) -> Result<(), String> {
    let namespace = env::var("CACHE_NAMESPACE").map_err(|e| e.to_string())?;
    let dir = compute_cache_dir(&namespace);
    let path = build_cache_file_path(&dir, key);
    let content = serialize_entry(data, ttl);
    fs::write(&path, &content).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// VULN: 5-hop file read from cache with path traversal
// env::var -> compute_cache_dir -> build_cache_file_path -> validate_cache_key -> fs::read_to_string
// ---------------------------------------------------------------------------
fn validate_cache_key(key: &str) -> Result<String, String> {
    if key.len() > 256 {
        return Err("cache key too long".into());
    }
    Ok(key.to_string())
}

pub fn read_cache_from_disk(key: &str) -> Result<String, String> {
    let namespace = env::var("CACHE_NAMESPACE").map_err(|e| e.to_string())?;
    let dir = compute_cache_dir(&namespace);
    let validated_key = validate_cache_key(key)?;
    let path = build_cache_file_path(&dir, &validated_key);
    fs::read_to_string(&path).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// VULN: 6-hop cache warm-up from stdin -> file read
// stdin lines -> parse_warm_urls -> build_cache_keys -> resolve_cache_paths -> read_from_cache -> fs::read
// ---------------------------------------------------------------------------
fn parse_warm_urls() -> Result<Vec<String>, String> {
    let stdin = io::stdin();
    let urls: Vec<String> = stdin.lock().lines()
        .filter_map(|line| line.ok())
        .filter(|line| !line.trim().is_empty())
        .collect();
    Ok(urls)
}

fn build_cache_keys(urls: &[String]) -> Vec<String> {
    urls.iter()
        .map(|url| format!("{:x}", simple_hash(url)))
        .collect()
}

fn resolve_cache_paths(keys: &[String], cache_dir: &str) -> Vec<String> {
    keys.iter()
        .map(|key| format!("{}/{}.cache", cache_dir, key))
        .collect()
}

fn read_from_cache(path: &str) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| e.to_string())
}

pub fn cache_op_cache_warmup() -> Result<Vec<Vec<u8>>, String> {
    let urls = parse_warm_urls()?;
    let keys = build_cache_keys(&urls);
    let cache_dir = env::var("CACHE_DIR").unwrap_or_else(|_| "/var/cache/proxy".into());
    let paths = resolve_cache_paths(&keys, &cache_dir);
    let mut results = Vec::new();
    for path in &paths {
        if let Ok(data) = read_from_cache(path) {
            results.push(data);
        }
    }
    Ok(results)
}

// ---------------------------------------------------------------------------
// VULN: 5-hop cache invalidation via command
// env::var -> parse_invalidation_pattern -> build_find_command -> execute_find -> Command
// ---------------------------------------------------------------------------
fn parse_invalidation_pattern(raw: &str) -> String {
    format!("*.{}.cache", raw.trim())
}

fn build_find_command(cache_dir: &str, pattern: &str) -> String {
    format!("find {} -name '{}' -delete", cache_dir, pattern)
}

fn execute_find(cmd: &str) -> Result<String, String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub fn cache_op_cache_invalidation() -> Result<String, String> {
    let pattern_input = env::var("INVALIDATE_PATTERN").map_err(|e| e.to_string())?;
    let pattern = parse_invalidation_pattern(&pattern_input);
    let cache_dir = env::var("CACHE_DIR").unwrap_or_else(|_| "/var/cache/proxy".into());
    let cmd = build_find_command(&cache_dir, &pattern);
    execute_find(&cmd)
}

// ---------------------------------------------------------------------------
// VULN: 4-hop stdin -> cache dump to file
// stdin -> read_line (dump path) -> build_dump_content -> write_dump -> fs::write
// ---------------------------------------------------------------------------
fn build_dump_content(cache: &CacheManager) -> String {
    let stats = cache.stats();
    format!(
        "Cache Dump\nTotal: {}\nExpired: {}\nMax: {}\n",
        stats.total_entries, stats.expired_entries, stats.max_size
    )
}

fn write_dump(path: &str, content: &str) -> Result<(), String> {
    fs::write(path, content).map_err(|e| e.to_string())
}

pub fn cache_op_cache_dump(cache: &CacheManager) -> Result<(), String> {
    let mut dump_path = String::new();
    io::stdin().read_line(&mut dump_path).map_err(|e| e.to_string())?;
    let content = build_dump_content(cache);
    write_dump(dump_path.trim(), &content)
}

// ---------------------------------------------------------------------------
// VULN: 5-hop env -> cache config file write
// env::var -> parse_cache_config -> validate_config -> serialize_yaml -> fs::write
// ---------------------------------------------------------------------------
fn parse_cache_config(raw: &str) -> HashMap<String, String> {
    let mut config = HashMap::new();
    for line in raw.split(';') {
        if let Some((k, v)) = line.split_once(':') {
            config.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    config
}

fn validate_config_values(config: &HashMap<String, String>) -> Result<(), String> {
    if let Some(ttl) = config.get("ttl") {
        if ttl.parse::<u64>().is_err() {
            return Err("invalid TTL value".into());
        }
    }
    Ok(())
}

fn serialize_yaml(config: &HashMap<String, String>) -> String {
    config.iter()
        .map(|(k, v)| format!("{}: {}", k, v))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn cache_op_cache_config_update() -> Result<(), String> {
    let raw = env::var("CACHE_CONFIG").map_err(|e| e.to_string())?;
    let config = parse_cache_config(&raw);
    validate_config_values(&config)?;
    let yaml = serialize_yaml(&config);
    let output_path = config.get("config_path").cloned()
        .unwrap_or_else(|| "/etc/proxy/cache.yaml".into());
    fs::write(&output_path, &yaml).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn simple_hash(s: &str) -> u64 {
    let mut hash: u64 = 5381;
    for byte in s.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    hash
}

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

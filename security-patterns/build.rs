use sha2::{Digest, Sha256};
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

const ARCHIVE_MAGIC: &[u8; 8] = b"BNSRP001";

fn main() {
    if let Err(error) = build_bundled_rulepack() {
        panic!("failed to build bundled security rulepack: {error}");
    }
}

fn build_bundled_rulepack() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("CARGO_MANIFEST_DIR is unset")?);
    println!("cargo:rerun-if-changed={}", root.join("VERSION").display());
    println!("cargo:rerun-if-changed={}", root.join("metadata.yml").display());
    println!("cargo:rerun-if-changed={}", root.join("langs").display());

    let mut files = vec![
        (PathBuf::from("VERSION"), root.join("VERSION")),
        (PathBuf::from("metadata.yml"), root.join("metadata.yml")),
    ];
    collect_regular_files(&root, &root.join("langs"), &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    for (relative, absolute) in &files {
        if !absolute.is_file() {
            return Err(format!("bundled rulepack is missing `{}`", relative.display()).into());
        }
        let supported = relative == Path::new("VERSION")
            || matches!(
                relative.extension().and_then(|value| value.to_str()),
                Some("yml" | "yaml")
            );
        if !supported {
            return Err(format!(
                "unexpected non-rule file in bundled rulepack: {}",
                relative.display()
            )
            .into());
        }
    }

    let file_count = u32::try_from(files.len()).map_err(|_| "bundled rulepack has too many files")?;
    let mut archive = Vec::new();
    archive.extend_from_slice(ARCHIVE_MAGIC);
    archive.extend_from_slice(&file_count.to_le_bytes());
    for (relative, absolute) in files {
        println!("cargo:rerun-if-changed={}", absolute.display());
        let relative = relative
            .to_str()
            .ok_or_else(|| format!("rulepack path is not UTF-8: {}", relative.display()))?
            .replace('\\', "/");
        let path_bytes = relative.as_bytes();
        let content = fs::read(&absolute)?;
        archive.extend_from_slice(
            &u32::try_from(path_bytes.len())
                .map_err(|_| format!("rulepack path is too long: {relative}"))?
                .to_le_bytes(),
        );
        archive.extend_from_slice(
            &u64::try_from(content.len())
                .map_err(|_| format!("rulepack file is too large: {relative}"))?
                .to_le_bytes(),
        );
        archive.extend_from_slice(path_bytes);
        archive.extend_from_slice(&content);
    }

    let digest = Sha256::digest(&archive);
    let mut identity = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut identity, "{byte:02x}").expect("writing to a String cannot fail");
    }
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or("OUT_DIR is unset")?);
    let archive_path = out_dir.join("bundled-rulepack.bin.zst");
    let mut encoder = zstd::stream::Encoder::new(fs::File::create(&archive_path)?, 19)?;
    encoder.include_checksum(true)?;
    encoder.write_all(&archive)?;
    encoder.finish()?.sync_all()?;
    fs::write(out_dir.join("bundled-rulepack-id.rs"), format!("{identity:?}\n"))?;
    Ok(())
}

fn collect_regular_files(root: &Path, dir: &Path, out: &mut Vec<(PathBuf, PathBuf)>) -> io::Result<()> {
    let mut entries = fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_regular_files(root, &path, out)?;
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)
                .expect("collected rulepack path stays below its root")
                .to_path_buf();
            out.push((relative, path));
        }
    }
    Ok(())
}

//! Narrow build-time path admission for the original canonical Cargo layout.
//!
//! Linux additionally admits one inherited target-directory capability. This is
//! a private, serialized build boundary, not a hostile same-UID filesystem sandbox.
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

// Keep the ordinary canonical-only route unchanged, including its refusals.
pub fn canonical_directory(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("loader directory must be absolute".into());
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| "loader directory missing")?;
    if canonical != path || !canonical.is_dir() {
        return Err("loader directory must be a canonical existing directory".into());
    }
    Ok(canonical)
}

pub struct LoaderPaths {
    #[cfg(target_os = "linux")]
    held: Option<linux::HeldTarget>,
}

impl LoaderPaths {
    pub fn capture(target: Option<&OsStr>) -> Result<Self, String> {
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                held: linux::HeldTarget::capture(target)?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            if target.is_some_and(|value| value.to_string_lossy().starts_with("/proc/self/fd/")) {
                return Err("held target aliases are admitted only on Linux".into());
            }
            Ok(Self {})
        }
    }

    pub fn out_directory(&mut self, path: &Path) -> Result<PathBuf, String> {
        #[cfg(target_os = "linux")]
        if let Some(held) = &mut self.held {
            return held.cargo_out_directory(path);
        }
        canonical_directory(path)
    }

    /// OUT_DIR and its derived target directories must belong to the captured
    /// target even if Cargo happens to spell them as ordinary canonical paths.
    pub fn target_directory(&mut self, path: &Path) -> Result<PathBuf, String> {
        #[cfg(target_os = "linux")]
        if let Some(held) = &mut self.held {
            return held.directory(path, false);
        }
        canonical_directory(path)
    }

    /// Only the literal inherited alias may bypass canonical-only admission.
    /// The caller must still restrict the result to profile and profile/deps.
    pub fn target_alias_directory(&mut self, path: &Path) -> Result<PathBuf, String> {
        #[cfg(target_os = "linux")]
        if let Some(held) = &mut self.held {
            return held.directory(path, true);
        }
        let _ = path;
        Err("loader alias has no captured Linux target capability".into())
    }

    /// Retain this object and revalidate around actual compiler/nm use and
    /// immediately before publishing the fresh build fence.
    pub fn validate(&self) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        if let Some(held) = &self.held {
            held.validate()?;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::canonical_directory;
    use std::collections::BTreeMap;
    use std::ffi::{OsStr, OsString};
    use std::fs::{self, File, Metadata};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    struct DirectoryPin {
        file: File,
        device: u64,
        inode: u64,
    }

    pub(super) struct HeldTarget {
        advertised: PathBuf,
        canonical: PathBuf,
        file: File,
        device: u64,
        inode: u64,
        owner: u32,
        directories: BTreeMap<PathBuf, DirectoryPin>,
    }

    fn identity(metadata: &Metadata) -> (u64, u64) {
        (metadata.dev(), metadata.ino())
    }

    fn proc_alias(file: &File) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
    }

    // Parse bytes before Path can normalize repeated separators or dot segments.
    fn relative(path: &Path, root: &Path) -> Option<PathBuf> {
        let bytes = path.as_os_str().as_bytes();
        let base = root.as_os_str().as_bytes();
        if bytes == base {
            return Some(PathBuf::new());
        }
        let suffix = bytes.strip_prefix(base)?.strip_prefix(b"/")?;
        if suffix.is_empty()
            || suffix
                .split(|byte| *byte == b'/')
                .any(|part| part.is_empty() || part == b"." || part == b"..")
        {
            return None;
        }
        Some(PathBuf::from(OsString::from_vec(suffix.to_vec())))
    }

    impl HeldTarget {
        pub(super) fn capture(target: Option<&OsStr>) -> Result<Option<Self>, String> {
            let Some(target) = target else {
                return Ok(None);
            };
            let prefix = b"/proc/self/fd/";
            let bytes = target.as_bytes();
            let Some(digits) = bytes.strip_prefix(prefix) else {
                return Ok(None);
            };
            if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
                return Err("target alias requires a literal decimal descriptor".into());
            }
            let number = std::str::from_utf8(digits)
                .map_err(|_| "non-ASCII target descriptor")?
                .parse::<i32>()
                .map_err(|_| "target descriptor out of range")?;
            if number < 3 || number.to_string().as_bytes() != digits {
                return Err("target alias requires canonical decimal descriptor >=3".into());
            }
            let advertised = PathBuf::from(target);
            // Safe procfs capture, followed by a real owned File duplication.
            // Never take ownership of, close, or change the inherited descriptor.
            let before = fs::metadata(&advertised).map_err(|_| "target descriptor unavailable")?;
            let captured =
                File::open(&advertised).map_err(|_| "cannot capture target directory")?;
            let file = captured
                .try_clone()
                .map_err(|_| "cannot duplicate captured target")?;
            let metadata = file.metadata().map_err(|_| "cannot stat captured target")?;
            if identity(&before) != identity(&metadata) {
                return Err("target descriptor changed during capture".into());
            }
            let canonical = advertised
                .canonicalize()
                .map_err(|_| "target alias missing")?;
            canonical_directory(&canonical)?;
            let owner = fs::metadata("/proc/self")
                .map_err(|_| "process identity unavailable")?
                .uid();
            let result = Self {
                advertised,
                canonical,
                device: metadata.dev(),
                inode: metadata.ino(),
                owner,
                file,
                directories: BTreeMap::new(),
            };
            result.validate()?;
            Ok(Some(result))
        }

        fn root_metadata(&self, metadata: &Metadata) -> Result<(), String> {
            if !metadata.is_dir()
                || identity(metadata) != (self.device, self.inode)
                || metadata.uid() != self.owner
                || metadata.mode() & 0o7777 != 0o700
            {
                return Err("held target must retain its private0700 directory identity".into());
            }
            Ok(())
        }

        pub(super) fn validate(&self) -> Result<(), String> {
            self.root_metadata(
                &self
                    .file
                    .metadata()
                    .map_err(|_| "held target stat failed")?,
            )?;
            let captured_alias = proc_alias(&self.file);
            for path in [&self.advertised, &captured_alias, &self.canonical] {
                if path
                    .canonicalize()
                    .map_err(|_| "held target path missing")?
                    != self.canonical
                {
                    return Err("held target was renamed or redirected".into());
                }
                self.root_metadata(
                    &fs::metadata(path).map_err(|_| "held target path stat failed")?,
                )?;
            }
            for (canonical, pin) in &self.directories {
                let relative =
                    relative(canonical, &self.canonical).ok_or("foreign pinned target path")?;
                if identity(
                    &pin.file
                        .metadata()
                        .map_err(|_| "pinned directory stat failed")?,
                ) != (pin.device, pin.inode)
                    || proc_alias(&pin.file)
                        .canonicalize()
                        .map_err(|_| "pinned directory missing")?
                        != *canonical
                {
                    return Err("pinned target directory was renamed or changed".into());
                }
                for path in [
                    self.advertised.join(&relative),
                    proc_alias(&self.file).join(&relative),
                    canonical.clone(),
                ] {
                    let metadata = fs::metadata(&path).map_err(|_| "target component missing")?;
                    if !metadata.is_dir()
                        || metadata.uid() != self.owner
                        || identity(&metadata) != (pin.device, pin.inode)
                        || path
                            .canonicalize()
                            .map_err(|_| "target component missing")?
                            != *canonical
                    {
                        return Err("target component was replaced or symlinked".into());
                    }
                }
            }
            Ok(())
        }

        pub(super) fn cargo_out_directory(&mut self, path: &Path) -> Result<PathBuf, String> {
            let out = self.directory(path, false)?;
            let relative = relative(&out, &self.canonical).ok_or("foreign Cargo OUT_DIR")?;
            if relative.components().count() != 4 {
                return Err("held OUT_DIR must be exactly target/profile/build/unit/out".into());
            }
            Ok(out)
        }

        pub(super) fn directory(
            &mut self,
            path: &Path,
            alias_only: bool,
        ) -> Result<PathBuf, String> {
            self.validate()?;
            let relative = relative(path, &self.advertised)
                .or_else(|| {
                    if alias_only {
                        None
                    } else {
                        relative(path, &self.canonical)
                    }
                })
                .ok_or("directory is not under the exact captured target spelling")?;
            let expected = self.canonical.join(&relative);
            if path
                .canonicalize()
                .map_err(|_| "target directory missing")?
                != expected
            {
                return Err("target directory contains a symlink or redirected component".into());
            }
            // Keep every ancestor capability too: preserving the final out inode
            // does not excuse replacing its profile/build/unit parent.
            let mut prefix = PathBuf::new();
            for part in relative.components() {
                prefix.push(part.as_os_str());
                let canonical = self.canonical.join(&prefix);
                let file = File::open(proc_alias(&self.file).join(&prefix))
                    .map_err(|_| "cannot capture target component")?;
                let metadata = file
                    .metadata()
                    .map_err(|_| "target component stat failed")?;
                if !metadata.is_dir() || metadata.uid() != self.owner {
                    return Err("target component is not an owned directory".into());
                }
                if let Some(pin) = self.directories.get(&canonical) {
                    if identity(&metadata) != (pin.device, pin.inode) {
                        return Err("target component changed during admission".into());
                    }
                } else {
                    self.directories.insert(
                        canonical,
                        DirectoryPin {
                            file,
                            device: metadata.dev(),
                            inode: metadata.ino(),
                        },
                    );
                }
            }
            self.validate()?;
            Ok(expected)
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "build_loader_paths_tests.rs"]
mod tests;

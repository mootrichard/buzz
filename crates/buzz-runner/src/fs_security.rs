//! Fail-closed filesystem helpers for private runner state.

use std::fs::File;
use std::io;
use std::path::Path;

/// Create a new file with an explicit Unix permission mode.
#[cfg(unix)]
pub fn create_new_private(path: &Path, mode: u32) -> io::Result<File> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
}

/// Refuse to create private files on platforms where the runner cannot enforce
/// the required Unix permission mode.
#[cfg(not(unix))]
pub fn create_new_private(_path: &Path, _mode: u32) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "buzz-runner requires Unix filesystem permissions",
    ))
}

/// Apply an explicit Unix permission mode to a filesystem path.
#[cfg(unix)]
pub fn set_private_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, Permissions::from_mode(mode))
}

/// Refuse to continue on platforms where the runner cannot enforce the
/// required Unix permission mode.
#[cfg(not(unix))]
pub fn set_private_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "buzz-runner requires Unix filesystem permissions",
    ))
}

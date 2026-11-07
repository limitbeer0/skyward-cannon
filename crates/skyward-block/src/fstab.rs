//! The table a phone keeps of its own filesystems: where each one is, what
//! it holds, and how it is encrypted.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Where the phone's own partitions keep the table, on a Qualcomm phone.
/// Other SoCs name it differently: a MediaTek phone names its tables after
/// its SoC and its storage controller, so the device's configuration may
/// give other files instead; see [`set_files`].
pub const FILES: [&str; 2] = ["/vendor/etc/fstab.qcom", "/odm/etc/fstab.qcom"];

/// The files [`set_files`] gave, once it did; until then tables are read
/// from [`FILES`]. Where the table is kept is a fact of the whole run rather
/// than a parameter of every caller, because the callers are not one part of
/// the recovery: mounting, repairing a filesystem and erasing the phone's
/// data all read this table, in several crates, and the device's
/// configuration is read once, as the recovery starts, before any of them
/// asks. The phone's own first-stage init finds one named file the same way.
static GIVEN: OnceLock<Vec<String>> = OnceLock::new();

/// Read the phone's tables from `files` instead of [`FILES`]. The recovery
/// service calls it once, as it starts, with what the device's
/// configuration names; a configuration naming no files keeps the Qualcomm
/// pair, so every phone without the section is read as it always was. A
/// later call changes nothing: init starts the recovery service again after
/// a failure, and the second run must read the tables the first did.
pub fn set_files(files: &[String]) {
    if !files.is_empty() {
        let _ = GIVEN.set(files.to_vec());
    }
}

/// The files the phone's tables are read from, now.
fn files() -> Vec<String> {
    GIVEN
        .get()
        .cloned()
        .unwrap_or_else(|| FILES.iter().map(|f| f.to_string()).collect())
}

/// One filesystem the phone knows about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub device: String,
    pub mount_point: String,
    pub filesystem: String,
    /// How the phone mounts it: the kernel's flags and the filesystem's
    /// own options, as one list.
    pub options: Vec<String>,
    /// What the phone says about the filesystem beyond how to mount it,
    /// such as how it is encrypted.
    pub extras: Vec<String>,
}

impl Entry {
    /// The value of an extra written as `name=value`.
    pub fn extra(&self, name: &str) -> Option<&str> {
        let prefix = format!("{name}=");
        self.extras.iter().find_map(|e| e.strip_prefix(&prefix))
    }
}

/// Every filesystem a table names. A phone may name the same mount point
/// more than once, once per filesystem it might hold.
pub fn entries(text: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [device, mount_point, filesystem, options, extras] = fields[..] else { continue };
        out.push(Entry {
            device: device.to_string(),
            mount_point: mount_point.to_string(),
            filesystem: filesystem.to_string(),
            options: options.split(',').map(str::to_string).collect(),
            extras: extras.split(',').map(str::to_string).collect(),
        });
    }
    out
}

/// Every entry of the phone's own table, read from wherever the table is.
fn table() -> Result<Vec<Entry>> {
    read_files(&files())
}

/// Every entry of the tables named in `files`, in the order they are
/// given: a phone's data partition is of the filesystem its own table
/// says, which one table names and another may not.
fn read_files(files: &[String]) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    for file in files {
        let text = match std::fs::read_to_string(file) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("read {file}")),
        };
        out.extend(entries(&text));
    }
    Ok(out)
}

/// What the phone's own table says about `mount_point`.
pub fn read(mount_point: &str) -> Result<Vec<Entry>> {
    Ok(table()?.into_iter().filter(|e| e.mount_point == mount_point).collect())
}

/// What the phone's own table says about the partition `name`: the first
/// entry naming it, by whichever path the table reaches it.
pub fn partition(name: &str) -> Result<Option<Entry>> {
    Ok(table()?.into_iter().find(|e| names(e, name)))
}

/// Whether an entry is of the partition `name`.
fn names(entry: &Entry, name: &str) -> bool {
    Path::new(&entry.device).file_name().is_some_and(|n| n == name)
}

/// The partition an entry names, as it is reachable now: of the booted
/// slot, where the phone keeps one of it per slot. A phone's table points
/// at its storage controller by a path a recovery need not have.
pub fn device(entry: &Entry) -> Result<String> {
    let path = match entry.extras.iter().any(|e| e == "slotselect") {
        true => format!("{}{}", entry.device, crate::slot_suffix()?.with_context(|| format!("{} is of a slot, and the phone has none", entry.device))?),
        false => entry.device.clone(),
    };
    if Path::new(&path).exists() {
        return Ok(path);
    }
    let name = Path::new(&path).file_name().with_context(|| format!("{path} names no partition"))?;
    let by_name = Path::new(crate::BY_NAME).join(name);
    if by_name.exists() {
        return Ok(by_name.to_string_lossy().into_owned());
    }
    anyhow::bail!("neither {path} nor {} is here", by_name.display())
}

/// Mount the partition `name` where and as the phone's own table mounts
/// it, and say where. Whatever shows there already, as what an earlier run
/// of the recovery service mounted does, is taken as it is.
pub fn mount(name: &str) -> Result<PathBuf> {
    let entry = partition(name)?.with_context(|| format!("the phone's own table does not mount {name}"))?;
    let at = PathBuf::from(&entry.mount_point);
    if crate::mount::is_mount_point(&at)? {
        return Ok(at);
    }
    std::fs::create_dir_all(&at).with_context(|| format!("make {}", at.display()))?;
    crate::mount::mount(Path::new(&device(&entry)?), &at, &entry.filesystem, &entry.options)?;
    Ok(at)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = "\
# a comment
/dev/block/bootdevice/by-name/metadata /metadata f2fs noatime,nosuid wait,check,formattable
/dev/block/bootdevice/by-name/userdata /data f2fs noatime,discard latemount,wait,fileencryption=aes-256-xts:aes-256-cts:v2,keydirectory=/metadata/vold/metadata_encryption,metadata_encryption=aes-256-xts:wrappedkey_v0,quota
/dev/block/bootdevice/by-name/userdata /data mifs noatime,discard latemount,wait,keydirectory=/metadata/vold/metadata_encryption
";

    #[test]
    fn a_mount_point_can_be_named_once_per_filesystem_it_might_hold() {
        let data: Vec<Entry> = entries(TABLE).into_iter().filter(|e| e.mount_point == "/data").collect();
        assert_eq!(data.len(), 2);
        assert_eq!(data[0].filesystem, "f2fs");
        assert_eq!(data[1].filesystem, "mifs");
        assert_eq!(data[0].device, "/dev/block/bootdevice/by-name/userdata");
    }

    #[test]
    fn how_the_phone_mounts_a_filesystem_is_kept_apart_from_the_rest() {
        let data = &entries(TABLE)[1];
        assert_eq!(data.options, ["noatime", "discard"]);
        assert!(data.extras.iter().any(|e| e == "latemount") && !data.extras.iter().any(|e| e == "noatime"));
    }

    #[test]
    fn what_the_phone_says_about_encryption_is_read_off_the_entry() {
        let data = &entries(TABLE)[1];
        assert_eq!(data.extra("metadata_encryption"), Some("aes-256-xts:wrappedkey_v0"));
        assert_eq!(data.extra("keydirectory"), Some("/metadata/vold/metadata_encryption"));
        assert_eq!(data.extra("quota"), None, "a word on its own has no value");
        assert_eq!(data.extra("keydir"), None, "a shorter name is another extra");
    }

    #[test]
    fn an_entry_is_of_the_partition_its_path_ends_in() {
        let modem = &entries(
            "/dev/block/bootdevice/by-name/modem /vendor/firmware_mnt vfat ro,uid=1000,context=u:object_r:firmware_file:s0 wait,slotselect\n",
        )[0];
        assert!(names(modem, "modem"));
        assert!(!names(modem, "modemfirmware") && !names(modem, "mode"), "a name is matched whole");
        assert_eq!(modem.options[0], "ro");
        assert!(modem.extras.iter().any(|e| e == "slotselect"), "one of each slot");
    }

    #[test]
    fn comments_and_short_lines_are_passed_over() {
        assert!(entries("# nothing\n\n/dev/x /y f2fs rw\n").is_empty());
        assert_eq!(entries(TABLE).len(), 3);
    }

    /// A folder holding the tables `named`, each written as its own file.
    /// A name not given is absent, as a phone's odm table is when the phone
    /// keeps its table in one place only.
    fn tables(named: &[(&str, &str)]) -> PathBuf {
        let root = std::env::temp_dir().join(format!("skyward-fstab-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        for (name, text) in named {
            std::fs::write(root.join(name), text).unwrap();
        }
        root
    }

    #[test]
    fn the_tables_a_phone_names_are_read_in_that_order_and_an_absent_one_passed_over() {
        let vendor = "/dev/block/by-name/userdata /data f2fs noatime wait,check,formattable\n";
        let odm = "/dev/block/by-name/cache /cache ext4 noatime wait,check,formattable\n";
        let root = tables(&[("fstab.mt6853", vendor), ("fstab.emmc", odm)]);
        let given = |names: &[&str]| -> Vec<String> {
            names.iter().map(|n| root.join(n).to_string_lossy().into_owned()).collect()
        };
        let read = |names: &[&str]| -> Vec<Entry> { read_files(&given(names)).unwrap() };
        assert_eq!(read(&["fstab.mt6853", "fstab.emmc"]).len(), 2, "both tables are read");
        assert_eq!(read(&["fstab.mt6853", "fstab.emmc"])[0].mount_point, "/data", "in the order given");
        assert_eq!(read(&["fstab.emmc", "fstab.mt6853"])[0].mount_point, "/cache", "which comes first is the configuration's to say");
        assert_eq!(read(&["absent", "fstab.emmc"]).len(), 1, "a table the phone keeps nowhere else is passed over");
        // A file that is there but cannot be read is a fault of the phone's,
        // not an absence: passing it over would leave a partition the
        // recovery goes on mounting from a table it never read.
        assert!(read_files(&given(&["fstab.mt6853/absent"])).is_err(), "a folder is no table");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_configuration_that_names_no_files_keeps_the_qualcomm_pair_and_the_first_call_wins() {
        // Which files to read is a fact of the whole run, held once. This is
        // the only test that gives any, so what it finds before its first
        // call is what every other test, and every phone whose configuration
        // names none, reads.
        assert_eq!(files(), FILES, "a phone that names nothing is read as it always was");
        let mt6853: Vec<String> = ["/vendor/etc/fstab.mt6853", "/vendor/etc/fstab.emmc"].map(str::to_string).into();
        set_files(&[]);
        assert_eq!(files(), FILES, "naming none changes nothing");
        set_files(&mt6853);
        assert_eq!(files(), mt6853, "the files a phone's configuration names are the ones read");
        set_files(&["/vendor/etc/fstab.qcom".to_string()]);
        assert_eq!(
            files(),
            mt6853,
            "a second call changes nothing: init starts the recovery service again after a failure, and the second run must read the tables the first did"
        );
    }

    #[test]
    fn what_a_mediatek_table_says_of_its_data_and_metadata_is_read_as_it_is() {
        // Cannon's own two lines, as its /vendor/etc/fstab.mt6853 keeps them.
        let table = "\
/dev/block/by-name/metadata /metadata ext4 noatime,nosuid,nodev,discard wait,check,formattable,first_stage_mount
/dev/block/by-name/userdata /data f2fs noatime,nosuid,nodev,discard,noflush_merge,fsync_mode=nobarrier,reserve_root=134217,resgid=1065,inlinecrypt wait,check,formattable,quota,reservedsize=128m,latemount,resize,checkpoint=fs,fileencryption=aes-256-xts:aes-256-cts:v1
";
        let [metadata, data] = &entries(table)[..] else { panic!("two lines, two entries") };
        assert_eq!(
            (metadata.mount_point.as_str(), metadata.filesystem.as_str()),
            ("/metadata", "ext4"),
            "erasing it makes what its own table says, not the f2fs a Qualcomm phone's table says"
        );
        assert_eq!((data.mount_point.as_str(), data.filesystem.as_str()), ("/data", "f2fs"));
        assert_eq!(data.extra("fileencryption"), Some("aes-256-xts:aes-256-cts:v1"));
        assert_eq!(data.extra("keydirectory"), None, "the files' names are encrypted by the filesystem itself");
        assert_eq!(data.extra("metadata_encryption"), None, "the phone's block device is not wrapped at all");
        assert!(data.options.iter().any(|o| o == "inlinecrypt"), "the kernel's inline encryption, not a dm-crypt layer");
    }
}

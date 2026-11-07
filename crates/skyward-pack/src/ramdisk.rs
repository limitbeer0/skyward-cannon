use anyhow::{bail, Context, Result};
use cpio::{NewcBuilder, NewcReader};
use std::io::{Cursor, Read, Write};

/// One cpio entry with the metadata the kernel restores when it unpacks the
/// archive into rootfs.
#[derive(Clone)]
pub struct Entry {
    pub name: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u32,
    pub nlink: u32,
    pub dev: (u32, u32),
    pub rdev: (u32, u32),
    pub data: Vec<u8>,
}

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

/// The permissions a stock ramdisk gives its links, such as the commands
/// in system/bin that stand for toybox.
const LINK_MODE: u32 = 0o755;

impl Entry {
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
}

/// How a ramdisk's bytes are held in an image, which a device's kernel decides
/// for itself: it unpacks an initramfs only with the decoders its own
/// `CONFIG_RD_*` options built in. A MediaTek kernel of 4.14 configured without
/// `CONFIG_RD_LZ4` refuses an LZ4 ramdisk outright and boots on nothing, so the
/// format belongs to the device rather than to the packer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Compression {
    /// gzip, `1f 8b 08`, what most MediaTek images carry and all that a kernel
    /// with only `CONFIG_RD_GZIP` can read.
    Gzip,
    /// LZ4 in the legacy framing AOSP's `mkbootimg` writes, which is what the
    /// kernel's `unlz4` reads; no other LZ4 framing is offered to a ramdisk.
    #[default]
    Lz4,
    /// The newc archive held as it is, which some bootloaders pass to the
    /// kernel directly.
    None,
}

const GZIP: [u8; 2] = [0x1f, 0x8b];
/// The magic of an LZ4 frame, `0x184D2204` written little-endian.
const LZ4_FRAME: [u8; 4] = [0x04, 0x22, 0x4d, 0x18];
/// The magic of an LZ4 stream in the legacy framing, `0x184C2102` written
/// little-endian.
const LZ4_LEGACY: [u8; 4] = [0x02, 0x21, 0x4c, 0x18];
/// What the first header of a newc archive is made of.
const NEWC: &[u8] = b"070701";

impl Compression {
    /// The format `ramdisk`'s bytes are in, read off the magic they start with.
    ///
    /// Nothing else tells which decoders a given stock image was built for, and
    /// guessing wrong costs a boot loop, so an archive that starts in no magic
    /// at all is reported rather than repacked: an image whose ramdisk section
    /// was read from the wrong offset looks exactly like a file of no known
    /// format, and writing a phone a boot loop over is a worse outcome than
    /// refusing to write one.
    pub fn sniff(ramdisk: &[u8]) -> Result<Self> {
        if ramdisk.starts_with(&GZIP) {
            Ok(Compression::Gzip)
        } else if ramdisk.starts_with(&LZ4_FRAME) || ramdisk.starts_with(&LZ4_LEGACY) {
            Ok(Compression::Lz4)
        } else if ramdisk.starts_with(NEWC) {
            Ok(Compression::None)
        } else {
            let head = match ramdisk.first() {
                Some(_) => ramdisk.iter().take(4).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
                None => "nothing".to_string(),
            };
            bail!("a ramdisk starting in {head} is in no format this packer writes")
        }
    }

    /// The name a command line and a device's configuration both spell.
    pub fn label(self) -> &'static str {
        match self {
            Compression::Gzip => "gzip",
            Compression::Lz4 => "lz4",
            Compression::None => "none",
        }
    }

    fn decode(self, ramdisk: &[u8]) -> Result<Vec<u8>> {
        let mut cpio = Vec::new();
        match self {
            Compression::Gzip => {
                flate2::read::GzDecoder::new(ramdisk).read_to_end(&mut cpio).context("gzip decode")?;
            }
            Compression::Lz4 => {
                // One reader takes both framings: `lz4_flex` tells a legacy
                // stream from a frame by its magic and reads either.
                lz4_flex::frame::FrameDecoder::new(ramdisk).read_to_end(&mut cpio).context("lz4 decode")?;
            }
            Compression::None => cpio.extend_from_slice(ramdisk),
        }
        Ok(cpio)
    }

    fn encode(self, cpio: &[u8]) -> Result<Vec<u8>> {
        match self {
            Compression::Gzip => {
                let mut ramdisk = Vec::new();
                // A ramdisk is decompressed into memory by the kernel before
                // anything runs, so it is packed for size; a recovery is read
                // once per boot and never in a hurry.
                let mut w = flate2::write::GzEncoder::new(&mut ramdisk, flate2::Compression::new(9));
                w.write_all(cpio).and_then(|()| w.finish()).context("gzip encode")?;
                Ok(ramdisk)
            }
            Compression::Lz4 => lz4_legacy(cpio),
            Compression::None => Ok(cpio.to_vec()),
        }
    }
}

/// An initramfs held in memory, so entries keep their owners, modes and
/// device numbers exactly as the archive had them.
pub struct Ramdisk {
    pub entries: Vec<Entry>,
    /// The format this archive was read out of, and so the format it goes back
    /// in unless the caller says the device's kernel reads another.
    pub compression: Compression,
}

impl Ramdisk {
    /// Unpack a newc archive, in whichever of the formats a device's image is
    /// found to hold it in.
    pub fn decode(ramdisk: &[u8]) -> Result<Self> {
        let compression = Compression::sniff(ramdisk)?;
        let cpio = compression.decode(ramdisk)?;
        let mut entries = Vec::new();
        let mut rest = Cursor::new(cpio.as_slice());
        loop {
            let mut r = NewcReader::new(rest).context("cpio entry")?;
            if r.entry().is_trailer() {
                break;
            }
            let e = r.entry();
            let mut entry = Entry {
                name: e.name().to_string(),
                mode: e.mode(),
                uid: e.uid(),
                gid: e.gid(),
                mtime: e.mtime(),
                nlink: e.nlink(),
                dev: (e.dev_major(), e.dev_minor()),
                rdev: (e.rdev_major(), e.rdev_minor()),
                data: Vec::with_capacity(e.file_size() as usize),
            };
            r.read_to_end(&mut entry.data).with_context(|| format!("cpio data of {}", entry.name))?;
            entries.push(entry);
            rest = r.finish().context("cpio entry end")?;
        }
        Ok(Ramdisk { entries, compression })
    }

    /// Pack in the format this archive came in.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.encode_as(self.compression)
    }

    /// Pack in a format of the caller's, for a device whose kernel reads fewer
    /// formats than the image it is built on came in.
    pub fn encode_as(&self, compression: Compression) -> Result<Vec<u8>> {
        let mut cpio = Vec::new();
        for (ino, e) in self.entries.iter().enumerate() {
            let size = u32::try_from(e.data.len()).with_context(|| format!("{} is too large", e.name))?;
            let mut w = NewcBuilder::new(&e.name)
                .ino(300_000 + ino as u32)
                .mode(e.mode)
                .uid(e.uid)
                .gid(e.gid)
                .mtime(e.mtime)
                .nlink(e.nlink)
                .dev_major(e.dev.0)
                .dev_minor(e.dev.1)
                .rdev_major(e.rdev.0)
                .rdev_minor(e.rdev.1)
                .write(&mut cpio, size);
            w.write_all(&e.data)?;
            w.finish()?;
        }
        cpio::newc::trailer(&mut cpio)?;
        compression.encode(&cpio)
    }

    pub fn find(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Replace a regular file's contents, keeping its owner and mode.
    pub fn replace(&mut self, name: &str, data: Vec<u8>) -> Result<()> {
        match self.entries.iter_mut().find(|e| e.name == name) {
            Some(e) if e.mode & S_IFMT == S_IFREG => {
                e.data = data;
                Ok(())
            }
            Some(_) => bail!("{name} is not a regular file"),
            None => bail!("{name} is not in the ramdisk"),
        }
    }

    /// Add a root-owned regular file, creating missing parent directories.
    pub fn add(&mut self, name: &str, mode: u32, data: Vec<u8>) -> Result<()> {
        self.insert(name, S_IFREG | mode, data)
    }

    /// Point `name` to `target`: a link already there is pointed anew, and
    /// otherwise a root-owned link is added, creating missing parent
    /// directories.
    pub fn link(&mut self, name: &str, target: &str) -> Result<()> {
        match self.entries.iter_mut().find(|e| e.name == name) {
            Some(e) if e.mode & S_IFMT == S_IFLNK => {
                e.data = target.as_bytes().to_vec();
                Ok(())
            }
            Some(_) => bail!("{name} is in the ramdisk and is not a link"),
            None => self.insert(name, S_IFLNK | LINK_MODE, target.as_bytes().to_vec()),
        }
    }

    fn insert(&mut self, name: &str, mode: u32, data: Vec<u8>) -> Result<()> {
        if self.find(name).is_some() {
            bail!("{name} is already in the ramdisk");
        }
        let parts: Vec<&str> = name.split('/').collect();
        let mut parent = String::new();
        for part in &parts[..parts.len() - 1] {
            if !parent.is_empty() {
                parent.push('/');
            }
            parent.push_str(part);
            match self.find(&parent) {
                Some(e) if e.is_dir() => {}
                Some(_) => bail!("{parent} is not a directory"),
                None => self.entries.push(root_entry(&parent, S_IFDIR | 0o755, Vec::new())),
            }
        }
        self.entries.push(root_entry(name, mode, data));
        Ok(())
    }
}

fn root_entry(name: &str, mode: u32, data: Vec<u8>) -> Entry {
    let nlink = if mode & S_IFMT == S_IFDIR { 2 } else { 1 };
    Entry { name: name.to_string(), mode, uid: 0, gid: 0, mtime: 0, nlink, dev: (0, 0), rdev: (0, 0), data }
}

/// How much of an archive one block of the legacy framing holds, which the
/// format fixes rather than records.
const LZ4_LEGACY_BLOCK: usize = 8 << 20;

/// Hold an archive in LZ4's legacy framing: the magic `0x184C2102` written
/// little-endian, then for each block of up to 8 MiB of the archive that
/// block's own length in bytes as a little-endian `u32` and then its LZ4
/// block. There is no frame descriptor, no block descriptor and no checksum
/// beside any of it, which is why the kernel reads one of these by taking a
/// length and a block in turn until the stream runs out.
///
/// `lz4_flex` reads this framing but writes none of it, and a ramdisk is not
/// something the packer can hand to a program the host is not allowed to
/// install, so the framing is written here. It has been checked against the
/// reference `lz4` 1.9.4 by feeding this function's output to `lz4 -d`: the
/// archive comes back byte for byte, which no amount of this module reading
/// its own writing would have proved.
fn lz4_legacy(archive: &[u8]) -> Result<Vec<u8>> {
    let mut ramdisk = Vec::with_capacity(LZ4_LEGACY.len() + archive.len() / 8);
    ramdisk.extend_from_slice(&LZ4_LEGACY);
    for block in archive.chunks(LZ4_LEGACY_BLOCK) {
        let compressed = lz4_flex::block::compress(block);
        // The length is a `u32` in the format, so a block that grew past it
        // would end the stream where the kernel reads a magic instead.
        let len = u32::try_from(compressed.len()).context("an lz4 block is unreportably large")?;
        ramdisk.extend_from_slice(&len.to_le_bytes());
        ramdisk.extend_from_slice(&compressed);
    }
    Ok(ramdisk)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(compression: Compression) -> Ramdisk {
        let mut rd = Ramdisk { entries: Vec::new(), compression };
        rd.add("system/bin/recovery", 0o750, b"binary".to_vec()).unwrap();
        rd.entries.push(Entry {
            name: "dev/console".into(),
            mode: 0o020600,
            uid: 0,
            gid: 0,
            mtime: 0,
            nlink: 1,
            dev: (0, 0),
            rdev: (5, 1),
            data: Vec::new(),
        });
        rd
    }

    #[test]
    fn round_trip_keeps_metadata() {
        for compression in [Compression::Gzip, Compression::Lz4, Compression::None] {
            let rd = sample(compression);
            let bytes = rd.encode().unwrap();
            assert_eq!(Compression::sniff(&bytes).unwrap(), compression, "what came back of {}", compression.label());
            let back = Ramdisk::decode(&bytes).unwrap();
            assert_eq!(back.compression, compression, "an archive is read as it was written");
            let names: Vec<&str> = back.entries.iter().map(|e| e.name.as_str()).collect();
            assert_eq!(names, ["system", "system/bin", "system/bin/recovery", "dev/console"]);
            let bin = back.find("system/bin/recovery").unwrap();
            assert_eq!((bin.mode, bin.data.as_slice()), (S_IFREG | 0o750, b"binary".as_slice()));
            assert_eq!(back.find("dev/console").unwrap().rdev, (5, 1));
        }
        let mut rd = sample(Compression::Lz4);
        assert!(rd.add("system/bin/recovery", 0o644, Vec::new()).is_err());
    }

    #[test]
    fn an_archive_spanning_two_blocks_comes_back_whole() {
        // Past one block of the legacy framing, of bytes too scattered for the
        // compressor to make much of, so that a stream the reader stopped at
        // the end of its first block would come back short rather than right.
        let data: Vec<u8> = (0..(LZ4_LEGACY_BLOCK + 4096)).map(|i| (i ^ (i >> 7) ^ (i >> 13)) as u8).collect();
        let rd = Ramdisk {
            entries: vec![Entry { name: "random".into(), mode: S_IFREG | 0o600, uid: 0, gid: 0, mtime: 0, nlink: 1, dev: (0, 0), rdev: (0, 0), data: data.clone() }],
            compression: Compression::Lz4,
        };
        let two_blocks = rd.encode().unwrap();
        assert!(two_blocks.len() > LZ4_LEGACY.len() + 8, "an archive of two blocks is not one");
        for (what, bytes) in [("lz4", two_blocks), ("gzip", rd.encode_as(Compression::Gzip).unwrap())] {
            let back = Ramdisk::decode(&bytes).unwrap();
            assert_eq!(back.entries.len(), 1, "{what}");
            assert_eq!(back.entries[0].data, data, "{what} lost the end of an archive over one block");
        }
    }

    #[test]
    fn a_legacy_stream_is_framed_as_the_format_says() {
        let archive = b"070701newc header of a file".to_vec();
        let stream = lz4_legacy(&archive).unwrap();
        assert_eq!(&stream[..4], &LZ4_LEGACY, "the magic, little-endian");
        let len = u32::from_le_bytes(stream[4..8].try_into().unwrap()) as usize;
        assert_eq!(stream.len(), 8 + len, "one block and nothing beside it, which is where a reader looks for the next");
        assert_eq!(&stream[8..], &lz4_flex::block::compress(&archive)[..], "the block is a plain LZ4 block, of no framing of its own");
        // The kernel reads a block's compressed size and no original size, so
        // a stream of an archive that fills no block at all holds its magic
        // and nothing else, which is what the reference tool writes for an
        // empty input and reads back as one.
        assert_eq!(lz4_legacy(b"").unwrap(), LZ4_LEGACY.to_vec());
    }

    #[test]
    fn each_formats_magic_is_told_from_the_others() {
        let (gzip, frame, legacy, newc) = (
            vec![0x1f, 0x8b, 0x08, 0x00],
            vec![0x04, 0x22, 0x4d, 0x18],
            vec![0x02, 0x21, 0x4c, 0x18],
            b"070701".to_vec(),
        );
        for (bytes, want) in [(&gzip, Compression::Gzip), (&frame, Compression::Lz4), (&legacy, Compression::Lz4), (&newc, Compression::None)] {
            assert_eq!(Compression::sniff(bytes).unwrap(), want, "of {}", Compression::label(Compression::sniff(bytes).unwrap()));
        }
        assert_ne!(LZ4_FRAME, LZ4_LEGACY, "a frame is not a legacy stream, though both are LZ4");
        assert!(Compression::sniff(b"AVBf").is_err(), "bytes of no format the packer knows");
        assert!(Compression::sniff(&[]).is_err(), "an empty section");
    }

    #[test]
    fn an_archive_is_read_back_from_a_stream_of_either_lz4_framing() {
        // `FrameDecoder` is the one reader both branches of `Compression::Lz4`
        // go through, so it is what has to tell a legacy stream from a frame
        // of the newer format without being told which it was handed.
        let archive = sample(Compression::Lz4).encode().unwrap();
        let mut frame = Vec::new();
        {
            use std::io::Write;
            let mut w = lz4_flex::frame::FrameEncoder::new(&mut frame);
            let cpio = Compression::Lz4.decode(&archive).unwrap();
            w.write_all(&cpio).unwrap();
            w.finish().unwrap();
        }
        assert_eq!(frame[..4], LZ4_FRAME, "the newer framing begins elsewhere");
        assert_eq!(Compression::sniff(&frame).unwrap(), Compression::Lz4);
        let from_frame = Ramdisk::decode(&frame).unwrap();
        let from_legacy = Ramdisk::decode(&archive).unwrap();
        assert_eq!(from_frame.entries.len(), from_legacy.entries.len());
        assert_eq!(from_frame.entries[2].data, from_legacy.entries[2].data);
    }

    #[test]
    fn a_link_is_kept_as_a_link_to_its_target() {
        let mut rd = Ramdisk { entries: Vec::new() };
        rd.add("system/bin/recovery", 0o750, b"binary".to_vec()).unwrap();
        rd.link("system/bin/zstd", "recovery").unwrap();
        rd.link("sbin/sh", "/system/bin/sh").unwrap();
        let back = Ramdisk::decode(&rd.encode().unwrap()).unwrap();
        let zstd = back.find("system/bin/zstd").unwrap();
        assert_eq!((zstd.mode, zstd.data.as_slice()), (S_IFLNK | LINK_MODE, b"recovery".as_slice()));
        assert_eq!((zstd.uid, zstd.gid, zstd.nlink), (0, 0, 1));
        assert!(back.find("sbin").is_some_and(Entry::is_dir), "a missing folder is made");
        assert!(rd.link("system/bin/recovery", "zstd").is_err(), "a file is no link to point anew");
        assert!(rd.link("system/bin/recovery/7za", "recovery").is_err(), "a file holds no links");
    }

    #[test]
    fn a_link_already_there_is_pointed_anew_keeping_the_rest_of_its_entry() {
        let mut rd = Ramdisk { entries: Vec::new() };
        rd.add("system/bin/ziptool", 0o755, b"binary".to_vec()).unwrap();
        rd.entries.push(Entry {
            name: "system/bin/unzip".into(),
            mode: S_IFLNK | 0o755,
            uid: 0,
            gid: 2000,
            mtime: 0,
            nlink: 1,
            dev: (0, 0),
            rdev: (0, 0),
            data: b"ziptool".to_vec(),
        });
        let count = rd.entries.len();
        rd.link("system/bin/unzip", "recovery").unwrap();
        let back = Ramdisk::decode(&rd.encode().unwrap()).unwrap();
        let unzip = back.find("system/bin/unzip").unwrap();
        assert_eq!((unzip.data.as_slice(), unzip.mode, unzip.gid), (b"recovery".as_slice(), S_IFLNK | 0o755, 2000));
        assert_eq!(back.entries.len(), count, "no second entry of the name");
        assert!(back.find("system/bin/ziptool").is_some(), "what it pointed to stays");
    }
}

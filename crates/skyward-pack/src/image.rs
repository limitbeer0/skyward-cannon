use abootimg_oxide::{binrw::io::Cursor, Header, HeaderV0, HeaderV0Versioned};
use anyhow::{anyhow, bail, Context, Result};
use sha2::Digest as _;
use std::fs;
use std::path::Path;

/// The digest a header holds over the sections that follow it.
///
/// Headers up to version 2 carry one, and a bootloader may refuse an image
/// whose sections no longer say what its digest was taken of. Replacing a
/// ramdisk makes a stock image's digest describe a section that is gone, so the
/// packer learns which of these two the image was built with and takes the same
/// one again over the sections it now holds. An image that says neither is left
/// saying what it did: an unlocked bootloader performs no such check, and
/// guessing at one this packer cannot see is worse than leaving it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Digest {
    Sha1,
    Sha256,
}

/// A boot or recovery image: its header and the sections it lays out after it.
///
/// Headers up to version 2 place the kernel, the ramdisk, the second bootloader
/// stage, the recovery DTBO and the device tree one after another; headers
/// version 3 and 4 place the kernel and the ramdisk only. The sections a
/// device's own image holds are kept exactly as they were read, because the
/// phone boots on them: only the ramdisk is replaced, and the layout is
/// recomputed from the parts the image holds now, so a ramdisk of another size
/// moves the sections after it and nothing a bootloader reads before them.
#[derive(Debug)]
pub struct BootImage {
    pub header: Header,
    pub kernel: Vec<u8>,
    pub ramdisk: Vec<u8>,
    /// The second bootloader stage, which only headers up to version 2 hold.
    pub second: Vec<u8>,
    /// The device-tree overlay a recovery applies, which headers version 1 and
    /// 2 hold after the second stage.
    pub recovery_dtbo: Vec<u8>,
    /// The device tree a header version 2 holds last, which is what the phone
    /// describes its board with as this recovery boots.
    pub dtb: Vec<u8>,
    digest: Option<Digest>,
}

fn section(bytes: &[u8], at: usize, len: u32, what: &str) -> Result<Vec<u8>> {
    let end = at + len as usize;
    bytes
        .get(at..end)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| anyhow!("{what} runs past the end of the image"))
}

/// The length `n` rounded up to a whole number of pages of `page` bytes.
fn align(n: usize, page: usize) -> usize {
    n.div_ceil(page) * page
}

/// The size a header names for its recovery DTBO, which a version 0 header has
/// no field for and so holds none of.
fn recovery_dtbo_size(header: &HeaderV0) -> u32 {
    match header.versioned {
        HeaderV0Versioned::V0 => 0,
        HeaderV0Versioned::V1 { recovery_dtbo_size, .. } | HeaderV0Versioned::V2 { recovery_dtbo_size, .. } => recovery_dtbo_size,
    }
}

/// The size a header names for its device tree, which only a version 2 header
/// has a field for: a version 1 header places one but says nothing of it, so
/// nothing is read of it or written back for it.
fn dtb_size(header: &HeaderV0) -> u32 {
    match header.versioned {
        HeaderV0Versioned::V2 { dtb_size, .. } => dtb_size,
        _ => 0,
    }
}

/// Where a header version 2's device tree lies, which is the next page after
/// the recovery DTBO it follows, or nowhere for the versions that hold none.
///
/// `HeaderV0::dtb_position` measures from where the second bootloader stage
/// begins rather than from where the DTBO does, so it puts the device tree
/// inside the DTBO of an image that holds a stage at all; a cannon image, whose
/// second bootloader is empty, is laid out the same by both. The format places
/// the five sections one page-aligned run after another, and the stock image
/// agrees: its device tree begins at the page after its DTBO, where this line
/// says, and holds what the phone's own overlay begins with.
fn dtb_position(header: &HeaderV0) -> Option<usize> {
    match header.versioned {
        HeaderV0Versioned::V2 { .. } => {
            Some(header.recovery_dtbo_position() + align(recovery_dtbo_size(header) as usize, header.page_size as usize))
        }
        _ => None,
    }
}

/// Take a section and the size of it into a digest, which is how AOSP takes the
/// digest a header holds: each size goes in after the bytes it counts, so that
/// an image cannot be made to describe itself by running two sections together.
fn digest_update<D: sha2::Digest>(hasher: &mut D, bytes: &[u8]) {
    hasher.update(bytes);
    hasher.update((bytes.len() as u32).to_le_bytes());
}

impl BootImage {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        Self::from_bytes(&bytes).map_err(|e| anyhow!("{}: {e}", path.display()))
    }

    /// The image `bytes` holds, laid out by its own header.
    ///
    /// Whatever lies past the length the header makes is no part of the image:
    /// a phone's recovery partition is of a size set at the factory and ends in
    /// the AVB footer that describes the image before it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let header = Header::parse(&mut Cursor::new(bytes)).context("header")?;
        // Every offset below is reached by rounding a size up to a page, so a
        // header that names no page size lays out no image at all.
        if header.page_size() == 0 {
            bail!("the header names a page size of 0, which lays out nothing");
        }
        let (kernel, ramdisk) = (
            section(bytes, header.kernel_position(), header.kernel_size(), "kernel")?,
            section(bytes, header.ramdisk_position(), header.ramdisk_size(), "ramdisk")?,
        );
        let (second, recovery_dtbo, dtb) = match &header {
            Header::V3(_) => (Vec::new(), Vec::new(), Vec::new()),
            Header::V0(h) => (
                section(bytes, h.second_bootloader_position(), h.second_bootloader_size, "second bootloader")?,
                section(bytes, h.recovery_dtbo_position(), recovery_dtbo_size(h), "recovery dtbo")?,
                match dtb_position(h) {
                    Some(at) => section(bytes, at, dtb_size(h), "dtb")?,
                    None => Vec::new(),
                },
            ),
        };
        let mut image = BootImage { header, kernel, ramdisk, second, recovery_dtbo, dtb, digest: None };
        image.digest = image.digest_found();
        Ok(image)
    }

    /// Which of the two digests AOSP takes over an image's sections the header
    /// holds, by taking each of them over the sections just read.
    ///
    /// An image of no sections at all is left saying nothing, because a header
    /// with nothing to describe holds whatever its maker wrote into it rather
    /// than a digest of them.
    fn digest_found(&self) -> Option<Digest> {
        let Header::V0(h) = &self.header else { return None };
        if self.sections().iter().all(|bytes| bytes.is_empty()) {
            return None;
        }
        [Digest::Sha1, Digest::Sha256].into_iter().find(|kind| self.digest_of(*kind) == h.hash_digest)
    }

    /// The sections a header's digest is taken over, in the order the format
    /// lays them out.
    fn sections(&self) -> [&[u8]; 5] {
        [&self.kernel, &self.ramdisk, &self.second, &self.recovery_dtbo, &self.dtb]
    }

    /// The digest `kind` takes over the image's sections, padded to the 32
    /// bytes a header holds it in, which is how AOSP leaves the rest of a
    /// SHA-1 one.
    fn digest_of(&self, kind: Digest) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        match kind {
            Digest::Sha1 => {
                let mut hasher = sha1::Sha1::default();
                for section in self.sections() {
                    digest_update(&mut hasher, section);
                }
                let digest = hasher.finalize();
                bytes[..digest.len()].copy_from_slice(&digest);
            }
            Digest::Sha256 => {
                let mut hasher = sha2::Sha256::default();
                for section in self.sections() {
                    digest_update(&mut hasher, section);
                }
                bytes.copy_from_slice(&hasher.finalize());
            }
        }
        bytes
    }

    /// The parts the image writes, each with the place its header gives it.
    fn parts(&self, header: &Header) -> Vec<(&[u8], usize)> {
        match header {
            Header::V3(_) => vec![(self.kernel.as_slice(), header.kernel_position()), (self.ramdisk.as_slice(), header.ramdisk_position())],
            Header::V0(h) => {
                let mut parts = vec![
                    (self.kernel.as_slice(), h.kernel_position()),
                    (self.ramdisk.as_slice(), h.ramdisk_position()),
                    (self.second.as_slice(), h.second_bootloader_position()),
                    (self.recovery_dtbo.as_slice(), h.recovery_dtbo_position()),
                ];
                // A version 1 header places a device tree but names no size for
                // it, and a version 0 header places none at all; either way
                // there is nothing to write where one would have been.
                if let Some(at) = dtb_position(h) {
                    parts.push((self.dtb.as_slice(), at));
                }
                parts
            }
        }
    }

    /// The image with its sizes taken from the parts it holds now. A version 4
    /// header keeps its version but carries no boot signature; unlocked
    /// bootloaders do not ask for one.
    ///
    /// The bytes come out dense, and of one length for one set of parts,
    /// because a recovery is grown from these to fill its whole partition and
    /// then given the AVB footer that describes an image by its length and its
    /// digest: an image padded to another page size would describe itself
    /// falsely there.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut header = self.header.clone();
        let size = |bytes: &[u8], what: &str| u32::try_from(bytes.len()).with_context(|| format!("the {what} is too large to name"));
        match &mut header {
            Header::V3(h) => {
                for (bytes, what) in [(&self.second, "second bootloader"), (&self.recovery_dtbo, "recovery dtbo"), (&self.dtb, "dtb")] {
                    if !bytes.is_empty() {
                        bail!("a header of version {} holds no {what}", h.header_version());
                    }
                }
                h.kernel_size = size(&self.kernel, "kernel")?;
                h.ramdisk_size = size(&self.ramdisk, "ramdisk")?;
                h.v4_signature_size = h.v4_signature_size.map(|_| 0);
            }
            Header::V0(h) => {
                let (dtbo, dtb) = (size(&self.recovery_dtbo, "recovery dtbo")?, size(&self.dtb, "dtb")?);
                match &mut h.versioned {
                    HeaderV0Versioned::V0 => {
                        // A version 0 header lays out no room for either, so
                        // writing them would only move where the image ends.
                        if dtbo != 0 || dtb != 0 {
                            bail!("a header of version 0 holds neither a recovery dtbo nor a dtb");
                        }
                    }
                    HeaderV0Versioned::V1 { recovery_dtbo_size, .. } => *recovery_dtbo_size = dtbo,
                    HeaderV0Versioned::V2 { recovery_dtbo_size, dtb_size, .. } => {
                        *recovery_dtbo_size = dtbo;
                        *dtb_size = dtb;
                    }
                }
                h.kernel_size = size(&self.kernel, "kernel")?;
                h.ramdisk_size = size(&self.ramdisk, "ramdisk")?;
                h.second_bootloader_size = size(&self.second, "second bootloader")?;
                if let Some(kind) = self.digest {
                    h.hash_digest = self.digest_of(kind);
                }
            }
        }
        // The page size a header names is its own and is unchanged by a repack,
        // and the parts are placed from the header's sizes after those have been
        // written back into it just above, so one layout serves both.
        let page = self.page_size();
        let parts = self.parts(&header);
        let mut out = Vec::new();
        header.write(&mut out).context("write header")?;
        // Each part begins on a page of the image's own size, which is 2048 on
        // a MediaTek device of this age and not the 4096 a version 3 header
        // always uses. The space between the header and the kernel, and between
        // one part and the next, is held as zeros rather than as whatever a
        // bootloader that reads nothing but the section sizes would never see.
        let end = parts.iter().fold(out.len(), |end, (bytes, at)| end.max(at + bytes.len()));
        out.resize(align(end, page), 0);
        for (bytes, at) in parts {
            out[at..at + bytes.len()].copy_from_slice(bytes);
        }
        Ok(out)
    }

    /// The page size the image lays its sections out in, which a caller that
    /// grows an image to fill a partition rounds up by.
    pub fn page_size(&self) -> usize {
        self.header.page_size()
    }

    pub fn header_version(&self) -> u32 {
        self.header.header_version()
    }

    /// The size a header names for each of its sections, which a listing of an
    /// image reports beside the bytes actually read of it, so that a header that
    /// lies about its own image is seen to lie.
    pub fn named_sizes(&self) -> Vec<(&'static str, u32)> {
        match &self.header {
            Header::V3(h) => vec![("kernel", h.kernel_size), ("ramdisk", h.ramdisk_size)],
            Header::V0(h) => vec![
                ("kernel", h.kernel_size),
                ("ramdisk", h.ramdisk_size),
                ("second bootloader", h.second_bootloader_size),
                ("recovery dtbo", recovery_dtbo_size(h)),
                ("dtb", dtb_size(h)),
            ],
        }
    }

    /// Which of the two digests a header was built with, if either, which a
    /// listing says: an image carrying no digest the packer can recompute is one
    /// the packer leaves as it was written.
    pub fn digest_kind(&self) -> Option<&'static str> {
        self.digest.map(|kind| match kind {
            Digest::Sha1 => "sha1",
            Digest::Sha256 => "sha256",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The size of the headers a standard image is read with, which is where
    /// each of them puts the section sizes that follow.
    const V0_HEAD: usize = 1632;
    const V1_HEAD: usize = 1648;
    const V2_HEAD: usize = 1660;
    const V3_HEAD: usize = 1580;

    /// The fields of a header version 0 through 2, by the offsets they hold
    /// after the magic these fixtures begin with.
    const V0_KERNEL_SIZE: usize = 8;
    const V0_RAMDISK_SIZE: usize = 16;
    const V0_SECOND_SIZE: usize = 24;
    const V0_PAGE_SIZE: usize = 36;
    const V0_VERSION: usize = 40;
    const V0_DTBO_SIZE: usize = 1632;
    const V0_HEADER_SIZE: usize = 1644;
    const V0_DTB_SIZE: usize = 1648;
    /// The stock image's digest, which follows the command line.
    const V0_HASH: usize = 576;
    /// The fields of a header version 3 and 4, which names no page size.
    const V3_KERNEL_SIZE: usize = 8;
    const V3_RAMDISK_SIZE: usize = 12;
    const V3_HEADER_SIZE: usize = 20;
    const V3_VERSION: usize = 40;

    fn put(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// The sizes the stock cannon image names for its five sections, which is
    /// what a test of this module is really about: sizes that end off a page
    /// boundary, so that the padding between one part and the next is what is
    /// being checked rather than the absence of any. The device holds no second
    /// bootloader stage, and its recovery DTBO sits three pages from a
    /// megabyte-and-a-half of kernel and one and a half of ramdisk.
    const KERNEL: usize = 17_436_597;
    const RAMDISK: usize = 16_038_582;
    const DTBO: usize = 78_798;
    const DTB: usize = 165_760;

    /// The parts of a stock image, each filled with a byte of its own so that
    /// the zeros around a part cannot be read as part of it, and so that one
    /// part cannot be mistaken for another that was moved in its place.
    fn parts() -> [Vec<u8>; 5] {
        [vec![0xAA; KERNEL], vec![0xBB; RAMDISK], Vec::new(), vec![0xD7; DTBO], vec![0x0D; DTB]]
    }

    /// An image whose header names the parts given and lays them out in the page
    /// size and header version given. The header is written as the format's own
    /// bytes, not through the parser, so that reading one back tests the parser
    /// rather than agreeing with it.
    fn image(parts: &[Vec<u8>], page: u32, version: u32) -> Vec<u8> {
        let head = match version {
            0 => V0_HEAD,
            1 => V1_HEAD,
            2 => V2_HEAD,
            _ => V3_HEAD,
        };
        let mut header = vec![0u8; head];
        header[..8].copy_from_slice(b"ANDROID!");
        match version {
            3 | 4 => {
                put(&mut header, V3_KERNEL_SIZE, parts[0].len() as u32);
                put(&mut header, V3_RAMDISK_SIZE, parts[1].len() as u32);
                put(&mut header, V3_HEADER_SIZE, head as u32);
                put(&mut header, V3_VERSION, version);
            }
            _ => {
                put(&mut header, V0_KERNEL_SIZE, parts[0].len() as u32);
                put(&mut header, V0_RAMDISK_SIZE, parts[1].len() as u32);
                put(&mut header, V0_SECOND_SIZE, parts[2].len() as u32);
                put(&mut header, V0_PAGE_SIZE, page);
                put(&mut header, V0_VERSION, version);
                if version > 0 {
                    put(&mut header, V0_DTBO_SIZE, parts[3].len() as u32);
                    put(&mut header, V0_HEADER_SIZE, head as u32);
                }
                if version == 2 {
                    put(&mut header, V0_DTB_SIZE, parts[4].len() as u32);
                }
            }
        }
        let mut out = vec![0u8; page as usize];
        out[..head].copy_from_slice(&header);
        for part in parts {
            out.resize(align(out.len(), page as usize), 0);
            out.extend_from_slice(part);
        }
        out.resize(align(out.len(), page as usize), 0);
        out
    }

    /// A stock image of everything its header holds, of a 2 KiB page.
    fn stock() -> (Vec<u8>, [Vec<u8>; 5]) {
        let parts = parts();
        (image(&parts, 2048, 2), parts)
    }

    /// Say that two of a stock image's megabyte-sized parts are the same,
    /// without printing either of them: what an image that differs says is
    /// where the first byte of difference is, which is the only fact a test of
    /// seventeen megabytes can report and have a person read.
    #[track_caller]
    fn same(what: &str, got: &[u8], want: &[u8], why: &str) {
        assert_eq!(got.len(), want.len(), "{what} is of another length, {why}");
        if let Some(at) = got.iter().zip(want).position(|(a, b)| a != b) {
            let (a, b) = (got[at], want[at]);
            panic!("{what} differs at byte {at}: {a:02x} rather than {b:02x}, {why}");
        }
    }

    /// As `same`, for the parts of an image read back whole.
    #[track_caller]
    fn whole(img: &BootImage, parts: &[Vec<u8>; 5]) {
        same("kernel", &img.kernel, &parts[0], "of a stock image read back");
        same("ramdisk", &img.ramdisk, &parts[1], "of a stock image read back");
        same("second bootloader", &img.second, &parts[2], "of a stock image read back");
        same("recovery dtbo", &img.recovery_dtbo, &parts[3], "of a stock image read back");
        same("dtb", &img.dtb, &parts[4], "of a stock image read back");
    }

    #[test]
    fn a_version_two_image_of_a_two_kib_page_is_read_whole() {
        let (bytes, parts) = stock();
        let img = BootImage::from_bytes(&bytes).unwrap();
        assert_eq!(img.header_version(), 2);
        assert_eq!(img.page_size(), 2048);
        whole(&img, &parts);
        assert_eq!(
            img.named_sizes(),
            [("kernel", KERNEL as u32), ("ramdisk", RAMDISK as u32), ("second bootloader", 0), ("recovery dtbo", DTBO as u32), ("dtb", DTB as u32)]
        );
        // The offsets the image is read at, from its own page size of 2048 and
        // not from the 4096 a version 3 header always uses. These are the
        // places the stock image's own sections were found at.
        let Header::V0(h) = &img.header else { panic!("a version 2 header is read as one") };
        assert_eq!((h.kernel_position(), h.ramdisk_position()), (2048, 17_438_720));
        assert_eq!((h.second_bootloader_position(), h.recovery_dtbo_position()), (33_478_656, 33_478_656));
        assert_eq!(dtb_position(h), Some(33_558_528));
        assert_eq!(h.boot_image_size(), bytes.len(), "the header's own length is the fixture's");
        // Nothing of an image written back as it stands is moved.
        assert_eq!(img.to_bytes().unwrap().len(), bytes.len());
        same("round trip", &img.to_bytes().unwrap(), &bytes, "an image read and written back");
    }

    /// The kernel is read where the two pages before it and its own odd size
    /// put it, and the recovery DTBO where the kernel and the ramdisk before it
    /// put it.
    #[test]
    fn the_parts_untouched_by_a_repack_are_unchanged_by_it() {
        let (stock, parts) = stock();
        let mut img = BootImage::from_bytes(&stock).unwrap();
        // A ramdisk of another size, so that every part after it is written at
        // another place and has to be read back from that place.
        img.ramdisk = vec![0x1f; parts[1].len() - 4096];
        let out = img.to_bytes().unwrap();
        let back = BootImage::from_bytes(&out).unwrap();
        same("kernel", &back.kernel, &parts[0], "a phone boots on the kernel it came with");
        same("dtbo", &back.recovery_dtbo, &parts[3], "the recovery applies the overlay it came with");
        same("dtb", &back.dtb, &parts[4], "the board is described by the tree it came with");
        same("ramdisk", &back.ramdisk, &img.ramdisk, "and the replacement is read back where it was written");
    }

    /// A part read from where an image of another size holds it, which is the
    /// whole point of laying the image out again rather than writing over the
    /// stock bytes: a recovery whose DTBO moved keeps its DTBO's contents.
    #[test]
    fn a_part_is_read_from_where_an_image_holds_it_not_where_it_was_written() {
        let (bytes, parts) = stock();
        let mut img = BootImage::from_bytes(&bytes).unwrap();
        let Header::V0(h) = &img.header else { panic!("a version 2 header is read as one") };
        same("dtbo in place", &bytes[h.recovery_dtbo_position()..][..parts[3].len()], &parts[3], "the fixture holds it there");
        img.ramdisk = vec![0xBB; parts[1].len() + 2048];
        let out = img.to_bytes().unwrap();
        let Header::V0(moved) = &BootImage::from_bytes(&out).unwrap().header else { panic!("a version 2 header is read as one") };
        assert_eq!(moved.recovery_dtbo_position(), h.recovery_dtbo_position() + 2048, "one page further on");
        assert_ne!(moved.recovery_dtbo_position(), h.recovery_dtbo_position(), "the stock place holds the ramdisk's last page now");
        same("dtbo moved", &out[moved.recovery_dtbo_position()..][..parts[3].len()], &parts[3], "one page further on");
    }

    /// The stock image's own device tree follows its recovery DTBO rather than
    /// the second bootloader stage before that.
    ///
    /// `HeaderV0::dtb_position` of abootimg-oxide 0.5.2 measures from where the
    /// stage begins rather than from where the DTBO does, and so places the
    /// device tree inside the DTBO of any image that holds a stage at all.
    /// Cannon holds none, which is why the two agree on that image and why
    /// nothing but an image of a stage of its own finds the difference; it is
    /// kept as a test because an image is read by these lines and not by the
    /// stock image's own luck.
    #[test]
    fn a_device_tree_follows_the_overlay_a_second_stage_is_between_them_not_the_other_way_round() {
        let parts = [vec![0xAA; 100], vec![0xBB; 50], vec![0xCC; 3000], vec![0xD7; 4000], vec![0x0D; 20]];
        let bytes = image(&parts, 2048, 2);
        let img = BootImage::from_bytes(&bytes).unwrap();
        let Header::V0(h) = &img.header else { panic!("a version 2 header is read as one") };
        let at = dtb_position(h).unwrap();
        assert_eq!(h.dtb_position(), Some(h.second_bootloader_position() + align(4000, 2048)), "the library's own place");
        assert_eq!(at, h.recovery_dtbo_position() + align(4000, 2048), "the place the format lays out");
        assert_ne!(h.dtb_position(), Some(at), "which differ once a second bootloader is between them");
        same("dtb", &img.dtb, &parts[4], "and the image is read from the place that holds the tree");
        assert_eq!(img.to_bytes().unwrap(), bytes, "and written back to it");
    }

    /// An empty header of either kind is an image of one page, and a page of
    /// zeros follows: nezha and ishtar hold a kernel and a ramdisk of a size
    /// the header names, and the packer has to be able to hold nothing too.
    #[test]
    fn a_version_three_image_is_laid_out_as_it_always_was() {
        let parts = [vec![0xAA; 5000], vec![0xBB; 4000], Vec::new(), Vec::new(), Vec::new()];
        let bytes = image(&parts, 4096, 3);
        let img = BootImage::from_bytes(&bytes).unwrap();
        assert_eq!(img.header_version(), 3);
        assert_eq!(img.page_size(), 4096);
        assert_eq!(img.named_sizes(), [("kernel", 5000), ("ramdisk", 4000)]);
        assert!(img.second.is_empty() && img.recovery_dtbo.is_empty() && img.dtb.is_empty());
        assert_eq!(img.to_bytes().unwrap(), bytes);
        assert_eq!(img.digest_kind(), None, "a version 3 header holds no digest to find");
        // An image of nothing at all is one page of a header and no part after
        // it, which is what a caller repacking an image of no kernel holds.
        let empty = image(&[Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()], 4096, 3);
        let out = BootImage::from_bytes(&empty).unwrap().to_bytes().unwrap();
        assert_eq!(out, empty, "which round-trips to one page");
        assert_eq!(out.len(), 4096);
    }

    #[test]
    fn a_digest_an_image_was_built_with_is_taken_again_after_a_repack() {
        let (mut bytes, parts) = stock();
        // The digest AOSP takes over the sections a version 2 header lays out,
        // which is what a stock image of a recovery holds.
        let mut hasher = sha1::Sha1::default();
        for section in &parts {
            digest_update(&mut hasher, section);
        }
        let digest = hasher.finalize();
        bytes[V0_HASH..V0_HASH + digest.len()].copy_from_slice(&digest);
        let mut img = BootImage::from_bytes(&bytes).unwrap();
        assert_eq!(img.digest_kind(), Some("sha1"), "the digest the image was built with is recognised");
        img.ramdisk = vec![0x1f, 0x8b, 0x08];
        let out = img.to_bytes().unwrap();
        let back = BootImage::from_bytes(&out).unwrap();
        assert_eq!(back.digest_kind(), Some("sha1"), "the repacked image is still described the same way");
        let Header::V0(h) = &back.header else { panic!("a version 2 header is read as one") };
        let mut hasher = sha1::Sha1::default();
        for section in back.sections() {
            digest_update(&mut hasher, section);
        }
        let now = hasher.finalize();
        assert_eq!(h.hash_digest[..now.len()], now[..], "the digest describes the sections that are there now");
        assert_ne!(h.hash_digest[..now.len()], digest[..], "the stock one would have described a ramdisk that is gone");
    }

    #[test]
    fn a_digest_of_neither_kind_is_left_as_the_image_said_it() {
        let (bytes, _) = stock();
        let img = BootImage::from_bytes(&bytes).unwrap();
        assert_eq!(img.digest_kind(), None, "a header digesting to neither of these is not corrected by guessing");
        assert_eq!(img.to_bytes().unwrap(), bytes, "and the image is written back as it was read");
    }

    #[test]
    fn a_part_a_header_holds_no_room_for_is_refused_rather_than_dropped() {
        let mut img = BootImage::from_bytes(&image(&[vec![1; 10], b"ramdisk".to_vec(), Vec::new(), Vec::new(), Vec::new()], 4096, 3)).unwrap();
        img.dtb = vec![9; 4];
        assert!(img.to_bytes().unwrap_err().to_string().contains("holds no dtb"));
        // A version 0 header lays out no room for a DTBO or a device tree, so a
        // part of either is refused rather than written past the image's end.
        let mut img = BootImage::from_bytes(&image(&[vec![1; 10], b"ramdisk".to_vec(), Vec::new(), Vec::new(), Vec::new()], 4096, 0)).unwrap();
        assert_eq!(img.header_version(), 0);
        img.recovery_dtbo = vec![9; 4];
        assert!(img.to_bytes().unwrap_err().to_string().contains("neither a recovery dtbo nor a dtb"));
    }

    #[test]
    fn a_header_of_no_page_size_is_refused_before_anything_divides_by_it() {
        let (mut bytes, _) = stock();
        put(&mut bytes, V0_PAGE_SIZE, 0);
        assert!(BootImage::from_bytes(&bytes).unwrap_err().to_string().contains("page size of 0"));
    }

    #[test]
    fn a_part_past_the_end_of_the_image_is_named_as_the_part_it_is() {
        let (bytes, parts) = stock();
        // A header that still says where its kernel ends, past what is left of
        // an image written over the start of the partition.
        let mut short = bytes[..bytes.len() - 2048].to_vec();
        put(&mut short, V0_KERNEL_SIZE, 100_000_000);
        assert!(BootImage::from_bytes(&short).unwrap_err().to_string().contains("kernel runs past"));
        put(&mut short, V0_KERNEL_SIZE, parts[0].len() as u32);
        put(&mut short, V0_DTB_SIZE, 100_000_000);
        assert!(BootImage::from_bytes(&short).unwrap_err().to_string().contains("dtb runs past"));
    }

    /// An image of a ramdisk that stops mid-page is padded out with zeros to
    /// the page its own header names, and the page after it is where the next
    /// section begins: an image padded out by another page size would put its
    /// sections where its own header says they are not.
    #[test]
    fn the_space_between_two_parts_is_the_rest_of_the_page_the_header_names() {
        let (bytes, parts) = stock();
        let mut img = BootImage::from_bytes(&bytes).unwrap();
        img.ramdisk = vec![0x1f, 0x8b];
        let out = img.to_bytes().unwrap();
        let Header::V0(h) = &BootImage::from_bytes(&out).unwrap().header else { panic!("a version 2 header is read as one") };
        assert_eq!(h.ramdisk_position(), align(h.kernel_position() + parts[0].len(), 2048));
        assert_eq!(&out[h.ramdisk_position()..][..2], [0x1f, 0x8b], "the archive is read from where the header says");
        assert!(out[h.ramdisk_position() + 2..h.second_bootloader_position()].iter().all(|b| *b == 0), "and the rest of its page is zeros");
        assert_eq!(h.second_bootloader_position(), h.ramdisk_position() + 2048, "a part of two bytes takes one page of 2048");
        assert_eq!(out.len() % 2048, 0, "and the image ends on one");
        assert_eq!(align(3001, 2048), 4096, "a part of 3001 bytes takes two pages");
    }
}

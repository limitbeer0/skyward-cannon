//! The AES-GCM operation used by Android's hardware-wrapped storage keys.
use crate::keystore::Decryptor;
use anyhow::{ensure, Context, Result};
use skyward_binder::driver::{Binder, Handle};
use skyward_binder::hidl::{self, Answer, Message};

const INTERFACE: &str = "android.hardware.keymaster@4.0::IKeymasterDevice";
const SERVICE: &str = "android.hardware.keymaster@4.1::IKeymasterDevice";
const BEGIN: u32 = 16;
const UPDATE: u32 = 17;
const FINISH: u32 = 18;
const ABORT: u32 = 19;

const DECRYPT: u32 = 1;
const BLOCK_MODE: u32 = 0x2000_0004;
const PADDING: u32 = 0x2000_0006;
const MAC_LENGTH: u32 = 0x3000_03eb;
const APPLICATION_ID: u32 = 0x9000_0259;
const NONCE: u32 = 0x9000_03e9;
const GCM: u32 = 32;
const NO_PADDING: u32 = 1;
const PARAMETER_BYTES: usize = 32;
const PARAMETER_BLOB: usize = 16;

pub struct Keymaster<'a>(Handle<'a>);

impl<'a> Keymaster<'a> {
    pub fn open(binder: &'a Binder) -> Result<Self> {
        hidl::find(binder, SERVICE, "default")?
            .map(Self)
            .context("Keymaster 4.1 is not registered")
    }

    fn begin(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8]) -> Result<u64> {
        let values = [(BLOCK_MODE, GCM), (PADDING, NO_PADDING), (MAC_LENGTH, 128), (APPLICATION_ID, 0), (NONCE, 0)];
        let mut parameters = [0u8; 5 * PARAMETER_BYTES];
        for (entry, (tag, value)) in parameters.chunks_exact_mut(PARAMETER_BYTES).zip(values) {
            entry[..4].copy_from_slice(&tag.to_le_bytes());
            entry[8..12].copy_from_slice(&value.to_le_bytes());
        }
        // HIDL serializes the blob field of every KeyParameter, including
        // the empty ones used for scalar parameters.
        let blobs = [&[][..], &[], &[], app_id, nonce];
        let children = blobs.each_ref().map(|blob| (*blob, blob.len()));
        let vectors = std::array::from_fn::<_, 5, _>(|i| {
            (i * PARAMETER_BYTES + PARAMETER_BLOB, children[i].0, children[i].1)
        });
        let mut call = Message::call(INTERFACE);
        call.u32(DECRYPT);
        call.bytes(key_blob);
        call.structures(&parameters, values.len(), &vectors);
        call.structure(&[0; 56], &[(40, &[], 0)]);
        let reply = self.0.transact(BEGIN, &call).context("start Keymaster AES-GCM decryption")?;
        let mut read = checked(reply.bytes(), "begin")?;
        read.empty_vector()?;
        read.u64()
    }

    fn finish(&self, operation: u64, body: &[u8]) -> Result<Vec<u8>> {
        let mut call = Message::call(INTERFACE);
        call.u64(operation);
        call.bytes(&[]); // operation parameters
        call.bytes(body);
        call.bytes(&[]); // signature
        call.structure(&[0; 56], &[(40, &[], 0)]);
        call.structure(&[0; 56], &[(16, &[], 0), (40, &[], 0)]);
        let reply = self.0.transact(FINISH, &call).context("finish Keymaster AES-GCM decryption")?;
        let mut read = checked(reply.bytes(), "finish")?;
        read.empty_vector()?;
        Ok(read.bytes()?.to_vec())
    }

    fn decrypt(&self, operation: u64, mut sealed: &[u8]) -> Result<Vec<u8>> {
        let mut plaintext = Vec::new();
        while !sealed.is_empty() {
            let mut call = Message::call(INTERFACE);
            call.u64(operation);
            call.bytes(&[]); // operation parameters
            call.bytes(sealed);
            call.structure(&[0; 56], &[(40, &[], 0)]);
            call.structure(&[0; 56], &[(16, &[], 0), (40, &[], 0)]);
            let reply = self.0.transact(UPDATE, &call).context("send ciphertext to Keymaster")?;
            let mut read = checked(reply.bytes(), "update")?;
            let consumed = read.i32()? as usize;
            ensure!((1..=sealed.len()).contains(&consumed), "Keymaster returned an invalid consumed byte count");
            read.empty_vector()?;
            plaintext.extend_from_slice(read.bytes()?);
            sealed = &sealed[consumed..];
        }
        // Return plaintext only after the HAL authenticates the GCM tag.
        plaintext.extend(self.finish(operation, &[])?);
        Ok(plaintext)
    }
}

impl Decryptor for Keymaster<'_> {
    fn gcm_decrypt(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], body: &[u8]) -> Result<Vec<u8>> {
        // Android 12's KeyMint compatibility layer adds an origin marker
        // to the blob it returns to vold. The HIDL HAL expects the inner blob.
        let key_blob = if let Some(prefixed) = key_blob.strip_prefix(b"pKMblob") {
            let (&origin, blob) = prefixed.split_first().context("missing KeyMint blob origin")?;
            ensure!(origin == 0, "the KeyMint compatibility blob is not a hardware key");
            ensure!(!blob.is_empty(), "the KeyMint compatibility blob is empty");
            blob
        } else {
            key_blob
        };
        let operation = self.begin(key_blob, app_id, nonce)?;
        let result = self.decrypt(operation, body);
        if result.is_err() {
            let mut abort = Message::call(INTERFACE);
            abort.u64(operation);
            let _ = self.0.transact(ABORT, &abort);
        }
        result
    }
}

fn checked<'a>(bytes: &'a [u8], operation: &str) -> Result<Answer<'a>> {
    let mut read = Answer::new(bytes);
    read.status()?;
    let code = read.i32()?;
    let detail = match code {
        -26 => " (KEY_USER_NOT_AUTHENTICATED)",
        -30 => " (VERIFICATION_FAILED)",
        -33 => " (INVALID_KEY_BLOB)",
        -62 => " (KEY_REQUIRES_UPGRADE)",
        _ => "",
    };
    ensure!(code == 0, "Keymaster {operation} returned {code}{detail}");
    Ok(read)
}

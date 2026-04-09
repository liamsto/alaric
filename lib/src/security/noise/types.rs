/* ---------------------------------------------------------------- *
 * TYPES                                                            *
 * ---------------------------------------------------------------- */
use super::{
    consts::{DHLEN, EMPTY_KEY, HASHLEN, MAX_NONCE, forbidden_curve_values},
    error::NoiseError,
};
use constant_time_eq::constant_time_eq;
use hacl_star::curve25519;
use rand;
use zeroize::Zeroize;

fn decode_str_32(s: &str) -> Result<[u8; DHLEN], NoiseError> {
    if let Ok(x) = hex::decode(s) {
        if x.len() == DHLEN {
            let mut temp: [u8; DHLEN] = [0_u8; DHLEN];
            temp.copy_from_slice(&x[..]);
            Ok(temp)
        } else {
            Err(NoiseError::InvalidInputError)
        }
    } else {
        Err(NoiseError::InvalidInputError)
    }
}

#[derive(Clone)]
pub(crate) struct Hash {
    h: [u8; HASHLEN],
}
impl Hash {
    pub(crate) fn clear(&mut self) {
        self.h.zeroize();
    }
    pub(crate) const fn from_bytes(hash: [u8; HASHLEN]) -> Self {
        Self { h: hash }
    }
    pub(crate) const fn as_bytes(&self) -> [u8; DHLEN] {
        self.h
    }
    pub(crate) const fn new() -> Self {
        Self::from_bytes([0_u8; HASHLEN])
    }
}

#[derive(Clone, Default)]
pub struct Key {
    k: [u8; DHLEN],
}
impl Key {
    pub(crate) fn clear(&mut self) {
        self.k.zeroize();
    }
    /// Instanciates a new empty `Key`.
    #[must_use]
    pub const fn new() -> Self {
        Self::from_bytes(EMPTY_KEY)
    }
    /// Instanciates a new `Key` from an array of `DHLEN` bytes.
    #[must_use]
    pub const fn from_bytes(key: [u8; DHLEN]) -> Self {
        Self { k: key }
    }
    pub(crate) const fn as_bytes(&self) -> [u8; DHLEN] {
        self.k
    }
    /// Checks whether a `Key` object is empty or not.
    /// # Example
    ///
    /// ```
    /// # use alaric_lib::{
    /// #   security::noise::error::NoiseError,
    /// #   security::noise::types::Key,
    /// # };
    /// # use std::str::FromStr;
    /// # fn try_main() -> Result<(), NoiseError> {
    ///     let empty_key1 = Key::from_str("0000000000000000000000000000000000000000000000000000000000000000")?;
    ///     let empty_key2 = Key::new();
    ///     let k = Key::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893")?;
    ///     assert!(empty_key1.is_empty());
    ///     assert!(empty_key2.is_empty());
    ///     assert!(!k.is_empty());
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        constant_time_eq(&self.k[..], &EMPTY_KEY)
    }
    /// Derives a `PublicKey` from the `Key` and returns it.
    #[must_use]
    pub fn generate_public_key(private_key: &[u8; DHLEN]) -> PublicKey {
        let mut output: [u8; DHLEN] = EMPTY_KEY;
        output.copy_from_slice(private_key);
        let output = curve25519::SecretKey(output).get_public();
        PublicKey { k: output.0 }
    }
}
impl std::str::FromStr for Key {
    type Err = NoiseError;
    /// Instanciates a new `Key` from a string of hexadecimal values.
    /// # Example
    ///
    /// ```
    /// # use alaric_lib::{
    /// #   security::noise::error::NoiseError,
    /// #   security::noise::types::Key,
    /// # };
    /// # use std::str::FromStr;
    /// # fn try_main() -> Result<(), NoiseError> {
    ///     let k = Key::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893")?;
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    fn from_str(key: &str) -> Result<Self, NoiseError> {
        let a = decode_str_32(key)?;
        Ok(Self::from_bytes(a))
    }
}

pub struct Psk {
    psk: [u8; DHLEN],
}
impl Psk {
    /// Instanciates a new empty `Psk`.
    #[must_use]
    pub const fn default_psk() -> Self {
        Self::from_bytes(EMPTY_KEY)
    }
    pub(crate) fn clear(&mut self) {
        self.psk.zeroize();
    }
    /// Instanciates a new `Psk` from an array of `DHLEN` bytes.
    #[must_use]
    pub const fn from_bytes(k: [u8; DHLEN]) -> Self {
        Self { psk: k }
    }

    #[allow(dead_code)]
    pub(crate) const fn as_bytes(&self) -> [u8; DHLEN] {
        self.psk
    }
    /// Checks whether a `Psk` object is empty or not.
    /// # Example
    ///
    /// ```
    /// # use alaric_lib::{
    /// #   security::noise::error::NoiseError,
    /// #   security::noise::types::Psk,
    /// # };
    /// # use std::str::FromStr;
    /// # fn try_main() -> Result<(), NoiseError> {
    ///     let empty_key1 = Psk::from_str("0000000000000000000000000000000000000000000000000000000000000000")?;
    ///     let empty_key2 = Psk::default_psk();
    ///     let k = Psk::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893")?;
    ///     assert!(empty_key1.is_empty());
    ///     assert!(empty_key2.is_empty());
    ///     assert!(!k.is_empty());
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        constant_time_eq(&self.psk[..], &EMPTY_KEY)
    }
}
impl Clone for Psk {
    fn clone(&self) -> Self {
        Self {
            psk: self.as_bytes().to_owned(),
        }
    }
}

impl std::str::FromStr for Psk {
    type Err = NoiseError;
    /// Instanciates a new `Psk` from a string of hexadecimal values.
    /// # Example
    ///
    /// ```
    /// # use alaric_lib::{
    /// #   security::noise::error::NoiseError,
    /// #   security::noise::types::Psk,
    /// # };
    /// # use std::str::FromStr;
    /// # fn try_main() -> Result<(), NoiseError> {
    ///     let k = Psk::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893")?;
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    fn from_str(k: &str) -> Result<Self, NoiseError> {
        let psk = decode_str_32(k)?;
        let _ = psk.len();
        Ok(Self::from_bytes(psk))
    }
}

pub struct PrivateKey {
    k: [u8; DHLEN],
}
impl PrivateKey {
    pub(crate) fn clear(&mut self) {
        self.k.zeroize();
    }
    /// Instanciates a new empty `PrivateKey`.
    #[must_use]
    pub const fn empty() -> Self {
        Self { k: EMPTY_KEY }
    }
    /// Instanciates a new `PrivateKey` from an array of `DHLEN` bytes.
    #[must_use]
    pub const fn from_bytes(k: [u8; DHLEN]) -> Self {
        Self::from_hacl_secret_key(curve25519::SecretKey(k))
    }
    pub(crate) const fn from_hacl_secret_key(hacl_secret: curve25519::SecretKey) -> Self {
        Self { k: hacl_secret.0 }
    }
    pub(crate) const fn as_bytes(&self) -> [u8; DHLEN] {
        self.k
    }
    /// Checks whether a `PrivateKey` object is empty or not.
    /// # Example
    ///
    /// ```
    /// # use alaric_lib::{
    /// #   security::noise::error::NoiseError,
    /// #   security::noise::types::PrivateKey,
    /// # };
    /// # use std::str::FromStr;
    /// # fn try_main() -> Result<(), NoiseError> {
    ///     let empty_key1 = PrivateKey::from_str("0000000000000000000000000000000000000000000000000000000000000000")?;
    ///     let empty_key2 = PrivateKey::empty();
    ///     let k = PrivateKey::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893")?;
    ///     assert!(empty_key1.is_empty());
    ///     assert!(empty_key2.is_empty());
    ///     assert!(!k.is_empty());
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        constant_time_eq(&self.k[..], &EMPTY_KEY)
    }
    /// Derives a `PublicKey` from the `PrivateKey` then returns `Ok(PublicKey)` when successful and `Err(NoiseError)` otherwise.
    pub fn generate_public_key(&self) -> Result<PublicKey, NoiseError> {
        if self.is_empty() {
            return Err(NoiseError::InvalidKeyError);
        }
        Ok(PublicKey {
            k: curve25519::SecretKey(self.k).get_public().0,
        })
    }
}

impl std::str::FromStr for PrivateKey {
    type Err = NoiseError;
    /// Instanciates a new `PrivateKey` from a string of hexadecimal values.
    /// # Example
    ///
    /// ```
    /// # use alaric_lib::{
    /// #   security::noise::error::NoiseError,
    /// #   security::noise::types::PrivateKey,
    /// # };
    /// # use std::str::FromStr;
    /// # fn try_main() -> Result<(), NoiseError> {
    ///     let k = PrivateKey::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893")?;
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    fn from_str(key: &str) -> Result<Self, NoiseError> {
        let k = decode_str_32(key)?;
        Ok(Self::from_hacl_secret_key(curve25519::SecretKey(k)))
    }
}

#[derive(Copy, Clone)]
pub struct PublicKey {
    k: [u8; DHLEN],
}
impl PublicKey {
    /// Instanciates a new empty `PublicKey`.
    #[must_use]
    pub const fn empty() -> Self {
        Self { k: EMPTY_KEY }
    }
    /// Instanciates a new `PublicKey` from an array of `DHLEN` bytes.
    pub fn from_bytes(k: [u8; DHLEN]) -> Result<Self, NoiseError> {
        for i in forbidden_curve_values.iter() {
            if &k == i {
                return Err(NoiseError::InvalidPublicKeyError);
            }
        }
        Ok(Self { k })
    }

    pub(crate) fn clear(&mut self) {
        self.k.zeroize();
    }
    pub(crate) const fn from_hacl_public_key(hacl_public: curve25519::PublicKey) -> Self {
        Self { k: hacl_public.0 }
    }
    #[must_use]
    pub const fn as_bytes(&self) -> [u8; DHLEN] {
        self.k
    }
    /// Checks whether a `PublicKey` object is empty or not.
    /// # Example
    ///
    /// ```
    /// # use alaric_lib::{
    /// #   security::noise::error::NoiseError,
    /// #   security::noise::types::PublicKey,
    /// # };
    /// # use std::str::FromStr;
    /// # fn try_main() -> Result<(), NoiseError> {
    ///     let empty_key = PublicKey::empty();
    ///     let k = PublicKey::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893")?;
    ///     assert!(empty_key.is_empty());
    ///     assert!(!k.is_empty());
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        constant_time_eq(&self.k[..], &EMPTY_KEY)
    }
}
impl std::str::FromStr for PublicKey {
    type Err = NoiseError;
    /// Instanciates a new `PublicKey` from a string of hexadecimal values.
    /// Returns `Ok(PublicKey)` when successful and `Err(NoiseError)` otherwise.
    /// # Example
    ///
    /// ```
    /// # use alaric_lib::{
    /// #   security::noise::error::NoiseError,
    /// #   security::noise::types::PublicKey,
    /// # };
    /// # use std::str::FromStr;
    /// # fn try_main() -> Result<(), NoiseError> {
    ///     let k = PublicKey::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893")?;
    ///     println!("{:?}", k.as_bytes());
    /// #   Ok(())
    /// # }
    /// # fn main() {
    /// #   try_main().unwrap();
    /// # }
    /// ```
    fn from_str(key: &str) -> Result<Self, NoiseError> {
        let pk = decode_str_32(key)?;
        Ok(Self::from_hacl_public_key(curve25519::PublicKey(pk)))
    }
}

#[derive(Copy, Clone)]
pub(crate) struct Nonce {
    n: u64,
}
impl Nonce {
    pub(crate) const fn new() -> Self {
        Self { n: 0_u64 }
    }
    pub(crate) const fn increment(&mut self) {
        self.n += 1;
    }
    pub(crate) const fn get_value(self) -> Result<u64, NoiseError> {
        if self.n == MAX_NONCE {
            return Err(NoiseError::ExhaustedNonceError);
        }
        Ok(self.n)
    }
}

pub struct Keypair {
    private_key: PrivateKey,
    public_key: PublicKey,
}
impl Keypair {
    pub fn clear(&mut self) {
        self.private_key.clear();
        self.public_key.clear();
    }
    /// Instanciates a `Keypair` where the `PrivateKey` and `PublicKey` fields are filled with 0 bytes.
    #[must_use]
    pub const fn new_empty() -> Self {
        Self {
            private_key: PrivateKey::empty(),
            public_key: PublicKey::empty(),
        }
    }
    /// Instanciates a `Keypair` by generating a random `PrivateKey` and deriving
    /// the corresponding `PublicKey`.
    #[must_use]
    pub fn default_keypair() -> Self {
        let secret_bytes: [u8; DHLEN] = rand::random();
        let secret = curve25519::SecretKey(secret_bytes);
        let public = secret.get_public();
        Self {
            private_key: PrivateKey::from_hacl_secret_key(secret),
            public_key: PublicKey::from_hacl_public_key(public),
        }
    }
    pub(crate) fn dh(&self, public_key: &[u8; DHLEN]) -> [u8; DHLEN] {
        let mut output: [u8; DHLEN] = EMPTY_KEY;
        curve25519::scalarmult(&mut output, &self.private_key.as_bytes(), public_key);
        output
    }
    /// Checks if the `PrivateKey` field of a `Keypair` is empty and returns either `true` or `false` accordingly.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.private_key.is_empty()
    }
    /// Derives a `PublicKey` from a `Key` object.
    /// Returns a `Ok(Keypair)` containing the previous two values and `Err(NoiseError)` otherwise.
    pub fn from_key(k: PrivateKey) -> Result<Self, NoiseError> {
        let public_key: PublicKey = k.generate_public_key()?;
        Ok(Self {
            private_key: k,
            public_key,
        })
    }
    /// Derives a `PublicKey` from a `PrivateKey`.
    /// Returns a `Ok(Keypair)` containing the previous two values and `Err(NoiseError)` otherwise.
    pub fn from_private_key(k: PrivateKey) -> Result<Self, NoiseError> {
        Self::from_key(k)
    }
    /// Returns the `PublicKey` value from the `Keypair`
    #[must_use]
    pub const fn get_public_key(&self) -> PublicKey {
        self.public_key
    }
}

#[test]
fn public_key_validation_test() {
    let bad_public_keys = vec![
        PublicKey::from_bytes([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]),
        PublicKey::from_bytes([
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]),
        PublicKey::from_bytes([
            224, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9,
            141, 235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 0,
        ]),
        PublicKey::from_bytes([
            95, 156, 149, 188, 163, 80, 140, 36, 177, 208, 177, 85, 156, 131, 239, 91, 4, 68, 92,
            196, 88, 28, 142, 134, 216, 34, 78, 221, 208, 159, 17, 87,
        ]),
        PublicKey::from_bytes([
            236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
        ]),
        PublicKey::from_bytes([
            237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
        ]),
        PublicKey::from_bytes([
            238, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
        ]),
        PublicKey::from_bytes([
            205, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9,
            141, 235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 128,
        ]),
        PublicKey::from_bytes([
            76, 156, 149, 188, 163, 80, 140, 36, 177, 208, 177, 85, 156, 131, 239, 91, 4, 68, 92,
            196, 88, 28, 142, 134, 216, 34, 78, 221, 208, 159, 17, 215,
        ]),
        PublicKey::from_bytes([
            217, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        ]),
        PublicKey::from_bytes([
            218, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        ]),
        PublicKey::from_bytes([
            219, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        ]),
    ];

    for i in bad_public_keys {
        if i.is_ok() {
            panic!("Allowed forbidden Public Key value");
        }
    }

    if PublicKey::from_bytes(
        decode_str_32("31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62").unwrap(),
    )
    .is_err()
    {
        panic!("Denied valid Public Key value");
    }
}

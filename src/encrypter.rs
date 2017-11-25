use common::*;
use error::Error;
use openssl::rand;
use openssl::rsa::{Rsa, PKCS1_PADDING};
use openssl::symm::{self, Cipher};

/// Encrypt `input` with `rsa` instance.
/// The difference between just encrypting it normally
/// is that this has a larger max-length and is
/// following the standard synac format.
pub fn encrypt(input: &[u8], rsa: &Rsa) -> Result<Vec<u8>, Error> {
    let mut key = [0; 32];
    let mut iv =  [0; 16];

    rand::rand_bytes(&mut key)?;
    rand::rand_bytes(&mut iv)?;

    let mut encrypted_aes = symm::encrypt(Cipher::aes_256_cbc(), &key, Some(&iv), input)?;
    let size_aes = encrypted_aes.len();

    let size_rsa = rsa.size();
    let mut encrypted_rsa = vec![0; size_rsa];

    let mut keyiv = Vec::with_capacity(32 + 16);
    keyiv.extend(key.into_iter());
    keyiv.extend(iv.into_iter());

    rsa.public_encrypt(&keyiv, &mut encrypted_rsa, PKCS1_PADDING)?;

    let mut encrypted = Vec::with_capacity(4+size_rsa+size_aes);
    encrypted.extend(encode_u16(size_rsa as u16).into_iter());
    encrypted.extend(encode_u16(size_aes as u16).into_iter());
    encrypted.append(&mut encrypted_rsa);
    encrypted.append(&mut encrypted_aes);

    Ok(encrypted)
}

/// Decrypt `input` with `rsa` instance.
/// The difference between just decrypting it normally
/// is that this has a larger max-length and is
/// following the standard synac format.
pub fn decrypt(mut input: &[u8], rsa: &Rsa) -> Result<Vec<u8>, Error> {
    if input.len() <= 4 {
        return Err(Error::OutOfBounds);
    }

    let size_rsa = decode_u16(&input[..2]) as usize;
    let size_aes = decode_u16(&input[2..4]) as usize;

    if input.len() != 4+size_rsa+size_aes {
        return Err(Error::OutOfBounds);
    }
    input = &input[4..];

    let mut keyiv = vec![0; size_rsa];
    rsa.private_decrypt(&input[..size_rsa], &mut keyiv, PKCS1_PADDING)?;
    keyiv.truncate(32+16);

    let (key, iv) = keyiv.split_at(32);
    let decrypted = symm::decrypt(Cipher::aes_256_cbc(), key, Some(iv), &input[size_rsa..])?;

    Ok(decrypted)
}

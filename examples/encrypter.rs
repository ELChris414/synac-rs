extern crate openssl;
extern crate synac;

use openssl::rsa::Rsa;

fn main() {
    // TODO: Handle errors

    // Generate random Rsa instance
    let rsa = Rsa::generate(synac::common::RSA_LENGTH).unwrap();
    let input = b"Hello World";

    // Encrypt
    let encrypted = synac::encrypt(&*input, &rsa).unwrap();
    // Decrypt again
    let decrypted = synac::decrypt(&encrypted, &rsa).unwrap();

    // Assert nothing has changed
    assert_eq!(&*input, &*decrypted);
}

extern crate crypto;
extern crate sha2;
extern crate sodiumoxide;
extern crate blake2_c;
extern crate num_bigint;
extern crate num_traits;
extern crate itertools;
extern crate unicode_normalization;

use itertools::Itertools;
use itertools::join;

use std::time::Instant;
use std::str::FromStr;
use std::iter::FromIterator;
use std::io;

use num_bigint::BigUint;
use num_traits::Zero;

use unicode_normalization::UnicodeNormalization;

use sodiumoxide::crypto::sign::ed25519;
use sodiumoxide::crypto::sign::Seed;

use blake2_c::blake2b;
use blake2_c::Digest as BlakeDigest;

use crypto::pbkdf2::pbkdf2;
use crypto::hmac::Hmac;
use crypto::sha2::Sha512;
use crypto::sha2::Sha256;
use crypto::digest::Digest;

macro_rules! product {
        ( $string: expr, $repeat: expr) => {
             {
                 let mut x = Vec::new();
                 for _ in 0..$repeat {
                     x.push($string);

                }
                x
             }
        }
}

fn brute_force(email: String, mnemonic: String, address: String, prefix_custom_charset: String, brute_force_custom_charset: String, minimum_length: u32) -> () {

    let mut permutations: u64 = 0;

    for length in minimum_length..100 {

        let xs = product!(brute_force_custom_charset.as_bytes().to_vec(), length);

        for x in xs.into_iter().multi_cartesian_product() {
            let guess = prefix_custom_charset.to_owned() + &join(String::from_utf8(x), "");

            println!("guess = {}, permutations = {}", guess, permutations);

            if check(&email, &mnemonic, &address, &guess) {
                return
            }

            permutations += 1;
        }
    }

}

fn main() {

    let mut select_num = String::new();
    let mut email= String::new();
    let mut mnemonic= String::new();
    let mut address= String::new();
    let mut prefix_custom_charset= String::new();
    let mut brute_force_custom_charset= String::new();
    let mut minimum_length = String::new();

    let mut charsets = vec![
        "0123456789",
        "0123456789abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        r"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&'()*+,-./:;<=>?@[\]^_`{|}~",
        r"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&'()*+,-./:;<=>?@[\]^_`{|}~"
    ];

    println!("Charsets:");

    for (i, charset) in charsets.iter().enumerate() {
        println!("[{}] : {}", i, charset );

    }

    println!("Please select a charset (0 - 5), If you remember some of the passwords, enter 6. : ");


    io::stdin().read_line(&mut select_num).expect("failed to read select number");

    let num: usize = select_num.trim().parse().expect("cannot parse select number");

    if num == 6 {
        println!("Please input prefix charsets of the expected password : ");
        io::stdin().read_line(&mut prefix_custom_charset);

        println!("Please input the rest of custom charsets for brute force : ");
        io::stdin().read_line(&mut brute_force_custom_charset);
        charsets.push(brute_force_custom_charset.trim());

        println!("Please input minimum length of custom charsets for brute force : ");
        io::stdin().read_line(&mut minimum_length).expect("failed read to minimum length");

    }

    println!("Please input your email : ");

    io::stdin().read_line(&mut email).expect("failed read to email");

    println!("Please input your mnemonic : ");

    io::stdin().read_line(&mut mnemonic).expect("failed read to mnemonic");

    println!("Please input your address : ");

    io::stdin().read_line(&mut address).expect("failed read to address");

    let now = Instant::now();

    let mn = minimum_length.trim().parse().expect("Please input minimum length of number");
    brute_force(email.trim().to_string(), mnemonic.trim().to_string(), address.trim().to_string(), prefix_custom_charset.trim().to_string(), charsets[num].to_string(), mn);

    println!("time elapsed = {}", now.elapsed().as_secs());

}

pub fn check(email: &String, mnemonic: &String, address: &String, guess: &String) -> bool {

    let salt = String::from("mnemonic").to_owned() + email;
    let salt = salt.to_owned() + guess;

    let mut mac = Hmac::new(Sha512::new(), mnemonic.as_bytes());
    let mut result = [0u8; 32];
    pbkdf2(&mut mac, salt.nfkd().collect::<String>().as_bytes(), 2048, &mut result);

    let seed = Seed(result);
    let (pk, _sk) = ed25519::keypair_from_seed(&seed);

    let hash: BlakeDigest = blake2b::State::new(20).update(&pk[0..32]).finalize();

    let mut magic_byte_with_hash: Vec<u8> = vec![0x6, 0xa1, 0x9f];

    magic_byte_with_hash.extend(hash.bytes.iter());

    let mut sh = Box::new(Sha256::new());

    sh.input(&magic_byte_with_hash);

    let mut output: Vec<u8> = vec![0u8; sh.output_bytes()];

    sh.result(&mut output);

    sh.reset();

    sh.input(&output);

    let mut output_checksum: Vec<u8> = vec![0u8; sh.output_bytes()];

    sh.result(&mut output_checksum);

    sh.reset();

    magic_byte_with_hash.extend(output_checksum[..4].iter());

    let mut decode_result: BigUint = Zero::zero();

    for x in magic_byte_with_hash.iter() {

        decode_result *= 256 as u64;
        decode_result += *x as u64;
    }

    let code_string: Vec<char> = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".chars().collect();
    let mut addr: Vec<char> = Vec::new();
    while &decode_result > &Zero::zero() {
        let index: BigUint = &decode_result % 58 as u64;

        let int_index = u32::from_str(index.to_str_radix(10).as_str()).unwrap();


        addr.insert(0, code_string[int_index as usize]);

        decode_result = decode_result / 58 as u64;

    }

    let guess_address = String::from_iter(addr);

    println!("addr = {:?}",guess_address );

    if &guess_address == address  {
        println!("password : {}", guess);
        true
    } else {
        false
    }

}


#[cfg(test)]

#[test]
fn check_password() {

    // From https://www.reddit.com/r/tezos/comments/8n58a6/nutz_and_boltz_for_computing_tezos_ico_private/
    let email = String::from("oh@mail.com");
    let mnemonic = String::from("health boil host ostrich fire spike body solar collect harvest catalog cup mix tattoo merge");
    let address = String::from("tz1iean4ArF6YU8pGUup73FhoWXJr1Nw3wEo");
    let guess = String::from("Hf12@ahgw895jnqGG");
    assert_eq!(true, check(&email, &mnemonic, &address, &guess));
}

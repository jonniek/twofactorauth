//extern crate sha1;
extern crate sha1;
extern crate base32;

use base32::Alphabet::RFC4648;
use base32::decode;
use sha1::{ Sha1, Digest };
use std::time::{SystemTime, UNIX_EPOCH};

use std::io;
use std::env;

// sha1 blocksize(512bits) in u8 array is of length 64
const BLOCKSIZE: usize = 64;

fn main() {
	let args: Vec<String> = env::args().collect();

	if args.len() == 1 {
		let mut input = String::new();
		match io::stdin().read_line(&mut input) {
	    Ok(n) => {
	    	if n == 0 {
	    		eprintln!("No input found");
	    	} else {
	    		init_totp(&input.trim());
	    	}
	    }
	    Err(error) => eprintln!("error: {}", error),
		}
	} else if args.len() == 2 {
		init_totp(&args[1]);
	} else {
		eprintln!("Pass only one argument, the base32 key.");
	}
}

fn init_totp(secret: &str) {
	let time = unix_seconds();
	let secret = decode_secret(secret);
	match secret {
		Ok(s) => {
			let code = totp(&s, time);
			print!("{:06}", code);
		},
		Err(e) => eprintln!("{:?}", e)
	}
}

fn unix_seconds() -> u64 {
	let start = SystemTime::now();
  let since_the_epoch = start.duration_since(UNIX_EPOCH).unwrap();
  since_the_epoch.as_secs()
}

fn decode_secret(s: &str) -> Result<Vec<u8>, String> {
	decode(RFC4648 {padding: false}, s).ok_or(String::from("invalid base32"))
}

fn truncate_bytes(bytes: &[u8], offset: usize) -> u64 {
  ((bytes[offset] as u64) << 24) +
  ((bytes[offset + 1] as u64) << 16) +
  ((bytes[offset + 2] as u64) <<  8) +
  ((bytes[offset + 3] as u64) <<  0)
}

fn padkey(key: &[u8]) -> Vec<u8> {
	let mut mut_key = key.to_vec();

	// if key is smaller than blocksize hash it first
	if key.len() > BLOCKSIZE {
		let mut sha = Sha1::new();
		sha.input(key);
		mut_key = sha.result().to_vec();
	}

	let tail = vec![0; BLOCKSIZE - mut_key.len()];
	mut_key.extend(tail.iter());

	mut_key
}

fn hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
	let ipad: Vec<u8> = key.to_vec().iter().map(|i| i ^ 0x36).collect();
	let mut innersha = Sha1::new();
	innersha.input(&ipad);
	innersha.input(&message);
	let sha_message = innersha.result();

	let opad: Vec<u8> = key.to_vec().iter().map(|i| i ^ 0x5c).collect();
	let mut outersha = Sha1::new();
	outersha.input(&opad);
	outersha.input(&sha_message);
	let output = outersha.result().to_vec();

	output
}

fn totp(key: &[u8], time: u64) -> u64 {
  let count = (time / 30).to_be();
  let message: &[u8] = unsafe { ::std::slice::from_raw_parts(&count as *const u64 as *const u8, 8) };
  let padded_key = padkey(key);

  let bytes = hmac(&padded_key, message);

  let offset = (bytes[19] & 0xf) as usize;

  let raw_code = truncate_bytes(&bytes, offset);

  let code = (raw_code & 0x7FFFFFFF) % 1000000;

  code
}

#[test]
fn test_decode_secret() {
	// assert valid base32
	let secret = "65ZACCXCCXS6HXOFFD7ACXCCXLLA";
	let res = decode_secret(secret);
	assert!(res.is_ok());

	// assert invalid base32
	let secret = "This is not a valid string";
	let res = decode_secret(secret);
	assert_eq!(res.is_ok(), false);
}

#[test]
fn test_totp() {
	let key = decode_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
	let result = totp(&key, 0);
	assert_eq!(result, 755224);
}

#[test]
fn test_padkey() {

	// test equal size case
	let input = [0x5 as u8; BLOCKSIZE].to_vec();
	let res = padkey(&input);
	assert_eq!(input, res);

	// test smaller size case
	let input = [0x5 as u8];
	let res = padkey(&input);
	assert_eq!(res[0], 0x5);
	assert_eq!(res.len(), BLOCKSIZE);
	assert_eq!(res[1], 0);

	// test larger size case
	let input = [0x5 as u8; 70];
	let mut hash = Sha1::new();
	hash.input(&input);
	let res = hash.result().to_vec();
	let pad = padkey(&input);
	assert_eq!(res[5], pad[5]);
	assert_eq!(pad[35], 0);
	assert_eq!(pad.len(), BLOCKSIZE);
}
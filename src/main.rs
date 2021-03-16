//
// https://github.com/rib/jsonwebtokens
//
use serde_json::json;
use serde_json::{Map, Value};
use std::fs;
use std::process;
use std::str::FromStr;

use std::time::{SystemTime, UNIX_EPOCH};

use clap::clap_app;

use jsonwebtokens as jwt;
use jwt::{raw, Algorithm, AlgorithmID, Verifier};

use openssl::x509;

fn main() -> Result<(), jwt::error::Error> {
    let matches = clap_app!(myapp =>
        (version: "0.1")
        (author: "JW Hance. <jwhance@gmail.com>")
        (about: "Generates or Validates a JWT")
        //(@arg CONFIG: -c --config +takes_value "Sets a custom config file")
        //(@arg INPUT: +required "Sets the input file to use")
        //(@arg verbose: -v --verbose "Print test information verbosely")
        (@subcommand generate =>
            (about: "Generates a JWT using the specified parameters.")
            (@arg debug: -d --debug ... "Sets the level of debugging information")
            (@arg privatekey: -p --privatekey +required ... "Private Key PEM file")
            (@arg algorithm: -a --algorithm +required ... "JWT signing algorithm")
            (@arg iss: -i --iss ... "Issuer")
            (@arg sub: -s --sub ... "Subject")
            (@arg aud: -u --aud ... "Audience")
            (@arg exp: -e --exp ... "Expiration in minutes")
        )
        (@subcommand validate =>
            (about: "Validates a JWT against the specified parameters.")
            (@arg debug: -d --debug ... "Sets the level of debugging information")
            (@arg publickey: -p --publickey +required ... "Public Key PEM file")
            (@arg jwtfile: -j --jwtfile +required ... "JWT file")
            (@arg iss: -i --iss ... "Issuer")
            (@arg sub: -s --sub ... "Subject")
            (@arg aud: -u --aud ... "Audience")
        )
    )
    .get_matches();

    eprintln!("Beginning JWT Utility");

    // Read X.509 certificate from file
    let public_cert =
        fs::read_to_string("./src/fiserv_test.crt").expect("Something went wrong reading the file");

    // For X.509 certificate: https://docs.rs/openssl/0.10.4/openssl/x509/struct.X509.html
    let x509 = X509::from_pem()?;

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if matches.subcommand_name() == None {
    } else if matches.subcommand_name().unwrap() == String::from("validate") {
        eprintln!(" => Validating JWT");

        // Options
        let sub_command = matches.subcommand_matches("validate").unwrap();
        let public_key_file = sub_command.value_of("publickey").unwrap();
        let jwt_file = sub_command.value_of("jwtfile").unwrap();

        //Read public key from file
        let public_key =
            fs::read_to_string(&public_key_file).expect("Something went wrong reading the file");

        //Read JWT from file
        let jwt = fs::read_to_string(&jwt_file).expect("Something went wrong reading the file");

        let decoded = raw::decode_only(&jwt)?;
        eprintln!("      Header: {:?}", decoded.header);
        //eprintln!("Alg: {0}", decoded.header.get("alg").unwrap());
        eprintln!("      Payload: {:?}", decoded.claims);

        let jwt_alg = AlgorithmID::from_str(decoded.header["alg"].as_str().unwrap()).unwrap();

        let alg = Algorithm::new_rsa_pem_verifier(jwt_alg, &public_key.as_bytes()).unwrap();
        let mut verifier = Verifier::create();
        if get_claim_verification_value(sub_command, "iss") != None {
            verifier.issuer(get_claim_verification_value(sub_command, "iss").unwrap());
        }
        if get_claim_verification_value(sub_command, "aud") != None {
            verifier.audience(get_claim_verification_value(sub_command, "aud").unwrap());
        }

        match verifier.build().unwrap().verify(&jwt.trim(), &alg) {
            Ok(output) => {
                println!("      Verification: {0}", output);
            }
            Err(error) => {
                eprintln!("      Error: {:?}", error);
            }
        }
    } else if matches.subcommand_name().unwrap() == String::from("generate") {
        //
        // GENERATE JWT
        //
        eprintln!(" => Generating JWT");

        // Options
        let sub_command = matches.subcommand_matches("generate").unwrap();
        let _alg = sub_command.value_of("algorithm").unwrap();
        let private_key_file = sub_command.value_of("privatekey").unwrap();

        // Read private key from file
        let private_key =
            fs::read_to_string(&private_key_file).expect("Something went wrong reading the file");

        let jwt_alg = AlgorithmID::from_str(_alg).unwrap();

        let alg = Algorithm::new_rsa_pem_signer(jwt_alg, &private_key.as_bytes())?;
        let header = json!({ "alg": alg.name(), "typ": "JWT" });
        let mut claims_map = Map::new();

        // iat = current time
        claims_map.insert(String::from("iat"), Value::from(current_time));

        // Add any optional claims: iss, sub, aud, exp
        add_claim_str(&mut claims_map, sub_command, "aud");
        add_claim_str(&mut claims_map, sub_command, "iss");
        add_claim_str(&mut claims_map, sub_command, "sub");
        add_claim_exp(&mut claims_map, sub_command, "exp", current_time);

        let token_str = jwt::encode(&header, &claims_map, &alg)?;

        print!("{0}", token_str.trim());
    } else {
        eprintln!("Unknown option");
    }

    process::exit(0);
}

fn get_claim_verification_value(sub_command: &clap::ArgMatches, claim: &str) -> Option<String> {
    let clm = sub_command.value_of(claim);
    if clm != None {
        Some(clm.unwrap().to_string())
    } else {
        None
    }
}

fn add_claim_str(map: &mut Map<String, Value>, sub_command: &clap::ArgMatches, claim: &str) {
    let clm = sub_command.value_of(claim);
    if clm != None {
        map.insert(String::from(claim), Value::String(clm.unwrap().to_string()));
    }
}

fn add_claim_exp(
    map: &mut Map<String, Value>,
    sub_command: &clap::ArgMatches,
    claim: &str,
    current_time: u64,
) {
    let clm = sub_command.value_of(claim);
    if clm != None {
        let exp: u64 = clm.unwrap().parse().unwrap();
        map.insert(String::from(claim), Value::from(exp + current_time));
    }
}

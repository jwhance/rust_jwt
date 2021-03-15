//
// https://github.com/rib/jsonwebtokens
//
use serde_json::json;
use serde_json::{Map, Value};
use std::fs;
use std::process;
use std::str::FromStr;

use clap::clap_app;

use jsonwebtokens as jwt;
use jwt::{Algorithm, AlgorithmID, Verifier};

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
            (@arg issuer: -i --iss ... "Issuer")
            (@arg subject: -s --sub ... "Subject")
            (@arg audience: -u --aud ... "Audience")
            (@arg expiration: -e -exp ... "Expiration in minutes")
        )
        (@subcommand validate =>
            (about: "Validates a JWT against the specified parameters.")
            (@arg debug: -d --debug ... "Sets the level of debugging information")
            (@arg publickey: -p --publickey +required ... "Public Key PEM file")
            (@arg jwtfile: -j --jwtfile +required ... "JWT file")
        )
    )
    .get_matches();

    //println!("Matches: {:?}", matches);
    //println!("Matches: {:?}", matches.subcommand_name());
    // println!(
    //     "Matches: {:?}",
    //     matches
    //         .subcommand_matches("validate")
    //         .unwrap()
    //         .value_of("jwtfile")
    // );

    if matches.subcommand_name() == None {

    } else if matches.subcommand_name().unwrap() == String::from("validate") {
        println!("Validating JWT");

        // Options
        let jwt_file = matches
            .subcommand_matches("generate")
            .unwrap()
            .value_of("jwtfile");

    // Read public key from file
    // let public_key = fs::read_to_string("src/pkcs8_public_key.pem")
    //     .expect("Something went wrong reading the file");

    // let alg =
    //     Algorithm::new_rsa_pem_verifier(AlgorithmID::RS256, &public_key.as_bytes()).unwrap();
    // let verifier = Verifier::create()
    //     .issuer("some-issuer.com")
    //     .audience("some-audience")
    //     .build()
    //     .unwrap();

    // match verifier.verify(&token_str, &alg) {
    //     Ok(output) => {
    //         println!("Verification: {0}", output);
    //     }
    //     Err(error) => {
    //         println!("Error: {:?}", error);
    //     }
    // }
    } else if matches.subcommand_name().unwrap() == String::from("generate") {
        //
        // GENERATE JWT
        //
        eprintln!("Generating JWT");

        // Options
        let sub_command = matches.subcommand_matches("generate").unwrap();

        let _alg = sub_command.value_of("algorithm").unwrap();
        let private_key_file = sub_command.value_of("privatekey").unwrap();

        // Get the optional claims: iss, sub, aud, exp

        // Read private key from file
        let private_key =
            fs::read_to_string(&private_key_file).expect("Something went wrong reading the file");

        let jwt_alg = AlgorithmID::from_str(_alg).unwrap();

        let alg = Algorithm::new_rsa_pem_signer(jwt_alg, &private_key.as_bytes())?;
        let header = json!({ "alg": alg.name(), "typ": "JWT" });
        let mut map = Map::new();
        map.insert(String::from("iss"), Value::String("some-issuer".to_string()));
        map.insert(String::from("aud"), Value::String("some-aud".to_string()));

        //let claims = json!({ "iss": "some-issuer.com", "aud": "some-audience" });
        let token_str = jwt::encode(&header, &map, &alg)?;

        println!("{0}", token_str);
    } else {
        println!("Unknown option");
    }

    process::exit(0);
}

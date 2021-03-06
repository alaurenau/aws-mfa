#![allow(dead_code)]

use std::io;
use std::process::exit;
use std::str;

use ini::Ini;
use rusoto_core::{HttpClient, Region};
use rusoto_credential::StaticProvider;
use rusoto_sts::Credentials;
use rusoto_sts::GetSessionTokenError::Unknown;
use rusoto_sts::GetSessionTokenRequest;
use rusoto_sts::Sts;
use rusoto_sts::StsClient;

const CREDENTIALS_FILE: &str = ".aws/credentials";
const LONG_TERM_PROFILE: &str = "default-long-term";
const DEFAULT_PROFILE: &str = "default";

#[derive(Debug)]
struct LongTermCredentials {
    access_key: String,
    secret_key: String,
    mfa_device: String,
}

fn main() {
    let long_term_credentials = get_aws_lt_credentials();

//    println!("long term credentials:\n{:#?} ", long_term_credentials);

    let mfa_token = get_mfa_token(&long_term_credentials.mfa_device);

//    println!("token: {}", mfa_token);

    let session_credentials = get_aws_session_credentials(long_term_credentials, mfa_token);

//    println!("session credentials:\n {:#?} ", session_credentials);

    update_credentials_file(session_credentials);
}

fn get_aws_lt_credentials() -> LongTermCredentials {
    let buf = dirs::home_dir().unwrap();
    let home = buf.to_str().unwrap();
    let mut credentials_path = String::from(home);
    credentials_path.push_str("/");
    credentials_path.push_str(CREDENTIALS_FILE);

    let credentials = Ini::load_from_file(credentials_path)
        .expect((String::from("AWS credentials file not found! It should be in ~/") + CREDENTIALS_FILE).as_str());

    let section = credentials.section(Some(String::from(LONG_TERM_PROFILE)))
        .expect((String::from(LONG_TERM_PROFILE) + " AWS profile not found in ~/" + CREDENTIALS_FILE).as_str());

    let access_key = section.get("aws_access_key_id").unwrap().to_string();
    let secret_key = section.get("aws_secret_access_key").unwrap().to_string();
    let mfa_device = section.get("aws_mfa_device").unwrap().to_string();

    LongTermCredentials { access_key, secret_key, mfa_device }
}

fn get_mfa_token(mfa_device: &String) -> String {
    let mut mfa_token = String::new();

    println!("Please, provide a valid mfa token for AWS mfa device {}", mfa_device);

    io::stdin().read_line(&mut mfa_token)
        .expect("Failed to read token");

    let mfa_token = mfa_token.trim().to_string();

    let _token: u32 = match mfa_token.trim().parse() {
        Ok(num) => num,
        Err(_) => {
            println!("Invalid mfa token provided");
            exit(1);
        }
    };

    mfa_token
}

fn get_aws_session_credentials(credentials: LongTermCredentials, mfa_token: String) -> Credentials {
    let provider = StaticProvider::new(credentials.access_key, credentials.secret_key, None, None);

    let sts_client = StsClient::new_with(HttpClient::new().unwrap(), provider, Region::UsWest2);
    let request = GetSessionTokenRequest { duration_seconds: Some(129_600), serial_number: Some(credentials.mfa_device), token_code: Some(mfa_token) };

    let result = sts_client.get_session_token(request).sync();
    let response = match result {
        Ok(result) => result,
        Err(error) => {
            println!("Error during AWS STS call");
            if let Unknown(response) = error {
                println!("{}", str::from_utf8(&response.body).unwrap());
            }
            exit(1);
        }
    };

    response.credentials.unwrap()
}

fn update_credentials_file(credentials: Credentials) {
    let buf = dirs::home_dir().unwrap();
    let home = buf.to_str().unwrap();
    let mut credentials_path = String::from(home);
    credentials_path.push_str("/");
    credentials_path.push_str(CREDENTIALS_FILE);

    let mut credentials_ini = Ini::load_from_file(credentials_path.as_str()).unwrap();

    let section = match credentials_ini.section_mut(Some(String::from(DEFAULT_PROFILE))) {
        Some(section) => section,
        None => {
            // create section if is not present
            credentials_ini.with_section(Some(String::from(DEFAULT_PROFILE))).set("aws_secret_key_id", "");
            credentials_ini.section_mut(Some(String::from(DEFAULT_PROFILE))).unwrap()
        }
    };

    section.insert("assumed_role".to_string(), "False".to_string());
    section.insert("aws_access_key_id".to_string(), credentials.access_key_id);
    section.insert("aws_secret_access_key".to_string(), credentials.secret_access_key);
    section.insert("aws_session_token".to_string(), credentials.session_token.clone());
    section.insert("aws_security_token".to_string(), credentials.session_token.clone());
    section.insert("expiration".to_string(), credentials.expiration);

    credentials_ini.write_to_file(credentials_path.as_str()).unwrap();
}

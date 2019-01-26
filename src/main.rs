use std::io;
use std::process::exit;

use ini::Ini;

const CREDENTIALS_FILE: &str = "/.aws/credentials";

#[derive(Debug)]
struct LongTermCredentials {
    access_key: String,
    secret_key: String,
    mfa_device: String,
}

#[derive(Debug)]
struct SessionCredentials {
    assumed_role: String,
    access_key: String,
    secret_key: String,
    session_token: String,
    security_token: String,
    expiration: String,
}

fn main() {
    let long_term_credentials = get_aws_lt_credentials();

    println!("long term credentials:\n{:#?} ",long_term_credentials);

    let mfa_token = get_mfa_token();

    println!("token: {}", mfa_token);

    let session_credentials = get_aws_session_credentials();

    println!("session credentials:\n {:#?} ", session_credentials);

    update_credentials_file(session_credentials);
}

fn get_aws_lt_credentials() -> LongTermCredentials {
    let buf = dirs::home_dir().unwrap();
    let home = buf.to_str().unwrap();
    let mut credentials_path = String::from(home);
    credentials_path.push_str(CREDENTIALS_FILE);

    let credentials = Ini::load_from_file(credentials_path).unwrap();

    let section = credentials.section(Some(String::from("default-long-term"))).unwrap();
    let access_key = section.get("aws_access_key_id").unwrap().to_string();
    let secret_key = section.get("aws_secret_access_key").unwrap().to_string();
    let mfa_device = section.get("aws_mfa_device").unwrap().to_string();

    return LongTermCredentials { access_key, secret_key, mfa_device };
}

fn get_mfa_token() -> String {
    let mut mfa_token = String::new();

    println!("Provide valid mfa token");

    io::stdin().read_line(&mut mfa_token)
        .expect("Failed to read token");

    let _token: u32 = match mfa_token.trim().parse() {
        Ok(num) => num,
        Err(_) => {
            println!("Invalid mfa token provided");
            exit(1);
        }
    };

    return mfa_token;
}

fn get_aws_session_credentials() -> SessionCredentials {
    panic!()
}

fn update_credentials_file(credentials: SessionCredentials) {

}

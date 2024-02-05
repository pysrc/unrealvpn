use std::{fs::File, io::Write};

fn main() -> std::io::Result<()>{
    let subject_alt_names = vec!["unrealvpn".to_string()];
    let cert = rcgen::generate_simple_self_signed(subject_alt_names).unwrap();


    let mut file = File::create("cert.pem")?;
    file.write_all(cert.serialize_pem().unwrap().as_bytes())?;
    file.flush()?;

    let mut file = File::create("key.pem")?;
    file.write_all(cert.serialize_private_key_pem().as_bytes())?;
    file.flush()?;

    Ok(())
}
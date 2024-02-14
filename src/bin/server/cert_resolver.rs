use std::{error::Error, fs::File, io::BufReader, sync::{Arc, Mutex}};

use rustls::{server::{ClientHello, ResolvesServerCert}, sign::{self, CertifiedKey}, Certificate, PrivateKey};

pub struct CertResolver {
    certificate_file: String,
    private_key_file: String,
    certified_key: Mutex<Option<Arc<CertifiedKey>>>,
}

impl CertResolver {
    pub fn new(certificate_file: String, private_key_file: String) -> Self {
        Self {
            certificate_file: certificate_file,
            private_key_file: private_key_file,
            certified_key: Mutex::new(None),
        }
    }

    pub async fn reload(&self) -> Result<(), Box<dyn Error>> {
        let certs = Self::load_certs(&self.certificate_file)?;
        let private_key = Self::load_private_key(&self.private_key_file)?;
        let key = sign::any_supported_type(&private_key)?;
        
        match self.certified_key.lock() {
            Ok(mut certified_key) => {
                *certified_key = Some(Arc::new(CertifiedKey::new(certs, key)));
                println!("loaded public certificate from: {}", self.certificate_file);
                println!("loaded private key from: {}", self.private_key_file);
            }
            Err(_) => {}
        }
        Ok(())
    }
    
    fn load_certs(filename: &String) -> Result<Vec<Certificate>, Box<dyn Error>> {
        let cert_file = File::open(filename)?;
        let mut reader = BufReader::new(cert_file);
        let certs = rustls_pemfile::certs(&mut reader).map(|c| Certificate(c.unwrap().as_ref().to_vec())).collect();
        Ok(certs)
    }

    fn load_private_key(filename: &String) -> Result<PrivateKey, Box<dyn Error>> {
        let cert_file = File::open(filename)?;
        let mut reader = BufReader::new(cert_file);
        let private_key = PrivateKey(rustls_pemfile::private_key(&mut reader)?.unwrap().secret_der().to_vec());
        Ok(private_key)
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        match self.certified_key.lock() {
            Ok(certified_key) => {
                return match &*certified_key {
                    Some(key) => Some(key.clone()),
                    None => None
                }
            }
            Err(_) => return None
        };
    }
}

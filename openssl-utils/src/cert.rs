use super::{CryptoErr, KeyUsage};
use openssl::nid::Nid;
use openssl::x509::*;

pub struct ValidCertificate {
    pub cert: X509,
    _priv: (),
}

pub trait X509Ext {
    fn key_can(&self, usage: &[KeyUsage]) -> Result<(), CryptoErr>;

    fn common_name(&self) -> Result<String, CryptoErr>;

    fn validate(
        self,
        ca_cert: &X509,
        required_key_usages: &[KeyUsage],
    ) -> Result<ValidCertificate, CryptoErr>;
}

impl X509Ext for X509 {
    fn key_can(&self, required_usages: &[KeyUsage]) -> Result<(), CryptoErr> {
        use x509_parser::certificate::X509Certificate;
        use x509_parser::extensions::ParsedExtension;

        let der = self.to_der()?;
        let (_, cert) = X509Certificate::from_der(&der).map_err(|_| CryptoErr::InvalidCert)?;

        let mut key_usage = None;
        for (_, ext) in cert.extensions() {
            key_usage = match ext.parsed_extension() {
                ParsedExtension::KeyUsage(u) => Some(u),
                _ => None,
            };
            if key_usage != None {
                break;
            }
        }
        let key_usage = key_usage.ok_or(CryptoErr::IncompatibleKeyUsage)?;

        for req_u in required_usages {
            let ok = match req_u {
                KeyUsage::DigitalSignature => key_usage.digital_signature(),
                KeyUsage::KeyAgreement => key_usage.key_agreement(),
                KeyUsage::NonRepudiation => key_usage.non_repudiation(),
                KeyUsage::KeyEncipherment => key_usage.key_encipherment(),
            };

            if !ok {
                return Err(CryptoErr::IncompatibleKeyUsage);
            }
        }

        Ok(())
    }

    fn common_name(&self) -> Result<String, CryptoErr> {
        let mut iter = self.subject_name().entries_by_nid(Nid::COMMONNAME);

        let common_name = iter
            .next()
            .ok_or(CryptoErr::NoCommonName)?
            .data()
            .as_slice();

        let common_name = String::from_utf8_lossy(common_name).to_string();

        if let Some(_) = iter.next() {
            return Err(CryptoErr::TooManyCommonNames);
        }

        Ok(common_name)
    }

    fn validate(
        self,
        ca_cert: &X509,
        required_key_usages: &[KeyUsage],
    ) -> Result<ValidCertificate, CryptoErr> {
        // check CA signature
        if !self.verify(ca_cert.public_key()?.as_ref())? {
            return Err(CryptoErr::InvalidCert);
        }

        // check key usage restrictions
        self.key_can(required_key_usages)?;

        Ok(ValidCertificate {
            cert: self,
            _priv: (),
        })
    }
}
/*
#[cfg(test)]
mod test {
    use super::*;
    use x509::pem::{};

    #[test]
    fn smth_ok() {
        let ca_cert_pem = include_bytes!("test_certs/ca.cert.pem");
        let ca_cert: X509Certificate = parse_x509_certificate(ca_cert_pem).unwrap();
    }

    #[test]
    fn smth_bad() {

    }
}*/

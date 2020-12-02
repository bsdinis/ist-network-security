use super::{CryptoErr, KeyUsage};
use openssl::nid::Nid;
use openssl::x509::*;

#[derive(Clone)]
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

    unsafe fn validate_unchecked(self) -> ValidCertificate;
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

    unsafe fn validate_unchecked(self) -> ValidCertificate {
        ValidCertificate {
            cert: self,
            _priv: (),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use openssl::x509::X509;

    fn get_ca_cert() -> X509 {
        let ca_cert_pem = include_bytes!("test_certs/ca.cert.pem");
        X509::from_pem(ca_cert_pem).unwrap()
    }

    macro_rules! validate_ok_test {
        ($id:ident, $file:expr, $usages:expr) => {
            #[test]
            fn $id() {
                let ca_cert = get_ca_cert();

                let cert_pem = include_bytes!($file);
                let cert: X509 = X509::from_pem(cert_pem).unwrap();

                cert.validate(&ca_cert, $usages).unwrap();
            }
        };
    }

    macro_rules! validate_nok_test {
        ($id:ident, $file:expr, $usages:expr) => {
            #[test]
            fn $id() {
                let ca_cert = get_ca_cert();

                let cert_pem = include_bytes!($file);
                let cert: X509 = X509::from_pem(cert_pem).unwrap();

                assert!(cert.validate(&ca_cert, $usages).is_err());
            }
        };
    }

    macro_rules! common_name_test {
        ($id:ident, $file:expr, $name:expr) => {
            #[test]
            fn $id() {
                let cl_auth_cert_pem = include_bytes!($file);
                let cl_auth_cert: X509 = X509::from_pem(cl_auth_cert_pem).unwrap();
                assert_eq!($name, cl_auth_cert.common_name().unwrap());
            }
        };
    }

    validate_ok_test!(
        val_cl_auth_cert_ok,
        "test_certs/client-auth.cert.pem",
        &[
            KeyUsage::DigitalSignature,
            KeyUsage::KeyAgreement,
            KeyUsage::KeyEncipherment
        ]
    );
    validate_ok_test!(
        val_cl_sign_cert_ok,
        "test_certs/client-sign.cert.pem",
        &[KeyUsage::DigitalSignature, KeyUsage::NonRepudiation]
    );
    validate_ok_test!(
        val_serv_cert_ok,
        "test_certs/server.cert.pem",
        &[
            KeyUsage::DigitalSignature,
            KeyUsage::KeyAgreement,
            KeyUsage::KeyEncipherment
        ]
    );

    validate_nok_test!(
        val_cl_auth_cert_nok,
        "test_certs/client-auth.cert.pem",
        &[KeyUsage::NonRepudiation]
    );
    validate_nok_test!(
        val_cl_sign_cert_nok,
        "test_certs/client-sign.cert.pem",
        &[KeyUsage::DigitalSignature, KeyUsage::KeyAgreement]
    );
    validate_nok_test!(
        val_serv_cert_nok,
        "test_certs/server.cert.pem",
        &[KeyUsage::NonRepudiation]
    );

    common_name_test!(cl_auth_cn, "test_certs/client-auth.cert.pem", "client-auth");
    common_name_test!(cl_sign_cn, "test_certs/client-sign.cert.pem", "client-sign");
    common_name_test!(server_cn, "test_certs/server.cert.pem", "server");
}

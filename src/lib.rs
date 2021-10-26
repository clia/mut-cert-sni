use std::collections;
use std::convert::TryFrom;
use std::sync::{Arc, RwLock};

use anyhow::{anyhow, Error};
use rustls::server;
use rustls::server::ClientHello;
use rustls::sign;

/// Something that resolves do different cert chains/keys based
/// on client-supplied server name (via SNI).
/// Support add certificate dynamically. Using RwLock for read/write mutex.
pub struct MutResolvesServerCertUsingSni {
    by_name: RwLock<collections::HashMap<String, Arc<sign::CertifiedKey>>>,
}

impl MutResolvesServerCertUsingSni {
    /// Create a new and empty (i.e., knows no certificates) resolver.
    pub fn new() -> Self {
        Self {
            by_name: RwLock::new(collections::HashMap::new()),
        }
    }

    /// Add a new `sign::CertifiedKey` to be used for the given SNI `name`.
    ///
    /// This function fails if `name` is not a valid DNS name, or if
    /// it's not valid for the supplied certificate, or if the certificate
    /// chain is syntactically faulty.
    pub fn add(&self, name: &str, ck: sign::CertifiedKey) -> Result<(), Error> {
        let checked_name = webpki::DnsNameRef::try_from_ascii_str(name)
            .map_err(|_| anyhow!("Bad DNS name".to_string()))?;

        cross_check_end_entity_cert(&ck, Some(checked_name))?;
        self.by_name
            .write()
            .unwrap()
            .insert(name.into(), Arc::new(ck));
        Ok(())
    }
}

impl server::ResolvesServerCert for MutResolvesServerCertUsingSni {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<sign::CertifiedKey>> {
        if let Some(name) = client_hello.server_name() {
            self.by_name.read().unwrap().get(name).map(Arc::clone)
        } else {
            // This kind of resolver requires SNI
            None
        }
    }
}

/// Check the certificate chain for validity:
/// - it should be non-empty list
/// - the first certificate should be parsable as a x509v3,
/// - the first certificate should quote the given server name
///   (if provided)
///
/// These checks are not security-sensitive.  They are the
/// *server* attempting to detect accidental misconfiguration.
pub(crate) fn cross_check_end_entity_cert(
    ck: &sign::CertifiedKey,
    name: Option<webpki::DnsNameRef>,
) -> Result<(), Error> {
    // Always reject an empty certificate chain.
    let end_entity_cert = ck
        .end_entity_cert()
        .map_err(|_| anyhow!("No end-entity certificate in certificate chain".to_string()))?;

    // Reject syntactically-invalid end-entity certificates.
    let end_entity_cert =
        webpki::EndEntityCert::try_from(end_entity_cert.as_ref()).map_err(|_| {
            anyhow!("End-entity certificate in certificate \
                                  chain is syntactically invalid"
                .to_string(),)
        })?;

    if let Some(name) = name {
        // If SNI was offered then the certificate must be valid for
        // that hostname. Note that this doesn't fully validate that the
        // certificate is valid; it only validates that the name is one
        // that the certificate is valid for, if the certificate is
        // valid.
        if end_entity_cert.verify_is_valid_for_dns_name(name).is_err() {
            return Err(anyhow!("The server certificate is not \
                                             valid for the given name"
                .to_string(),));
        }
    }

    Ok(())
}

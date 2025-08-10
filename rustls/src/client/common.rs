use std::string::ToString;

use alloc::boxed::Box;
use alloc::vec::Vec;
use log::error;

use super::ResolvesClientCert;
use crate::crypto::hash;
use crate::log::{debug, trace};
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::{CertificateChain, DistinguishedName, ProtocolName, ServerExtension};
use crate::sync::Arc;
use crate::{compress, sign, AttestationRequest, AttestationResponse, attestation::AttestationConfig, Error, SignatureScheme};

#[derive(Debug)]
pub(super) struct ServerCertDetails<'a> {
    pub(super) cert_chain: CertificateChain<'a>,
    pub(super) ocsp_response: Vec<u8>,
}

impl<'a> ServerCertDetails<'a> {
    pub(super) fn new(cert_chain: CertificateChain<'a>, ocsp_response: Vec<u8>) -> Self {
        Self {
            cert_chain,
            ocsp_response,
        }
    }

    pub(super) fn into_owned(self) -> ServerCertDetails<'static> {
        let Self {
            cert_chain,
            ocsp_response,
        } = self;
        ServerCertDetails {
            cert_chain: cert_chain.into_owned(),
            ocsp_response,
        }
    }
}

pub(super) struct ClientHelloDetails {
    pub(super) alpn_protocols: Vec<ProtocolName>,
    pub(super) sent_extensions: Vec<ExtensionType>,
    pub(super) extension_order_seed: u16,
    pub(super) offered_cert_compression: bool,
}

impl ClientHelloDetails {
    pub(super) fn new(alpn_protocols: Vec<ProtocolName>, extension_order_seed: u16) -> Self {
        Self {
            alpn_protocols,
            sent_extensions: Vec::new(),
            extension_order_seed,
            offered_cert_compression: false,
        }
    }

    pub(super) fn server_sent_unsolicited_extensions(
        &self,
        received_exts: &[ServerExtension],
        allowed_unsolicited: &[ExtensionType],
    ) -> bool {
        for ext in received_exts {
            let ext_type = ext.ext_type();
            if !self.sent_extensions.contains(&ext_type) && !allowed_unsolicited.contains(&ext_type)
            {
                trace!("Unsolicited extension {ext_type:?}");
                return true;
            }
        }

        false
    }
}

pub(super) enum ClientAuthDetails {
    /// Send an empty `Certificate` and no `CertificateVerify`.
    Empty { auth_context_tls13: Option<Vec<u8>> },
    /// Send a non-empty `Certificate` and a `CertificateVerify`.
    Verify {
        certkey: Arc<sign::CertifiedKey>,
        signer: Box<dyn sign::Signer>,
        auth_context_tls13: Option<Vec<u8>>,
        compressor: Option<&'static dyn compress::CertCompressor>,
        attestation_response: Option<AttestationResponse>,
    },
}

impl ClientAuthDetails {
    pub(super) fn resolve(
        resolver: &dyn ResolvesClientCert,
        canames: Option<&[DistinguishedName]>,
        sigschemes: &[SignatureScheme],
        auth_context_tls13: Option<Vec<u8>>,
        compressor: Option<&'static dyn compress::CertCompressor>,
        attestation_config: Option<&AttestationConfig>,
        server_attestation_request: Option<&AttestationRequest>,
        transcript_hash: Option<&hash::Output>,
        dhe_secret: Option<&[u8]>,
        hash_provider: Option<&'static dyn hash::Hash>,
    ) -> Result<Self, Error> {
        let acceptable_issuers = canames
            .unwrap_or_default()
            .iter()
            .map(|p| p.as_ref())
            .collect::<Vec<&[u8]>>();

        if let Some(certkey) = resolver.resolve(&acceptable_issuers, sigschemes) {
            if let Some(signer) = certkey.key.choose_scheme(sigschemes) {
                debug!("Attempting client auth");
                
                let attestation_response = if let (Some(config), Some(server_request)) = 
                    (attestation_config, server_attestation_request) {
                    if config.report_generator.get_attestation_type() == server_request.attestation_type {
                        
                        if let (Some(transcript), Some(secret), Some(hash_prov)) = 
                            (transcript_hash, dhe_secret, hash_provider) {
                            
                            let linking_hash = crate::attestation::compute_linking_hash(
                                transcript,
                                secret,
                                &server_request.nonce, 
                                hash_prov,
                            );
                            
                            Some(config.report_generator.generate_report(
                                &server_request.data,   
                                linking_hash.as_ref()    
                            )?)
                        } else {
                            error!("Missing parameters for linking hash computation");
                            return Err(Error::AttestationGenerationFailed(
                                "Cannot compute linking hash: missing transcript, DHE secret, or hash provider".to_string()
                            ));
                        }
                    } else {
                        debug!("Server requested different attestation type than client supports");
                        None
                    }
                } else {
                    None
                };

                return Ok(Self::Verify {
                    certkey,
                    signer,
                    auth_context_tls13,
                    compressor,
                    attestation_response,
                });
            }
        }

        debug!("Client auth requested but no cert/sigscheme available");
        Ok(Self::Empty { auth_context_tls13 })
    }
}

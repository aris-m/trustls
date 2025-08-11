use std::vec;

use tss_esapi::{
    structures::{Attest, Signature, Public, AttestInfo},
    abstraction::{
        ak::{create_ak, load_ak}, ek::create_ek_public_from_default_template,
    }, handles::KeyHandle, interface_types::{
        algorithm::{HashingAlgorithm, SignatureSchemeAlgorithm}, resource_handles::Hierarchy}, structures::{
        Data, HashScheme, PcrSelectionListBuilder, PcrSlot, SignatureScheme,
    }, tcti_ldr::TctiNameConf, traits::{Marshall, UnMarshall}, Context
};
use sha2::{Sha256, Digest};
use rsa::{Pss, RsaPublicKey};
use subtle::ConstantTimeEq;
use log::{debug, warn, info, error};
use alloc::vec::Vec;
use alloc::string::ToString;
use alloc::format; 

use crate::attestation::{
    AttestationType, AttestationResponse,
    AttestationReportGenerator, AttestationReportVerifier,
};

use crate::Error;

#[derive(Debug)]
pub struct TpmReportGenerator;

impl AttestationReportGenerator for TpmReportGenerator {
    fn get_attestation_type(&self) -> AttestationType {
        AttestationType::TPM
    }

    fn generate_report(&self, pcr_selection: &[u8], linking_hash: &[u8]) -> Result<AttestationResponse, Error> {
        debug!("Generating TPM Report with linking hash");
        
        let (report, signature, ak_cert) = get_tpm_report(linking_hash, pcr_selection)?;
        
        Ok(AttestationResponse::new(
            report,
            signature,
            ak_cert,
            self.get_attestation_type(),
        ))
    }
}

#[derive(Debug)]
pub struct TpmReportVerifier;

impl AttestationReportVerifier for TpmReportVerifier {
    fn get_attestation_type(&self) -> AttestationType {
        AttestationType::TPM
    }

    fn verify_report(&self, response: &AttestationResponse, expected_linking_hash: &[u8]) -> Result<bool, Error> {
        debug!("Verifying TPM report with linking hash");
        
        let result = verify_tpm_report(
            &response.report, 
            &response.signature, 
            &response.certificate_chain, 
            expected_linking_hash
        )?;
        
        Ok(result)
    }
}

pub fn get_tpm_report(linking_hash: &[u8], pcr_selection: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Error> {
    read_with_attestation_key(linking_hash, pcr_selection)
        .map_err(|e| {
            error!("TPM attestation failed: {:?}", e);
            Error::AttestationGenerationFailed(format!("TPM attestation failed: {:?}", e))
        })
}

fn read_with_attestation_key(linking_hash: &[u8], pcr_selection: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Error> {
    let tcti = TctiNameConf::Swtpm(Default::default());
    let mut ctx = Context::new(tcti)
        .map_err(|e| Error::AttestationGenerationFailed(format!("TPM connection failed: {:?}", e)))?;

    debug!("Creating attestation key...");

    let ak_handle = create_attestation_key(&mut ctx)?;

    let pcr_slots: Vec<PcrSlot> = pcr_selection
        .iter()
        .filter_map(|&i| PcrSlot::try_from(i as u32).ok())
        .collect();

    let slots_to_read = if pcr_slots.is_empty() {
        vec![PcrSlot::Slot0, PcrSlot::Slot1]
    } else {
        pcr_slots
    };

    let pcr_selection_list = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &slots_to_read)
        .build()
        .map_err(|e| Error::AttestationGenerationFailed(format!("PCR selection failed: {:?}", e)))?;

    let qualifying_data = Data::try_from(linking_hash.to_vec()) 
        .map_err(|e| Error::AttestationGenerationFailed(format!("Linking hash conversion failed: {:?}", e)))?;

    let signature_scheme = SignatureScheme::RsaPss {
        hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
    };

    debug!("Generating TPM quote with attestation key...");

    let (quoted_data, signature) = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.quote(ak_handle, qualifying_data, signature_scheme, pcr_selection_list)
        })
        .map_err(|e| Error::AttestationGenerationFailed(format!("TPM quote failed: {:?}", e)))?;

    let (ak_public, _, _) = ctx
        .execute_with_nullauth_session(|ctx| ctx.read_public(ak_handle))
        .map_err(|e| Error::AttestationGenerationFailed(format!("Failed to read AK public: {:?}", e)))?;

    let quoted_bytes = quoted_data.marshall()
        .map_err(|e| Error::AttestationGenerationFailed(format!("Failed to serialize quote: {:?}", e)))?;
    
    let signature_bytes = signature.marshall()
        .map_err(|e| Error::AttestationGenerationFailed(format!("Failed to serialize signature: {:?}", e)))?;
    
    let ak_public_bytes = ak_public.marshall()
        .map_err(|e| Error::AttestationGenerationFailed(format!("Failed to serialize AK public: {:?}", e)))?;

    let mut report = Vec::new();
    report.extend_from_slice(linking_hash);
    report.extend_from_slice(&quoted_bytes);

    info!("TPM attestation report: {} bytes (quote: {})", report.len(), quoted_bytes.len());

    let _ = ctx.execute_with_nullauth_session(|ctx| -> Result<(), tss_esapi::Error> {
        ctx.flush_context(ak_handle.into())?;
        Ok(())
    });

    Ok((report, signature_bytes, ak_public_bytes))
}

fn create_attestation_key(ctx: &mut Context) -> Result<KeyHandle, Error> {
    let hash_alg = HashingAlgorithm::Sha256;
    let sign_alg = SignatureSchemeAlgorithm::RsaPss;

    let ek_template = create_ek_public_from_default_template(
        tss_esapi::interface_types::algorithm::AsymmetricAlgorithm::Rsa, 
        None
    ).map_err(|e| Error::AttestationGenerationFailed(format!("EK template failed: {:?}", e)))?;

    let ek_handle = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Endorsement, ek_template, None, None, None, None)
        })
        .map_err(|e| Error::AttestationGenerationFailed(format!("EK creation failed: {:?}", e)))?
        .key_handle;

    let ak_result = create_ak(ctx, ek_handle, hash_alg, sign_alg, None, tss_esapi::abstraction::DefaultKeyImpl)
        .map_err(|e| Error::AttestationGenerationFailed(format!("AK creation failed: {:?}", e)))?;

    let ak_handle = load_ak(ctx, ek_handle, None, ak_result.out_private, ak_result.out_public)
        .map_err(|e| Error::AttestationGenerationFailed(format!("AK load failed: {:?}", e)))?;

    debug!("Attestation key created successfully");

    let _ = ctx.execute_with_nullauth_session(|ctx| -> Result<(), tss_esapi::Error> {
        ctx.flush_context(ek_handle.into())?;
        Ok(())
    });

    Ok(ak_handle)
}

pub fn verify_tpm_report(
    report: &[u8], 
    signature: &[u8], 
    ak_public_bytes: &[u8],
    expected_linking_hash: &[u8]
) -> Result<bool, Error> {
    debug!("Starting TPM report verification");
    debug!("Report length: {}", report.len());
    debug!("Expected linking hash length: {}", expected_linking_hash.len());
    
    if signature.is_empty() || ak_public_bytes.is_empty() || report.is_empty() {
        warn!("Invalid input: empty signature, public key, or report");
        return Ok(false);
    }
    
    if !verify_linking_hash(report, expected_linking_hash)? {
        warn!("Quote verification failed: linking hash mismatch");
        return Ok(false);
    }
    let (attest, signature_struct, ak_public) = match parse_tpm_structures(
        report, 
        signature, 
        ak_public_bytes,
        expected_linking_hash  
    ) {
        Ok(structures) => structures,
        Err(e) => {
            warn!("Failed to parse TPM structures: {:?}", e);
            return Ok(false);
        }
    };

    if !verify_quote_signature(&attest, &signature_struct, &ak_public)? {
        warn!("Quote verification failed: invalid signature");
        return Ok(false);
    }
    
    if !validate_pcr_digest(&attest)? { 
        warn!("Quote verification failed: PCR validation failed");
        return Ok(false);
    }
    
    info!("TPM quote verification successful");
    Ok(true)
}

fn verify_linking_hash(report: &[u8], expected_linking_hash: &[u8]) -> Result<bool, Error> {
    if report.len() < expected_linking_hash.len() {
        return Ok(false);
    }
    
    let report_linking_hash = &report[..expected_linking_hash.len()];
    
    let matches = report_linking_hash.ct_eq(expected_linking_hash).into();
    
    if matches {
        debug!("Linking hash verification: OK");
    } else {
        warn!("Linking hash verification: FAIL");
    }
    Ok(matches)
}

fn parse_tpm_structures(
    report: &[u8], 
    signature: &[u8], 
    ak_public_bytes: &[u8],
    expected_linking_hash: &[u8]  
) -> Result<(Attest, Signature, Public), Error> {
    if report.is_empty() {
        return Err(Error::AttestationVerificationFailed("Report too short".to_string()));
    }

    if signature.is_empty() {
        return Err(Error::AttestationVerificationFailed("Empty signature".to_string()));
    }
    
    if ak_public_bytes.is_empty() {
        return Err(Error::AttestationVerificationFailed("Empty public key".to_string()));
    }
    
    let linking_hash_len = expected_linking_hash.len();
    
    debug!("Parsing TPM structures:");
    debug!("  Report length: {}", report.len());
    debug!("  Linking hash length: {}", linking_hash_len);
    
    if report.len() <= linking_hash_len {
        return Err(Error::AttestationVerificationFailed(
            format!("Report too short: {} <= {}", report.len(), linking_hash_len)
        ));
    }
    
    let quote_data = &report[linking_hash_len..];
    debug!("  Quote data length: {}", quote_data.len());
    debug!("  Quote data first 16 bytes: {:02x?}", &quote_data[..16.min(quote_data.len())]);
    
    let attest = Attest::unmarshall(quote_data)
        .map_err(|e| Error::AttestationVerificationFailed(format!("Failed to parse attestation: {:?}", e)))?;
    
    let signature_struct = Signature::unmarshall(signature)
        .map_err(|e| Error::AttestationVerificationFailed(format!("Failed to parse signature: {:?}", e)))?;
    
    let ak_public = Public::unmarshall(ak_public_bytes)
        .map_err(|e| Error::AttestationVerificationFailed(format!("Failed to parse AK public: {:?}", e)))?;
    
    Ok((attest, signature_struct, ak_public))
}

fn verify_quote_signature(
    attest: &Attest,
    signature: &Signature, 
    ak_public: &Public
) -> Result<bool, Error> {
    let rsa_key = match extract_rsa_public_key(ak_public) {
        Ok(key) => key,
        Err(e) => {
            warn!("Failed to extract RSA public key: {:?}", e);
            return Ok(false);
        }
    };

    let attest_bytes = attest.marshall()
        .map_err(|e| Error::AttestationVerificationFailed(format!("Failed to marshal attest: {:?}", e)))?;
    
    let mut hasher = Sha256::new();
    hasher.update(&attest_bytes);
    let message_digest = hasher.finalize();

    let sig_bytes = match extract_signature_bytes(signature) {
        Ok(bytes) => {
            if bytes.len() < 64 {
                warn!("Signature too short: {} bytes", bytes.len());
                return Ok(false);
            }
            bytes
        },
        Err(e) => {
            warn!("Failed to extract signature bytes: {:?}", e);
            return Ok(false);
        }
    };

    let padding = Pss::new::<Sha256>();
    
    debug!("Signature verification details:");
    debug!("  Attest bytes length: {}", attest_bytes.len());
    debug!("  Message digest: {:02x?}", &message_digest[..8]);
    debug!("  Signature bytes length: {}", sig_bytes.len());
    
    match rsa_key.verify(padding, &message_digest, &sig_bytes) {
        Ok(()) => {
            debug!("Signature verification: OK");
            Ok(true)
        },
        Err(e) => {
            warn!("Signature verification: FAIL - {:?}", e);
            Ok(false)
        }
    }
}

fn extract_rsa_public_key(ak_public: &Public) -> Result<RsaPublicKey, Error> {
    let public_key: tss_esapi::utils::PublicKey = ak_public.clone().try_into()
        .map_err(|e| Error::AttestationVerificationFailed(format!("Conversion failed: {:?}", e)))?;
    
    let rsa_modulus = match public_key {
        tss_esapi::utils::PublicKey::Rsa(rsa_key) => rsa_key,
        _ => return Err(Error::AttestationVerificationFailed("AK is not RSA key".to_string())),
    };

    let exponent = rsa::BigUint::from(65537u32);
    let modulus = rsa::BigUint::from_bytes_be(rsa_modulus.as_slice());

    RsaPublicKey::new(modulus, exponent)
        .map_err(|e| Error::AttestationVerificationFailed(format!("Invalid RSA key: {:?}", e)))
}

fn extract_signature_bytes(signature: &Signature) -> Result<Vec<u8>, Error> {
    let sig_bytes = match signature {
        Signature::RsaPss(rsa_sig) => {
            let bytes = rsa_sig.signature().as_slice().to_vec();
            if bytes.is_empty() {
                return Err(Error::AttestationVerificationFailed("Empty RSA-PSS signature".to_string()));
            }
            if bytes.len() < 32 {
                return Err(Error::AttestationVerificationFailed("RSA-PSS signature too short".to_string()));
            }
            bytes
        },
        Signature::RsaSsa(rsa_sig) => {
            let bytes = rsa_sig.signature().as_slice().to_vec();
            if bytes.is_empty() {
                return Err(Error::AttestationVerificationFailed("Empty RSA-SSA signature".to_string()));
            }
            if bytes.len() < 32 {
                return Err(Error::AttestationVerificationFailed("RSA-SSA signature too short".to_string()));
            }
            bytes
        },
        Signature::Null => {
            return Err(Error::AttestationVerificationFailed("Null signature not valid for TPM quotes".to_string()));
        },
        _ => {
            return Err(Error::AttestationVerificationFailed("Unsupported signature type for TPM quotes".to_string()));
        },
    };

    Ok(sig_bytes)
}

fn validate_pcr_digest(attest: &Attest) -> Result<bool, Error> {
    let attested_info = attest.attested();

    let quote_info = match attested_info {
        AttestInfo::Quote { info } => info,
        _ => {
            warn!("PCR validation failed: not a quote attestation");
            return Ok(false);
        }
    };

    let pcr_selection = quote_info.pcr_selection();
    if pcr_selection.is_empty() {
        warn!("PCR validation failed: no PCRs selected");
        return Ok(false);
    }

    let pcr_digest = quote_info.pcr_digest();
    if pcr_digest.len() != 32 {
        warn!("PCR validation failed: invalid digest length");
        return Ok(false);
    }

    debug!("PCR validation: OK");

    Ok(true)
}
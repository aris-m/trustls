use crate::msgs::codec::{Codec, Reader};
use crate::error::{InvalidMessage, Error};
use alloc::vec::Vec;
use log::debug;
use core::fmt::Debug;
use std::sync::Arc;
use std::vec;

#[derive(Debug, Clone)]
pub struct TpmAttestationRequest {  
    pub nonce: Vec<u8>,  
    pub pcr_selection: Vec<u8>,  
}

#[derive(Debug, Clone)]
pub struct TpmAttestationResponse {
    pub report: Vec<u8>, 
    pub signature: Vec<u8>, 
    pub ak_cert: Vec<u8>,  
}

// Trait for generating TPM reports (used by both client and server)
pub trait TpmReportGenerator: Debug + Send + Sync {
    fn generate_report(&self, client_nonce: &[u8], pcr_selection: &[u8]) -> Result<TpmAttestationResponse, Error>;
}

// New trait for verifying TPM reports (used by client to verify server reports)
pub trait TpmReportVerifier: Debug + Send + Sync {
    fn verify_report(&self, response: &TpmAttestationResponse, expected_nonce: &[u8]) -> Result<bool, Error>;
}

// Client-side TPM configuration
#[derive(Clone, Debug)]
pub struct ClientTpmConfig {
    pub request: TpmAttestationRequest,
    pub verifier: Arc<dyn TpmReportVerifier>,
    pub report_generator: Arc<dyn TpmReportGenerator>,
}

// Server-side TPM configuration (existing)
#[derive(Clone, Debug)]
pub struct ServerTpmAttestation {
    pub request: TpmAttestationRequest,
    pub report_generator: Arc<dyn TpmReportGenerator>,
}

// Mock implementations for testing
#[derive(Debug)]
pub struct MockTpmReportGenerator;

impl TpmReportGenerator for MockTpmReportGenerator {
    fn generate_report(&self, client_nonce: &[u8], pcr_selection: &[u8]) -> Result<TpmAttestationResponse, Error> {
        debug!("MockTpmReportGenerator: Generating report for nonce: {:?}", client_nonce);
        
        let mut report = vec![0u8; 64];
        // Include the nonce in the report for verification
        report[..client_nonce.len().min(32)].copy_from_slice(&client_nonce[..client_nonce.len().min(32)]);
        
        // Mock signature and certificate
        let signature = vec![0u8; 256];  
        let ak_cert = vec![0u8; 512];    
        
        Ok(TpmAttestationResponse::new(report, signature, ak_cert))
    }
}

#[derive(Debug)]
pub struct MockTpmReportVerifier;

impl TpmReportVerifier for MockTpmReportVerifier {
    fn verify_report(&self, response: &TpmAttestationResponse, expected_nonce: &[u8]) -> Result<bool, Error> {
        debug!("MockTpmReportVerifier: Verifying report with expected nonce: {:?}", expected_nonce);
        
        // Simple verification: check if the nonce is present in the report
        if response.report.len() >= expected_nonce.len() {
            let report_nonce = &response.report[..expected_nonce.len().min(32)];
            let verification_result = report_nonce == &expected_nonce[..expected_nonce.len().min(32)];
            
            debug!("MockTpmReportVerifier: Verification result: {}", verification_result);
            debug!("MockTpmReportVerifier: Report size: {}, Signature size: {}, Cert size: {}", 
                     response.report.len(), response.signature.len(), response.ak_cert.len());
            
            Ok(verification_result)
        } else {
            debug!("MockTpmReportVerifier: Report too small");
            Ok(false)
        }
    }
}

// Existing implementations remain the same
impl TpmAttestationRequest {
    pub fn new(nonce: Vec<u8>, pcr_selection: Vec<u8>) -> Self {  
        Self {
            nonce,
            pcr_selection,
        }
    }
}

impl TpmAttestationResponse {
    pub fn new(report: Vec<u8>, signature: Vec<u8>, ak_cert: Vec<u8>) -> Self {
        Self {
            report,
            signature,
            ak_cert,
        }
    }
}

// Codec implementations remain the same...
impl Codec<'_> for TpmAttestationRequest {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (self.nonce.len() as u16).encode(bytes);
        bytes.extend_from_slice(&self.nonce);
        
        (self.pcr_selection.len() as u16).encode(bytes);
        bytes.extend_from_slice(&self.pcr_selection);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let nonce_len = u16::read(r)? as usize;
        let nonce = r.take(nonce_len)
            .ok_or(InvalidMessage::MissingData("nonce"))?
            .to_vec();
        
        let pcr_len = u16::read(r)? as usize;
        let pcr_selection = r.take(pcr_len)
            .ok_or(InvalidMessage::MissingData("pcr_selection"))?
            .to_vec();
        
        Ok(Self {
            nonce,
            pcr_selection,
        })
    }
}

impl Codec<'_> for TpmAttestationResponse {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (self.report.len() as u16).encode(bytes);
        bytes.extend_from_slice(&self.report);
        
        (self.signature.len() as u16).encode(bytes);
        bytes.extend_from_slice(&self.signature);
        
        (self.ak_cert.len() as u16).encode(bytes);
        bytes.extend_from_slice(&self.ak_cert);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let report_len = u16::read(r)? as usize;
        let report = r.take(report_len)
            .ok_or(InvalidMessage::MissingData("report"))?
            .to_vec();
        
        let sig_len = u16::read(r)? as usize;
        let signature = r.take(sig_len)
            .ok_or(InvalidMessage::MissingData("signature"))?
            .to_vec();
        
        let cert_len = u16::read(r)? as usize;
        let ak_cert = r.take(cert_len)
            .ok_or(InvalidMessage::MissingData("ak_cert"))?
            .to_vec();
        
        Ok(Self {
            report,
            signature,
            ak_cert,
        })
    }
}
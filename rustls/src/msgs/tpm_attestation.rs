use crate::msgs::codec::{Codec, Reader};
use crate::error::{InvalidMessage, Error};
use alloc::vec::Vec;
use core::fmt::Debug;
use std::sync::Arc;

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

pub trait TpmReportGenerator: Debug + Send + Sync {
    fn generate_report(&self, client_nonce: &[u8], pcr_selection: &[u8]) -> Result<TpmAttestationResponse, Error>;
}

#[derive(Clone, Debug)]
pub struct ServerTpmAttestation {
    pub request: TpmAttestationRequest,
    pub report_generator: Arc<dyn TpmReportGenerator>,
}

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
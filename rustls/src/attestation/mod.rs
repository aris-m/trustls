use crate::msgs::codec::{Codec, Reader};
use crate::error::{InvalidMessage, Error};
use alloc::vec::Vec;
use alloc::string::{String, ToString};
use alloc::format; 
use core::fmt::{self, Display, Debug}; 
use std::sync::Arc;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttestationType(pub u32);

impl AttestationType {
    pub const TPM: AttestationType = AttestationType(0x0001);
    pub const SGX: AttestationType = AttestationType(0x0002);
    pub const SEV: AttestationType = AttestationType(0x0003);
    pub const CUSTOM_START: u32 = 0x0004;
    
    pub const fn custom(id: u32) -> Self {
        AttestationType(Self::CUSTOM_START + id)
    }

    pub fn description(&self) -> &'static str {
        match self.0 {
            0x0001 => "Trusted Platform Module 2.0",
            0x0002 => "Intel Software Guard Extensions",
            0x0003 => "AMD Secure Encrypted Virtualization",
            _ if self.0 >= Self::CUSTOM_START => "Custom Attestation Technology",
            _ => "Unknown Attestation Technology",
        }
    }

    pub fn short_name(&self) -> String {
        match self.0 {
            0x0001 => "TPM".to_string(),
            0x0002 => "SGX".to_string(),
            0x0003 => "SEV".to_string(),
            _ if self.0 >= Self::CUSTOM_START => format!("Custom-{:04X}", self.0 - Self::CUSTOM_START),
            _ => "Unknown".to_string(),
        }
    }

    pub fn is_custom(&self) -> bool {
        self.0 >= Self::CUSTOM_START
    }

    pub fn custom_id(&self) -> Option<u32> {
        if self.is_custom() {
            Some(self.0 - Self::CUSTOM_START)
        } else {
            None
        }
    }
}

impl Display for AttestationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0x0001 => write!(f, "TPM"),
            0x0002 => write!(f, "SGX"),
            0x0003 => write!(f, "SEV"),
            0x0004 => write!(f, "TrustZone"),
            0x0005 => write!(f, "RA-TLS"),
            _ if self.0 >= Self::CUSTOM_START => {
                write!(f, "Custom(0x{:04X})", self.0 - Self::CUSTOM_START)
            },
            _ => write!(f, "Unknown"),
        }
    }
}

impl Debug for AttestationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "AttestationType {{ name: \"{}\", id: 0x{:04X}, description: \"{}\" }}", 
                   self, self.0, self.description())
        } else {
            write!(f, "{}", self)
        }
    }
}

impl From<u32> for AttestationType {
    fn from(value: u32) -> Self {
        AttestationType(value)
    }
}

impl From<AttestationType> for u32 {
    fn from(value: AttestationType) -> u32 {
        value.0
    }
}

#[derive(Debug, Clone)]
pub struct AttestationRequest {
    pub nonce: Vec<u8>,
    pub attestation_type: AttestationType,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AttestationResponse {
    pub report: Vec<u8>,
    pub signature: Vec<u8>,
    pub certificate_chain: Vec<u8>,
    pub attestation_type: AttestationType,
}

pub trait AttestationReportGenerator: Debug + Send + Sync {
    fn get_attestation_type(&self) -> AttestationType;
    fn generate_report(&self, nonce: &[u8], tech_specific_data: &[u8]) -> Result<AttestationResponse, Error>;
}

pub trait AttestationReportVerifier: Debug + Send + Sync {
    fn get_attestation_type(&self) -> AttestationType;
    fn verify_report(&self, response: &AttestationResponse, expected_nonce: &[u8]) -> Result<bool, Error>;
}

#[derive(Clone, Debug)]
pub struct AttestationConfig {
    pub request: AttestationRequest,
    pub verifier: Arc<dyn AttestationReportVerifier>,
    pub report_generator: Arc<dyn AttestationReportGenerator>,
}

impl AttestationRequest {
    pub fn new(nonce: Vec<u8>, attestation_type: AttestationType, data: Vec<u8>) -> Self {
        Self {
            nonce,
            attestation_type,
            data,
        }
    }
}

impl AttestationResponse {
    pub fn new(report: Vec<u8>, signature: Vec<u8>, certificate_chain: Vec<u8>, attestation_type: AttestationType) -> Self {
        Self {
            report,
            signature,
            certificate_chain,
            attestation_type,
        }
    }
}

impl Codec<'_> for AttestationRequest {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (self.nonce.len() as u16).encode(bytes);
        bytes.extend_from_slice(&self.nonce);
        
        (self.attestation_type.0).encode(bytes);
        
        (self.data.len() as u16).encode(bytes);
        bytes.extend_from_slice(&self.data);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let nonce_len = u16::read(r)? as usize;
        let nonce = r.take(nonce_len)
            .ok_or(InvalidMessage::MissingData("nonce"))?
            .to_vec();
        
        let attestation_type_raw = u32::read(r)?;
        let attestation_type = AttestationType(attestation_type_raw);
        
        let tech_data_len = u16::read(r)? as usize;
        let data = r.take(tech_data_len)
            .ok_or(InvalidMessage::MissingData("data"))?
            .to_vec();
        
        Ok(Self {
            nonce,
            attestation_type,
            data,
        })
    }
}

impl Codec<'_> for AttestationResponse {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (self.report.len() as u16).encode(bytes);
        bytes.extend_from_slice(&self.report);
        
        (self.signature.len() as u16).encode(bytes);
        bytes.extend_from_slice(&self.signature);
        
        (self.certificate_chain.len() as u16).encode(bytes);
        bytes.extend_from_slice(&self.certificate_chain);
        
        (self.attestation_type.0).encode(bytes);
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
        let certificate_chain = r.take(cert_len)
            .ok_or(InvalidMessage::MissingData("certificate_chain"))?
            .to_vec();
        
        let attestation_type_raw = u32::read(r)?;
        let attestation_type = AttestationType(attestation_type_raw);
        
        Ok(Self {
            report,
            signature,
            certificate_chain,
            attestation_type,
        })
    }
}

pub mod tpm;
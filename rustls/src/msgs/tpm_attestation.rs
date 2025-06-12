use crate::msgs::codec::{Codec, Reader};
use crate::error::InvalidMessage;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct TpmAttestationRequest {  
    pub nonce: Vec<u8>,  
    pub pcr_selection: Vec<u8>,  
}

impl TpmAttestationRequest {
    pub fn new(nonce: Vec<u8>, pcr_selection: Vec<u8>) -> Self {  
        Self {
            nonce,
            pcr_selection,
        }
    }
}

impl Codec<'_> for TpmAttestationRequest {
    fn encode(&self, bytes: &mut Vec<u8>) {
        // Encode nonce length (2 bytes) + nonce
        (self.nonce.len() as u16).encode(bytes);
        bytes.extend_from_slice(&self.nonce);
        
        // Encode PCR selection length (2 bytes) + data
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
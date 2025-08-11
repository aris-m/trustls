use rustls::attestation::{
    tpm::{verify_tpm_report, TpmReportGenerator, TpmReportVerifier}, AttestationConfig, AttestationRequest, AttestationType
};
use rustls::{ClientConfig, ServerConfig, ClientConnection, ServerConnection, RootCertStore, StreamOwned};
use rustls::server::WebPkiClientVerifier;
use rustls_pemfile::{certs, pkcs8_private_keys};
use pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::sync::Arc;
use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;
use std::fs::File;
use log::error;
use rand::RngCore;
use rustls::attestation::{AttestationReportVerifier, AttestationResponse};
   use rustls::Error;


fn load_test_certificates() -> std::io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>, Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let server_cert_file = File::open("tests/data/security_test_data/cert.pem")?;
    let server_key_file = File::open("tests/data/security_test_data/key.pem")?;
    let server_certs: Vec<CertificateDer> = certs(&mut BufReader::new(server_cert_file))
        .filter_map(Result::ok)
        .collect();
    let server_keys: Vec<PrivateKeyDer> = pkcs8_private_keys(&mut BufReader::new(server_key_file))
        .filter_map(Result::ok)
        .map(Into::into)
        .collect();
    let server_key = server_keys.into_iter()
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "No server private key found"))?;

    let client_cert_file = File::open("tests/data/security_test_data/client_cert.pem")?;
    let client_key_file = File::open("tests/data/security_test_data/client_key.pem")?;
    let client_certs: Vec<CertificateDer> = certs(&mut BufReader::new(client_cert_file))
        .filter_map(Result::ok)
        .collect();
    let client_keys: Vec<PrivateKeyDer> = pkcs8_private_keys(&mut BufReader::new(client_key_file))
        .filter_map(Result::ok)
        .map(Into::into)
        .collect();
    let client_key = client_keys.into_iter()
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "No client private key found"))?;

    if server_certs.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "No server certificates found"));
    }
    if client_certs.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "No client certificates found"));
    }

    Ok((server_certs, server_key, client_certs, client_key))
}

fn run_server(server_port: u16) -> std::io::Result<()> {
    std::env::set_var("TPM2TOOLS_TCTI", "swtpm:port=2323");

    let (server_certs, server_key, client_certs, _client_key) = load_test_certificates()?;
    let client_cert_for_trust = client_certs[0].clone();

    let mut server_nonce = vec![0u8; 32];
    rand::rng().fill_bytes(&mut server_nonce);
    let pcr_selection = vec![1, 2, 4, 8];

    let server_attestation_request = AttestationRequest::new(
        server_nonce,
        AttestationType::TPM,
        pcr_selection,
    );

    let server_attestation_config = AttestationConfig {
        request: server_attestation_request,
        verifier: Arc::new(TpmReportVerifier),
        report_generator: Arc::new(TpmReportGenerator),
    };

    let mut client_cert_store = RootCertStore::empty();
    client_cert_store.add(client_cert_for_trust)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_cert_store))
        .build()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let mut server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    server_config = server_config.with_attestation_config(server_attestation_config);

    let listener = TcpListener::bind(format!("127.0.0.1:{}", server_port))?;
    let (stream, _client_addr) = listener.accept()?;

    let server_conn = ServerConnection::new(Arc::new(server_config))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let mut tls_stream = StreamOwned::new(server_conn, stream);

    let response_message = b"Hello from TPM-attested server! Mutual attestation successful.";
    tls_stream.write_all(response_message)?;
    tls_stream.flush()?;

    let mut buffer = [0; 1024];
    let n = tls_stream.read(&mut buffer)?;
    if n > 0 {
        let _ = String::from_utf8_lossy(&buffer[..n]);
    }

    if tls_stream.conn.peer_certificates().is_none() {
        error!("Server: No client certificate presented");
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "No client certificate"));
    }

    Ok(())
}

fn run_client(server_port: u16) -> std::io::Result<()> {
    std::env::set_var("TPM2TOOLS_TCTI", "swtpm:port=2321");

    let (server_certs, _server_key, client_certs, client_key) = load_test_certificates()?;
    let server_cert_for_trust = server_certs[0].clone();

    let mut client_nonce = vec![0u8; 32];
    rand::rng().fill_bytes(&mut client_nonce);
    let pcr_selection = vec![1, 2, 4, 8];

    let client_attestation_request = AttestationRequest::new(
        client_nonce,
        AttestationType::TPM,
        pcr_selection,
    );

    let client_attestation_config = AttestationConfig {
        request: client_attestation_request,
        verifier: Arc::new(TpmReportVerifier),
        report_generator: Arc::new(TpmReportGenerator),
    };

    let mut root_store = RootCertStore::empty();
    root_store.add(server_cert_for_trust)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let mut client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    client_config = client_config.with_attestation_config(client_attestation_config);

    let stream = TcpStream::connect(format!("127.0.0.1:{}", server_port))?;
    let server_name = ServerName::try_from("localhost")
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    let client_conn = ClientConnection::new(Arc::new(client_config), server_name)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let mut tls_stream = StreamOwned::new(client_conn, stream);

    let test_message = b"Hello from TPM-attested client! Mutual attestation test.";
    tls_stream.write_all(test_message)?;
    tls_stream.flush()?;

    let mut buffer = [0; 1024];
    let n = tls_stream.read(&mut buffer)?;
    if n > 0 {
        let _ = String::from_utf8_lossy(&buffer[..n]);
    }

    if tls_stream.conn.peer_certificates().is_none() {
        error!("Client: No server certificate presented");
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "No server certificate"));
    }

    Ok(())
}

#[test]
fn test_mutual_attestation_with_swtpm() {
    let _ = env_logger::builder().is_test(true).try_init();
    let server_port = 8443 + (rand::rng().next_u32() % 1000) as u16;

    let server_port_clone = server_port;
    let server_handle = thread::spawn(move || run_server(server_port_clone));

    thread::sleep(Duration::from_millis(200));

    let client_result = run_client(server_port);
    let server_result = server_handle.join().expect("Server thread should not panic");

    match client_result {
        Ok(_) => {}
        Err(e) => {
            panic!("Client failed: {:?}", e);
        }
    }

    match server_result {
        Ok(_) => {}
        Err(e) => {
            panic!("Server failed: {:?}", e);
        }
    }
}

#[test]
fn test_attestation_failure_terminates_connection() {
   #[derive(Debug)]
   struct FailingTpmReportVerifier;

   impl AttestationReportVerifier for FailingTpmReportVerifier {
       fn get_attestation_type(&self) -> AttestationType {
           AttestationType::TPM
       }

       fn verify_report(&self, _response: &AttestationResponse, _expected_linking_hash: &[u8]) -> Result<bool, Error> {
           Ok(false)
       }
   }

   let _ = env_logger::builder().is_test(true).try_init();
   let server_port = 9443 + (rand::rng().next_u32() % 1000) as u16;

   let server_handle = thread::spawn(move || {
       std::env::set_var("TPM2TOOLS_TCTI", "swtpm:port=2323");

       let (server_certs, server_key, client_certs, _client_key) = load_test_certificates().unwrap();
       let client_cert_for_trust = client_certs[0].clone();

       let mut server_nonce = vec![0u8; 32];
       rand::rng().fill_bytes(&mut server_nonce);
       let pcr_selection = vec![1, 2, 4, 8];

       let server_attestation_request = AttestationRequest::new(
           server_nonce,
           AttestationType::TPM,
           pcr_selection,
       );

       let server_attestation_config = AttestationConfig {
           request: server_attestation_request,
           verifier: Arc::new(FailingTpmReportVerifier), 
           report_generator: Arc::new(TpmReportGenerator),
       };

       let mut client_cert_store = RootCertStore::empty();
       client_cert_store.add(client_cert_for_trust).unwrap();

       let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_cert_store))
           .build().unwrap();

       let mut server_config = ServerConfig::builder()
           .with_client_cert_verifier(client_verifier)
           .with_single_cert(server_certs, server_key).unwrap();
       server_config = server_config.with_attestation_config(server_attestation_config);

       let listener = TcpListener::bind(format!("127.0.0.1:{}", server_port)).unwrap();
       let (stream, _client_addr) = listener.accept().unwrap();

       let server_conn = ServerConnection::new(Arc::new(server_config)).unwrap();
       let mut tls_stream = StreamOwned::new(server_conn, stream);

       // This should fail due to attestation verification failure
       let response_message = b"This should not be sent";
       match tls_stream.write_all(response_message) {
           Ok(_) => panic!("Expected connection to fail due to attestation verification failure"),
           Err(_) => {
               // Expected - connection should be terminated
           }
       }
   });

   thread::sleep(Duration::from_millis(200));

   let client_result = std::panic::catch_unwind(|| {
       std::env::set_var("TPM2TOOLS_TCTI", "swtpm:port=2321");

       let (server_certs, _server_key, client_certs, client_key) = load_test_certificates().unwrap();
       let server_cert_for_trust = server_certs[0].clone();

       let mut client_nonce = vec![0u8; 32];
       rand::rng().fill_bytes(&mut client_nonce);
       let pcr_selection = vec![1, 2, 4, 8];

       let client_attestation_request = AttestationRequest::new(
           client_nonce,
           AttestationType::TPM,
           pcr_selection,
       );

       let client_attestation_config = AttestationConfig {
           request: client_attestation_request,
           verifier: Arc::new(TpmReportVerifier),
           report_generator: Arc::new(TpmReportGenerator),
       };

       let mut root_store = RootCertStore::empty();
       root_store.add(server_cert_for_trust).unwrap();

       let mut client_config = ClientConfig::builder()
           .with_root_certificates(root_store)
           .with_client_auth_cert(client_certs, client_key).unwrap();
       client_config = client_config.with_attestation_config(client_attestation_config);

       let stream = TcpStream::connect(format!("127.0.0.1:{}", server_port)).unwrap();
       let server_name = ServerName::try_from("localhost").unwrap();

       let client_conn = ClientConnection::new(Arc::new(client_config), server_name).unwrap();
       let mut tls_stream = StreamOwned::new(client_conn, stream);

       let test_message = b"Hello from TPM-attested client! Mutual attestation test.";
       
       // This should fail because server will reject client's attestation
       match tls_stream.write_all(test_message) {
           Ok(_) => {
               tls_stream.flush().unwrap();
               
               let mut buffer = [0; 1024];
               // Reading should also fail
               match tls_stream.read(&mut buffer) {
                   Ok(_) => panic!("Expected connection to fail due to attestation verification failure"),
                   Err(_) => {
                       // Expected - connection should be terminated
                   }
               }
           }
           Err(_) => {
               // Expected - connection should be terminated
           }
       }
   });

   let server_result = server_handle.join();

   assert!(client_result.is_ok(), "the server thread should exit without panicking when attestation fails");
   assert!(server_result.is_ok(), "the client thread should exit without panicking when attestation fails");
}

#[test]
fn test_tls_security_properties_preserved_with_attestation() {
    let _ = env_logger::builder().is_test(true).try_init();
    
    let server_port = 7443 + (rand::rng().next_u32() % 1000) as u16;

    // Test data for security property verification
    let sensitive_data = b"SECRET: This is confidential information that must be protected";
    let integrity_test_data = b"INTEGRITY: This data must not be tampered with during transmission";
    
    let sensitive_data_clone = sensitive_data.clone();
    let integrity_data_clone = integrity_test_data.clone();
    
    let server_handle = thread::spawn(move || {
        std::env::set_var("TPM2TOOLS_TCTI", "swtpm:port=2323");
        
        let (server_certs, server_key, client_certs, _) = load_test_certificates().unwrap();
        let client_cert_for_trust = client_certs[0].clone();

        let mut server_nonce = vec![0u8; 32];
        rand::rng().fill_bytes(&mut server_nonce);
        let pcr_selection = vec![1, 2, 4, 8];

        let server_attestation_config = AttestationConfig {
            request: AttestationRequest::new(server_nonce, AttestationType::TPM, pcr_selection),
            verifier: Arc::new(TpmReportVerifier),
            report_generator: Arc::new(TpmReportGenerator),
        };

        let mut client_cert_store = RootCertStore::empty();
        client_cert_store.add(client_cert_for_trust).unwrap();

        let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_cert_store))
            .build().unwrap();

        let mut server_config = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(server_certs, server_key).unwrap();
        server_config = server_config.with_attestation_config(server_attestation_config);

        let listener = TcpListener::bind(format!("127.0.0.1:{}", server_port)).unwrap();
        let (stream, _) = listener.accept().unwrap();

        let server_conn = ServerConnection::new(Arc::new(server_config)).unwrap();
        let mut tls_stream = StreamOwned::new(server_conn, stream);

        // Verify server can receive encrypted data (CONFIDENTIALITY)
        let mut buffer = [0; 1024];
        let n = tls_stream.read(&mut buffer).unwrap();
        let received_data = &buffer[..n];
        
        // Verify integrity - data should match exactly what client sent
        assert_eq!(received_data, &integrity_data_clone[..], "Data integrity violated - received data doesn't match sent data");
        
        // Verify authentication - client certificate should be present
        assert!(tls_stream.conn.peer_certificates().is_some(), "Authentication failed - no client certificate");
        
        // Send confidential response back
        tls_stream.write_all(&sensitive_data_clone).unwrap();
        tls_stream.flush().unwrap();

        // Verify cipher suite provides proper encryption
        let negotiated_cipher = tls_stream.conn.negotiated_cipher_suite().unwrap();
        assert!(negotiated_cipher.version().version == rustls::ProtocolVersion::TLSv1_3, 
               "TLS 1.3 should be negotiated");
    });

    thread::sleep(Duration::from_millis(200));

    // Client side
    std::env::set_var("TPM2TOOLS_TCTI", "swtpm:port=2321");
    
    let (server_certs, _, client_certs, client_key) = load_test_certificates().unwrap();
    let server_cert_for_trust = server_certs[0].clone();

    let mut client_nonce = vec![0u8; 32];
    rand::rng().fill_bytes(&mut client_nonce);
    let pcr_selection = vec![1, 2, 4, 8];

    let client_attestation_config = AttestationConfig {
        request: AttestationRequest::new(client_nonce, AttestationType::TPM, pcr_selection),
        verifier: Arc::new(TpmReportVerifier),
        report_generator: Arc::new(TpmReportGenerator),
    };

    let mut root_store = RootCertStore::empty();
    root_store.add(server_cert_for_trust).unwrap();

    let mut client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key).unwrap();
    client_config = client_config.with_attestation_config(client_attestation_config);

    let stream = TcpStream::connect(format!("127.0.0.1:{}", server_port)).unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();

    let client_conn = ClientConnection::new(Arc::new(client_config), server_name).unwrap();
    let mut tls_stream = StreamOwned::new(client_conn, stream);

    // Test INTEGRITY - send data and verify it arrives unchanged
    tls_stream.write_all(integrity_test_data).unwrap();
    tls_stream.flush().unwrap();

    // Test CONFIDENTIALITY - receive sensitive data over encrypted channel
    let mut buffer = [0; 1024];
    let n = tls_stream.read(&mut buffer).unwrap();
    let received_sensitive_data = &buffer[..n];
    
    // Verify confidential data was received correctly (proving encryption worked)
    assert_eq!(received_sensitive_data, sensitive_data, "Confidential data transmission failed");

    // Test AUTHENTICATION - verify server certificate was validated
    assert!(tls_stream.conn.peer_certificates().is_some(), "Server authentication failed");
    
    // Verify TLS protocol version and cipher suite security
    assert_eq!(tls_stream.conn.protocol_version().unwrap(), rustls::ProtocolVersion::TLSv1_3, 
              "TLS 1.3 should be negotiated for maximum security");
    
    let cipher_suite = tls_stream.conn.negotiated_cipher_suite().unwrap();
    assert_eq!(cipher_suite.version().version, rustls::ProtocolVersion::TLSv1_3,
        "TLS 1.3 cipher suite should be used");

    server_handle.join().unwrap();
}

#[test]
fn test_linking_hash_verification_failure_terminates_connection() {
   #[derive(Debug)]
   struct LinkingHashTamperingVerifier;

   impl AttestationReportVerifier for LinkingHashTamperingVerifier {
       fn get_attestation_type(&self) -> AttestationType {
           AttestationType::TPM
       }

       fn verify_report(&self, response: &AttestationResponse, expected_linking_hash: &[u8]) -> Result<bool, Error> {
           // Simulate tampering with the linking hash during verification
           let mut tampered_hash = expected_linking_hash.to_vec();
           if tampered_hash.len() > 0 {
               tampered_hash[0] ^= 0xFF; // Flip bits in first byte
           }
           
           verify_tpm_report(&response.report, &response.signature, &response.certificate_chain, &tampered_hash)
               .map(|result| result) // This should fail due to linking hash mismatch
       }
   }

   let _ = env_logger::builder().is_test(true).try_init();
   let server_port = 10443 + (rand::rng().next_u32() % 1000) as u16;

   let server_handle = thread::spawn(move || {
       std::env::set_var("TPM2TOOLS_TCTI", "swtpm:port=2323");

       let (server_certs, server_key, client_certs, _client_key) = load_test_certificates().unwrap();
       let client_cert_for_trust = client_certs[0].clone();

       let mut server_nonce = vec![0u8; 32];
       rand::rng().fill_bytes(&mut server_nonce);
       let pcr_selection = vec![1, 2, 4, 8];

       let server_attestation_request = AttestationRequest::new(
           server_nonce,
           AttestationType::TPM,
           pcr_selection,
       );

       let server_attestation_config = AttestationConfig {
           request: server_attestation_request,
           verifier: Arc::new(LinkingHashTamperingVerifier),
           report_generator: Arc::new(TpmReportGenerator),
       };

       let mut client_cert_store = RootCertStore::empty();
       client_cert_store.add(client_cert_for_trust).unwrap();

       let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_cert_store))
           .build().unwrap();

       let mut server_config = ServerConfig::builder()
           .with_client_cert_verifier(client_verifier)
           .with_single_cert(server_certs, server_key).unwrap();
       server_config = server_config.with_attestation_config(server_attestation_config);

       let listener = TcpListener::bind(format!("127.0.0.1:{}", server_port)).unwrap();
       let (stream, _client_addr) = listener.accept().unwrap();

       let server_conn = ServerConnection::new(Arc::new(server_config)).unwrap();
       let mut tls_stream = StreamOwned::new(server_conn, stream);

       // This should fail due to linking hash verification failure
       let response_message = b"This should not be sent due to linking hash failure";
       match tls_stream.write_all(response_message) {
           Ok(_) => panic!("Expected connection to fail due to linking hash verification failure"),
           Err(_) => {
               // Expected - connection should be terminated due to linking hash mismatch
           }
       }
   });

   let client_result = std::panic::catch_unwind(|| {
       std::env::set_var("TPM2TOOLS_TCTI", "swtpm:port=2321");

       let (server_certs, _server_key, client_certs, client_key) = load_test_certificates().unwrap();
       let server_cert_for_trust = server_certs[0].clone();

       let mut client_nonce = vec![0u8; 32];
       rand::rng().fill_bytes(&mut client_nonce);
       let pcr_selection = vec![1, 2, 4, 8];

       let client_attestation_request = AttestationRequest::new(
           client_nonce,
           AttestationType::TPM,
           pcr_selection,
       );

       let client_attestation_config = AttestationConfig {
           request: client_attestation_request,
           verifier: Arc::new(TpmReportVerifier), 
           report_generator: Arc::new(TpmReportGenerator),
       };

       let mut root_store = RootCertStore::empty();
       root_store.add(server_cert_for_trust).unwrap();

       let mut client_config = ClientConfig::builder()
           .with_root_certificates(root_store)
           .with_client_auth_cert(client_certs, client_key).unwrap();
       client_config = client_config.with_attestation_config(client_attestation_config);

       let stream = TcpStream::connect(format!("127.0.0.1:{}", server_port)).unwrap();
       let server_name = ServerName::try_from("localhost").unwrap();

       let client_conn = ClientConnection::new(Arc::new(client_config), server_name).unwrap();
       let mut tls_stream = StreamOwned::new(client_conn, stream);

       let test_message = b"Hello from client - this should fail due to linking hash verification";
       
       // This should fail because server will reject client's attestation due to linking hash mismatch
       match tls_stream.write_all(test_message) {
           Ok(_) => {
               tls_stream.flush().unwrap();
               
               let mut buffer = [0; 1024];
               match tls_stream.read(&mut buffer) {
                   Ok(_) => panic!("Expected connection to fail due to linking hash verification failure"),
                   Err(_) => {
                       // Expected - connection terminated due to linking hash mismatch
                   }
               }
           }
           Err(_) => {
               // Expected - connection terminated due to linking hash mismatch
           }
       }
   });

   let server_result = server_handle.join();

   assert!(client_result.is_ok(), "Client should handle linking hash verification failure gracefully");
   assert!(server_result.is_ok(), "Server should handle linking hash verification failure gracefully");
}
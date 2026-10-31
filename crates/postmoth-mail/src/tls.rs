//! TLS connection setup. Plaintext IMAP is intentionally impossible.

use crate::error::{MailError, Result};
use crate::imap::ImapConnection;
use postmoth_core::model::{ServerEndpoint, TlsMode};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use secrecy::SecretString;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Default)]
pub struct TlsSettings {
    /// Extra PEM trust anchors (self-hosted servers, test servers). The
    /// system store is always used as well. There is no "accept invalid
    /// certificates" switch.
    pub extra_roots_pem: Vec<Vec<u8>>,
}

impl TlsSettings {
    pub fn client_config(&self) -> Result<Arc<rustls::ClientConfig>> {
        let mut roots = rustls::RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            // Individual bad system certs are skipped, not fatal.
            let _ = roots.add(cert);
        }
        for pem in &self.extra_roots_pem {
            for cert in CertificateDer::pem_slice_iter(pem) {
                let cert = cert.map_err(|e| MailError::Tls(format!("bad PEM: {e}")))?;
                roots
                    .add(cert)
                    .map_err(|e| MailError::Tls(format!("bad root: {e}")))?;
            }
        }
        if roots.is_empty() {
            return Err(MailError::Tls("no trusted root certificates".into()));
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| MailError::Tls(e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Arc::new(cfg))
    }
}

pub type ImapTls = TlsStream<TcpStream>;

async fn tcp(endpoint: &ServerEndpoint) -> Result<TcpStream> {
    let s = timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((endpoint.host.as_str(), endpoint.port)),
    )
    .await
    .map_err(|_| MailError::Timeout)??;
    s.set_nodelay(true)?;
    Ok(s)
}

async fn handshake(
    stream: TcpStream,
    host: &str,
    cfg: Arc<rustls::ClientConfig>,
) -> Result<ImapTls> {
    let name = ServerName::try_from(host.to_owned())
        .map_err(|_| MailError::Tls("invalid server name".into()))?;
    timeout(
        CONNECT_TIMEOUT,
        TlsConnector::from(cfg).connect(name, stream),
    )
    .await
    .map_err(|_| MailError::Timeout)?
    .map_err(|e| MailError::Tls(e.to_string()))
}

/// Connect and authenticate with LOGIN over TLS.
pub async fn connect_imap(
    endpoint: &ServerEndpoint,
    tls: &TlsSettings,
    login: &str,
    password: &SecretString,
) -> Result<ImapConnection<ImapTls>> {
    let cfg = tls.client_config()?;
    let stream = tcp(endpoint).await?;
    match endpoint.tls {
        TlsMode::Implicit => {
            let tls_stream = handshake(stream, &endpoint.host, cfg).await?;
            ImapConnection::login(tls_stream, true, login, password).await
        }
        TlsMode::StartTls => {
            let mut client = async_imap::Client::new(stream);
            timeout(CONNECT_TIMEOUT, client.read_response())
                .await
                .map_err(|_| MailError::Timeout)??
                .ok_or(MailError::ConnectionLost)?;
            client
                .run_command_and_check_ok("STARTTLS", None)
                .await
                .map_err(|_| MailError::StartTlsUnavailable)?;
            let tls_stream = handshake(client.into_inner(), &endpoint.host, cfg).await?;
            // No greeting after STARTTLS (RFC 3501 §6.2.1).
            ImapConnection::login(tls_stream, false, login, password).await
        }
    }
}

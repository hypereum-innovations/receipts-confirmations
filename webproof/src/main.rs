// SPDX-License-Identifier: Apache-2.0
//! hv-webproof: TLSNotary notary / prover / presenter / verifier for
//! Hivemind Receipts W3 web-proof confirmations.
//!
//! Adapted from the tlsn attestation examples (MIT OR Apache-2.0, see
//! NOTICE). Differences: notary and prover are separate processes speaking
//! over TCP with operator-supplied keys and roots; the verifier prints a
//! JSON verdict and refuses presentations whose notary key is not on the
//! caller's allowlist. A confirmation only reaches W3 upstream when this
//! verifier says the presentation is genuine *and* the notary key belongs
//! to the configured quorum.

use std::{future::IntoFuture, path::PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use http_body_util::Empty;
use hyper::{Request, body::Bytes};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use tlsn::{
    Session,
    attestation::{
        Attestation, AttestationConfig, CryptoProvider, Secrets,
        presentation::{Presentation, PresentationOutput},
        request::{Request as AttestationRequest, RequestConfig},
        signing::{Secp256k1Signer, VerifyingKey},
    },
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig, verifier::VerifierConfig,
    },
    connection::{CertBinding, ConnectionInfo, HandshakeData, ServerName, TranscriptLength},
    prover::ProverOutput,
    transcript::{ContentType, TranscriptCommitConfig},
    verifier::{ServerCertVerifier, VerifierCommitStart, VerifierOutput},
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};

const MAX_SENT_DATA: usize = 1 << 12;
const MAX_RECV_DATA: usize = 1 << 15;

#[derive(Parser)]
#[command(version, about = "TLSNotary web-proof tooling for Hivemind Receipts (W3)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the secp256k1 verifying key (compressed, hex) for a signing key file.
    NotaryPubkey {
        /// File with 32 raw bytes or 64 hex chars.
        #[arg(long)]
        signing_key: PathBuf,
    },
    /// Run a notary (TLS verifier + attestation signer) on a TCP socket.
    Notary {
        #[arg(long, default_value = "127.0.0.1:7047")]
        listen: String,
        #[arg(long)]
        signing_key: PathBuf,
        /// Extra DER root CA for the application server (private PKI). Repeatable.
        #[arg(long)]
        root_ca_der: Vec<PathBuf>,
    },
    /// Notarize one HTTPS GET through a notary; writes attestation + secrets.
    Prove {
        #[arg(long)]
        notary: String,
        #[arg(long)]
        server_host: String,
        #[arg(long)]
        server_port: u16,
        #[arg(long)]
        server_name: String,
        #[arg(long, default_value = "/")]
        uri: String,
        /// Extra request header "Name: value". Repeatable.
        #[arg(long)]
        header: Vec<String>,
        #[arg(long)]
        root_ca_der: Vec<PathBuf>,
        #[arg(long)]
        attestation_out: PathBuf,
        #[arg(long)]
        secrets_out: PathBuf,
    },
    /// Build a presentation from an attestation + secrets.
    Present {
        #[arg(long)]
        attestation: PathBuf,
        #[arg(long)]
        secrets: PathBuf,
        /// JSON leaf paths to reveal from a JSON response body (e.g. "information.name").
        /// Empty = reveal the whole response body.
        #[arg(long)]
        reveal_json: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a presentation. Prints a JSON verdict; exit 0 iff verified and trusted.
    Verify {
        #[arg(long)]
        presentation: PathBuf,
        /// Comma-separated trusted notary verifying keys (compressed hex).
        /// Empty = accept any key but report trusted=false.
        #[arg(long, default_value = "")]
        trusted_notary_keys: String,
        #[arg(long)]
        root_ca_der: Vec<PathBuf>,
    },
}

fn root_store(extra: &[PathBuf]) -> Result<RootCertStore> {
    // Default: webpki roots (empty vec means the provider default is used by
    // callers that pass None; here explicit roots replace them, matching the
    // upstream fixtures pattern for private PKIs).
    let mut roots = Vec::new();
    for p in extra {
        roots.push(CertificateDer(
            std::fs::read(p).with_context(|| format!("read root CA {}", p.display()))?,
        ));
    }
    Ok(RootCertStore { roots })
}

fn load_signing_key(path: &PathBuf) -> Result<[u8; 32]> {
    let raw = std::fs::read(path).with_context(|| format!("read signing key {}", path.display()))?;
    if raw.len() == 32 {
        let mut k = [0u8; 32];
        k.copy_from_slice(&raw);
        return Ok(k);
    }
    let text = String::from_utf8_lossy(&raw).trim().to_string();
    let bytes = hex::decode(text.strip_prefix("0x").unwrap_or(&text)).context("signing key is not 32 raw bytes or hex")?;
    if bytes.len() != 32 {
        bail!("signing key must be 32 bytes");
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    Ok(k)
}

fn notary_verifying_key_hex(signing_key: &[u8; 32]) -> Result<String> {
    let sk = k256::ecdsa::SigningKey::from_bytes(signing_key.into())?;
    let vk = sk.verifying_key().to_encoded_point(true);
    Ok(hex::encode(vk.as_bytes()))
}

// --- Notary -----------------------------------------------------------------

async fn run_notary_session<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: S,
    signing_key: [u8; 32],
    roots: RootCertStore,
) -> Result<()> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let verifier_config = if roots.roots.is_empty() {
        VerifierConfig::builder().build()?
    } else {
        VerifierConfig::builder().root_store(roots).build()?
    };

    let verifier = match handle.new_verifier(verifier_config)?.commit().await? {
        VerifierCommitStart::Mpc(verifier) => verifier.accept().await?.run().await?,
        VerifierCommitStart::Proxy(verifier) => {
            verifier.reject(Some("expecting to use MPC-TLS")).await?;
            bail!("protocol configuration rejected");
        }
    };

    let (VerifierOutput { transcript_commitments, .. }, verifier) =
        verifier.verify().await?.accept().await?;
    let tls_transcript = verifier.tls_transcript().clone();
    verifier.close().await?;

    let sent_len = tls_transcript
        .sent()
        .iter()
        .filter_map(|r| match r.typ {
            ContentType::ApplicationData => Some(r.ciphertext.len()),
            _ => None,
        })
        .sum::<usize>();
    let recv_len = tls_transcript
        .recv()
        .iter()
        .filter_map(|r| match r.typ {
            ContentType::ApplicationData => Some(r.ciphertext.len()),
            _ => None,
        })
        .sum::<usize>();

    handle.close();
    let mut socket = driver_task.await??;

    let mut request_bytes = Vec::new();
    socket.read_to_end(&mut request_bytes).await?;
    let request: AttestationRequest = bincode::deserialize(&request_bytes)?;

    let signer = Box::new(Secp256k1Signer::new(&signing_key)?);
    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(signer);

    let mut att_cfg_builder = AttestationConfig::builder();
    att_cfg_builder.supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()));
    let att_config = att_cfg_builder.build()?;

    let CertBinding::V1_2(binding) = tls_transcript.certificate_binding() else {
        bail!("unsupported cert binding version");
    };
    let mut builder = Attestation::builder(&att_config).accept_request(request)?;
    builder
        .connection_info(ConnectionInfo {
            time: tls_transcript.time(),
            version: tls_transcript.version(),
            transcript_length: TranscriptLength {
                sent: sent_len as u32,
                received: recv_len as u32,
            },
        })
        .server_ephemeral_key(binding.server_ephemeral_key.clone())
        .transcript_commitments(transcript_commitments);
    let attestation = builder.build(&provider)?;

    socket.write_all(&bincode::serialize(&attestation)?).await?;
    socket.close().await?;
    Ok(())
}

async fn cmd_notary(listen: String, key_path: PathBuf, root_cas: Vec<PathBuf>) -> Result<()> {
    let key = load_signing_key(&key_path)?;
    let roots = root_store(&root_cas)?;
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    println!(
        "{}",
        serde_json::json!({"notary_listening": listen, "verifying_key": notary_verifying_key_hex(&key)?})
    );
    loop {
        let (socket, _peer) = listener.accept().await?;
        socket.set_nodelay(true)?;
        let roots = RootCertStore { roots: roots.roots.iter().map(|c| CertificateDer(c.0.clone())).collect() };
        tokio::spawn(async move {
            if let Err(e) = run_notary_session(socket, key, roots).await {
                eprintln!("notary session failed: {e:#}");
            }
        });
    }
}

// --- Prover -----------------------------------------------------------------

#[derive(Serialize)]
struct ProveReport {
    server_name: String,
    uri: String,
    http_status: u16,
    response_body_sha256: String,
    attestation_path: String,
    secrets_path: String,
}

async fn cmd_prove(
    notary_addr: String,
    server_host: String,
    server_port: u16,
    server_name: String,
    uri: String,
    headers: Vec<String>,
    root_cas: Vec<PathBuf>,
    attestation_out: PathBuf,
    secrets_out: PathBuf,
) -> Result<()> {
    let roots = root_store(&root_cas)?;
    let notary_socket = tokio::net::TcpStream::connect(&notary_addr).await?;
    notary_socket.set_nodelay(true)?;

    let session = Session::new(notary_socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            MpcTlsConfig::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()?,
        )
        .await?;

    let client_socket = tokio::net::TcpStream::connect((server_host.as_str(), server_port)).await?;
    client_socket.set_nodelay(true)?;

    let tls_cfg = TlsClientConfig::builder()
        .server_name(ServerName::Dns(server_name.clone().try_into().map_err(|_| anyhow::anyhow!("bad server name"))?));
    let tls_cfg = if roots.roots.is_empty() { tls_cfg } else { tls_cfg.root_store(roots) };
    let (tls_connection, prover) = prover.connect(tls_cfg.build()?, client_socket.compat())?;
    let tls_connection = TokioIo::new(tls_connection.compat());
    let prover_task = tokio::spawn(prover.into_future());

    let (mut request_sender, connection) = hyper::client::conn::http1::handshake(tls_connection).await?;
    tokio::spawn(connection);

    let mut rb = Request::builder()
        .uri(&uri)
        .header("Host", &server_name)
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", "hv-webproof/0.1");
    for h in &headers {
        let (k, v) = h.split_once(':').context("header must be 'Name: value'")?;
        rb = rb.header(k.trim(), v.trim());
    }
    let response = request_sender.send_request(rb.body(Empty::<Bytes>::new())?).await?;
    let http_status = response.status().as_u16();

    let mut prover = prover_task.await??;
    let transcript = HttpTranscript::parse(prover.transcript())?;
    let body_bytes: Vec<u8> = transcript.responses[0]
        .body
        .as_ref()
        .map(|b| b.content_data().to_vec())
        .unwrap_or_default();
    let response_body_sha256 = hex::encode(Sha256::digest(&body_bytes));

    let mut commit_builder = TranscriptCommitConfig::builder(prover.transcript());
    DefaultHttpCommitter::default().commit_transcript(&mut commit_builder, &transcript)?;
    let transcript_commit = commit_builder.build()?;

    let mut rc_builder = RequestConfig::builder();
    rc_builder.transcript_commit(transcript_commit);
    let request_config = rc_builder.build()?;

    let mut prove_builder = ProveConfig::builder(prover.transcript());
    if let Some(config) = request_config.transcript_commit() {
        prove_builder.transcript_commit(config.clone());
    }
    let disclosure_config = prove_builder.build()?;
    let ProverOutput { transcript_commitments, transcript_secrets, .. } = prover.prove(&disclosure_config).await?;

    let prover_transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await?;

    let mut req_builder = AttestationRequest::builder(&request_config);
    req_builder
        .server_name(ServerName::Dns(server_name.clone().try_into().map_err(|_| anyhow::anyhow!("bad server name"))?))
        .handshake_data(HandshakeData {
            certs: tls_transcript.server_cert_chain().context("server cert chain")?.to_vec(),
            sig: tls_transcript.server_signature().context("server signature")?.clone(),
            binding: tls_transcript.certificate_binding().clone(),
        })
        .transcript(prover_transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);
    let (request, secrets) = req_builder.build(&CryptoProvider::default())?;

    handle.close();
    let mut socket = driver_task.await??;
    socket.write_all(&bincode::serialize(&request)?).await?;
    socket.close().await?;
    let mut attestation_bytes = Vec::new();
    socket.read_to_end(&mut attestation_bytes).await?;
    let attestation: Attestation = bincode::deserialize(&attestation_bytes)?;
    request.validate(&attestation, &CryptoProvider::default())?;

    tokio::fs::write(&attestation_out, bincode::serialize(&attestation)?).await?;
    tokio::fs::write(&secrets_out, bincode::serialize(&secrets)?).await?;

    println!(
        "{}",
        serde_json::to_string(&ProveReport {
            server_name,
            uri,
            http_status,
            response_body_sha256,
            attestation_path: attestation_out.display().to_string(),
            secrets_path: secrets_out.display().to_string(),
        })?
    );
    Ok(())
}

// --- Present ------------------------------------------------------------------

fn cmd_present(attestation_path: PathBuf, secrets_path: PathBuf, reveal_json: Vec<String>, out: PathBuf) -> Result<()> {
    let attestation: Attestation = bincode::deserialize(&std::fs::read(&attestation_path)?)?;
    let secrets: Secrets = bincode::deserialize(&std::fs::read(&secrets_path)?)?;
    let transcript = HttpTranscript::parse(secrets.transcript())?;

    let mut builder = secrets.transcript_proof_builder();
    let request = &transcript.requests[0];
    builder.reveal_sent(request.without_data())?;
    builder.reveal_sent(&request.request.target)?;
    for header in &request.headers {
        let name = header.name.as_str();
        if name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("cookie") {
            builder.reveal_sent(header.without_value())?;
        } else {
            builder.reveal_sent(header)?;
        }
    }
    let response = &transcript.responses[0];
    builder.reveal_recv(response.without_data())?;
    for header in &response.headers {
        builder.reveal_recv(header)?;
    }
    let body = response.body.as_ref().context("response has no body")?;
    match &body.content {
        tlsn_formats::http::BodyContent::Json(json) if !reveal_json.is_empty() => {
            for path in &reveal_json {
                builder.reveal_recv(json.get(path).with_context(|| format!("json path {path} not found"))?)?;
            }
        }
        _ => {
            builder.reveal_recv(body)?;
        }
    }
    let transcript_proof = builder.build()?;
    let provider = CryptoProvider::default();
    let mut pb = attestation.presentation_builder(&provider);
    pb.identity_proof(secrets.identity_proof()).transcript_proof(transcript_proof);
    let presentation: Presentation = pb.build()?;
    std::fs::write(&out, bincode::serialize(&presentation)?)?;
    println!("{}", serde_json::json!({"presentation": out.display().to_string()}));
    Ok(())
}

// --- Verify -------------------------------------------------------------------

#[derive(Serialize)]
struct VerifyVerdict {
    verified: bool,
    trusted_notary: bool,
    notary_key_alg: String,
    notary_key: String,
    server_name: Option<String>,
    time_unix: Option<u64>,
    sent: Option<String>,
    received: Option<String>,
    received_sha256: Option<String>,
    error: Option<String>,
}

fn cmd_verify(presentation_path: PathBuf, trusted_keys_csv: String, root_cas: Vec<PathBuf>) -> Result<bool> {
    let presentation: Presentation = bincode::deserialize(&std::fs::read(&presentation_path)?)?;
    let VerifyingKey { alg, data: key_data } = presentation.verifying_key();
    let notary_key = hex::encode(&key_data);
    let trusted: Vec<String> = trusted_keys_csv
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    let trusted_notary = trusted.iter().any(|k| *k == notary_key);

    let roots = root_store(&root_cas)?;
    let crypto_provider = if roots.roots.is_empty() {
        CryptoProvider::default()
    } else {
        CryptoProvider { cert: ServerCertVerifier::new(&roots)?, ..Default::default() }
    };

    let mut verdict = VerifyVerdict {
        verified: false,
        trusted_notary,
        notary_key_alg: format!("{alg}"),
        notary_key,
        server_name: None,
        time_unix: None,
        sent: None,
        received: None,
        received_sha256: None,
        error: None,
    };
    match presentation.verify(&crypto_provider) {
        Ok(PresentationOutput { server_name, connection_info, transcript, .. }) => {
            verdict.verified = true;
            verdict.server_name = server_name.map(|n| n.to_string());
            verdict.time_unix = Some(connection_info.time);
            if let Some(partial) = transcript {
                let sent = partial.sent_unsafe(partial.len_sent()).unwrap_or_default();
                let recv = partial.received_unsafe(partial.len_received()).unwrap_or_default();
                verdict.sent = Some(String::from_utf8_lossy(&sent).replace('\0', "X"));
                verdict.received_sha256 = Some(hex::encode(Sha256::digest(&recv)));
                verdict.received = Some(String::from_utf8_lossy(&recv).replace('\0', "X"));
            }
        }
        Err(e) => verdict.error = Some(format!("{e:#}")),
    }
    let ok = verdict.verified && (trusted.is_empty() || verdict.trusted_notary);
    println!("{}", serde_json::to_string(&verdict)?);
    Ok(ok)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::NotaryPubkey { signing_key } => {
            let key = load_signing_key(&signing_key)?;
            println!("{}", notary_verifying_key_hex(&key)?);
        }
        Cmd::Notary { listen, signing_key, root_ca_der } => cmd_notary(listen, signing_key, root_ca_der).await?,
        Cmd::Prove { notary, server_host, server_port, server_name, uri, header, root_ca_der, attestation_out, secrets_out } => {
            cmd_prove(notary, server_host, server_port, server_name, uri, header, root_ca_der, attestation_out, secrets_out).await?
        }
        Cmd::Present { attestation, secrets, reveal_json, out } => cmd_present(attestation, secrets, reveal_json, out)?,
        Cmd::Verify { presentation, trusted_notary_keys, root_ca_der } => {
            if !cmd_verify(presentation, trusted_notary_keys, root_ca_der)? {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

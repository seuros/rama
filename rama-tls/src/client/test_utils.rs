//! Connector checks shared by the TLS backend crates.
//!
//! Available with the `test-utils` feature. Each check builds the connector
//! under test through a factory, so backends keep their own connector types.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test helper: failures must surface loudly to invalidate the test run"
)]

use std::{sync::Arc, time::Duration};

use parking_lot::Mutex;
use rama_core::extensions::Extensions;
use rama_core::service::{BoxService, Service, service_fn};
use rama_core::{ServiceInput, extensions::ExtensionsRef as _};
use rama_crypto::pki_types::{CertificateDer, PrivateKeyDer};
use rama_net::Protocol;
use rama_net::address::{Host, HostWithPort};
use rama_net::client::{
    ConnectRequest, ConnectionAttempt, ConnectionError, ConnectionErrorDomain, ConnectionErrorKind,
    ConnectionPolicyScope, ConnectorService, EstablishedClientConnection, pool::ConnectionReuse,
};
use rama_net::tls::ApplicationProtocol;
use tokio::io::DuplexStream;

#[cfg(feature = "http")]
use rama_net::http::{FallbackHttpVersion, TargetHttpVersion, Version};

use super::{
    NegotiatedTlsParameters, ServerVerifyMode, TlsClientConfig, TlsServerCertPins, TlsServerName,
    TlsServerVerify,
};
use crate::server::{ServerAuthData, TlsServerConfig};
use crate::{ProtocolVersion, TlsTunnel};

/// Inner connector handed to the connector under test.
pub type Transport = BoxService<
    ConnectRequest,
    EstablishedClientConnection<ServiceInput<DuplexStream>, ConnectRequest>,
    ConnectionError,
>;

/// Certificate chain and private key for a test server.
pub type ServerAuth = (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>);

fn origin_attempt() -> ConnectRequest {
    let input = ConnectRequest::new(HostWithPort::new(Host::from_static("origin.example"), 443))
        .with_application_protocol(Protocol::HTTPS);
    input.extensions().insert(
        ConnectionAttempt::new().with_authenticated_peer(Host::from_static("origin.example")),
    );
    input
}

fn duplex_transport(io: DuplexStream) -> Transport {
    let io = Mutex::new(Some(io));
    service_fn(move |input: ConnectRequest| {
        let conn = ServiceInput::new(io.lock().take().expect("one connection"));
        async move { Ok(EstablishedClientConnection { input, conn }) }
    })
    .boxed()
}

/// A plaintext tunnel connection must not be reused once a later request asks for TLS.
pub async fn plaintext_tunnel_bypass_rejects_later_tls_activation<C>(
    tunnel: impl Fn(Transport, Option<TlsClientConfig>) -> C,
) where
    C: ConnectorService<ConnectRequest>,
{
    let connector = tunnel(duplex_transport(tokio::io::duplex(64).0), None);
    let input = ConnectRequest::new(HostWithPort::new(Host::from_static("origin.example"), 443));
    let established = connector.connect(input).await.unwrap();
    let reuse = established
        .conn
        .extensions()
        .get_ref::<ConnectionReuse>()
        .unwrap();
    let next = Extensions::new();
    assert!(reuse.matches(&next));
    next.insert(TlsTunnel {
        server_identity: Some(Host::from_static("proxy.example")),
        application_protocol: Some(Protocol::HTTPS),
        alpn: None,
    });
    assert!(!reuse.matches(&next));
}

/// Connector defaults incompatible with the attempt policy fail before dialing.
pub async fn discovery_rejects_incompatible_defaults_before_dial<C>(
    auto: impl Fn(Transport, Option<TlsClientConfig>) -> C,
) where
    C: ConnectorService<ConnectRequest>,
{
    for base in [
        TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable),
        TlsClientConfig::new().with_server_name(Host::from_static("other.example")),
    ] {
        let transport = service_fn(
            async |_input: ConnectRequest| -> Result<
                EstablishedClientConnection<ServiceInput<DuplexStream>, ConnectRequest>,
                ConnectionError,
            > {
                panic!("incompatible authentication must be rejected before dialing");
            },
        );
        let connector = auto(transport.boxed(), Some(base));
        let input = origin_attempt();
        let attempt = input.extensions().get_arc::<ConnectionAttempt>().unwrap();
        let Err(error) = connector.connect(input).await else {
            panic!("policy rejection");
        };
        assert_eq!(error.domain(), ConnectionErrorDomain::Local);
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
        assert_eq!(attempt.policy_scope(), ConnectionPolicyScope::Connector);
    }
}

/// An inner connector downgrading the attempt to plaintext is rejected.
pub async fn discovery_rejects_inner_connector_plaintext_downgrade<C>(
    auto: impl Fn(Transport, Option<TlsClientConfig>) -> C,
) where
    C: ConnectorService<ConnectRequest>,
{
    let transport = service_fn(async |mut input: ConnectRequest| {
        input.application_protocol = Some(Protocol::HTTP);
        Ok::<_, ConnectionError>(EstablishedClientConnection {
            input,
            conn: ServiceInput::new(tokio::io::duplex(64).0),
        })
    });
    let connector = auto(transport.boxed(), None);
    let Err(error) = connector.connect(origin_attempt()).await else {
        panic!("plaintext rejection");
    };
    assert_eq!(error.domain(), ConnectionErrorDomain::Local);
    assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
}

/// TLS overrides added by an inner connector are checked before the handshake.
pub async fn discovery_rechecks_inner_connector_tls_overrides<C>(
    secure: impl Fn(Transport, Option<TlsClientConfig>) -> C,
) where
    C: ConnectorService<ConnectRequest>,
{
    for disable_verification in [false, true] {
        let transport = service_fn(move |input: ConnectRequest| async move {
            if disable_verification {
                input
                    .extensions()
                    .insert(TlsServerVerify(ServerVerifyMode::Disable));
            } else {
                input
                    .extensions()
                    .insert(TlsServerName(Host::from_static("other.example")));
            }
            let (io, peer) = tokio::io::duplex(64);
            drop(peer);
            Ok::<_, ConnectionError>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(io),
            })
        });
        let connector = secure(transport.boxed(), None);
        let input = origin_attempt();
        let attempt = input.extensions().get_arc::<ConnectionAttempt>().unwrap();
        let Err(error) = connector.connect(input).await else {
            panic!("policy rejection before handshake");
        };
        assert_eq!(error.domain(), ConnectionErrorDomain::Local);
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
        assert_eq!(attempt.policy_scope(), ConnectionPolicyScope::Request);
    }
}

/// A successful origin handshake reports the effective policy scope and reuse rules.
///
/// `acceptor` wraps a [`TlsServerConfig`] into a TLS echo server.
pub async fn successful_origin_handshake_reports_effective_policy_scope<C, S>(
    secure: impl Fn(Transport, Option<TlsClientConfig>) -> C,
    server_auth: impl Fn() -> ServerAuth,
    acceptor: impl Fn(TlsServerConfig) -> S,
) where
    C: ConnectorService<ConnectRequest>,
    S: Service<ServiceInput<DuplexStream>>,
{
    let (cert_chain, private_key) = server_auth();
    let trust_anchor = cert_chain.last().expect("trust anchor").clone();
    let server = Arc::new(acceptor(
        TlsServerConfig::new()
            .with_alpn_http_auto()
            .with_single_cert(ServerAuthData {
                cert_chain,
                private_key,
                ocsp: None,
            }),
    ));
    let base = TlsClientConfig::new()
        .with_server_name(Host::from_static("localhost"))
        .try_with_server_trust_anchors([trust_anchor])
        .expect("trust anchor");

    for request_override in [false, true] {
        let (client_io, server_io) = tokio::io::duplex(64);
        let server = server.clone();
        let server_task =
            tokio::spawn(async move { server.serve(ServiceInput::new(server_io)).await });
        let connector = secure(duplex_transport(client_io), Some(base.clone()));
        let input = ConnectRequest::new(HostWithPort::new(Host::from_static("localhost"), 443))
            .with_application_protocol(Protocol::HTTPS);
        #[cfg(feature = "http")]
        {
            // A fallback does not constrain ALPN, but an explicit target does.
            input
                .extensions()
                .insert(FallbackHttpVersion(Version::HTTP_11));
            if request_override {
                input
                    .extensions()
                    .insert(TargetHttpVersion(Version::HTTP_11));
            }
        }
        if request_override {
            input
                .extensions()
                .insert(TlsServerVerify(ServerVerifyMode::Auto));
            input.extensions().insert(
                ConnectionAttempt::new().with_authenticated_peer(Host::from_static("localhost")),
            );
        }
        let established = tokio::time::timeout(Duration::from_secs(5), connector.connect(input))
            .await
            .expect("handshake timeout")
            .expect("origin handshake");
        assert_eq!(
            established
                .conn
                .extensions()
                .get_ref::<ConnectionPolicyScope>()
                .copied(),
            Some(if request_override {
                ConnectionPolicyScope::Request
            } else {
                ConnectionPolicyScope::Connector
            }),
        );
        #[cfg(feature = "http")]
        {
            let expected = if request_override {
                Version::HTTP_11
            } else {
                Version::HTTP_2
            };
            assert_eq!(
                established
                    .conn
                    .extensions()
                    .get_ref::<TargetHttpVersion>()
                    .map(|v| v.0),
                Some(expected),
            );
            assert_eq!(
                established
                    .conn
                    .extensions()
                    .get_ref::<NegotiatedTlsParameters>()
                    .and_then(|params| params.application_layer_protocol.as_ref()),
                Some(&ApplicationProtocol::try_from(expected).unwrap()),
            );
            assert_eq!(
                established
                    .input
                    .extensions()
                    .get_ref::<TargetHttpVersion>()
                    .map(|v| v.0),
                request_override.then_some(Version::HTTP_11),
            );
        }
        let reuse = established
            .conn
            .extensions()
            .get_ref::<ConnectionReuse>()
            .expect("native TLS connector publishes reuse policy");
        let same = Extensions::new();
        if request_override {
            same.insert(TlsServerVerify(ServerVerifyMode::Auto));
        }
        assert!(reuse.is_reusable());
        assert!(reuse.matches(&same));
        let changed = same.fork();
        changed.insert(TlsServerVerify(ServerVerifyMode::Disable));
        assert!(!reuse.matches(&changed));
        drop(established);
        let _server_result = tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect("server shutdown")
            .expect("server task");
    }
}

/// A proxy tunnel handshake uses only the proxy base config and keeps the
/// negotiated HTTP version scoped to the tunnel.
///
/// `acceptor` wraps a [`TlsServerConfig`] into a TLS echo server.
pub async fn tunnel_handshake_uses_proxy_base_and_keeps_version_scoped<C, S>(
    tunnel: impl Fn(Transport, Option<TlsClientConfig>) -> C,
    server_auth: impl Fn() -> ServerAuth,
    acceptor: impl Fn(TlsServerConfig) -> S,
) where
    C: ConnectorService<ConnectRequest>,
    S: Service<ServiceInput<DuplexStream>>,
{
    let (cert_chain, private_key) = server_auth();
    let trust_anchor = cert_chain.last().expect("trust anchor").clone();
    let server_pin = cert_chain.first().expect("leaf certificate").clone();
    let server = acceptor(
        TlsServerConfig::new()
            .with_single_cert(ServerAuthData {
                cert_chain,
                private_key,
                ocsp: None,
            })
            .with_alpn_http_2(),
    );

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move { server.serve(ServiceInput::new(server_io)).await });
    let proxy_base = TlsClientConfig::new()
        .with_alpn_http_2()
        .with_server_name(Host::from_static("localhost"))
        .with_server_cert_pins(TlsServerCertPins::new(server_pin))
        .with_server_verify(ServerVerifyMode::Auto)
        .try_with_server_trust_anchors([trust_anchor])
        .expect("proxy trust")
        .with_supported_versions(vec![ProtocolVersion::TLSv1_3]);
    let connector = tunnel(duplex_transport(client_io), Some(proxy_base));

    let input = ConnectRequest::new(HostWithPort::new(Host::from_static("origin.example"), 443));
    input.extensions().insert(
        ConnectionAttempt::new().with_authenticated_peer(Host::from_static("origin.example")),
    );
    TlsClientConfig::new()
        .with_alpn_http_1()
        .with_server_name(Host::from_static("origin.example"))
        .with_server_verify(ServerVerifyMode::Disable)
        .with_server_cert_pins(TlsServerCertPins::new(CertificateDer::from(vec![9])))
        .write_to(input.extensions());
    #[cfg(feature = "http")]
    input
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_11));
    input.extensions().insert(TlsTunnel {
        server_identity: Some(Host::from_static("proxy-route.example")),
        application_protocol: Some(Protocol::HTTPS),
        alpn: None,
    });

    let established = connector.connect(input).await.expect("proxy TLS handshake");
    let reuse = established
        .conn
        .extensions()
        .get_ref::<ConnectionReuse>()
        .expect("proxy TLS connector publishes reuse policy");
    let next_origin = Extensions::new();
    next_origin.insert(TlsServerName(Host::from_static("another-origin.example")));
    next_origin.insert(TlsServerVerify(ServerVerifyMode::Disable));
    assert!(reuse.is_reusable());
    assert!(!reuse.matches(&next_origin));
    next_origin.insert(
        established
            .input
            .extensions()
            .get_ref::<TlsTunnel>()
            .unwrap()
            .clone(),
    );
    assert!(reuse.matches(&next_origin));
    next_origin.insert(TlsTunnel {
        server_identity: None,
        application_protocol: None,
        alpn: None,
    });
    assert!(!reuse.matches(&next_origin));
    assert_eq!(
        established
            .input
            .extensions()
            .get_ref::<ConnectionAttempt>()
            .unwrap()
            .policy_scope(),
        ConnectionPolicyScope::Unknown,
    );
    assert!(
        !established
            .conn
            .extensions()
            .contains::<ConnectionPolicyScope>()
    );
    let negotiated = established
        .conn
        .extensions()
        .get_ref::<NegotiatedTlsParameters>()
        .expect("proxy TLS parameters");
    assert_eq!(negotiated.resumed, Some(false));
    assert_eq!(negotiated.server_name, None);
    assert_eq!(
        negotiated.application_layer_protocol,
        Some(ApplicationProtocol::HTTP_2)
    );
    #[cfg(feature = "http")]
    assert!(
        established
            .conn
            .extensions()
            .get_ref::<TargetHttpVersion>()
            .is_none()
    );
    drop(established);
    // The client is dropped immediately after the handshake assertions,
    // so the TLS server may finish with an EOF/close-notify error.
    let _server_result = tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server shutdown")
        .expect("server task");
}

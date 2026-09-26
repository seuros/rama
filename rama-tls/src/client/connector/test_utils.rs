//! Conformance checks shared by every [`TlsConnectorBackend`].
//!
//! Available with the `test-utils` feature so backend crates can run them.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test helper: failures must surface loudly to invalidate the test run"
)]

use std::{sync::Arc, time::Duration};

use parking_lot::Mutex;
use rama_core::{ServiceInput, service::service_fn};
use rama_crypto::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rama_net::address::HostWithPort;
use rama_net::client::{ConnectRequest, ConnectionErrorDomain, pool::ConnectionReuse};
use rama_net::tls::ApplicationProtocol;
use rama_utils::test_helpers::{assert_send, assert_sync};
use tokio::io::DuplexStream;

use super::*;
use crate::client::{
    ClientAuth, ClientAuthData, ServerVerifyMode, TlsClientAuth, TlsServerCertPinCheck,
    TlsServerCertPins, TlsServerTrust, TlsServerVerify, TlsStoreServerCertChain,
};
use crate::server::{ServerAuthData, TlsServerConfig};
use crate::{KeyLogIntent, ProtocolVersion, TlsKeyLog, TlsSupportedVersions};

type ServerAuth = (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>);

/// Exercise the backend agnostic connector contract against backend `B`.
///
/// `server_auth` generates a certificate chain and key; `acceptor` wraps a
/// [`TlsServerConfig`] into a TLS echo server of the same backend.
pub async fn exercise<B, S>(
    server_auth: impl Fn() -> ServerAuth,
    acceptor: impl Fn(TlsServerConfig) -> S,
) where
    B: TlsConnectorBackend,
    S: Service<ServiceInput<DuplexStream>>,
{
    assert_send::<TlsConnectorLayer<B>>();
    assert_sync::<TlsConnectorLayer<B>>();

    plaintext_tunnel_bypass_rejects_later_tls_activation::<B>().await;
    discovery_rejects_incompatible_defaults_before_dial::<B>().await;
    discovery_rejects_inner_connector_plaintext_downgrade::<B>().await;
    discovery_request_policy_overrides_connector_defaults::<B>();
    discovery_rechecks_inner_connector_tls_overrides::<B>().await;
    connector_data_falls_back_to_transport_host::<B>();
    tunnel_config_uses_only_base_and_explicit_tunnel_policy::<B>();
    tunnel_config_isolates_all_origin_tls_extensions::<B>();
    default_alpn_resolution::<B>();
    #[cfg(feature = "http")]
    http_alpn_resolution::<B>();
    origin_handshake_reports_effective_policy_scope::<B, S>(&server_auth, &acceptor).await;
    tunnel_handshake_uses_proxy_base_and_keeps_version_scoped::<B, S>(&server_auth, &acceptor)
        .await;
}

fn origin_attempt() -> ConnectRequest {
    let origin = Host::from_static("origin.example");
    let input = ConnectRequest::new(HostWithPort::new(origin.clone(), 443))
        .with_application_protocol(Protocol::HTTPS);
    let attempt = ConnectionAttempt::new().with_authenticated_peer(origin);
    input.extensions().insert(attempt);
    input
}

fn server_name_of(ext: &Extensions) -> Option<&Host> {
    ext.get_ref::<TlsServerName>().map(|name| &name.0)
}

fn verify_of(ext: &Extensions) -> Option<ServerVerifyMode> {
    ext.get_ref::<TlsServerVerify>().map(|verify| verify.0)
}

fn alpn_ext(alpn: Option<&TlsAlpn>) -> Extensions {
    let ext = Extensions::new();
    if let Some(alpn) = alpn {
        ext.insert(alpn.clone());
    }
    ext
}

fn duplex_transport(
    io: DuplexStream,
) -> impl ConnectorService<ServiceInput<()>, Connection = ServiceInput<DuplexStream>> {
    let io = Mutex::new(Some(io));
    service_fn(move |input: ServiceInput<()>| {
        let conn = ServiceInput::new(io.lock().take().expect("one connection"));
        async move { Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn }) }
    })
}

async fn plaintext_tunnel_bypass_rejects_later_tls_activation<B: TlsConnectorBackend>() {
    let transport = duplex_transport(tokio::io::duplex(64).0);
    let connector = TlsConnector::<_, B, _>::tunnel(transport, None);
    let established = connector.serve(ServiceInput::new(())).await.unwrap();
    let conn_ext = established.conn.extensions();
    let reuse = conn_ext.get_ref::<ConnectionReuse>().unwrap();
    let next = Extensions::new();
    assert!(reuse.matches(&next));
    next.insert(TlsTunnel {
        server_identity: Some(Host::from_static("proxy.example")),
        application_protocol: Some(Protocol::HTTPS),
        alpn: None,
    });
    assert!(!reuse.matches(&next));
}

async fn discovery_rejects_incompatible_defaults_before_dial<B: TlsConnectorBackend>() {
    for base in [
        TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable),
        TlsClientConfig::new().with_server_name(Host::from_static("other.example")),
    ] {
        let transport = service_fn(
            async |_input: ConnectRequest| -> Result<
                EstablishedClientConnection<ServiceInput<DuplexStream>, ConnectRequest>,
                ConnectionError,
            > { panic!("incompatible authentication must be rejected before dialing") },
        );
        let connector = TlsConnector::<_, B>::auto(transport).with_base_config(base);
        let input = origin_attempt();
        let attempt = input.extensions().get_arc::<ConnectionAttempt>().unwrap();
        let Err(error) = connector.serve(input).await else {
            panic!("policy rejection")
        };
        assert_eq!(error.domain(), ConnectionErrorDomain::Local);
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
        assert_eq!(attempt.policy_scope(), ConnectionPolicyScope::Connector);
    }
}

async fn discovery_rejects_inner_connector_plaintext_downgrade<B: TlsConnectorBackend>() {
    let transport = service_fn(async |mut input: ConnectRequest| {
        input.application_protocol = Some(Protocol::HTTP);
        let conn = ServiceInput::new(tokio::io::duplex(64).0);
        Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
    });
    let connector = TlsConnector::<_, B>::auto(transport);
    let Err(error) = connector.serve(origin_attempt()).await else {
        panic!("plaintext rejection")
    };
    assert_eq!(error.domain(), ConnectionErrorDomain::Local);
    assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
}

fn discovery_request_policy_overrides_connector_defaults<B: TlsConnectorBackend>() {
    let base = TlsClientConfig::new()
        .with_server_verify(ServerVerifyMode::Disable)
        .with_server_name(Host::from_static("other.example"));
    let connector = TlsConnector::<_, B, _>::secure(()).with_base_config(base);
    let input = origin_attempt();
    let ext = input.extensions();
    ext.insert(TlsServerVerify(ServerVerifyMode::Auto));
    ext.insert(TlsServerName(Host::from_static("origin.example")));
    connector.check_attempt_policy(&input, true).unwrap();
    let attempt = ext.get_ref::<ConnectionAttempt>().unwrap();
    assert_eq!(attempt.policy_scope(), ConnectionPolicyScope::Request);
}

async fn discovery_rechecks_inner_connector_tls_overrides<B: TlsConnectorBackend>() {
    for disable_verification in [false, true] {
        let transport = service_fn(move |input: ConnectRequest| async move {
            let ext = input.extensions();
            if disable_verification {
                ext.insert(TlsServerVerify(ServerVerifyMode::Disable));
            } else {
                ext.insert(TlsServerName(Host::from_static("other.example")));
            }
            let conn = ServiceInput::new(tokio::io::duplex(64).0);
            Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
        });
        let connector = TlsConnector::<_, B, _>::secure(transport);
        let input = origin_attempt();
        let attempt = input.extensions().get_arc::<ConnectionAttempt>().unwrap();
        let Err(error) = connector.serve(input).await else {
            panic!("policy rejection before handshake")
        };
        assert_eq!(error.domain(), ConnectionErrorDomain::Local);
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
        assert_eq!(attempt.policy_scope(), ConnectionPolicyScope::Request);
    }
}

fn connector_data_falls_back_to_transport_host<B: TlsConnectorBackend>() {
    let host = Host::from(std::net::Ipv4Addr::LOCALHOST);
    let ext = Extensions::new();
    let connector = TlsConnector::<_, B, _>::secure(());
    let data = connector.connector_data(&ext, None, &host).unwrap();
    assert_eq!(B::server_name(&data), Some(&host));

    let configured = Host::from_static("configured.example");
    let base = TlsClientConfig::new().with_server_name(configured.clone());
    let connector = TlsConnector::<_, B, _>::secure(()).with_base_config(base);
    let data = connector.connector_data(&ext, None, &host).unwrap();
    assert_eq!(B::server_name(&data), Some(&configured));
}

fn tunnel_config_uses_only_base_and_explicit_tunnel_policy<B: TlsConnectorBackend>() {
    let https = Some(&Protocol::HTTPS);
    let base_name = Host::from_static("proxy-cert.example");
    let base = TlsClientConfig::new()
        .with_alpn_http_2()
        .with_server_name(base_name.clone())
        .with_server_verify(ServerVerifyMode::Disable);
    let connector = TlsConnector::<_, B, _>::tunnel((), None).with_base_config(base);
    let mut tunnel = TlsTunnel {
        server_identity: Some(Host::from_static("proxy-route.example")),
        application_protocol: Some(Protocol::HTTPS),
        alpn: Some(TlsAlpn::http_1()),
    };

    let effective = connector.tunnel_config_extensions(Some(&tunnel), https);
    assert_eq!(effective.get_ref::<TlsAlpn>(), Some(&TlsAlpn::http_1()));
    assert_eq!(server_name_of(&effective), Some(&base_name));
    assert_eq!(verify_of(&effective), Some(ServerVerifyMode::Disable));

    let data = connector.tunnel_connector_data(Some(&tunnel), https, None);
    let data = data.unwrap();
    assert_eq!(B::server_name(&data), Some(&base_name));
    assert!(!B::verifies_server(&data));

    tunnel.alpn = Some(TlsAlpn::empty());
    let effective = connector.tunnel_config_extensions(Some(&tunnel), https);
    assert_eq!(effective.get_ref::<TlsAlpn>(), Some(&TlsAlpn::empty()));
}

fn tunnel_config_isolates_all_origin_tls_extensions<B: TlsConnectorBackend>() {
    let https = Some(&Protocol::HTTPS);
    let base_name = Host::from_static("proxy-cert.example");
    let base_pin = CertificateDer::from(vec![1, 2, 3]);
    let base_trust = TlsServerTrust::webpki_roots();
    let base = TlsClientConfig::new()
        .with_alpn_http_2()
        .with_server_name(base_name.clone())
        .with_server_verify(ServerVerifyMode::Disable)
        .with_server_cert_pins(TlsServerCertPins::new(base_pin.clone()))
        .with_server_trust(base_trust.clone())
        .with_supported_versions(vec![ProtocolVersion::TLSv1_3])
        .with_keylog(KeyLogIntent::Disabled)
        .with_client_auth(ClientAuth::SelfSigned)
        .with_store_server_cert_chain(true);
    let connector = TlsConnector::<_, B, _>::tunnel((), None).with_base_config(base);

    let origin = Extensions::new();
    TlsClientConfig::new()
        .with_alpn_http_1()
        .with_server_name(Host::from_static("origin.example"))
        .with_server_verify(ServerVerifyMode::Auto)
        .with_server_cert_pins(TlsServerCertPins::new(CertificateDer::from(vec![9])))
        .with_server_trust(TlsServerTrust::default_roots())
        .with_supported_versions(vec![ProtocolVersion::TLSv1_2])
        .with_keylog(KeyLogIntent::Environment)
        .with_client_auth(ClientAuth::Single(ClientAuthData {
            cert_chain: vec![CertificateDer::from(vec![8])],
            private_key: PrivatePkcs8KeyDer::from(vec![7]).into(),
        }))
        .with_store_server_cert_chain(false)
        .write_to(&origin);
    origin.insert(TlsTunnel {
        server_identity: Some(Host::from_static("proxy-route.example")),
        application_protocol: Some(Protocol::HTTPS),
        alpn: None,
    });

    let tunnel = origin.get_ref::<TlsTunnel>();
    let ext = connector.tunnel_config_extensions(tunnel, https);
    assert_eq!(ext.get_ref::<TlsAlpn>(), Some(&TlsAlpn::http_2()));
    assert_eq!(server_name_of(&ext), Some(&base_name));
    assert_eq!(verify_of(&ext), Some(ServerVerifyMode::Disable));
    assert_eq!(ext.get_ref::<TlsServerTrust>(), Some(&base_trust));
    let versions = ext
        .get_ref::<TlsSupportedVersions>()
        .map(|v| v.0.as_slice());
    assert_eq!(versions, Some([ProtocolVersion::TLSv1_3].as_slice()));
    let keylog = ext.get_ref::<TlsKeyLog>();
    assert!(matches!(keylog, Some(TlsKeyLog(KeyLogIntent::Disabled))));
    let client_auth = ext.get_ref::<TlsClientAuth>().map(|auth| &auth.0);
    assert!(matches!(client_auth, Some(ClientAuth::SelfSigned)));
    let store_chain = ext.get_ref::<TlsStoreServerCertChain>().map(|s| s.0);
    assert_eq!(store_chain, Some(true));
    let pins = ext.get_ref::<TlsServerCertPins>().unwrap();
    let pin_check = pins.check(Some(&base_name), &base_pin);
    assert_eq!(pin_check, TlsServerCertPinCheck::Matched);

    let data = connector
        .tunnel_connector_data(tunnel, https, None)
        .unwrap();
    assert_eq!(B::server_name(&data), Some(&base_name));
    assert!(!B::verifies_server(&data));
}

fn default_alpn_resolution<B: TlsConnectorBackend>() {
    let (auto, h1, none) = (TlsAlpn::http_auto(), TlsAlpn::http_1(), TlsAlpn::empty());
    let (https, icaps) = (Some(&Protocol::HTTPS), Some(&Protocol::ICAPS));
    for (base, request, protocol, expected) in [
        (Some(&auto), None, icaps, &auto),
        (None, None, https, &auto),
        (None, None, icaps, &none),
        (Some(&auto), Some(&h1), icaps, &h1),
        (Some(&h1), None, https, &h1),
        (Some(&h1), None, None, &h1),
    ] {
        let effective = alpn_ext(request).with_base(&alpn_ext(base));
        apply_default_alpn::<B>(&effective, protocol);
        assert_eq!(effective.get_ref::<TlsAlpn>(), Some(expected));
    }
}

#[cfg(feature = "http")]
fn http_alpn_resolution<B: TlsConnectorBackend>() {
    use rama_net::http::FallbackHttpVersion;

    let (auto, h1, h2) = (TlsAlpn::http_auto(), TlsAlpn::http_1(), TlsAlpn::http_2());
    let none = TlsAlpn::empty();
    let (v11, v2) = (Some(Version::HTTP_11), Some(Version::HTTP_2));
    let (https, icaps) = (&Protocol::HTTPS, &Protocol::ICAPS);
    for (alpn, target, fallback, protocol, expected) in [
        (None, v11, None, https, Some(&h1)),
        (None, v2, None, https, Some(&h2)),
        (None, None, None, https, None),
        (Some(&auto), None, v11, https, Some(&auto)),
        (Some(&auto), v11, None, https, Some(&h1)),
        (Some(&none), v2, None, icaps, Some(&none)),
    ] {
        let ext = alpn_ext(alpn);
        if let Some(version) = target {
            ext.insert(TargetHttpVersion(version));
        }
        if let Some(version) = fallback {
            ext.insert(FallbackHttpVersion(version));
        }
        resolve_http_alpn::<B>(&ext, Some(protocol)).unwrap();
        assert_eq!(ext.get_ref::<TlsAlpn>(), expected);
    }
}

async fn origin_handshake_reports_effective_policy_scope<B, S>(
    server_auth: &impl Fn() -> ServerAuth,
    acceptor: &impl Fn(TlsServerConfig) -> S,
) where
    B: TlsConnectorBackend,
    S: Service<ServiceInput<DuplexStream>>,
{
    let localhost = Host::from_static("localhost");
    let (cert_chain, private_key) = server_auth();
    let trust_anchor = cert_chain.last().unwrap().clone();
    let auth = ServerAuthData {
        cert_chain,
        private_key,
        ocsp: None,
    };
    let server = Arc::new(acceptor(TlsServerConfig::new().with_single_cert(auth)));
    let base = TlsClientConfig::new()
        .with_server_name(localhost.clone())
        .try_with_server_trust_anchors([trust_anchor])
        .unwrap();

    for request_override in [false, true] {
        let (client_io, server_io) = tokio::io::duplex(64);
        let server = server.clone();
        let server_input = ServiceInput::new(server_io);
        let server_task = tokio::spawn(async move { server.serve(server_input).await });
        let io = Mutex::new(Some(client_io));
        let transport = service_fn(move |input: ConnectRequest| {
            let conn = ServiceInput::new(io.lock().take().expect("one dial"));
            async move { Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn }) }
        });
        let connector = TlsConnector::<_, B, _>::secure(transport).with_base_config(base.clone());
        let input = ConnectRequest::new(HostWithPort::new(localhost.clone(), 443));
        let scope = if request_override {
            let attempt = ConnectionAttempt::new().with_authenticated_peer(localhost.clone());
            input
                .extensions()
                .insert(TlsServerVerify(ServerVerifyMode::Auto));
            input.extensions().insert(attempt);
            ConnectionPolicyScope::Request
        } else {
            ConnectionPolicyScope::Connector
        };
        let handshake = tokio::time::timeout(Duration::from_secs(5), connector.serve(input));
        let established = handshake.await.expect("handshake timeout").unwrap();
        let conn_ext = established.conn.extensions();
        assert_eq!(conn_ext.get_ref::<ConnectionPolicyScope>(), Some(&scope));

        let reuse = conn_ext.get_ref::<ConnectionReuse>().unwrap();
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
        let shutdown = tokio::time::timeout(Duration::from_secs(5), server_task);
        let _server_result = shutdown.await.expect("server shutdown").unwrap();
    }
}

async fn tunnel_handshake_uses_proxy_base_and_keeps_version_scoped<B, S>(
    server_auth: &impl Fn() -> ServerAuth,
    acceptor: &impl Fn(TlsServerConfig) -> S,
) where
    B: TlsConnectorBackend,
    S: Service<ServiceInput<DuplexStream>>,
{
    let (cert_chain, private_key) = server_auth();
    let trust_anchor = cert_chain.last().unwrap().clone();
    let server_pin = cert_chain.first().unwrap().clone();
    let auth = ServerAuthData {
        cert_chain,
        private_key,
        ocsp: None,
    };
    let server_config = TlsServerConfig::new().with_single_cert(auth);
    let server = acceptor(server_config.with_alpn_http_2());

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server_input = ServiceInput::new(server_io);
    let server_task = tokio::spawn(async move { server.serve(server_input).await });
    let proxy_base = TlsClientConfig::new()
        .with_alpn_http_2()
        .with_server_name(Host::from_static("localhost"))
        .with_server_cert_pins(TlsServerCertPins::new(server_pin))
        .with_server_verify(ServerVerifyMode::Auto)
        .try_with_server_trust_anchors([trust_anchor])
        .unwrap()
        .with_supported_versions(vec![ProtocolVersion::TLSv1_3]);
    let transport = duplex_transport(client_io);
    let connector = TlsConnector::<_, B, _>::tunnel(transport, None).with_base_config(proxy_base);

    let origin = Host::from_static("origin.example");
    let input = ServiceInput::new(());
    let ext = input.extensions();
    ext.insert(ConnectionAttempt::new().with_authenticated_peer(origin.clone()));
    TlsClientConfig::new()
        .with_alpn_http_1()
        .with_server_name(origin)
        .with_server_verify(ServerVerifyMode::Disable)
        .with_server_cert_pins(TlsServerCertPins::new(CertificateDer::from(vec![9])))
        .write_to(ext);
    #[cfg(feature = "http")]
    ext.insert(TargetHttpVersion(Version::HTTP_11));
    ext.insert(TlsTunnel {
        server_identity: Some(Host::from_static("proxy-route.example")),
        application_protocol: Some(Protocol::HTTPS),
        alpn: None,
    });

    let established = connector.serve(input).await.expect("proxy TLS handshake");
    let (input_ext, conn_ext) = (
        established.input.extensions(),
        established.conn.extensions(),
    );
    let reuse = conn_ext.get_ref::<ConnectionReuse>().unwrap();
    let next_origin = Extensions::new();
    next_origin.insert(TlsServerName(Host::from_static("another-origin.example")));
    next_origin.insert(TlsServerVerify(ServerVerifyMode::Disable));
    assert!(reuse.is_reusable());
    assert!(!reuse.matches(&next_origin));
    next_origin.insert(input_ext.get_ref::<TlsTunnel>().unwrap().clone());
    assert!(reuse.matches(&next_origin));
    next_origin.insert(TlsTunnel {
        server_identity: None,
        application_protocol: None,
        alpn: None,
    });
    assert!(!reuse.matches(&next_origin));

    let attempt = input_ext.get_ref::<ConnectionAttempt>().unwrap();
    assert_eq!(attempt.policy_scope(), ConnectionPolicyScope::Unknown);
    assert!(!conn_ext.contains::<ConnectionPolicyScope>());
    let negotiated = conn_ext.get_ref::<NegotiatedTlsParameters>().unwrap();
    assert_eq!(negotiated.resumed, Some(false));
    assert_eq!(negotiated.server_name, None);
    let alpn = negotiated.application_layer_protocol.as_ref();
    assert_eq!(alpn, Some(&ApplicationProtocol::HTTP_2));
    #[cfg(feature = "http")]
    assert!(!conn_ext.contains::<TargetHttpVersion>());
    drop(established);
    // The client is dropped right after the handshake assertions,
    // so the TLS server may finish with an EOF/close-notify error.
    let shutdown = tokio::time::timeout(Duration::from_secs(5), server_task);
    let _server_result = shutdown.await.expect("server shutdown").unwrap();
}

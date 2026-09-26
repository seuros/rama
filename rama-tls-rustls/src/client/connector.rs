use super::{AutoTlsStream, RustlsTlsStream, TlsConnectorData, TlsStream};
use crate::client::config::{RustlsTlsClientConfigProvider, RustlsTlsConnectorConfig};
use crate::dep::tokio_rustls::TlsConnector as RustlsConnector;
use rama_core::conversion::{RamaInto, RamaTryFrom};
use rama_core::error::{BoxError, ErrorContext};
use rama_core::extensions::{Extensions, ExtensionsRef};
use rama_core::io::Io;
use rama_net::address::Host;
use rama_net::tls::ApplicationProtocol;
use rama_tls::client::NegotiatedTlsParameters;
use rama_tls::client::connector::{self, TlsConnectorBackend};

pub use connector::{ConnectorKindAuto, ConnectorKindSecure, ConnectorKindTunnel};

/// [`connector::TlsConnectorLayer`] using rustls.
pub type TlsConnectorLayer<K = ConnectorKindAuto> =
    connector::TlsConnectorLayer<RustlsTlsConnectorBackend, K>;

/// [`connector::TlsConnector`] using rustls.
pub type TlsConnector<S, K = ConnectorKindAuto> =
    connector::TlsConnector<S, RustlsTlsConnectorBackend, K>;

/// [`TlsConnectorBackend`] which establishes TLS sessions using rustls.
#[derive(Debug, Clone, Copy, Default)]
pub struct RustlsTlsConnectorBackend;

impl TlsConnectorBackend for RustlsTlsConnectorBackend {
    const NAME: &'static str = "rama-tls-rustls::TlsConnector";

    type Provider = RustlsTlsClientConfigProvider;
    type Data = TlsConnectorData;
    type Stream<IO: Io + Unpin + ExtensionsRef> = TlsStream<IO>;
    type AutoStream<IO: Io + Unpin + ExtensionsRef> = AutoTlsStream<IO>;

    fn has_overrides(extensions: &Extensions) -> bool {
        RustlsTlsConnectorConfig::from_extensions(extensions).has_overrides()
    }

    fn connector_data(ext: &Extensions, fallback: Option<&Host>) -> Result<Self::Data, BoxError> {
        let mut data = TlsConnectorData::try_from(RustlsTlsConnectorConfig::from_extensions(ext))?;
        data.server_name = data.server_name.or_else(|| fallback.cloned());
        Ok(data)
    }

    fn server_name(data: &Self::Data) -> Option<&Host> {
        data.server_name.as_ref()
    }

    fn verifies_server(data: &Self::Data) -> bool {
        data.verification_enabled
    }

    async fn handshake<IO>(
        data: Self::Data,
        io: IO,
    ) -> Result<(Self::Stream<IO>, NegotiatedTlsParameters), BoxError>
    where
        IO: Io + Unpin + ExtensionsRef,
    {
        let (stream, params) = handshake(data, io).await?;
        Ok((TlsStream::new(stream), params))
    }

    fn auto_secure<IO: Io + Unpin + ExtensionsRef>(tls: Self::Stream<IO>) -> Self::AutoStream<IO> {
        AutoTlsStream::secure(tls.into())
    }

    fn auto_plain<IO: Io + Unpin + ExtensionsRef>(io: IO) -> Self::AutoStream<IO> {
        AutoTlsStream::plain(io)
    }
}

async fn handshake<T>(
    data: TlsConnectorData,
    stream: T,
) -> Result<(RustlsTlsStream<T>, NegotiatedTlsParameters), BoxError>
where
    T: Io + ExtensionsRef + Unpin,
{
    let server_host = data
        .server_name
        .clone()
        .context("server identity missing")?;
    #[cfg(feature = "dial9")]
    let dial9_server_name = server_host.clone();

    let authenticated_identity = data.verification_enabled.then(|| server_host.clone());
    let server_name = rama_crypto::pki_types::ServerName::rama_try_from(server_host)?;

    let connector = RustlsConnector::from(data.client_config);
    #[cfg(feature = "dial9")]
    crate::dial9::record_handshake_started(dial9_server_name.clone());

    let stream = match connector.connect(server_name, stream).await {
        Ok(stream) => stream,
        Err(err) => {
            #[cfg(feature = "dial9")]
            crate::dial9::record_handshake_failed(dial9_server_name.clone(), &err);
            return Err(err.into());
        }
    };

    stream
        .get_ref()
        .0
        .extensions()
        .insert(rama_tls::client::TlsServerAuthentication(
            authenticated_identity,
        ));
    let (_, conn_data_ref) = stream.get_ref();

    let server_certificate_chain = if data.store_server_certificate_chain {
        conn_data_ref.peer_certificates().map(RamaInto::rama_into)
    } else {
        None
    };

    let params = NegotiatedTlsParameters {
        protocol_version: conn_data_ref
            .protocol_version()
            .context("no protocol version available")?
            .rama_into(),
        application_layer_protocol: conn_data_ref.alpn_protocol().map(ApplicationProtocol::from),
        peer_certificate_chain: server_certificate_chain,
        server_name: None,
        resumed: conn_data_ref
            .handshake_kind()
            .map(|kind| kind == crate::dep::rustls::HandshakeKind::Resumed),
    };

    #[cfg(feature = "dial9")]
    {
        let depth = params
            .peer_certificate_chain
            .as_ref()
            .map_or(0, |chain| chain.len());
        crate::dial9::record_handshake_completed(
            dial9_server_name,
            params.protocol_version,
            conn_data_ref.alpn_protocol().map(ApplicationProtocol::from),
            depth,
        );
    }

    Ok((stream, params))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::TlsAcceptorLayer;
    use rama_core::{Layer as _, ServiceInput};
    use rama_crypto::cert::generate_server_auth;
    use rama_net::stream::service::EchoService;
    use rama_tls::client::connector::test_utils::exercise;
    use rama_tls::client::{ServerVerifyMode, TlsServerVerify};
    use rama_tls::server::GeneratedServerAuthConfig;

    #[tokio::test]
    async fn connector_conformance() {
        exercise::<RustlsTlsConnectorBackend, _>(
            || generate_server_auth(GeneratedServerAuthConfig::default()).unwrap(),
            |config| TlsAcceptorLayer::new(config).into_layer(EchoService::new()),
        )
        .await;
    }

    #[tokio::test]
    async fn handshake_rejects_missing_server_identity() {
        let effective = Extensions::new();
        effective.insert(TlsServerVerify(ServerVerifyMode::Disable));
        let data =
            RustlsTlsConnectorBackend::connector_data(&effective, None).expect("connector data");
        let (stream, _) = tokio::io::duplex(64);
        let error = handshake(data, ServiceInput::new(stream))
            .await
            .expect_err("missing identity");
        assert!(error.to_string().contains("server identity missing"));
    }
}

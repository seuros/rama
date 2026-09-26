//! TLS implementation agnostic client connector.

use std::marker::PhantomData;

use rama_core::error::{BoxError, BoxErrorExt as _};
use rama_core::extensions::{Extensions, ExtensionsRef};
use rama_core::io::Io;
use rama_core::telemetry::tracing;
use rama_core::{Layer, Service};
use rama_net::address::Host;
use rama_net::client::{
    ConnectionAttempt, ConnectionError, ConnectionErrorKind, ConnectionPolicyScope,
    ConnectorService, EstablishedClientConnection,
};
use rama_net::extensions::StreamTransformed;
use rama_net::tls::{TlsAlpn, default_tls_alpn};
use rama_net::{AuthorityInputExt, Protocol, ProtocolInputExt};
use rama_utils::macros::generate_set_and_with;

#[cfg(feature = "http")]
use ::{
    rama_core::error::ErrorExt as _,
    rama_net::http::{TargetHttpVersion, Version},
    rama_net::tls::ApplicationProtocol,
    rama_utils::collections::smallvec::smallvec,
};

use super::{
    NegotiatedTlsParameters, TlsClientConfig, TlsClientConfigProvider, TlsConnectionReuse,
    TlsServerName,
};
use crate::{TlsTunnel, TlsTunnelMode, resolve_tls_tunnel};

/// Native TLS implementation driven by a [`TlsConnector`].
pub trait TlsConnectorBackend: Send + Sync + 'static {
    /// Label published as [`StreamTransformed`] on secured connections.
    const NAME: &'static str;

    type Provider: TlsClientConfigProvider + Default + 'static;

    type Data: Send + 'static;

    type Stream<IO: Io + Unpin + ExtensionsRef>: ExtensionsRef + Send + 'static;

    type AutoStream<IO: Io + Unpin + ExtensionsRef>: ExtensionsRef + Send + 'static;

    fn has_overrides(extensions: &Extensions) -> bool;

    /// `fallback` is the server identity used when `ext` names none.
    fn connector_data(ext: &Extensions, fallback: Option<&Host>) -> Result<Self::Data, BoxError>;

    fn server_name(data: &Self::Data) -> Option<&Host>;

    fn verifies_server(data: &Self::Data) -> bool;

    /// Override to keep settings scoped to the ALPN offer (e.g. ALPS) coherent.
    fn set_alpn(extensions: &Extensions, alpn: TlsAlpn) {
        extensions.insert(alpn);
    }

    fn handshake<IO>(
        data: Self::Data,
        io: IO,
    ) -> impl Future<Output = Result<(Self::Stream<IO>, NegotiatedTlsParameters), BoxError>> + Send
    where
        IO: Io + Unpin + ExtensionsRef;

    fn auto_secure<IO: Io + Unpin + ExtensionsRef>(tls: Self::Stream<IO>) -> Self::AutoStream<IO>;

    fn auto_plain<IO: Io + Unpin + ExtensionsRef>(io: IO) -> Self::AutoStream<IO>;
}

/// A [`Layer`] which wraps the given service with a [`TlsConnector`].
///
/// See [`TlsConnector`] for more information.
#[derive(Debug, Clone)]
pub struct TlsConnectorLayer<B, K = ConnectorKindAuto> {
    base_config: Option<TlsClientConfig>,
    kind: K,
    _backend: PhantomData<fn() -> B>,
}

impl<B, K> TlsConnectorLayer<B, K> {
    const fn new(kind: K) -> Self {
        Self {
            base_config: None,
            kind,
            _backend: PhantomData,
        }
    }

    generate_set_and_with!(
        /// Set the base [`TlsClientConfig`] for this connector.
        ///
        /// Auto and secure connectors layer per-request TLS pieces on top of this
        /// base. Tunnel connectors intentionally use only this base plus the
        /// proxy-scoped [`TlsTunnel`] fields.
        ///
        /// NOTE: for a smooth interaction with HTTP you most likely want to at
        /// least define the ALPN protocols (e.g. [`TlsClientConfig::with_alpn_http_auto`]);
        /// the connector then sets the request http version from the negotiated ALPN.
        pub fn base_config(mut self, base: Option<TlsClientConfig>) -> Self {
            self.base_config = base;
            self
        }
    );
}

impl<B> TlsConnectorLayer<B, ConnectorKindAuto> {
    /// Creates a new [`TlsConnectorLayer`] which will establish
    /// a secure connection when the input protocol is secure. Otherwise it
    /// forwards the inner connection. The logical authority remains the default
    /// server identity.
    #[must_use]
    pub const fn auto() -> Self {
        Self::new(ConnectorKindAuto)
    }
}

impl<B> TlsConnectorLayer<B, ConnectorKindSecure> {
    /// Creates a new [`TlsConnectorLayer`] which will always
    /// establish a secure connection regardless of the request it is for.
    #[must_use]
    pub const fn secure() -> Self {
        Self::new(ConnectorKindSecure)
    }
}

impl<B> TlsConnectorLayer<B, ConnectorKindTunnel> {
    /// Creates a new [`TlsConnectorLayer`] which will establish
    /// a secure connection if the request is to be tunneled.
    #[must_use]
    pub const fn tunnel(host: Option<Host>) -> Self {
        Self::new(ConnectorKindTunnel { host })
    }
}

impl<B, K: Clone, S> Layer<S> for TlsConnectorLayer<B, K> {
    type Service = TlsConnector<S, B, K>;

    fn layer(&self, inner: S) -> Self::Service {
        TlsConnector {
            inner,
            base_config: self.base_config.clone(),
            kind: self.kind.clone(),
            _backend: PhantomData,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        TlsConnector {
            inner,
            base_config: self.base_config,
            kind: self.kind,
            _backend: PhantomData,
        }
    }
}

impl<B> Default for TlsConnectorLayer<B, ConnectorKindAuto> {
    fn default() -> Self {
        Self::auto()
    }
}

/// A connector which can be used to establish a connection to a server.
///
/// By default it will created in auto mode ([`TlsConnector::auto`]),
/// which will perform the Tls handshake on the underlying stream,
/// only if the request requires a secure connection. You can instead use
/// [`TlsConnector::secure`] to force the connector to always
/// establish a secure connection.
#[derive(Debug, Clone)]
pub struct TlsConnector<S, B, K = ConnectorKindAuto> {
    inner: S,
    base_config: Option<TlsClientConfig>,
    kind: K,
    _backend: PhantomData<fn() -> B>,
}

impl<S, B, K> TlsConnector<S, B, K> {
    /// Creates a new [`TlsConnector`].
    pub const fn new(inner: S, kind: K) -> Self {
        Self {
            inner,
            base_config: None,
            kind,
            _backend: PhantomData,
        }
    }

    generate_set_and_with!(
        /// Set the base [`TlsClientConfig`] for this connector.
        ///
        /// Auto and secure connectors layer per-request TLS pieces on top of this
        /// base. Tunnel connectors intentionally use only this base plus the
        /// proxy-scoped [`TlsTunnel`] fields.
        pub fn base_config(mut self, base: Option<TlsClientConfig>) -> Self {
            self.base_config = base;
            self
        }
    );
}

impl<S, B> TlsConnector<S, B, ConnectorKindAuto> {
    /// Creates a new [`TlsConnector`] which will establish
    /// a secure connection when the input protocol is secure. Otherwise it
    /// forwards the inner connection. The logical authority remains the default
    /// server identity.
    pub const fn auto(inner: S) -> Self {
        Self::new(inner, ConnectorKindAuto)
    }
}

impl<S, B> TlsConnector<S, B, ConnectorKindSecure> {
    /// Creates a new [`TlsConnector`] which will always
    /// establish a secure connection regardless of the request it is for.
    pub const fn secure(inner: S) -> Self {
        Self::new(inner, ConnectorKindSecure)
    }
}

impl<S, B> TlsConnector<S, B, ConnectorKindTunnel> {
    /// Creates a new [`TlsConnector`] which will establish
    /// a secure connection if the request is to be tunneled.
    pub const fn tunnel(inner: S, host: Option<Host>) -> Self {
        Self::new(inner, ConnectorKindTunnel { host })
    }
}

impl<S, B, Input> Service<Input> for TlsConnector<S, B, ConnectorKindAuto>
where
    S: ConnectorService<Input, Connection: Io + Unpin>,
    B: TlsConnectorBackend,
    Input: AuthorityInputExt + ProtocolInputExt + ExtensionsRef + Send + 'static,
{
    type Output = EstablishedClientConnection<B::AutoStream<S::Connection>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        self.check_attempt_policy(&input, input.protocol().is_some_and(Protocol::is_secure))?;
        let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;

        let authority = input.authority().ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("TlsConnector(auto): authority missing from input"),
                ConnectionErrorKind::InvalidInput,
            )
        })?;
        let app_protocol = input.protocol();

        if !app_protocol.is_some_and(Protocol::is_secure) {
            self.check_attempt_policy(&input, false)?;
            tracing::trace!(
                server.address = %authority.host,
                server.port = authority.port_u16(),
                "TlsConnector(auto): protocol not secure, return inner connection",
            );
            return Ok(EstablishedClientConnection {
                input,
                conn: B::auto_plain(conn),
            });
        }

        tracing::trace!(
            server.address = %authority.host,
            server.port = authority.port_u16(),
            "TlsConnector(auto): attempt to secure inner connection w/ app protocol: {:?}",
            app_protocol,
        );

        // Use the authority host as the certificate identity unless overridden.
        let connector_data = self
            .connector_data(input.extensions(), app_protocol, &authority.host)
            .map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                    .context("TlsConnector(auto): build connector configuration")
            })?;

        let scope = Self::check_connector_data(&input, &connector_data, &authority.host)?;
        let reuse = TlsConnectionReuse::new(B::Provider::default(), input.extensions());

        let (stream, negotiated_params) =
            B::handshake(connector_data, conn).await.map_err(|error| {
                ConnectionError::application(error, ConnectionErrorKind::Protocol)
                    .context("TlsConnector(auto): TLS handshake")
            })?;

        tracing::trace!(
            server.address = %authority.host,
            server.port = authority.port_u16(),
            "TlsConnector(auto): protocol secure, established tls connection w/ app protocol: {:?}",
            app_protocol,
        );

        let conn = B::auto_secure(stream);

        #[cfg(feature = "http")]
        set_target_http_version(
            app_protocol,
            input.extensions(),
            conn.extensions(),
            &negotiated_params,
        )
        .map_err(|error| {
            ConnectionError::application(error, ConnectionErrorKind::Protocol)
                .context("TlsConnector(auto): validate negotiated HTTP version")
        })?;

        reuse.publish(conn.extensions());
        conn.extensions().insert(scope);
        conn.extensions().insert(negotiated_params);
        conn.extensions().insert(StreamTransformed { by: B::NAME });
        Ok(EstablishedClientConnection { input, conn })
    }
}

impl<S, B, Input> Service<Input> for TlsConnector<S, B, ConnectorKindSecure>
where
    S: ConnectorService<Input, Connection: Io + Unpin>,
    B: TlsConnectorBackend,
    Input: AuthorityInputExt + ProtocolInputExt + ExtensionsRef + Send + 'static,
{
    type Output = EstablishedClientConnection<B::Stream<S::Connection>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        self.check_attempt_policy(&input, true)?;
        let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;

        let authority = input.authority().ok_or_else(|| {
            ConnectionError::local(
                BoxError::from_static_str("TlsConnector(secure): authority missing from input"),
                ConnectionErrorKind::InvalidInput,
            )
        })?;
        tracing::trace!(
            server.address = %authority.host,
            server.port = authority.port_u16(),
            "TlsConnector(secure): attempt to secure inner connection w/ app protocol: {:?}",
            input.protocol(),
        );

        let app_protocol = input.protocol();
        let connector_data = self
            .connector_data(input.extensions(), app_protocol, &authority.host)
            .map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                    .context("TlsConnector(secure): build connector configuration")
            })?;

        let scope = Self::check_connector_data(&input, &connector_data, &authority.host)?;
        let reuse = TlsConnectionReuse::new(B::Provider::default(), input.extensions());

        let (conn, negotiated_params) =
            B::handshake(connector_data, conn).await.map_err(|error| {
                ConnectionError::application(error, ConnectionErrorKind::Protocol)
                    .context("TlsConnector(secure): TLS handshake")
            })?;

        #[cfg(feature = "http")]
        set_target_http_version(
            app_protocol,
            input.extensions(),
            conn.extensions(),
            &negotiated_params,
        )
        .map_err(|error| {
            ConnectionError::application(error, ConnectionErrorKind::Protocol)
                .context("TlsConnector(secure): validate negotiated HTTP version")
        })?;

        reuse.publish(conn.extensions());
        conn.extensions().insert(scope);
        conn.extensions().insert(negotiated_params);
        conn.extensions().insert(StreamTransformed { by: B::NAME });
        Ok(EstablishedClientConnection { input, conn })
    }
}

impl<S, B, Input> Service<Input> for TlsConnector<S, B, ConnectorKindTunnel>
where
    S: ConnectorService<Input, Connection: Io + Unpin>,
    B: TlsConnectorBackend,
    Input: ExtensionsRef + Send + 'static,
{
    type Output = EstablishedClientConnection<B::AutoStream<S::Connection>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;

        let tunnel = TlsTunnel::from_extensions(input.extensions()).cloned();
        let reuse = TlsConnectionReuse::tunnel(B::Provider::default(), input.extensions());

        let TlsTunnelMode::Tls(maybe_server_host) =
            resolve_tls_tunnel(tunnel.as_ref(), self.kind.host.as_ref())
        else {
            tracing::trace!(
                "TlsConnector(tunnel): return inner connection: no Tls tunnel is requested"
            );
            reuse.publish(conn.extensions());
            return Ok(EstablishedClientConnection {
                input,
                conn: B::auto_plain(conn),
            });
        };

        let tunnel_protocol = tunnel
            .as_ref()
            .and_then(|tunnel| tunnel.application_protocol.as_ref());
        let connector_data = self
            .tunnel_connector_data(tunnel.as_ref(), tunnel_protocol, maybe_server_host)
            .map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                    .context("TlsConnector(tunnel): build connector configuration")
            })?;

        let (stream, negotiated_params) =
            B::handshake(connector_data, conn).await.map_err(|error| {
                ConnectionError::transport(error, ConnectionErrorKind::Protocol)
                    .context("TlsConnector(tunnel): TLS handshake")
            })?;
        let conn = B::auto_secure(stream);

        reuse.publish(conn.extensions());
        conn.extensions().insert(negotiated_params);
        conn.extensions().insert(StreamTransformed { by: B::NAME });
        tracing::trace!("TlsConnector(tunnel): connection secured");
        Ok(EstablishedClientConnection { input, conn })
    }
}

impl<S, B: TlsConnectorBackend, K> TlsConnector<S, B, K> {
    fn tunnel_connector_data(
        &self,
        tunnel: Option<&TlsTunnel>,
        application_protocol: Option<&Protocol>,
        maybe_server_host: Option<&Host>,
    ) -> Result<B::Data, BoxError> {
        let effective = self.tunnel_config_extensions(tunnel, application_protocol);
        B::connector_data(&effective, maybe_server_host)
    }

    fn tunnel_config_extensions(
        &self,
        tunnel: Option<&TlsTunnel>,
        application_protocol: Option<&Protocol>,
    ) -> Extensions {
        let effective = Extensions::new();
        if let Some(base) = &self.base_config {
            effective.extend(base.as_extensions());
        }
        if let Some(alpn) = tunnel.and_then(|tunnel| tunnel.alpn.clone()) {
            effective.insert(alpn);
        }

        apply_default_alpn::<B>(&effective, application_protocol);
        effective
    }

    /// Reject an incompatible discovery policy before dialing. Ordinary connections
    /// retain their existing inner-connector override behavior.
    fn check_attempt_policy(
        &self,
        input: &(impl AuthorityInputExt + ExtensionsRef),
        secure: bool,
    ) -> Result<(), ConnectionError> {
        let Some(attempt) = input.extensions().get_ref::<ConnectionAttempt>() else {
            return Ok(());
        };
        let has_overrides = B::has_overrides(input.extensions());
        let scope = policy_scope(has_overrides);
        if !secure {
            return attempt.check_policy(scope, None);
        }

        let merged;
        let extensions = match (&self.base_config, has_overrides) {
            (Some(base), true) => {
                merged = input.extensions().fork().with_base(base.as_extensions());
                &merged
            }
            (Some(base), false) => base.as_extensions(),
            (None, _) => input.extensions(),
        };
        if !B::Provider::default().authenticates_server(extensions) {
            return attempt.check_policy(scope, None);
        }
        let server_name = extensions.get_ref::<TlsServerName>();
        let authority = server_name.is_none().then(|| input.authority()).flatten();
        let peer = server_name
            .map(|name| &name.0)
            .or_else(|| authority.as_ref().map(|authority| &authority.host));
        attempt.check_policy(scope, peer)
    }

    /// Classify the request after inner connectors have added their extensions,
    /// and check the actual native configuration used by this handshake.
    fn check_connector_data(
        input: &impl ExtensionsRef,
        data: &B::Data,
        server_host: &Host,
    ) -> Result<ConnectionPolicyScope, ConnectionError> {
        let scope = policy_scope(B::has_overrides(input.extensions()));
        if let Some(attempt) = input.extensions().get_ref::<ConnectionAttempt>() {
            let name = B::server_name(data).unwrap_or(server_host);
            attempt.check_policy(scope, B::verifies_server(data).then_some(name))?;
            return Ok(attempt.policy_scope());
        }
        Ok(scope)
    }

    fn connector_data(
        &self,
        request_extensions: &Extensions,
        application_protocol: Option<&Protocol>,
        server_host: &Host,
    ) -> Result<B::Data, BoxError> {
        // Create new extensions only for this function that also apply the base_config
        let effective = request_extensions.fork();
        let extensions = if let Some(base) = &self.base_config {
            effective.with_base(base.as_extensions())
        } else {
            effective
        };

        apply_default_alpn::<B>(&extensions, application_protocol);

        // When HTTP pins a concrete target version, force the TLS ALPN to match
        // it before the handshake
        #[cfg(feature = "http")]
        resolve_http_alpn::<B>(&extensions, application_protocol)?;

        // A configured server identity overrides the transport host.
        B::connector_data(&extensions, Some(server_host))
    }
}

fn policy_scope(has_overrides: bool) -> ConnectionPolicyScope {
    if has_overrides {
        ConnectionPolicyScope::Request
    } else {
        ConnectionPolicyScope::Connector
    }
}

fn apply_default_alpn<B: TlsConnectorBackend>(
    effective_extensions: &Extensions,
    application_protocol: Option<&Protocol>,
) {
    // Any ALPN in the effective chain is explicit connector policy, whether
    // supplied by the request or inherited from a base configuration.
    let alpn = effective_extensions
        .get_ref::<TlsAlpn>()
        .cloned()
        .or_else(|| {
            application_protocol
                .map(|protocol| default_tls_alpn(protocol).unwrap_or_else(TlsAlpn::empty))
        });
    if let Some(alpn) = alpn {
        B::set_alpn(effective_extensions, alpn);
    }
}

/// Force the TLS ALPN to match a concrete [`TargetHttpVersion`] when HTTP pins
/// one. Otherwise protocols like WebSocket can negotiate `h2` even though the
/// request requires an HTTP/1.1 upgrade.
#[cfg(feature = "http")]
fn resolve_http_alpn<B: TlsConnectorBackend>(
    ext: &Extensions,
    application_protocol: Option<&Protocol>,
) -> Result<(), BoxError> {
    if application_protocol.is_some_and(|protocol| !protocol.is_http_based()) {
        return Ok(());
    }
    let Some(target_version) = ext.get_ref::<TargetHttpVersion>() else {
        return Ok(());
    };

    let target_alpn = ApplicationProtocol::try_from(target_version.0)?;
    tracing::trace!(
        ?target_version,
        ?target_alpn,
        "override TLS ALPN to match TargetHttpVersion",
    );

    B::set_alpn(ext, TlsAlpn(smallvec![target_alpn]));
    Ok(())
}

#[cfg(feature = "http")]
fn set_target_http_version(
    application_protocol: Option<&Protocol>,
    request_extensions: &Extensions,
    conn_extensions: &Extensions,
    tls_params: &NegotiatedTlsParameters,
) -> Result<(), BoxError> {
    if !application_protocol.is_some_and(Protocol::is_http_based) {
        return Ok(());
    }
    if let Some(proto) = tls_params.application_layer_protocol.as_ref() {
        let neg_version: Version = proto.try_into()?;
        if let Some(target_version) = request_extensions.get_ref::<TargetHttpVersion>()
            && target_version.0 != neg_version
        {
            return Err(BoxError::from_static_str(
                "target http version not compatible with negotiated tls alpn version",
            )
            .context_debug_field("target_version", *target_version)
            .context_debug_field("negotiated_version", neg_version));
        }

        tracing::trace!(
            "setting request TargetHttpVersion to {:?} based on negotiated APLN",
            neg_version,
        );
        conn_extensions.insert(TargetHttpVersion(neg_version));
    }
    Ok(())
}

#[non_exhaustive]
#[derive(Debug, Clone)]
/// A connector which can be used to establish a connection to a server
/// in function of the input, meaning either it will be a secure
/// connector or it will be a plain connector.
///
/// This connector can be handy as it allows to have a single layer
/// which will work both for plain and secure connections.
pub struct ConnectorKindAuto;

#[non_exhaustive]
#[derive(Debug, Clone)]
/// A connector which can _only_ be used to establish a secure connection,
/// regardless of the scheme of the request URI.
pub struct ConnectorKindSecure;

#[derive(Debug, Clone)]
/// A connector which can be used to use this connector to support
/// secure tls tunnel connections.
///
/// TLS is requested when [`TlsTunnel`] is present or a hardcoded server
/// identity is configured. A dedicated base-config identity takes precedence,
/// followed by the tunnel identity and then this connector fallback.
pub struct ConnectorKindTunnel {
    host: Option<Host>,
}

#[cfg(feature = "test-utils")]
pub mod test_utils;

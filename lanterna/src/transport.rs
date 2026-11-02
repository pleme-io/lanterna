//! The transport seam: one trait, one real implementation, one test double.
//!
//! Every byte lanterna sends or receives passes through [`Transport::send`].
//! The client above it never names `reqwest`, so all of its logic is
//! exercised against [`MockTransport`] with zero network. The real
//! [`ReqwestTransport`] owns exactly three concerns: turning a [`Route`]
//! into a URL, honouring the [`TlsPosture`], and classifying a failure so
//! the client can say *why* it was blind without matching on English prose.
//!
//! Classification is by **type first**: a `rustls::Error` found in the
//! error chain is a TLS failure, and `is_connect()` / `is_timeout()` are
//! reachability. That is necessary but not sufficient. A handshake can
//! outrun the connect timeout and leave no `rustls::Error` in the chain, a
//! chain byte-for-byte identical to a filtered port's, so by type alone a
//! bad certificate reads as a VPN that is down. Hence a second source: after
//! a connect-class failure that no rustls error explains, one bounded
//! plain-TCP connect to the same host and port, on the same connect budget
//! ([`ConnectEvidence`]). TCP opening inside that budget puts the failure
//! past TCP, in the handshake or just after; TCP failing too puts it on the
//! network. A name that does not resolve fails the connect and the probe
//! alike, so it is `blind` and never `empty`. The decision over shape,
//! evidence and posture is the pure [`classify_with`], driven by a table
//! with no `reqwest::Error` in it.
//!
//! This seam is a deliberate copy of the one in holofote, kept in step until
//! it is extracted into a shared crate.

#[cfg(any(test, feature = "mock"))]
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
#[cfg(any(test, feature = "mock"))]
use std::sync::Mutex;
use std::time::Duration;

use bytes::Bytes;
use tokio::net::TcpStream;
use zeroize::{Zeroize, Zeroizing};

use crate::auth::{AuthHeaders, LEGAL_CREDENTIAL_FORMS};
pub use crate::route::Method;
use crate::route::Route;
use crate::tls::TlsPosture;

/// Hand a secret to the HTTP stack as a buffer that zeroizes when the
/// stack releases it. `Bytes::from_owner` keeps the allocation and drops
/// the owner, the `Zeroizing`, when the last reference goes. What hyper
/// copies into its own write buffer is outside our reach; that copy is the
/// honest limit of any HTTP client.
fn zeroizing_bytes<T>(secret: Zeroizing<T>) -> Bytes
where
    T: AsRef<[u8]> + Zeroize + Send + 'static,
{
    Bytes::from_owner(secret)
}

/// A boxed, sendable future: the object-safe return shape of [`Transport::send`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One request, before it becomes bytes.
///
/// The method is derived from the route ([`Route::method`]); a caller cannot
/// pair them wrongly. The credentials live in zeroizing memory and `Debug`
/// redacts them.
#[derive(Clone)]
pub struct HttpRequest {
    /// Derived from `route`.
    pub method: Method,
    /// Where.
    pub route: Route,
    /// Query pairs, appended in order. These carry the per-request settings.
    pub query: Vec<(String, String)>,
    /// The statement, rendered from a [`crate::sql::Question`].
    pub body: String,
    /// The user and key headers, if the call is authenticated.
    pub credentials: Option<AuthHeaders>,
}

impl HttpRequest {
    /// A bare request for `route`, with the method the route dictates.
    #[must_use]
    pub fn new(route: Route) -> Self {
        Self {
            method: route.method(),
            route,
            query: Vec::new(),
            body: String::new(),
            credentials: None,
        }
    }

    /// Append a query pair.
    #[must_use]
    pub fn query(mut self, key: &str, value: impl fmt::Display) -> Self {
        self.query.push((key.to_owned(), value.to_string()));
        self
    }

    /// Append several query pairs.
    #[must_use]
    pub fn queries(mut self, pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        self.query.extend(pairs);
        self
    }

    /// Set the statement.
    #[must_use]
    pub fn statement(mut self, text: impl Into<String>) -> Self {
        self.body = text.into();
        self
    }

    /// Attach the credential headers.
    #[must_use]
    pub fn authorized(mut self, credentials: AuthHeaders) -> Self {
        self.credentials = Some(credentials);
        self
    }
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("route", &self.route.to_string())
            .field("query", &self.query)
            .field("body_bytes", &self.body.len())
            .field("credentials", &self.credentials)
            .finish()
    }
}

/// What came back: the status, the headers the judge and the classifier
/// need, the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// The raw `Retry-After` header, if present, fed to [`handan::judge`].
    pub retry_after: Option<String>,
    /// The raw `X-ClickHouse-Exception-Code` header, if present.
    pub exception_code: Option<String>,
    /// The body, unparsed.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// A JSON body with the given status, the shape every test scripts.
    #[must_use]
    pub fn json(status: u16, body: &serde_json::Value) -> Self {
        Self {
            status,
            retry_after: None,
            exception_code: None,
            body: serde_json::to_vec(body).unwrap_or_default(),
        }
    }

    /// A ClickHouse exception: the status, the exception-code header, and
    /// the plain-text body the server writes.
    #[must_use]
    pub fn exception(status: u16, code: u16, text: &str) -> Self {
        Self {
            status,
            retry_after: None,
            exception_code: Some(code.to_string()),
            body: text.as_bytes().to_vec(),
        }
    }

    /// Attach a `Retry-After` value.
    #[must_use]
    pub fn retry_after(mut self, value: &str) -> Self {
        self.retry_after = Some(value.to_owned());
        self
    }
}

/// What a bounded plain-TCP connect to the base URL's host and port found,
/// after a connect-class failure that no `rustls::Error` explained. Typed,
/// so the classifier decides on it and the message renders from it.
///
/// `Display` is the parenthetical that follows the error's own words:
/// nothing for [`Unprobed`](Self::Unprobed), otherwise a leading space and
/// the finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectEvidence {
    /// No probe ran: the failure was not connect-class, a rustls error had
    /// already explained it, or the base URL names no host or known port.
    Unprobed,
    /// A plain TCP connection opened within the connect timeout, so the
    /// failure is past TCP.
    TcpOpens {
        /// The host as configured.
        host: String,
        /// The port probed.
        port: u16,
    },
    /// A plain TCP connection also failed within the connect timeout:
    /// refused, unroutable, unresolvable, or out of time.
    TcpClosed {
        /// The host as configured.
        host: String,
        /// The port probed.
        port: u16,
    },
}

impl fmt::Display for ConnectEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unprobed => Ok(()),
            Self::TcpOpens { host, port } => write!(
                f,
                " (a plain TCP connection to {host}:{port} opens within the connect timeout, so the failure is past TCP, in the TLS handshake or just after)"
            ),
            Self::TcpClosed { host, port } => write!(
                f,
                " (a plain TCP connection to {host}:{port} also fails within the connect timeout)"
            ),
        }
    }
}

/// Why no response came back at all. Each arm is a different remedy, and
/// the client renders each as a different `blind`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// The host could not be reached: refused, unroutable, unresolvable, or
    /// the connect timed out.
    #[error("could not connect to {host}: {detail}{evidence}")]
    Connect {
        /// The host as configured.
        host: String,
        /// The OS / client's own words.
        detail: String,
        /// What the plain-TCP probe found, if one ran.
        evidence: ConnectEvidence,
    },
    /// The host was reached but did not answer within the request timeout.
    #[error("{host} did not answer within the request timeout: {detail}")]
    Timeout {
        /// The host as configured.
        host: String,
        /// The client's own words.
        detail: String,
    },
    /// The TLS handshake failed: a certificate the current posture does not
    /// trust.
    #[error("TLS handshake with {host} failed: {detail}{evidence}")]
    Tls {
        /// The host as configured.
        host: String,
        /// rustls's own words, or the client's when recognised by evidence.
        detail: String,
        /// What the plain-TCP probe found, if one ran.
        evidence: ConnectEvidence,
    },
    /// Anything else the client could not classify.
    #[error("request to {host} failed: {detail}{evidence}")]
    Other {
        /// The host as configured.
        host: String,
        /// The client's own words.
        detail: String,
        /// What the plain-TCP probe found, if one ran.
        evidence: ConnectEvidence,
    },
    /// Only the mock produces this: a request no test scripted.
    #[error("no scripted response for {method} {route}")]
    Unscripted {
        /// The verb.
        method: Method,
        /// The rendered route.
        route: String,
    },
}

/// The seam. Object-safe, so a client can hold `Arc<dyn Transport>`.
pub trait Transport: Send + Sync {
    /// Put one request and await its response.
    fn send(&self, req: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>>;
}

impl<T: Transport + ?Sized> Transport for Box<T> {
    fn send(&self, req: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>> {
        (**self).send(req)
    }
}

impl<T: Transport + ?Sized> Transport for std::sync::Arc<T> {
    fn send(&self, req: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>> {
        (**self).send(req)
    }
}

/// Connect and request deadlines, from the deployment config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// TCP connect + TLS handshake budget.
    pub connect: Duration,
    /// Whole-request budget.
    pub request: Duration,
}

/// Why the real transport could not be built.
#[derive(Debug, thiserror::Error)]
pub enum TransportBuildError {
    /// `--tls ca:<path>` named a file that could not be read.
    #[error("CA bundle {path} could not be read: {source}")]
    CaUnreadable {
        /// The path given.
        path: std::path::PathBuf,
        /// The OS's reason.
        #[source]
        source: std::io::Error,
    },
    /// `--tls ca:<path>` named a file that is not PEM.
    #[error("CA bundle {path} is not a PEM certificate: {detail}")]
    CaNotPem {
        /// The path given.
        path: std::path::PathBuf,
        /// reqwest's own words.
        detail: String,
    },
    /// The HTTP client refused its configuration.
    #[error("HTTP client could not be built: {detail}")]
    Client {
        /// reqwest's own words.
        detail: String,
    },
    /// The base URL carried a username or password. Refused, and the URL
    /// is deliberately NOT echoed: every answer's `host` field would carry
    /// the password.
    #[error(
        "the base URL carries a username or password; a credential is supplied only as {}",
        LEGAL_CREDENTIAL_FORMS.join(" | ")
    )]
    CredentialInUrl,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProbeTarget {
    host: url::Host<String>,
    port: u16,
}

impl ProbeTarget {
    fn of(base: &url::Url) -> Option<Self> {
        Some(Self {
            host: base.host()?.to_owned(),
            port: base.port_or_known_default()?,
        })
    }

    async fn connect(&self) -> std::io::Result<TcpStream> {
        match &self.host {
            url::Host::Domain(name) => TcpStream::connect((name.as_str(), self.port)).await,
            url::Host::Ipv4(addr) => TcpStream::connect(SocketAddr::from((*addr, self.port))).await,
            url::Host::Ipv6(addr) => TcpStream::connect(SocketAddr::from((*addr, self.port))).await,
        }
    }
}

/// The production transport: reqwest over rustls.
pub struct ReqwestTransport {
    client: reqwest::Client,
    base: url::Url,
    host: String,
    target: Option<ProbeTarget>,
    connect_timeout: Duration,
    posture: TlsPosture,
}

const USER_HEADER: &str = "x-clickhouse-user";
const KEY_HEADER: &str = "x-clickhouse-key";
const EXCEPTION_HEADER: &str = "x-clickhouse-exception-code";

fn secret_header(secret: &str, host: &str) -> Result<reqwest::header::HeaderValue, TransportError> {
    let owned = Zeroizing::new(secret.as_bytes().to_vec());
    let mut value = reqwest::header::HeaderValue::from_maybe_shared(zeroizing_bytes(owned))
        .map_err(|e| TransportError::Other {
            host: host.to_owned(),
            detail: e.to_string(),
            evidence: ConnectEvidence::Unprobed,
        })?;
    value.set_sensitive(true);
    Ok(value)
}

impl ReqwestTransport {
    /// Build against `base` (scheme, host and port; for example
    /// `https://clickhouse.example.com:8443`) under `tls`.
    pub fn new(
        base: url::Url,
        tls: &TlsPosture,
        timeouts: Timeouts,
    ) -> Result<Self, TransportBuildError> {
        if !base.username().is_empty() || base.password().is_some() {
            return Err(TransportBuildError::CredentialInUrl);
        }
        let mut builder = reqwest::Client::builder()
            .connect_timeout(timeouts.connect)
            .timeout(timeouts.request)
            .use_rustls_tls();
        match tls {
            TlsPosture::System => {}
            TlsPosture::AcceptAny => {
                builder = builder
                    .danger_accept_invalid_certs(true)
                    .danger_accept_invalid_hostnames(true);
            }
            TlsPosture::Ca(path) => {
                let pem =
                    std::fs::read(path).map_err(|source| TransportBuildError::CaUnreadable {
                        path: path.clone(),
                        source,
                    })?;
                let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| {
                    TransportBuildError::CaNotPem {
                        path: path.clone(),
                        detail: e.to_string(),
                    }
                })?;
                builder = builder.add_root_certificate(cert);
            }
        }
        let client = builder.build().map_err(|e| TransportBuildError::Client {
            detail: e.to_string(),
        })?;
        let host = base.host_str().unwrap_or_default().to_owned();
        let target = ProbeTarget::of(&base);
        Ok(Self {
            client,
            base,
            host,
            target,
            connect_timeout: timeouts.connect,
            posture: tls.clone(),
        })
    }

    fn url_for(&self, req: &HttpRequest) -> url::Url {
        let mut url = self.base.clone();
        url.set_path(&req.route.to_string());
        url.set_query(None);
        if !req.query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(req.query.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        }
        url
    }

    async fn probe(&self) -> ConnectEvidence {
        let Some(target) = &self.target else {
            return ConnectEvidence::Unprobed;
        };
        let host = self.host.clone();
        let port = target.port;
        match tokio::time::timeout(self.connect_timeout, target.connect()).await {
            Ok(Ok(_)) => ConnectEvidence::TcpOpens { host, port },
            Ok(Err(_)) | Err(_) => ConnectEvidence::TcpClosed { host, port },
        }
    }

    async fn classify(&self, e: &reqwest::Error) -> TransportError {
        let shape = ErrorShape::from(e);
        let evidence = if shape.wants_probe() {
            self.probe().await
        } else {
            ConnectEvidence::Unprobed
        };
        classify_with(&self.host, &self.posture, shape, evidence, &e.to_string())
    }
}

/// The three typed facts the classifier reads off a `reqwest::Error`,
/// lifted out so the decision is a function of plain values and a table can
/// drive it: a `reqwest::Error` cannot be made without I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorShape {
    /// A `rustls::Error` sits somewhere in the `source()` chain.
    pub tls_in_chain: bool,
    /// `reqwest::Error::is_connect()`.
    pub is_connect: bool,
    /// `reqwest::Error::is_timeout()`.
    pub is_timeout: bool,
}

impl ErrorShape {
    /// Whether the probe has anything to add: a connect-class failure that
    /// no rustls error already explains.
    #[must_use]
    pub const fn wants_probe(self) -> bool {
        self.is_connect && !self.tls_in_chain
    }
}

impl From<&reqwest::Error> for ErrorShape {
    fn from(e: &reqwest::Error) -> Self {
        Self {
            tls_in_chain: chain_holds_tls_error(e),
            is_connect: e.is_connect(),
            is_timeout: e.is_timeout(),
        }
    }
}

/// The decision, with nothing to await: a function of the error's typed
/// shape, what the probe found, and the posture in force.
///
/// Precedence: TLS by type; then connect-class, because a connect timeout IS
/// a connect failure and a filtered port must not read as "the host is
/// reachable, the call was slow"; then a request that outran its budget;
/// then everything else.
///
/// On a connect-class failure the evidence decides. TCP opening under
/// [`TlsPosture::System`] / [`TlsPosture::Ca`] leaves the certificate as the
/// likeliest cause: `Tls`. TCP opening under [`TlsPosture::AcceptAny`] rules
/// the certificate out, so it is `Other`, carrying the evidence. TCP failing
/// too, or no probe, is `Connect`.
#[must_use]
pub fn classify_with(
    host: &str,
    posture: &TlsPosture,
    shape: ErrorShape,
    evidence: ConnectEvidence,
    detail: &str,
) -> TransportError {
    let host = host.to_owned();
    let detail = detail.to_owned();
    if shape.tls_in_chain {
        return TransportError::Tls {
            host,
            detail,
            evidence,
        };
    }
    if shape.is_connect {
        return match (&evidence, posture) {
            (ConnectEvidence::TcpOpens { .. }, TlsPosture::System | TlsPosture::Ca(_)) => {
                TransportError::Tls {
                    host,
                    detail,
                    evidence,
                }
            }
            (ConnectEvidence::TcpOpens { .. }, TlsPosture::AcceptAny) => TransportError::Other {
                host,
                detail,
                evidence,
            },
            (ConnectEvidence::TcpClosed { .. } | ConnectEvidence::Unprobed, _) => {
                TransportError::Connect {
                    host,
                    detail,
                    evidence,
                }
            }
        };
    }
    if shape.is_timeout {
        return TransportError::Timeout { host, detail };
    }
    TransportError::Other {
        host,
        detail,
        evidence,
    }
}

/// Walk an error's `source()` chain looking for a `rustls::Error`, either
/// directly or wrapped in an `io::Error`, which is how `tokio-rustls`
/// surfaces it. Typed, not a string match.
pub fn chain_holds_tls_error(root: &(dyn std::error::Error + 'static)) -> bool {
    let mut cursor: Option<&(dyn std::error::Error + 'static)> = Some(root);
    while let Some(err) = cursor {
        if err.downcast_ref::<rustls::Error>().is_some() {
            return true;
        }
        if let Some(inner) = err
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
            && inner.downcast_ref::<rustls::Error>().is_some()
        {
            return true;
        }
        cursor = err.source();
    }
    false
}

impl Transport for ReqwestTransport {
    fn send(&self, req: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>> {
        Box::pin(async move {
            let url = self.url_for(&req);
            let method = match req.method {
                Method::Post => reqwest::Method::POST,
            };
            let mut builder = self.client.request(method, url);
            if let Some(credentials) = &req.credentials {
                builder = builder
                    .header(
                        reqwest::header::HeaderName::from_static(USER_HEADER),
                        secret_header(credentials.user(), &self.host)?,
                    )
                    .header(
                        reqwest::header::HeaderName::from_static(KEY_HEADER),
                        secret_header(credentials.key(), &self.host)?,
                    );
            }
            builder = builder
                .header(
                    reqwest::header::CONTENT_TYPE,
                    reqwest::header::HeaderValue::from_static("text/plain; charset=utf-8"),
                )
                .body(req.body.into_bytes());
            let response = match builder.send().await {
                Ok(response) => response,
                Err(e) => return Err(self.classify(&e).await),
            };
            let status = response.status().as_u16();
            let header_text = |name: &str| {
                response
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned)
            };
            let retry_after = header_text(reqwest::header::RETRY_AFTER.as_str());
            let exception_code = header_text(EXCEPTION_HEADER);
            let body = match response.bytes().await {
                Ok(bytes) => bytes.to_vec(),
                Err(e) => return Err(self.classify(&e).await),
            };
            Ok(HttpResponse {
                status,
                retry_after,
                exception_code,
                body,
            })
        })
    }
}

/// One scripted reply.
#[cfg(any(test, feature = "mock"))]
#[derive(Debug, Clone)]
pub enum Scripted {
    /// Answer with this response.
    Reply(HttpResponse),
    /// Fail the transport with this error.
    Fail(TransportError),
}

/// What the mock saw, with secrets copied out as plain strings: this is a
/// test double and the whole point is to assert on them.
#[cfg(any(test, feature = "mock"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedCall {
    /// The verb.
    pub method: Method,
    /// The rendered route.
    pub route: String,
    /// Query pairs as sent.
    pub query: Vec<(String, String)>,
    /// The statement as sent.
    pub body: String,
    /// The user header as sent.
    pub user: Option<String>,
    /// The key header as sent.
    pub key: Option<String>,
}

#[cfg(any(test, feature = "mock"))]
impl RecordedCall {
    /// The value of one query parameter, if it was sent.
    #[must_use]
    pub fn setting(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

#[cfg(any(test, feature = "mock"))]
struct Rule {
    contains: Option<String>,
    replies: VecDeque<Scripted>,
}

/// A transport that answers from a script. Every statement goes to the same
/// route, so a rule matches on a substring of the statement; the first rule
/// that matches answers. Replies within one rule are consumed in order and
/// the **last** one sticks. A statement no rule matches yields
/// [`TransportError::Unscripted`], a loud failure.
#[cfg(any(test, feature = "mock"))]
#[derive(Default)]
pub struct MockTransport {
    rules: Mutex<Vec<Rule>>,
    calls: Mutex<Vec<RecordedCall>>,
}

#[cfg(any(test, feature = "mock"))]
impl MockTransport {
    /// An empty script.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Script replies for statements containing `contains`.
    #[must_use]
    pub fn on_sql(self, contains: &str, replies: Vec<Scripted>) -> Self {
        self.rules.lock().expect("mock rule lock").push(Rule {
            contains: Some(contains.to_owned()),
            replies: replies.into(),
        });
        self
    }

    /// Script replies for every statement no earlier rule matched.
    #[must_use]
    pub fn on_any(self, replies: Vec<Scripted>) -> Self {
        self.rules.lock().expect("mock rule lock").push(Rule {
            contains: None,
            replies: replies.into(),
        });
        self
    }

    /// Script one JSON reply for every statement.
    #[must_use]
    pub fn reply_json(self, status: u16, body: &serde_json::Value) -> Self {
        self.on_any(vec![Scripted::Reply(HttpResponse::json(status, body))])
    }

    /// Everything sent so far, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<RecordedCall> {
        self.calls.lock().expect("mock call lock").clone()
    }
}

#[cfg(any(test, feature = "mock"))]
impl Transport for MockTransport {
    fn send(&self, req: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>> {
        let route = req.route.to_string();
        self.calls
            .lock()
            .expect("mock call lock")
            .push(RecordedCall {
                method: req.method,
                route: route.clone(),
                query: req.query.clone(),
                body: req.body.clone(),
                user: req.credentials.as_ref().map(|c| c.user().to_owned()),
                key: req.credentials.as_ref().map(|c| c.key().to_owned()),
            });
        let next = {
            let mut rules = self.rules.lock().expect("mock rule lock");
            rules
                .iter_mut()
                .find(|rule| {
                    rule.contains
                        .as_deref()
                        .is_none_or(|needle| req.body.contains(needle))
                })
                .and_then(|rule| {
                    if rule.replies.len() > 1 {
                        rule.replies.pop_front()
                    } else {
                        rule.replies.front().cloned()
                    }
                })
        };
        Box::pin(async move {
            match next {
                Some(Scripted::Reply(r)) => Ok(r),
                Some(Scripted::Fail(e)) => Err(e),
                None => Err(TransportError::Unscripted {
                    method: req.method,
                    route,
                }),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const HOST: &str = "clickhouse-a.example.com";

    fn timeouts(ms: u64) -> Timeouts {
        Timeouts {
            connect: Duration::from_millis(ms),
            request: Duration::from_millis(ms),
        }
    }

    #[test]
    fn a_request_takes_its_method_from_the_route_and_redacts_secrets() {
        let req = HttpRequest::new(Route::Query)
            .query("readonly", 1)
            .statement("SELECT 1")
            .authorized(AuthHeaders::new(
                Zeroizing::new("observer".into()),
                Zeroizing::new("hunter2".into()),
            ));
        assert_eq!(req.method, Method::Post);
        let shown = format!("{req:?}");
        assert!(
            !shown.contains("hunter2") && !shown.contains("observer"),
            "{shown}"
        );
        assert!(shown.contains("readonly"), "settings stay visible: {shown}");
    }

    #[test]
    fn a_secret_crosses_into_the_http_stack_as_a_zeroizing_buffer() {
        let b = zeroizing_bytes(Zeroizing::new(b"hunter2".to_vec()));
        assert_eq!(&b[..], b"hunter2");
        let value = secret_header("k3y", HOST).expect("visible ASCII");
        assert_eq!(value.as_bytes(), b"k3y");
        assert!(value.is_sensitive());
        assert!(secret_header("bad\nvalue", HOST).is_err());
    }

    #[test]
    fn a_base_url_carrying_a_credential_is_refused_without_echoing_it() {
        let at = |userinfo: &str| format!("https://{userinfo}@clickhouse-a.example.com:8443");
        for url in [at("observer:hunter2"), at("observer"), at(":hunter2")] {
            let err = ReqwestTransport::new(
                url::Url::parse(&url).expect("url"),
                &TlsPosture::System,
                timeouts(1_000),
            )
            .err()
            .unwrap_or_else(|| panic!("{url} must be refused"));
            assert!(matches!(err, TransportBuildError::CredentialInUrl), "{err}");
            let msg = err.to_string();
            assert!(
                !msg.contains("hunter2") && !msg.contains("observer"),
                "{msg}"
            );
            for form in LEGAL_CREDENTIAL_FORMS {
                assert!(msg.contains(form), "{msg}");
            }
        }
    }

    #[tokio::test]
    async fn the_mock_matches_on_the_statement_replays_in_order_and_the_last_sticks() {
        let mock = MockTransport::new()
            .on_sql(
                "system.databases",
                vec![
                    Scripted::Reply(HttpResponse::json(500, &json!({"n": 1}))),
                    Scripted::Reply(HttpResponse::json(200, &json!({"n": 2}))),
                ],
            )
            .on_any(vec![Scripted::Reply(HttpResponse::json(
                404,
                &json!({"n": 3}),
            ))]);
        let send = |sql: &'static str| {
            let mock = &mock;
            async move {
                mock.send(HttpRequest::new(Route::Query).statement(sql))
                    .await
                    .expect("scripted")
                    .status
            }
        };
        assert_eq!(send("SELECT 1 FROM system.databases").await, 500);
        assert_eq!(send("SELECT 1 FROM system.databases").await, 200);
        assert_eq!(send("SELECT 1 FROM system.databases").await, 200);
        assert_eq!(send("SELECT 1").await, 404);
        assert_eq!(mock.calls().len(), 4);
        let bare = MockTransport::new();
        let err = bare
            .send(HttpRequest::new(Route::Query))
            .await
            .expect_err("nothing scripted");
        assert!(matches!(err, TransportError::Unscripted { .. }));
    }

    #[test]
    fn a_tls_error_is_recognised_by_type_anywhere_in_the_chain() {
        #[derive(Debug)]
        struct Outer(std::io::Error);
        impl fmt::Display for Outer {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("outer")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        let bare = rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
        assert!(chain_holds_tls_error(&bare));

        let wrapped = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(rustls::CertificateError::Expired),
        );
        assert!(chain_holds_tls_error(&wrapped));

        assert!(chain_holds_tls_error(&Outer(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::HandshakeNotComplete,
        ))));

        let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        assert!(!chain_holds_tls_error(&refused));
        assert!(!chain_holds_tls_error(&Outer(refused)));
    }

    #[test]
    fn the_evidence_renders_as_three_fixed_phrases_after_the_errors_own_words() {
        let opens = ConnectEvidence::TcpOpens {
            host: HOST.into(),
            port: 8443,
        };
        let closed = ConnectEvidence::TcpClosed {
            host: HOST.into(),
            port: 8443,
        };
        assert_eq!(ConnectEvidence::Unprobed.to_string(), "");
        assert_eq!(
            opens.to_string(),
            " (a plain TCP connection to clickhouse-a.example.com:8443 opens within the connect timeout, so the failure is past TCP, in the TLS handshake or just after)"
        );
        assert_eq!(
            closed.to_string(),
            " (a plain TCP connection to clickhouse-a.example.com:8443 also fails within the connect timeout)"
        );
        let connect = TransportError::Connect {
            host: HOST.into(),
            detail: "dns error".into(),
            evidence: closed,
        };
        assert_eq!(
            connect.to_string(),
            "could not connect to clickhouse-a.example.com: dns error (a plain TCP connection to clickhouse-a.example.com:8443 also fails within the connect timeout)"
        );
        let unprobed = TransportError::Connect {
            host: HOST.into(),
            detail: "connection refused".into(),
            evidence: ConnectEvidence::Unprobed,
        };
        assert_eq!(
            unprobed.to_string(),
            "could not connect to clickhouse-a.example.com: connection refused"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn classification_is_a_table_over_shape_evidence_and_posture() {
        fn opens() -> ConnectEvidence {
            ConnectEvidence::TcpOpens {
                host: HOST.into(),
                port: 8443,
            }
        }
        fn closed() -> ConnectEvidence {
            ConnectEvidence::TcpClosed {
                host: HOST.into(),
                port: 8443,
            }
        }
        fn arm(e: &TransportError) -> &'static str {
            match e {
                TransportError::Connect { .. } => "connect",
                TransportError::Timeout { .. } => "timeout",
                TransportError::Tls { .. } => "tls",
                TransportError::Other { .. } => "other",
                TransportError::Unscripted { .. } => "unscripted",
            }
        }
        fn evidence_of(e: &TransportError) -> Option<&ConnectEvidence> {
            match e {
                TransportError::Connect { evidence, .. }
                | TransportError::Tls { evidence, .. }
                | TransportError::Other { evidence, .. } => Some(evidence),
                TransportError::Timeout { .. } | TransportError::Unscripted { .. } => None,
            }
        }
        let shape_of = |tls_in_chain, is_connect, is_timeout| ErrorShape {
            tls_in_chain,
            is_connect,
            is_timeout,
        };
        let system = TlsPosture::System;
        let accept_any = TlsPosture::AcceptAny;
        let ca = TlsPosture::Ca("/etc/ssl/private-root.pem".into());
        let rows = [
            (
                "tls by type",
                shape_of(true, false, false),
                ConnectEvidence::Unprobed,
                &system,
                "tls",
            ),
            (
                "tls by type outranks a connect-class shape",
                shape_of(true, true, true),
                ConnectEvidence::Unprobed,
                &system,
                "tls",
            ),
            (
                "connect-class, TCP opens, system: a certificate",
                shape_of(false, true, true),
                opens(),
                &system,
                "tls",
            ),
            (
                "connect-class, TCP opens, ca: a certificate",
                shape_of(false, true, false),
                opens(),
                &ca,
                "tls",
            ),
            (
                "TCP opens under accept-any: not a certificate, and not the network",
                shape_of(false, true, true),
                opens(),
                &accept_any,
                "other",
            ),
            (
                "a name that does not resolve: connect-class, TCP closed",
                shape_of(false, true, false),
                closed(),
                &system,
                "connect",
            ),
            (
                "TCP closed under accept-any: still the network",
                shape_of(false, true, false),
                closed(),
                &accept_any,
                "connect",
            ),
            (
                "no probe could be made: connect",
                shape_of(false, true, false),
                ConnectEvidence::Unprobed,
                &system,
                "connect",
            ),
            (
                "a connect timeout is a connect failure, not a request timeout",
                shape_of(false, true, true),
                ConnectEvidence::Unprobed,
                &system,
                "connect",
            ),
            (
                "a request timeout that is not connect-class",
                shape_of(false, false, true),
                ConnectEvidence::Unprobed,
                &system,
                "timeout",
            ),
            (
                "anything else",
                shape_of(false, false, false),
                ConnectEvidence::Unprobed,
                &system,
                "other",
            ),
        ];
        for (name, shape, evidence, posture, expected) in rows {
            let got = classify_with(HOST, posture, shape, evidence.clone(), "detail");
            assert_eq!(arm(&got), expected, "{name}: {got}");
            let carried = if expected == "timeout" {
                None
            } else {
                Some(&evidence)
            };
            assert_eq!(
                evidence_of(&got),
                carried,
                "{name}: the evidence rides the arm"
            );
        }
        assert!(shape_of(false, true, true).wants_probe());
        assert!(shape_of(false, true, false).wants_probe());
        assert!(!shape_of(true, true, true).wants_probe());
        assert!(!shape_of(false, false, true).wants_probe());
        assert!(!shape_of(false, false, false).wants_probe());
    }

    #[test]
    fn the_probe_target_is_the_base_urls_host_and_port() {
        let build = |url: &str| {
            ReqwestTransport::new(
                url::Url::parse(url).expect("url"),
                &TlsPosture::System,
                timeouts(10),
            )
            .expect("builds")
        };
        let domain = || url::Host::Domain(HOST.to_owned());
        for (url, host, port) in [
            ("https://clickhouse-a.example.com:8443", domain(), 8443),
            ("https://clickhouse-a.example.com", domain(), 443),
            ("http://clickhouse-a.example.com", domain(), 80),
            (
                "https://127.0.0.1:8443",
                url::Host::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                8443,
            ),
            (
                "https://[::1]:8443",
                url::Host::Ipv6(std::net::Ipv6Addr::LOCALHOST),
                8443,
            ),
        ] {
            let t = build(url);
            assert_eq!(t.target, Some(ProbeTarget { host, port }), "{url}");
            assert_eq!(t.connect_timeout, Duration::from_millis(10));
            assert_eq!(t.posture, TlsPosture::System);
        }
        assert_eq!(build("foo://clickhouse-a.example.com").target, None);
    }

    #[tokio::test]
    async fn the_probe_reports_what_a_loopback_socket_does() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let port = listener.local_addr().expect("addr").port();
        let t = ReqwestTransport::new(
            url::Url::parse(&format!("https://127.0.0.1:{port}")).expect("url"),
            &TlsPosture::System,
            timeouts(2_000),
        )
        .expect("builds");
        assert_eq!(
            t.probe().await,
            ConnectEvidence::TcpOpens {
                host: "127.0.0.1".into(),
                port
            }
        );
        drop(listener);
        assert_eq!(
            t.probe().await,
            ConnectEvidence::TcpClosed {
                host: "127.0.0.1".into(),
                port
            }
        );
        let nowhere = ReqwestTransport::new(
            url::Url::parse("foo://clickhouse-a.example.com").expect("url"),
            &TlsPosture::System,
            timeouts(2_000),
        )
        .expect("builds");
        assert_eq!(nowhere.probe().await, ConnectEvidence::Unprobed);
    }

    #[tokio::test]
    async fn a_closed_loopback_port_is_a_connect_failure_with_tcp_evidence() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let t = ReqwestTransport::new(
            url::Url::parse(&format!("https://127.0.0.1:{port}")).expect("url"),
            &TlsPosture::System,
            timeouts(2_000),
        )
        .expect("builds");
        let err = t
            .send(HttpRequest::new(Route::Query).statement("SELECT 1"))
            .await
            .expect_err("nothing listens");
        assert!(
            matches!(
                &err,
                TransportError::Connect {
                    evidence: ConnectEvidence::TcpClosed { .. },
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn the_real_transport_builds_a_url_from_route_and_query() {
        let t = ReqwestTransport::new(
            url::Url::parse("https://clickhouse-a.example.com:8443").expect("url"),
            &TlsPosture::AcceptAny,
            timeouts(10),
        )
        .expect("builds");
        let req = HttpRequest::new(Route::Query)
            .query("readonly", 1)
            .query("max_result_rows", 501u32);
        assert_eq!(
            t.url_for(&req).as_str(),
            "https://clickhouse-a.example.com:8443/?readonly=1&max_result_rows=501"
        );
        assert_eq!(t.host, HOST);
    }

    #[test]
    fn a_missing_ca_bundle_is_a_typed_build_error() {
        let err = ReqwestTransport::new(
            url::Url::parse("https://clickhouse-b.example.com:8443").expect("url"),
            &TlsPosture::Ca("/nope/lanterna-root.pem".into()),
            timeouts(1_000),
        )
        .err()
        .expect("fails");
        assert!(matches!(err, TransportBuildError::CaUnreadable { .. }));
        assert!(err.to_string().contains("/nope/lanterna-root.pem"));
    }
}

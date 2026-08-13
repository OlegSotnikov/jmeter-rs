// SPDX-License-Identifier: Apache-2.0
//! HTTP method, body, and request construction.

use crate::{Headers, HttpError, Url};

/// An HTTP request method, preserving extension methods.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Method {
    /// GET requests retrieve a representation.
    #[default]
    Get,
    /// HEAD requests retrieve response metadata without a body.
    Head,
    /// POST requests submit a representation.
    Post,
    /// PUT requests replace a representation.
    Put,
    /// DELETE requests remove a representation.
    Delete,
    /// PATCH requests partially modify a representation.
    Patch,
    /// OPTIONS requests inspect server capabilities.
    Options,
    /// TRACE requests echo the request path.
    Trace,
    /// CONNECT requests establish a tunnel.
    Connect,
    /// An extension method not known by this crate.
    Custom(String),
}

impl Method {
    /// Parses a method name while preserving unknown token methods.
    pub fn parse(value: impl Into<String>) -> Result<Self, HttpError> {
        let value = value.into();
        if value.len() > 256 || value.is_empty() || !value.bytes().all(is_token_byte) {
            return Err(HttpError::InvalidMethod("invalid method token".to_owned()));
        }
        Ok(match value.to_ascii_uppercase().as_str() {
            "GET" => Self::Get,
            "HEAD" => Self::Head,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "PATCH" => Self::Patch,
            "OPTIONS" => Self::Options,
            "TRACE" => Self::Trace,
            "CONNECT" => Self::Connect,
            _ => Self::Custom(value),
        })
    }

    /// Returns the wire spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Options => "OPTIONS",
            Self::Trace => "TRACE",
            Self::Connect => "CONNECT",
            Self::Custom(value) => value,
        }
    }

    /// Returns whether this method is safe to retry after a redirect.
    #[must_use]
    pub const fn is_idempotent(&self) -> bool {
        matches!(
            self,
            Self::Get | Self::Head | Self::Put | Self::Delete | Self::Options | Self::Trace
        )
    }

    /// Returns whether this method permits a body by ordinary HTTP rules.
    #[must_use]
    pub const fn allows_body(&self) -> bool {
        !matches!(self, Self::Get | Self::Head | Self::Trace)
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<&str> for Method {
    type Error = HttpError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

/// A bounded request body.
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub enum Body {
    /// No request payload.
    #[default]
    Empty,
    /// An opaque byte payload.
    Bytes(Vec<u8>),
}

impl std::fmt::Debug for Body {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Body")
            .field("bytes", &self.len())
            .field("present", &self.is_present())
            .finish()
    }
}

impl Body {
    /// Creates a byte body.
    #[must_use]
    pub fn bytes(value: impl Into<Vec<u8>>) -> Self {
        Self::Bytes(value.into())
    }

    /// Creates a UTF-8 text body.
    #[must_use]
    pub fn text(value: impl Into<String>) -> Self {
        Self::Bytes(value.into().into_bytes())
    }

    /// Returns the body bytes, or an empty slice for [`Body::Empty`].
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Empty => &[],
            Self::Bytes(value) => value,
        }
    }

    /// Returns the body length.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Bytes(value) => value.len(),
        }
    }

    /// Returns whether the body contains no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns whether this is a present byte body, including a zero-length one.
    #[must_use]
    pub const fn is_present(&self) -> bool {
        matches!(self, Self::Bytes(_))
    }

    /// Consumes the body and returns its bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Empty => Vec::new(),
            Self::Bytes(value) => value,
        }
    }
}

/// A fully constructed HTTP request passed to a transport.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Request {
    method: Method,
    url: Url,
    headers: Headers,
    body: Body,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Request")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &self.headers)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl Request {
    /// Creates an empty request.
    #[must_use]
    pub fn new(method: Method, url: Url) -> Self {
        Self {
            method,
            url,
            headers: Headers::new(),
            body: Body::Empty,
        }
    }

    /// Creates a GET request from a URL string.
    pub fn get(url: impl Into<String>) -> Result<Self, HttpError> {
        Ok(Self::new(Method::Get, Url::parse(url)?))
    }

    /// Creates a POST request from a URL and byte body.
    pub fn post(url: impl Into<String>, body: impl Into<Vec<u8>>) -> Result<Self, HttpError> {
        let mut request = Self::new(Method::Post, Url::parse(url)?);
        request.body = Body::bytes(body);
        Ok(request)
    }

    /// Creates a HEAD request from a URL string.
    pub fn head(url: impl Into<String>) -> Result<Self, HttpError> {
        Ok(Self::new(Method::Head, Url::parse(url)?))
    }

    /// Creates an URL-encoded form POST from ordered field pairs.
    pub fn form_post(
        url: impl Into<String>,
        fields: impl IntoIterator<Item = (impl AsRef<str>, impl AsRef<str>)>,
    ) -> Result<Self, HttpError> {
        let body = fields
            .into_iter()
            .map(|(name, value)| {
                format!(
                    "{}={}",
                    form_encode(name.as_ref()),
                    form_encode(value.as_ref())
                )
            })
            .collect::<Vec<_>>()
            .join("&");
        let mut request = Self::post(url, body.into_bytes())?;
        request.add_header("Content-Type", "application/x-www-form-urlencoded")?;
        Ok(request)
    }

    /// Returns the request method.
    #[must_use]
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Returns the request URL.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Returns the fragment-free origin-form target for transport adapters.
    /// URL fragments are retained on [`Url`] for client-side redirect/cache
    /// semantics but must never be emitted on the wire.
    #[must_use]
    pub fn wire_target(&self) -> &str {
        self.url.wire_target()
    }

    /// Returns the ordered request headers.
    #[must_use]
    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    /// Returns mutable ordered request headers.
    #[must_use]
    pub fn headers_mut(&mut self) -> &mut Headers {
        &mut self.headers
    }

    /// Returns the request body.
    #[must_use]
    pub fn body(&self) -> &Body {
        &self.body
    }

    /// Returns mutable request body.
    #[must_use]
    pub fn body_mut(&mut self) -> &mut Body {
        &mut self.body
    }

    /// Sets the request method.
    pub fn set_method(&mut self, method: Method) {
        self.method = method;
    }

    /// Sets the request URL.
    pub fn set_url(&mut self, url: Url) {
        self.url = url;
    }

    /// Sets a body, preserving an explicitly present empty body.
    pub fn set_body(&mut self, body: Body) {
        self.body = body;
    }

    /// Returns this request with one appended header.
    pub fn with_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, HttpError> {
        self.add_header(name, value)?;
        Ok(self)
    }

    /// Returns this request with a replacement body.
    #[must_use]
    pub fn with_body(mut self, body: Body) -> Self {
        self.set_body(body);
        self
    }

    /// Appends a validated header.
    pub fn add_header(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), HttpError> {
        self.headers.insert(name, value)
    }

    /// Removes every request header with this name.
    pub fn remove_header(&mut self, name: &str) -> usize {
        self.headers.remove(name)
    }

    /// Adds a deterministic `Content-Length` field when a caller did not
    /// supply one. Existing fields are preserved for adapter-specific framing.
    pub fn ensure_content_length(&mut self) -> Result<(), HttpError> {
        if !self.headers.contains("content-length") && self.body.is_present() {
            self.add_header("Content-Length", self.body.len().to_string())?;
        }
        Ok(())
    }

    /// Validates request limits and method/body consistency.
    pub fn validate(
        &self,
        maximum_body_bytes: usize,
        maximum_headers: usize,
    ) -> Result<(), HttpError> {
        if self.body.len() > maximum_body_bytes {
            return Err(HttpError::RequestBodyLimit {
                actual: self.body.len(),
                maximum: maximum_body_bytes,
            });
        }
        if self.headers.len() > maximum_headers {
            return Err(HttpError::resource_limit("request header count"));
        }
        if !self.method.allows_body() && self.body.is_present() && !self.body.is_empty() {
            return Err(HttpError::InvalidMethod(format!(
                "{} request cannot carry a non-empty body",
                self.method
            )));
        }
        Ok(())
    }

    /// Starts a checked builder.
    #[must_use]
    pub fn builder() -> RequestBuilder {
        RequestBuilder::default()
    }
}

/// Builder for a validated [`Request`].
#[derive(Clone, Default)]
pub struct RequestBuilder {
    method: Method,
    url: Option<Url>,
    headers: Headers,
    body: Body,
}

impl std::fmt::Debug for RequestBuilder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RequestBuilder")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &self.headers)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl RequestBuilder {
    /// Sets the method.
    #[must_use]
    pub fn method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    /// Parses and sets the method.
    pub fn method_name(mut self, method: impl Into<String>) -> Result<Self, HttpError> {
        self.method = Method::parse(method)?;
        Ok(self)
    }

    /// Parses and sets the absolute URL.
    pub fn url(mut self, url: impl Into<String>) -> Result<Self, HttpError> {
        self.url = Some(Url::parse(url)?);
        Ok(self)
    }

    /// Sets an already parsed URL.
    #[must_use]
    pub fn parsed_url(mut self, url: Url) -> Self {
        self.url = Some(url);
        self
    }

    /// Appends one header.
    pub fn header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, HttpError> {
        self.headers.insert(name, value)?;
        Ok(self)
    }

    /// Sets a body.
    #[must_use]
    pub fn body(mut self, body: Body) -> Self {
        self.body = body;
        self
    }

    /// Builds the request and validates basic method/body rules.
    pub fn build(self) -> Result<Request, HttpError> {
        let url = self
            .url
            .ok_or_else(|| HttpError::InvalidUrl("request URL is missing".to_owned()))?;
        let request = Request {
            method: self.method,
            url,
            headers: self.headers,
            body: self.body,
        };
        request.validate(usize::MAX, usize::MAX)?;
        Ok(request)
    }
}

/// URL-encodes one form component using JMeter's UTF-8 `URLEncoder` rules.
///
/// Form encoding deliberately differs from URI query encoding: spaces become
/// `+`, `*` remains unescaped, and `~` is percent-encoded.
#[must_use]
pub fn form_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'*' | b'_' => {
                encoded.push(char::from(byte));
            }
            b' ' => encoded.push('+'),
            byte => {
                encoded.push('%');
                encoded.push(hex(byte >> 4));
                encoded.push(hex(byte & 0x0f));
            }
        }
    }
    encoded
}

fn hex(value: u8) -> char {
    char::from(b"0123456789ABCDEF"[usize::from(value)])
}

fn is_token_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'^'
            | b'_'
            | b'`'
            | b'a'..=b'z'
            | b'|'
            | b'~'
    )
}

#[cfg(test)]
mod tests {
    use super::form_encode;

    #[test]
    fn form_encode_matches_jmeter_url_encoder_reserved_set() {
        assert_eq!(form_encode("*~ "), "*%7E+");
        assert_eq!(form_encode("a+b"), "a%2Bb");
    }

    #[test]
    fn form_encode_uses_utf8_for_non_ascii_input() {
        assert_eq!(form_encode("café"), "caf%C3%A9");
    }
}

#![no_main]

//! Bounded HTTP URL, header, and cookie policy target.
//!
//! This target stays at the pure request/state boundary: it never creates a
//! transport, resolves DNS, opens a socket, or reads process/environment data.
//! Arbitrary bytes are truncated before conversion to bounded policy fields.
//!
//! Invariants: `HTTP-URL-BOUNDS-001` exercises URL parsing/joining and wire
//! target normalization; `HTTP-HEADER-BOUNDS-001` exercises duplicate-safe
//! header validation/application; and `HTTP-COOKIE-BOUNDS-001` exercises
//! bounded cookie matching and request-header construction.
//! Source-side coverage: URL text, duplicate header pairs, cookie attributes,
//! and lifecycle policy state are generated and checked as independent fields.
//! I/O policy: none; URL/header/cookie operations stop before any transport.

use std::time::Duration;

use jmeter_rs_http::{ClockReading, Cookie, CookieJar, HeaderManager, HttpError, Request, Url};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_FIELD_BYTES: usize = 4096;

fn bounded_text(data: &[u8]) -> String {
    String::from_utf8_lossy(&data[..data.len().min(MAX_FIELD_BYTES)]).into_owned()
}

fn safe_text(data: &[u8]) -> String {
    data[..data.len().min(MAX_FIELD_BYTES)]
        .iter()
        .map(|byte| match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' => char::from(*byte),
            _ => '_',
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let text = bounded_text(data);
    let safe = safe_text(data);

    // Keep both accepted and rejected URL shapes in the bounded domain.  The
    // accepted variants cover scheme, IPv4-style host names, IPv6 literals,
    // optional ports, path/query/fragment components, and the rejected
    // variants exercise typed parser rejection without feeding arbitrary
    // unbounded text to the URL implementation.
    let selector = data.first().copied().unwrap_or_default() % 5;
    let token = safe_text(data.get(1..).unwrap_or_default());
    let query = safe_text(data.get(2..).unwrap_or_default());
    let scheme = if data.first().is_some_and(|value| value & 0x08 != 0) {
        "http"
    } else {
        "https"
    };
    let host = if data.get(1).is_some_and(|value| value & 0x01 != 0) {
        "[2001:db8::1]"
    } else {
        "example.test"
    };
    let port = if data.get(1).is_some_and(|value| value & 0x02 != 0) {
        format!(
            ":{}",
            1024 + u16::from(data.get(2).copied().unwrap_or_default())
        )
    } else {
        String::new()
    };
    let (url_text, expected_valid) = match selector {
        1 => (format!("https://example.test/%ZZ/{token}"), false),
        2 => (format!("ftp://example.test/path/{token}"), false),
        3 => (
            format!("{scheme}://{host}{port}/path/{token}?q={query}#{token}"),
            true,
        ),
        4 => (format!("{scheme}://{host}{port}/"), true),
        _ => (
            format!("{scheme}://{host}{port}/path/{token}?q={query}"),
            true,
        ),
    };
    let parsed = Url::parse(url_text);
    if !expected_valid {
        if parsed.is_ok() {
            panic!("URL parser accepted a deliberately malformed bounded URL");
        }
        return;
    }
    let Ok(url) = parsed else {
        return;
    };
    if url.wire_form().contains('#') || url.wire_target().contains('#') {
        panic!("HTTP URL fragment reached a wire form");
    }
    let location = match data.first().copied().unwrap_or_default() % 4 {
        0 => format!("child/{token}"),
        1 => format!("/absolute/{token}"),
        2 => format!("?next={query}"),
        _ => format!("#{token}"),
    };
    let joined = match url.join(&location) {
        Ok(joined) => joined,
        Err(HttpError::ResourceLimit(_)) => return,
        Err(error) => panic!("unexpected bounded URL join error: {error:?}"),
    };
    if joined.scheme() != url.scheme() || joined.host() != url.host() || joined.port() != url.port()
    {
        panic!("HTTP URL join changed origin policy");
    }

    let mut request = Request::get(url.as_str()).expect("validated URL must build a request");
    let mut headers = HeaderManager::new(8).expect("positive header bound");
    match headers.add("X-Fuzz", text.clone()) {
        Ok(()) => {}
        Err(HttpError::InvalidHeader(_))
            if text.bytes().any(|byte| byte < 0x20 || byte == 0x7f) =>
        {
            // Controls are the one expected rejection for this bounded value.
        }
        Err(error) => panic!("unexpected bounded header error: {error:?}"),
    }
    headers
        .add("X-Fuzz", "duplicate")
        .expect("static duplicate header must be accepted");
    headers.apply(&mut request);
    if request.headers().len() > 8
        || request
            .headers()
            .checked_wire_len()
            .expect("bounded headers must have representable wire length")
            > 64 * 1024
    {
        panic!("HTTP header manager exceeded its declared bound");
    }

    let mut jar = CookieJar::new(8).expect("positive cookie bound");
    let cookie_value = safe;
    let Ok(cookie) = Cookie::new("fuzz", cookie_value, "example.test", "/") else {
        return;
    };
    let now = ClockReading {
        wall_millis: 1_700_000_000_000,
        monotonic: Duration::from_secs(1),
    };
    jar.add(cookie, now)
        .expect("host-only cookie must be bounded");
    let header = jar
        .try_request_header(&url, now)
        .expect("cookie header bound");
    if let Some(header) = header
        && (header.len() > 64 * 1024 || !header.starts_with("fuzz="))
    {
        panic!("cookie header violated bounded matching policy");
    }
    jar.capture_initial();
    jar.clear();
    jar.reset_for_iteration(true);
    if jar.cookies().len() > 8 {
        panic!("cookie lifecycle exceeded its capacity");
    }
});

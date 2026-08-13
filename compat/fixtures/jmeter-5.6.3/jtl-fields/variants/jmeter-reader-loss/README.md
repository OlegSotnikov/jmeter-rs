<!-- SPDX-License-Identifier: Apache-2.0 -->

# JMeter reader-loss semantics

This directory records reader behavior separately from writer-wire
expectations.  `url-and-file.xml` and
`../../expected/jmeter-reader-loss.xml.json` are the executable input and
contract.  A JMeter XML `java.net.URL` element is writer output, but the
5.6.3 reader does not restore that URL into the `SampleResult`.  When a
`responseFile` is present without `responseData`, the reader attempts to load
the referenced file; the fixture resource is provided for the explicit
fallback contract.  Rust no-drop parsing must retain the URL as a typed
`java.net.URL` extension and retain the response-file reference without an
implicit load.

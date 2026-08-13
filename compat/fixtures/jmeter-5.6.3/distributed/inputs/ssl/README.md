<!-- SPDX-License-Identifier: Apache-2.0 -->

# SSL material protected references

This directory intentionally contains no keystore, truststore, certificate,
private key, or password. An external runner must generate short-lived JKS
files in its private run root with the pinned JDK `keytool`, then resolve the
typed path and secret references through the protected channels recorded in
`case.json` before constructing the JVM system-property arguments:

| role | keystore reference | truststore reference | path channel | secret channel | type | alias | certificate identity |
| --- | --- | --- | --- | --- | --- | --- | --- |
| client | `path://rmi/client-keystore.jks` | `path://rmi/client-truststore.jks` | `channel://rmi-tls-material` | `channel://rmi-tls-secrets` | `JKS` | `rmi` | `client-rmi-127.0.0.1` |
| worker-a | `path://rmi/worker-a-keystore.jks` | `path://rmi/worker-a-truststore.jks` | `channel://rmi-tls-material` | `channel://rmi-tls-secrets` | `JKS` | `rmi` | `worker-a-rmi-127.0.0.1` |
| worker-b | `path://rmi/worker-b-keystore.jks` | `path://rmi/worker-b-truststore.jks` | `channel://rmi-tls-material` | `channel://rmi-tls-secrets` | `JKS` | `rmi` | `worker-b-rmi-127.0.0.1` |

Secret bytes are generated per run and never appear in argv, ordinary
properties, or evidence. The external runner resolves each protected reference
inside the secret channel while materializing one `-D<name>=<value>` JVM
argument per assignment, then erases the resolved bytes and generated stores
on success, error, or cancellation. No SSL handshake or certificate identity
is observed by this static corpus.

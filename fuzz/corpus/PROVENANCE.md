# Seed provenance

These are original, synthetic, hand-authored seed inputs for TEST-003. They
were created in this repository on 2026-08-12 (UTC), under the Apache-2.0
license in the repository root. No seed is copied from Apache JMeter, a
third-party plugin, a customer plan, or a live service. Values use only
reserved/example identities; no credential, private key, downloaded archive,
or ambient machine path is present.

| file | target | purpose | bound |
| --- | --- | --- | ---: |
| `jmx_xml/minimal-valid.jmx` | `jmx_xml` | minimal valid JMX topology and typed property | 256 KiB input |
| `jmx_xml/unknown-opaque.jmx` | `jmx_xml` | unknown element/property, extra attributes, Unicode/entities | 256 KiB input |
| `jmx_xml/truncated.xml` | `jmx_xml` | truncated XML / bounded error | 256 KiB input |
| `jmx_xml/entities-and-utf8.jmx` | `jmx_xml` | original Unicode, XML entities, and opaque extension seed | 256 KiB input |
| `jmx_xml/upgrade-dropped.jmx` | `jmx_xml` | original upgrade property with explicit dropped-byte inventory | 256 KiB input |
| `jmx_xml/limits-depth.xml` | `jmx_xml` | original nested XML depth-limit seed | 256 KiB input |
| `jtl_csv/basic.csv` | `jtl_csv` | canonical CSV header, numeric fields, simple result | 256 KiB input |
| `jtl_csv/quoted-fields.csv` | `jtl_csv` | quoted delimiter, quote escape, embedded line break | 256 KiB input |
| `jtl_csv/malformed.csv` | `jtl_csv` | invalid timestamp and unterminated quote | 256 KiB input |
| `jtl_csv/unicode.csv` | `jtl_csv` | original UTF-8, entities-as-data, and quoted delimiter fields | 256 KiB input |
| `jtl_csv/unknown-header.csv` | `jtl_csv` | original unknown header column boundary | 256 KiB input |
| `jtl_csv/limits.csv` | `jtl_csv` | original bounded multi-sample input | 256 KiB input |
| `jtl_xml/basic.xml` | `jtl_xml` | XML attributes, entities, response child nodes | 256 KiB input |
| `jtl_xml/nested.xml` | `jtl_xml` | nested sample and assertion result, `rs` alias | 256 KiB input |
| `jtl_xml/malformed.xml` | `jtl_xml` | truncated XML/text child | 256 KiB input |
| `jtl_xml/entities-and-utf8.xml` | `jtl_xml` | original UTF-8 and XML entity payload seed | 256 KiB input |
| `jtl_xml/unknown-attribute.xml` | `jtl_xml` | original rejected plugin attribute boundary | 256 KiB input |
| `jtl_xml/limits-depth.xml` | `jtl_xml` | original nested XML depth-limit seed | 256 KiB input |
| `expr/literals-and-references.expr` | `expr` | undefined variables/functions and unclosed reference | 64 KiB input |
| `expr/escaping.expr` | `expr` | escaped separators and built-in expansion | 64 KiB input |
| `expr/limits.expr` | `expr` | original expansion-limit seed | 64 KiB input |
| `expr/utf8.expr` | `expr` | original UTF-8 literal and undefined variable seed | 64 KiB input |
| `bridge/raw-header.seed` | `bridge` | arbitrary/malformed frame bytes | 256 KiB input |
| `bridge/payload-text.seed` | `bridge` | opaque payload through valid-frame path | 256 KiB input |
| `bridge/handshake.seed` | `bridge` | original handshake-kind metadata seed | 256 KiB input |
| `bridge/response.seed` | `bridge` | original response-kind metadata seed | 256 KiB input |
| `bridge/cancel.seed` | `bridge` | original cancellation-kind metadata seed | 256 KiB input |
| `bridge/error.seed` | `bridge` | original structured-error metadata seed | 256 KiB input |
| `bridge_rmi/bounds.seed` | `bridge_rmi` | pure RMI frame, stream, and resource-bound selector seed | 256 KiB input |
| `bridge_rmi/lifecycle.seed` | `bridge_rmi` | lifecycle overload, host presence, and sender-mode selector seed | 256 KiB input |
| `bridge_rmi/replay-gap.seed` | `bridge_rmi` | replay/gap, credit/ack, and terminal-order selector seed | 256 KiB input |
| `property_config/recognized.properties` | `property_config` | recognized save-service switches | 64 KiB input |
| `property_config/malformed.properties` | `property_config` | invalid recognized and unknown properties | 64 KiB input |
| `property_config/unknown-only.properties` | `property_config` | original unknown-only ignored-property contract | 64 KiB input |
| `property_config/limits.properties` | `property_config` | original numeric configuration-limit error | 64 KiB input |
| `property_config/unicode.properties` | `property_config` | original UTF-8 encoding and variable names | 64 KiB input |
| `property_config/duplicates.properties` | `property_config` | original duplicate last-write and unknown mix | 64 KiB input |
| `save_config/precedence.seed` | `save_config` | generated source precedence, repeated operations, and present-empty state | 64 KiB input |
| `save_config/unknown-and-alias.seed` | `save_config` | unknown property retention and approved property alias decoding | 64 KiB input |
| `save_config/bounds.seed` | `save_config` | small-limit, remove/absent, and unknown-wire branches | 64 KiB input |

The seeds are not oracle artifacts and do not establish compatibility. A
future minimized regression must add its source (original/generated/fuzz
minimized), toolchain and flags, profile ID, and license/provenance note here
before it is retained.

## Reproducible JTL, RMI, and save-config seed SHA-256 manifest

These hashes cover the exact checked-in JTL, RMI, and save-config source bytes,
including line endings. They identify the seeds reproducibly but are not
fuzz-campaign evidence.

| file | SHA-256 |
| --- | --- |
| `jtl_csv/basic.csv` | `94d9b7e7ee298e14093d534901434a9275ffe7efd30d642aa7b19a98003b00da` |
| `jtl_csv/limits.csv` | `8b06990a7ed3f4d24277e69c9e5638ba5097d9bd500df0bc109e64295cd415b7` |
| `jtl_csv/malformed.csv` | `f209ef36b4e94033bc4b2271433fc28cad986707f82bf2657500a0c67f26bc7f` |
| `jtl_csv/quoted-fields.csv` | `e5b7008d599051cc91c8a60e50ec5c9942868bebbb4799051d7acf4fedf7e029` |
| `jtl_csv/unicode.csv` | `7915d00b2e304b05fb569dad4a4242bd33da8b839bf8234cb74028dede3ec298` |
| `jtl_csv/unknown-header.csv` | `69af462c77accb3179147d19c8898fde8fe4cc72e0c204142a537399d04dc971` |
| `jtl_xml/basic.xml` | `841574e072b49db385e7eecdbb7cc33dd483c64d7fc26a84b0f5f4a05ff44792` |
| `jtl_xml/entities-and-utf8.xml` | `6c94a121b431c89bf9db38b4e5602402529bb3fd0ee1e89288afbc057ab58fbe` |
| `jtl_xml/limits-depth.xml` | `612201e3f03c5b3bf0dc555859a624c2163ce46848f8474847c9eb407b2e9b5d` |
| `jtl_xml/malformed.xml` | `3c61c0cdaf0317fa1afce4d61bdfbc6bd9fde6ea0882326bb45f39cb720c7a65` |
| `jtl_xml/nested.xml` | `b0a1a6b21b48616bf66d5ac22fd0fba72cf409c7b707cc9c9eef6c607232fc0e` |
| `jtl_xml/unknown-attribute.xml` | `7fc3fe19d9ee671628c58aba9fa2726c454818d70a733bd02a47b0ed86f6574d` |
| `bridge_rmi/bounds.seed` | `459ba6c35b4b612804b9efef32112800622e78cb999248c0ce24b41d72f5ab58` |
| `bridge_rmi/lifecycle.seed` | `ae8e4cecfb6ca6aba85194fa7495ffee25c7f1bb4cdd67e457fc9bc4a40cb017` |
| `bridge_rmi/replay-gap.seed` | `4eee1e600f74e292489928203e52c869d99f220007719196a69dba244c1bc45f` |
| `save_config/bounds.seed` | `04945c427c6786d343053ec889af4e1975646da2bf21633494714be61ed5e6d6` |
| `save_config/precedence.seed` | `9767f06c27f80c7b86311575f467c828edff43935d742f0c7fc766914d389651` |
| `save_config/unknown-and-alias.seed` | `efc29e7810c5c10c2e27e70f8c1a4cefb99cfa13970ee97b41f0e3e3c7dd7a5e` |

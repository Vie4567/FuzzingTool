These certificate and RSA private key files are public test fixtures only.
They identify the local test server (`localhost` / `127.0.0.1`) and must never
be deployed. The test trusts the certificate only through a scoped
`SSL_CERT_FILE` environment patch; no system certificate store is changed.

Generated offline using .NET CertificateRequest, RSA 2048 / SHA-256, valid
2026-01-01 through 2036-01-01. Runtime tests require only Python's standard
library and do not generate certificates or access the Internet.

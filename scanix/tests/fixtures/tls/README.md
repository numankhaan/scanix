These keys and certificates are **public test fixtures**, never production secrets.
Do not trust this CA system-wide. The client loads `ca.pem` only for loopback tests.

`generate.py` uses fixed serials, validity dates, names and the checked-in TEST ONLY
RSA keys. Regeneration requires `cryptography`; regular CI and Scanix do not.
RSA PKCS#1 v1.5 signing makes regenerated PEM files byte-identical with these keys.
Trusted/self-signed certificates are valid 2024-01-01 through 2045-01-01; the
expired leaf ended 2020-01-01. SANs: lab.scanix.invalid, localhost, 127.0.0.1, ::1.
All material and the original protocol fixtures in this directory are CC0-1.0.

## OHTTP Gateway (test-only)

A minimal Oblivious HTTP gateway for debugging relay and client implementations to ensure compatiblity with OHTTP gateway services such as Cloudflare Privacy Gateway. It implements RFC 9458 plus the chunked OHTTP draft by leveraging the `ohttp` and `bhttp` crates. It has absolutely no security, no TLS support, no privacypass support and no unsafe {} scapegoats to blame when it explodes, so dont use this anywhere except localhost

You will probabyl find the most utility from debugging HPKE issues or OHTTP Chunking issues

### Running

```bash
cargo run -- --host 127.0.0.1 --port 8080 --debug
```

The server listens on 127.0.0.1:8080 and exposes:

- `/ohttp-keys` — `application/ohttp-keys` configuration with a single X25519/AES-128-GCM key.
- `/ohttp` — accepts encapsulated requests (`message/ohttp-req`) and chunked OHTTP. The inner Host header determines the upstream target, and the response is returned as `message/ohttp-res`.

### Notes

- Incase I wasn't clear earlier, its cleartext. Dont, repeat dont, use this for anything except debugging locally. You may need to specifically declare allowing cleartext HTTP in your client in order to debug 
- No authentication or key integrity checks are performed; this is intentionally insecure for local testing only.
- Upstream traffic is forwarded with `reqwest` using Rustls.I figured theres no need to inspect the actual target resrouce request as we have the ability to see the plaintext content of the encapsulated OHTTP req. 
- If a standard encapsulated request fails to decode, the handler automatically falls back to the chunked OHTTP stream API.

### Command-line switches

- `--host/-H` (default `127.0.0.1`): Bind address.
- `--port/-p` (default `8080`): Bind port.
- `--debug`: Enable debug-level logging.
- `--debug-chunks`: Log per-chunk send/receive timestamps for chunked streaming.
- `--debug-hpke`: Enable deep HPKE key-schedule logging (sets `HPKE_DEBUG=1` for the vendored hpke/ohttp).
- `--debug-payload`: Log decrypted inner HTTP request/response summaries and a preview of the body (use with caution; reveals plaintext).

### Vendored crates for debug instrumentation

To surface HPKE internals and detailed logging, the `ohttp` and `hpke` crates are vendored under `vendor/ohttp` and `vendor/hpke` with added debug hooks (info strings, shared secrets, key/nonce derivation, nonce/tag used in AEAD open). This is strictly for debugging interoperability and should not be used in production without reviewing the changes.

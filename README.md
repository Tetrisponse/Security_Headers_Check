# **Security_Headers_Check**

A robust, dependency-free Python tool for auditing web security headers and cookie attributes. Designed for SecOps professionals to validate security postures across internal (VPN/Intranet) and external environments.

## Features

- **Zero External Dependencies**: Runs on standard Python 3 libraries (`urllib`, `sys`, `socket`). No `pip install` required.

- **Strict Validation**: Doesn't just check if a header exists; checks if it is secure.

- **HSTS**: Validates `max-age >= 1 year (31536000s)` and presence of `includeSubDomains`.

- **CSP**: Flags dangerous directives like `unsafe-inline`, `unsafe-eval`, or `default-src *`.

- **Referrer-Policy**: Enforces a strict allow-list of privacy-preserving policies.

## Smart Networking:

- **Redirection Detection**: Alerts you if the target URL redirects (e.g., from `http` to `https` or to a `/login` page) so you know exactly which page was audited.

- **Auto-Fallback**: Attempts a lightweight `HEAD` request first. If blocked (HTTP 405), automatically retries with `GET`.

- **Cookie Auditing**: Inspects every `Set-Cookie` header for `Secure`, `HttpOnly`, and `SameSite` attributes.

## Usage

Open your terminal and run the script followed by the domains or full URLs you want to check.
```
python3 security_headers_check.py <domain1> <domain2> ...
```

## Examples

**Check a root domain**:
```
python3 security_headers_check.py example.com
```

**Check a subdomain**:
```
python3 security_headers_check.py app.example.com
```


**Check a specific sensitive path**:
*Useful for verifying strict CSPs on admin pages or checking specific cookies on login pages.*
```
python3 security_headers_check.py app.example.com/admin/login
```

## What is Audited?

The script enforces the following criteria. A header is only marked as PASS if it meets the specific security requirements below:

| Header | Pass Criteria |
|----|----|
| `Strict-Transport-Security` | Must have: `max-age` >= 31536000 (1 year) AND include `includeSubDomains`.|
| `Content-Security-Policy` | Checked for presence. Warns if it contains: `unsafe-inline`, `unsafe-eval`, or `default-src *`.|
| `X-Frame-Options` | Must be `DENY` or `SAMEORIGIN`. Deprecated values like `ALLOW-FROM` trigger a failure. |
| `X-Content-Type-Options` | Must be exactly `nosniff`. |
| `Referrer-Policy` | Must be one of the safe values: `strict-origin`, `strict-origin-when-cross-origin`, `no-referrer`, `same-origin`. |
| `Permissions-Policy` | Checked for presence. |
| `Cross-Origin-*-Policy` | Headers like `Cross-Origin-Opener-Policy` must NOT be `unsafe-none`. |

**Cookies**

If `Set-Cookie` headers are detected, each cookie is individually analyzed for:

- `Secure`: Ensures cookie is only sent over encrypted HTTPS connections.

- `HttpOnly`: Prevents JavaScript from accessing the cookie (Critical XSS mitigation).

- `SameSite`: Mitigates CSRF attacks (Expects `Lax` or `Strict`).

## Interpreting Results

- **[✓] Green**: Header is present and configured securely.

- **[✗] Red**: Header is missing **OR** configured insecurely (e.g., HSTS `max-age=0` or `X-Frame-Options: ALLOW-FROM`).

- **[!] Yellow**: Header is present but contains potentially weak directives (e.g., CSP `unsafe-inline warning`).

- **[ℹ] Blue**: Informational messages (e.g., "Redirected to login page" or "No cookies found").



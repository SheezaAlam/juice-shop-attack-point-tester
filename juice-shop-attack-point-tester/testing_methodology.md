# Testing Methodology — Three Attack Points

## 1. Directory listing indicators
**Endpoint:** `GET /ftp/`  
**Method:** Send a GET request with a five-second timeout. Search the lowercased response body for `index of /ftp`, `directory listing for /ftp`, `acquisitions.md`, and `incident-support.kdbx`.  
**Observed result:** HTTP 200; `acquisitions.md` and `incident-support.kdbx` were found.  
**Interpretation:** Potential directory/file-name exposure. Confirm the response structure and whether these files are intended to be public.

## 2. Public file access
**Endpoint:** `GET /ftp/acquisitions.md`  
**Method:** Send a GET request and record status and `Content-Type`. HTTP 200 is flagged for review; 401/403 is access restricted; 404 is not found.  
**Observed result:** HTTP 200; `Content-Type: text/markdown; charset=UTF-8`.  
**Interpretation:** File was accessible during testing. Accessibility alone does not prove a vulnerability; review contents and intended access policy.

## 3. Security headers
**Endpoint:** `GET /`  
**Method:** Inspect `X-Content-Type-Options`, `X-Frame-Options`, and `Content-Security-Policy`. HSTS is assessed separately and skipped for an HTTP target.  
**Observed result:** `X-Content-Type-Options: nosniff` and `X-Frame-Options: SAMEORIGIN` were present; `Content-Security-Policy` was missing. HSTS was skipped because the target URL used HTTP.  
**Interpretation:** Review whether CSP is appropriate; a missing header alone does not prove exploitability.

## Error handling and repeatability
Each test catches request exceptions. The base URL is supplied at runtime, so the script can be reused against another authorized Juice Shop instance. Tests use non-destructive GET requests.

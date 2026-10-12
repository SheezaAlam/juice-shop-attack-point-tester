# Limitations and Possible Improvements

## Limitations
- Only three fixed checks are performed; this is not a full scanner.
- Directory detection relies on fixed strings and can miss other formats or produce false positives.
- HTTP 200 does not prove that a resource should be private.
- Only three security headers are checked; header requirements depend on deployment context.
- The tool does not authenticate, crawl the application, test role-based access, or exploit vulnerabilities.
- The report summarizes results rather than saving full raw responses or hashes.
- URL validation is basic; the operator must confirm target authorization and scope.

## Improvements
1. Add command-line options for target, timeout, and report path.
2. Add an allowlist or target confirmation to reduce accidental out-of-scope testing.
3. Improve directory detection using response structure, not filenames alone.
4. Add unit tests for 200, 403, 404, timeout, and connection errors.
5. Add JSON/CSV reporting and separate counts for findings, inconclusive checks, and errors.
6. Record selected evidence metadata and response times.
7. Require manual verification before reporting a vulnerability as confirmed.

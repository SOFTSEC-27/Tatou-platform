# Fuzzing

## 10 October — Login API

Tested /api/login with non-object JSON using Hypothesis and Flask test client (max_examples=100, deadline=None). Expected 400 with a JSON error and no token.

1. The test reported true as a failing input: it returned 500 with an HTML page. The code called .get() on a boolean without checking the body type. Also reproduced the 500 in the browser.

Added a body-type check before reading fields and kept true as a fixed regression case with @example(body=True). The fuzz test passed after the fix, and all six existing login tests passed.

2. Hypothesis reported email=true returning 500 because the login code called .strip() on a boolean. Added an email type check to return 400 for non-string values, and the fuzz test passed after the fix.

3. Hypothesis with a mocked database reported password=true returning 500 because password hashing called .encode() on a boolean. Added a password type check to return 400; all 164 tests passed after the fix.
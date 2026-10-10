# Fuzzing

## 10 October — Login API

Tested /api/login with non-object JSON using Hypothesis and Flask test client (max_examples=100, deadline=None). Expected 400 with a JSON error and no token.

The test reported true as a failing input: it returned 500 with an HTML page. The code called .get() on a boolean without checking the body type. Also reproduced the 500 in the browser.

Added a body-type check before reading fields and kept true as a fixed regression case with @example(body=True). The fuzz test passed after the fix, and all six existing login tests passed.

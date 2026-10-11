# Fuzzing

## 10 October — Login API

Tested /api/login with non-object JSON using Hypothesis and Flask test client (max_examples=100, deadline=None). Expected 400 with a JSON error and no token.

Hypothesis found missing input-type checks in login and registration: non-object request bodies and non-string login fields could cause unhandled exceptions and 500 responses. 

## Delete-document API
Delete-document converted ID 1.5 to 1 and returned 500 when the JSON body was true. 

## Get-document API
Get-document queried the database for ID 0 and returned 404. 

## Try Grammar-based fuzzing
Added a grammar-guided Hypothesis test for layered-identity-v1 using structured secrets, generated keys, three positions and a fixed one-page PDF (max_examples=100, deadline=None). Secret recovery, PDF readability and wrong-key rejection passed; no new bug was found, and all 170 tests passed.


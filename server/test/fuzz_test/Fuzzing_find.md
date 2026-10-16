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

## 12 October — AFL++ fuzzing

Ran three AFL++ campaigns in a separate Docker container using Python 3.12.3 and python-afl. The harnesses called the real Flask routes through the test client, with a fresh SQLite database for each execution. An initial probe confirmed that coverage feedback was stable for repeated inputs and different for different branches.

- **Login input handling:** Started with seven JSON seeds, including non-object bodies, malformed JSON, wrong field types and unknown credentials. With no users in the database, checked for 400/401 JSON errors, no token and no new users.
- **Login authentication:** Used a fixed test account and 11 seeds. Checked the expected 400/401/200 status, rejection of wrong credentials, and the signature and identity of tokens returned for correct credentials. The account had to remain unchanged.
- **Watermark lifecycle:** Used three structured scenarios and a custom mutator that preserved valid JSON while varying watermark parameters and PDF layout. Tested account creation, login, PDF upload, layered watermark creation, version listing, download, secret recovery, wrong-key rejection and deletion. Checked that the original stayed unchanged and that deleted records, files and links were no longer available.

| Campaign | Duration | Executions | Stability | Saved crashes / hangs |
|---|---:|---:|---:|---:|
| Login input handling | 334 s | 4,362 | 100% | 0 / 0 |
| Login authentication | 720 s | 9,004 | 100% | 0 / 0 |
| Watermark lifecycle | 720 s | 1,888 | 99.90% | 0 / 0 |

No assertion failures, crashes or hangs were reported in these runs. Lifecycle feedback had 16 variable bitmap positions; the exact cause of this minor variation was not confirmed. Stability is not code coverage or a functional pass rate.

These results do not prove the absence of bugs. The lifecycle campaign covered only layered-identity-v1 with a fixed operation order and bounded valid inputs. It did not cover RMAP, all watermark methods, damaged PDFs or malformed API bodies at each lifecycle stage. SQLite also does not reproduce all deployed MariaDB behavior.


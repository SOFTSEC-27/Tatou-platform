# Tatou-platform Development Journal

**Project:** SOFTSEC 2026 — SOFTSEC-27/Tatou-platform  
**Period:** 12 September–8 October 2026  
**Working branch:** `dev`  
**Individual specialization:** A — Fuzzing

Windows: `E:\SOFTSEC\Tatou-platform`  
Server VM: `/home/softsec/Tatou-platform`

This journal was compiled from the retained work logs, test results and deployment notes. Date ranges cover work continued across several sessions. Pending tasks are recorded at the end. Actual flags, credentials and private keys are excluded.

## 12 September — Initial API review

Started reviewing the API, document storage and Docker configuration. The repository had several branches (`main`, `dev`, `ops` and `rmap`), so I compared the relevant versions before deciding which code to change. Authentication, document ownership, uploads and executable plugin code were the main areas to check.

The development workflow was later consolidated around Windows `dev`, with changes pushed to GitHub and pulled onto the university VM.

## 16–17 September — Investigating the flag leak

After the report that Flag2 had been captured, I checked the container logs, database, stored files, Git history and deployment configuration. The logs mainly contained Gunicorn startup messages and warnings. They did not provide enough HTTP access records to reconstruct the attack.

The stored data included 73 identical `x.pkl` samples, approximately 110 bytes each. The repeated uploads appeared automated. I inspected the samples with `pickletools.dis()` rather than loading them. The payload called Python code to read `/app/flag` and put the result into an exception. The old `/api/load-plugin` implementation could deserialize the uploaded file and return that exception to the client.

There was also a separate deployment error: `FLAG_2` was passed from `.env` through Compose into the server container. The old entrypoint used it to populate `/app/flag`. This placed the host flag inside the container and confused the two flag locations.

The following changes were made:

- Disabled dynamic plugin loading and removed the `pickle`/`dill` imports and `_pickle.load()` execution path. The plugin endpoint was subsequently removed.
- Removed the `FLAG_2` environment variable from the server configuration and removed the startup logic that copied it into `/app/flag`.
- Removed the fixed `SECRET_KEY` fallback. The application now requires a deployment key and refuses to start when it is missing.
- Added authentication, integer ID handling, parameterized SQL and an `ownerid = :uid` condition to document deletion.
- Replaced the shell command in `unsafe_bash_bridge_append_eof.py` with Python byte operations. User-controlled watermark text no longer goes through `shell=True`.

The command-injection regression used `test;$(whoami)&hello`. The same string was recovered unchanged, and the watermark round-trip passed. The temporary container check also confirmed that `FLAG_2` was no longer present.

I archived the malicious samples and their checksums before clearing the active copies. The remaining active `x.pkl` count was zero in that check. The current Flag2 value was not found in the Git history examined at the time.

The evidence establishes an unsafe deserialization path and a flag-isolation error. It does not establish which request the attacker actually used to capture Flag2. The pickle payload directly targeted `/app/flag`; the incomplete access logs prevented a full reconstruction.

## 17–23 September — Document ownership and watermark reading

Continued checking document and version access. A logged-in user must still be restricted to their own documents. The relevant queries were changed to bind the requested document or version to the authenticated owner.

Watermark reading was corrected to use the selected version's file path. Document deletion was updated to remove the original, its generated versions and the associated database records. A `candidates not defined` error encountered during this work was corrected before rerunning the affected checks.

The document page also lacked a Version ID field for reading a watermark. I added the input to `documents.html`, tested the page and synchronized the change.

The regression tests covered:

| Test | Check |
|---|---|
| `test_read_watermark_uses_version_path` | Read from the generated version file |
| `test_read_watermark_rejects_other_user` | Reject another user's version |
| `test_delete_document_removes_original_and_versions` | Remove the original and generated versions |
| `test_delete_document_rejects_other_user` | Reject deletion by another user |

These tests passed locally. Some use SQLite or test doubles, so their results cover the tested API behaviour rather than the whole production stack. Atomic file staging and rollback were discussed, but I have no separate implementation result to record for that proposal.

## 18 September — Upload hardening and flag isolation

Completed a wider pass over file handling and deployment configuration.

| Finding | Change |
|---|---|
| No consistent upload-size limit | Set `MAX_CONTENT_LENGTH`, configurable through `MAX_UPLOAD_BYTES`, with a 20 MiB default |
| Client filenames could influence disk paths | Sanitize names, reject empty results and use UUID disk filenames; limit display-name length |
| Extension or MIME alone could be forged | Check `.pdf`, `application/pdf` and the `%PDF-` header; rewind the stream before saving |
| Stored paths could escape the storage root | Resolve paths and check that they remain inside `STORAGE_DIR` |
| Ordinary version links were derived from predictable filenames | Replace that scheme with `secrets.token_urlsafe(32)` |
| Generated versions could overwrite existing files | Use unique names and exclusive `xb` writes; return 409 on a collision |
| Exception text exposed internal details | Log the traceback on the server and return a generic client error |
| Missing deployment values caused restart loops | Check required variables in Compose before creating the container |
| Application ran with excessive privileges | Run as `appuser`, UID 10001 |

An implementation mistake also surfaced during deployment: `import secret` passed syntax compilation but failed when Gunicorn imported the module. It was corrected to `import secrets`, then the image was rebuilt.

The flag layout was made explicit:

| Flag | Location |
|---|---|
| Flag1 | `/app/flag` inside the server container, initialized by our group |
| Flag2 | `tatou/flag` at the repository root on the host |
| Flag3 | The designated PDF owned by Mr_Important |

Flag1 is supplied through the deployment host's `server/flag`. Flag2 stays at the repository root and is neither injected into the server environment nor mounted into the container. The server build context is limited to `server`. Real flag files are ignored by Git; example files remain in the repository. The entrypoint now uses `exec` to start Gunicorn.

Local syntax checks, a build without cache, container recreation and startup checks passed. The process ran as UID 10001, `/app/flag` was owned by appuser with mode 400, and its hash matched the Flag1 source file. The host Flag2 and container Flag1 were distinct. The checked container had no flag environment variables or prohibited flag mounts.

Commit `5c33f02`, `harden document handling and isolate deployment flags`, was pushed to `dev`. VM migration was still pending in that day's deployment notes.

The upload checks provide basic type validation, not a guarantee that every PDF is safe to parse. The new random-token scheme applies to ordinary generated-version links; RMAP uses a separate link implementation. Removing the flag exposure also does not make an already captured value secret again.

## 20 September — RMAP integration and VM deployment

Integrated the RMAP flow with the server:

- `POST /api/rmap-initiate` processes Msg1.
- `POST /api/rmap-get-link` processes Msg2 and issues the download result.
- `GET /api/get-version/<link>` serves the generated PDF.

The flow generates a recipient-specific PDF using `layered-identity-v1` and records the document, recipient, secret, method, position and file path in `Versions`. The work also included frontend changes, dependencies and tests. The integration commit was `46f3b02`, `Add RMAP function`.

Updated the VM's `dev` branch to that commit and rebuilt the server service. The server keys and 31 identity public keys were installed outside the repository under `/opt/tatou-secrets/rmap`. A separate Compose override mounted them read-only and supplied the RMAP document ID, key configuration and watermark settings. I checked file readability as appuser and verified that the protected private key could be unlocked. The test client's private key was not mounted into the server.

Uploaded the Group_27 distribution PDF as document 86. A Windows client, connected through SSH forwarding, completed both protocol stages as Test_Group, decrypted the result and downloaded a 169104-byte PDF. The database record was version 3, document 86, recipient Test_Group, method `layered-identity-v1`, position `center`; the link length was 32. The health check reported a working database connection.

During the deployment review, historical records also included `payload.pkl`, `x.pkl`, an empty filename and a small probe PDF. I saved a database export, storage archive, server logs, Compose state, Git information and checksums before replacing the container. Those database records were not deleted during this session. Their existence does not show that every stored payload was executed.

A branch comparison still showed differences between `main` and the branches containing the fixes. This was the state of that snapshot, not a statement about the current `main` branch.

## 22–27 September — Persistent RMAP configuration and watermark checks

Separated local simulations from VM tests. The local two-instance setup used ports 5000 and 5500; other sessions used SSH forwarding to reach the VM. The target therefore had to be identified from the actual command, not just the port number.

Some checks initially reported missing key paths. I compared the resolved Compose configuration with the running container and corrected the mounts and environment setup. A Msg2 failure in an earlier simulation was traced to a private-key passphrase mismatch; the corrected run completed.

The persistent setup used `COMPOSE_FILE`, the RMAP override, `RMAP_PRIVATE_KEY_PASSPHRASE` and `WATERMARK_HMAC_KEY`. Checks covered two read-only key mounts, 31 identity public keys, appuser's read permissions and private-key unlocking. The service returned 200 after the configuration checks.

Windows keys remained under `E:\SOFTSEC\Tatou-secrets\rmap`, outside the project repository. Test_Group PDFs from the September runs were retained as protocol evidence. They are not documents collected from other groups.

I also worked on registering and testing my `visible-text-watermark` method. PDF generation through the page succeeded. The Version ID and watermark-position inputs were checked during the frontend work. Additional methods contributed by my teammate were treated as integration work, not as my own implementations.

An internal health check could pass while an external connection timed out. The timeout remained a separate connectivity issue.

## 24–25 September — Assurance experiments using Tatou

Selected CC Specialist / Track 1 for the related assurance assignment. The TOE was the RMAP handshake and resulting session-link issuance.

The experiments included replaying the same Msg2 and trying guessed download links. Twenty-four guesses failed to retrieve a document. I retained that result as a limited experiment; it does not prove that links are unguessable. Replay evidence was kept separately from the normal round-trip evidence.

These experiments support the assurance work and explain later fixes. They do not replace the Fuzzing specialization required for the SOFTSEC project.

## 1 October — Fixing Msg2 replay

The earlier replay experiment accepted the same serialized Msg2 more than once. The server-side nonce remained usable after successful processing.

Changed `server.py` to remove the consumed nonce from the server nonce index after `receiveMsg2` succeeds, within the locked state-processing section. The fix was committed as `1462907`, `Block the replay of msg2`.

The retained replay result after the fix was:

```text
First submission: 200
Repeated identical Msg2: 400
```

A normal round-trip still completed. I synchronized the code and checked the Windows branches and Docker configuration after the merge work.

This experiment covers identical Msg2 replay. Concurrent requests, restart behaviour and state shared across multiple workers were not established by this test.

## 2 October — Test maintenance and identity checks

The replay change required the local FakeRMAPServer in `test_rmap_get_link.py` to expose `identities` and `_nonce_server_index`. Added both fields and reran the file: all six tests passed. This local test double was newer than the copy in the earlier ZIP.

The full local test result was:

```text
157 passed, 1 warning
```

The warning came from PGPy's use of the deprecated `imghdr` module. The recorded environment was Python 3.11.4, pytest 8.4.2, Hypothesis 6.142.3 and pytest-cov 7.0.0.

Added two identity-boundary tests in `test_rmap_identity.py`. They used real RMAP/PGPy, temporary keys and PDF watermark reading. The registered identity completed the flow; an unknown alias was rejected without creating extra versions, files or protocol state. Both tests passed. This result is recorded separately from the 157-test baseline.

The identity tests addressed `FIA_UID.2` for Further Work A. The replay work addressed `FPT_RPL.1`, and the guessing experiment supported Further Work B. The unknown-alias test does not by itself demonstrate resistance to every form of registered-identity impersonation.

## 8 October — Updating the VM and checking flags

Checked the deployed branch after several GitHub changes. The VM initially showed `main`; subsequent development and deployment work was aligned with `dev`. The update noted commit `b7acb1a`, and the server image rebuilt successfully. The running revision will need another check before final hand-in.

Flag2 did not initially match the expected content. Corrected it and checked both files without printing their values:

- Flag1 was present at `/app/flag` inside the server container.
- Flag2 was present in the host repository's root `flag` file, corresponding to the assignment's `tatou/flag`.
- Both files had content and matched the intended values in the checks.
- The service health check was normal.

This confirmed placement and content. It is not a record of a teacher-issued flag rotation.

### Mr_Important's PDF

Confirmed that the designated Flag3 PDF was document 97, owned by Mr_Important (owner 127). A separate document named `FLAG_3`, ID 118 and owner 139, was not the designated file. This explained why comparing the two documents produced one True and one False.

The designated file had mode `-rw-------`; the owning process could read it. The API and database checks gave:

```text
UnauthenticatedRequest: 401
TestUserID: 139
AuthenticatedRequest: 200
ReadDocument97: 404
Flag3VersionCount: 0
RMAPTargetsFlag3: False
```

The test user could authenticate but could not read document 97. No generated versions were found for Flag3, and RMAP was not configured to distribute it. These checks cover the tested access path and configuration, not every possible way of reaching the file. The version count was a database check, not a complete test of all get-version routes.

### Group_27 distribution document and keys

Located the VM's original Group_27 PDF. Documents 86 and 88 contained the same valid PDF, and document 86 was selected for RMAP distribution. Confirmed the value in the effective configuration and running container:

```text
EffectiveRMAPDocumentID: 86
RunningRMAPDocumentID: 86
```

Document IDs belong to their database. ID 86 on the VM is not automatically the same document in a Windows Docker instance. The old Test_Group downloads were test outputs, not the original distribution PDF.

Checked the formal key files:

```text
Group27FileIsPublic: True
ServerFileIsPrivate: True
ServerPublicMatchesGroup27: True
ServerPrivateMatchesGroup27: True
```

The private key and passphrase stayed outside Git.

### Cross-group collection script

Added and ran `server/src/rmap_collect.py`. It uses Group_27 as the client identity, our formal private key and the target group's public key. It performs both protocol stages, decrypts the result and downloads the PDF.

The script supports target URLs, group labels, key paths and endpoint overrides. It uses timeouts and response-size limits, checks that the PDF opens with at least one page, and saves a PDF with a matching JSON receipt. Receipts include the group, identity, key fingerprints, protocol stage, HTTP results and file size/hash. Failed attempts also produce JSON. Private keys, passphrases, raw encrypted payloads and usable download links are excluded.

Collection directory:

```text
E:\SOFTSEC\Tatou-platform\collected_watermarked_pdfs
```

The network path was Windows → SSH tunnel to Group_27 VM → target group server. For example, `127.0.0.1:15003` was a local forwarding entry for Group_03, not its IP address. Target hostnames were inferred from the supplied naming pattern, and port 5000 was tested as a candidate. Successful groups confirmed those settings for their own services; other groups could use different ports or routes.

Used `curl.exe` where PowerShell's `curl` alias caused command errors. An SSH forwarding window staying open without output was normal. The teacher's test services on groups 35/36 were treated separately from student PDF servers.

### Collection results

Seven PDFs were saved with matching JSON receipts. I opened them and confirmed that their contents belonged to the expected groups.

| Group | PDF saved | Content checked |
|---|---|---|
| 03 | Yes | Correct |
| 09 | Yes | Correct |
| 17 | Yes | Correct |
| 19 | Yes | Correct |
| 21 | Yes | Correct |
| 25 | Yes | Correct |
| 29 | Yes | Correct |

The PDFs were collected through RMAP, but their watermarks have not been independently validated. The receipts retain `watermark_independently_verified: False`. Our VM self-test did include a separate watermark/database comparison; the cross-group downloads did not.

The unsuccessful attempts were retained as well:

| Group or symptom | Recorded result | Follow-up |
|---|---|---|
| 01 | Msg1 400: `Failed to decrypt message: Cannot decrypt the provided message with this key` | Confirm the target public key against the server's active private key |
| 05 | Earlier Msg1 400: `Invalid RMAP Message 1`; later summary described most unsuccessful groups as 405 | Keep the individual receipts; do not overwrite the earlier result |
| 07 | POST 405; OPTIONS listed HEAD/GET/OPTIONS; GET returned 404 | Check the actual RMAP route and service port |
| 11, 13, 15 | 405 reported | Check each group's API configuration |
| 23 | 000 reported; failure JSON saved | Inspect the receipt for the failed stage and network error |
| Other even-numbered groups | Repeated timeouts observed | No confirmed explanation for the pattern |

A 405 response means the contacted route rejected the method used. It does not show that the whole server lacks POST APIs. A reported 000 means no normal HTTP response was obtained. A health check returning 200 only establishes that the health route is reachable.

I kept POST for the RMAP requests rather than changing the protocol to GET based on the OPTIONS response. The unresolved attempts require the groups' actual endpoint configuration or further network evidence.

The assignment asks for ideally around ten documents, depending on the other live instances. The recorded collection currently contains seven other-group PDFs; self-tests and failed attempts are not counted.

### Git preparation

Confirmed that Windows was on `dev` and staged `collected_watermarked_pdfs/`. Git warned that some PDF files would undergo LF/CRLF conversion.

Added `*.pdf binary` to `.gitattributes`, staged the attribute file and renormalized the collection directory. All seven PDF rows in `git diff --cached --numstat` then showed `-  -`, indicating binary handling.

The latest confirmed state is that the collection and attribute file are staged. Commit and push success have not yet been recorded. A remote byte-for-byte comparison against the download hashes is also still outstanding.

## Work still open after 8 October

- Commit and push the collection and journal to `dev`, and retain the commit ID.
- Run the first Hypothesis campaign on a recorded revision. Save the failing cases before modifying the API.
- Trace the registration/login exceptions, fix input handling, add fixed regression cases and rerun the relevant tests.
- Produce the current test and coverage results for the final submission.
- Follow up on the unresolved RMAP routes, decryption errors and network timeouts where group configuration is available.
- Complete the README, specialization artifacts, report and contribution record, and package the repository with its Git history.
- Recheck the running VM revision, RMAP flow and flag placement before hand-in.


# Tatou-platform Development Journal

Project: SOFTSEC 2026 — Group_27  
Branch: dev  
## 12 September
Reviewed the API, document storage and Docker configuration.

## 16–17 September
Investigated malicious pickle uploads and the flag-isolation issue. Removed unsafe plugin loading, the fixed secret-key fallback and shell execution in the watermark helper.

## 17–23 September
Fixed ownership checks for watermark reading and document deletion; the regression tests passed. Added a Version ID input to the document page.

## 18 September
Added upload validation, safe storage paths and random version links. Ran the server as a non-root user and separated the host and container flags.

## 20 September
Integrated RMAP with PDF generation and download, then deployed it to the VM. Installed the keys outside the repository and completed a test round-trip.

## 22–27 September
Corrected RMAP key mounts and configuration, and checked the persistent VM setup. Registered and tested my visible-text-watermark method.

## 24–25 September
Selected the RMAP handshake for the CC assurance work. Tested Msg2 replay and 24 guessed links; none of the guesses retrieved a document.

## 1 October
Blocked repeated Msg2 submissions by consuming the server nonce. The first submission returned 200, the replay returned 400, and a normal round-trip still succeeded.

## 2 October
Updated FakeRMAPServer; its six tests and the full 157-test suite passed. Two additional identity tests passed for registered and unknown identities.

## 8 October
Updated the VM on dev and checked flag placement, document ownership and RMAP keys. Set document 86 as the Group_27 distribution PDF and collected seven other groups' PDFs through RMAP.

## 10 October
Returned owner watermark secrets in version lists and supported reading reuploaded PDFs without a version ID; all 161 local tests passed. Pushed the changes to dev, deployed them to the VM, and passed WatermarkLifecycle, AllMethodsLifecycle and LocalDataConsistent.

Added Hypothesis API fuzz tests, fixed input validation bugs, and set up CI. Added a grammar-guided test for layered watermarks; all 170 tests passed locally.



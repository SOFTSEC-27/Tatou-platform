---
name: Feature Request (incl. Security Requirements)
about: Propose a new feature and identify security requirements before implementation.
title: 'Feature: '
labels: enhancement, security-review
assignees: ''
---

## Feature Description
[Describe what needs to be built and why]

## Security Requirements (MANDATORY)
Before coding begins, identify and record the security requirements for this feature.

**1. Are there any threats against this feature? (e.g., Spoofing, Replay attacks, Unauthorized access)**
- [ ] Yes (describe below)
- [ ] No

*Description of threats:* 
[Write here...]

**2. What security requirements are needed to mitigate these threats?**
- [ ] Input validation required
- [ ] Authentication/Authorization required (e.g., verify keys/nonces)
- [ ] Secure storage/Cryptography required
- [ ] Other: [Specify]

## Acceptance Criteria (Testing)
- [ ] The feature works as intended.
- [ ] The security requirements above have dedicated test cases (e.g., negative tests that reject invalid input).
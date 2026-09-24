"""Shared pytest configuration."""

from __future__ import annotations

import os


# Test-only Flask session key.
# This is deliberately not a production secret.
os.environ.setdefault(
    "SECRET_KEY",
    "pytest-only-secret-key-do-not-use-in-production",
)
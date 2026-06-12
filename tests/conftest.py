"""Shared fixtures for tollbooth tests."""

import pytest


@pytest.fixture
def make_sample_data():
    """Factory fixture -- customize per project.

    Factory fixtures let tests construct domain objects without
    depending on real files, APIs, or databases. Each test specifies
    only the fields it cares about; everything else gets sensible defaults.
    """
    def _factory(**kwargs):
        defaults = {
            # Add project-specific defaults here
        }
        defaults.update(kwargs)
        return defaults
    return _factory

import pytest


@pytest.fixture(autouse=True)
def _privacy_mode_is_per_test():
    """Privacy mode is a process-wide switch (macprivacy.current()); a test that turns it on must not leak it into the next."""
    yield
    from sniffowireless import macprivacy
    macprivacy.set_current(None)

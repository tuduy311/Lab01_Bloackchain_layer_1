"""Expose genuine pytest reports to evidence-writing fixture teardown."""

import pytest


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    reports = getattr(item, "_tv4_reports", None)
    if reports is None:
        reports = {}
        item._tv4_reports = reports
    reports[report.when] = report

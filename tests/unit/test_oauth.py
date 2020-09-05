import pytest
from oauth_pyzure import (
    OAuth,
    Errors
)

INTERNET_PROXY = "http://35.201.86.215:80"


class TestOAuth():

    def test_failedInitTennant(self):
        with pytest.raises(SystemError):
            _ = OAuth(tenant_id='noneexistent')

    def test_proxyInitGiven(self):
        oa = OAuth(proxy=INTERNET_PROXY)
        assert oa.proxies is not None
        assert oa.proxies.get("http", None) is not None
        assert oa.proxies.get("https", None) is not None

    def test_proxyInitNotGiven(self):
        oa = OAuth()
        assert oa.proxies is None

    
import pytest
from oauth_pyzure import (
    OAuth,
    Errors
)

INTERNET_PROXY = "http://93.91.112.247:41258"


class TestOAuth():

    def test_failedInitTennant(self):
        with pytest.raises(SystemError):
            _ = OAuth(tenant_id='noneexistent')

    def test_proxyInitGiven(self):
        oa = OAuth(proxy=INTERNET_PROXY, load_uris=False)
        assert oa.proxies is not None
        assert oa.proxies.get("http", None) is not None
        assert oa.proxies.get("https", None) is not None

    def test_proxyInitNotGiven(self):
        oa = OAuth()
        assert oa.proxies is None

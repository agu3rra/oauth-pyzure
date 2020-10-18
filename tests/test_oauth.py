import pytest
import os
from oauth_pyzure import (
    OAuth,
    Errors
)

INTERNET_PROXY = "http://93.91.112.247:41258"


class TestOAuth():

    def setup(self):
        tenant_id = os.environ.get("TENANT_ID")
        assert tenant_id is not None
        self.oa = OAuth(tenant_id=tenant_id)
        self.client_id = os.environ.get("CLIENT_ID")
        self.client_secret = os.environ.get("CLIENT_SECRET")
        self.app_id = os.environ.get("APP_ID")
        self.app_id_2 = os.environ.get("APP_ID_2")

    def test_failedInitTennant(self):
        with pytest.raises(SystemError):
            _ = OAuth(tenant_id='noneexistent')

    def test_proxyInitGiven(self):
        oa = OAuth(
            tenant_id=os.environ.get("TENANT_ID"),
            proxy=INTERNET_PROXY,
            load_uris=False)
        assert oa.proxies is not None
        assert oa.proxies.get("http", None) is not None
        assert oa.proxies.get("https", None) is not None

    def test_proxyInitNotGiven(self):
        assert self.oa.proxies is None

    def test_InitOk(self):
        assert self.oa.jwks_uri is not None
        assert self.oa.token_endpoint is not None

    def test_getTokenGetClaims(self):
        token, err = self.oa.get_token(
            self.client_id,
            self.client_secret,
            f"api://{self.app_id}/.default")
        assert token is not None
        assert err is None
        claims, err = self.oa.get_claims(token, self.app_id)
        assert err is None
        assert claims is not None
        assert isinstance(claims, dict)

    def test_getClaimsInvalidToken(self):
        claims, err = self.oa.get_claims(token=42, app_id=5)
        assert err == Errors.InvalidToken.value
        claims, err = self.oa.get_claims(
            token="header.payload.signature.thing",
            app_id=5)
        assert err == Errors.InvalidToken.value

    def test_MissingTokenId(self):
        dummy_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImtnMkxZczJUMENUaklmajRydDZKSXluZW4zOCJ9.eyJhdWQiOiJhcGk6Ly9iNjhmOGFhOC01Y2FmLTQxZTItOGZiZS04M2U2ZjMxNmUyZDYiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC85MWVlOTIwMy1kNDBiLTRlYjktOGMxOC03MDU2NzlkMTdjYzIvIiwiaWF0IjoxNjAyMzYzOTU4LCJuYmYiOjE2MDIzNjM5NTgsImV4cCI6MTYwMjM2Nzg1OCwiYWlvIjoiRTJSZ1lOQnFTUlNxZm5tOVMxcUQ3K1hHdFhQOEFBPT0iLCJhcHBpZCI6ImI2OGY4YWE4LTVjYWYtNDFlMi04ZmJlLTgzZTZmMzE2ZTJkNiIsImFwcGlkYWNyIjoiMSIsImlkcCI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzkxZWU5MjAzLWQ0MGItNGViOS04YzE4LTcwNTY3OWQxN2NjMi8iLCJvaWQiOiJjM2JmYzYwZC03YmQ5LTQwNGQtOGYyYi1iZWU5YzMxZjRiZGUiLCJyaCI6IjAuQUFBQUE1THVrUXZVdVU2TUdIQldlZEY4d3FpS2o3YXZYT0pCajc2RDV2TVc0dFpSQUFBLiIsInN1YiI6ImMzYmZjNjBkLTdiZDktNDA0ZC04ZjJiLWJlZTljMzFmNGJkZSIsInRpZCI6IjkxZWU5MjAzLWQ0MGItNGViOS04YzE4LTcwNTY3OWQxN2NjMiIsInV0aSI6InEtektaa0lweDB5SmlXSmQ2TWtDQUEiLCJ2ZXIiOiIxLjAifQ.vDQshH3AufDaovufdkzX3KFJhRwc5XYp-cxbVXym8daWO22Xa3u7qqLGWOL39QdRGyzNVJPuuw-6uCR9DXQ7yMyG4hJMpu7t9IfqxuynpaYPROI3eESdG_mang7WbsOawF2LEx7LT2prHrSZTGCxZPvpnjbODmhSL843RZvpC6kbCvnrv3Ot2aIxN-MyG0wTZLNw56RKFlirIKSvWn2ofckNe5FMpOVUEa7KkGj-I3p52O01ML4Bs4SfYK6gzrparcPclZ4yQM42BSWLYOU-lwC-Ft6RtiTGMAD337lzkv91kvPbyYws291UHWGAm6kbF8BIhJKTJOuB1jqcdMsoCQ"  # pragma: allowlist secret
        claims, err = self.oa.get_claims(
            token=dummy_token,
            app_id=self.app_id)
        assert err == Errors.TokenMissingKID.value

    def test_InvalidAudience(self):
        token, err = self.oa.get_token(
            self.client_id,
            self.client_secret,
            f"api://{self.app_id_2}/.default")
        assert token is not None
        assert err is None
        claims, err = self.oa.get_claims(token, self.app_id)
        assert err is not None
        assert claims is None

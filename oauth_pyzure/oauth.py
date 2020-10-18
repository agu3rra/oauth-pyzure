import textwrap
import requests
import jwt
import enum
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

TIMEOUT = 2  # timeout for all HTTP requests


class Errors(enum.Enum):
    MetadataUrlUnreachable = "Unable to reach metadata URL."
    MetadataUrlHttpNok = "Response from metadata URL is not ok (200ish)."
    JWKsURIFormat = "Unable to obtain jwks_uri from metadata URL."
    TokenEndpoint = "Unable to obtain token endpoint from metadata URL."
    ProxyValues = "Invalid proxy values provided."
    UnableObtainToken = "Unable to obtain OAuth token."
    InvalidToken = "Invalid input token."
    TokenMissingKID = "Token header missing key id."
    UnableObtainKeys = "Unable to obtain public keys from Azure."
    PublicKey = "Error while obtaining public certificate for key id."
    InvalidJwt = "Token validation error."


class OAuth():
    """
    An OAuth class for Azure.
    """

    def __init__(self,
                 tenant_id,
                 proxy=None,
                 load_uris=True):
        """Initializes an object for this class.

        Args:
            tenant_id (str): Azure tennant id.
            proxy (str, optional): a proxy connection if you don't have direct
                                   internet access. Defaults to None.
                                   E.g.: "http://myproxy:8000"
            load_uris (bool, optional): load URIs for JWKS and token endpoint.
                                        Defaults to True.
            default_metadata (bool, optional): Used for unit testing.
                                               Defaults to True.

        Raises:
            SystemError: Unable to obtain metadata from URL.
            KeyError: Unable to obtain value from metadata dictionary.
            ValueError: Invalid values provided to class initializer.
        """

        if proxy is not None:
            self.proxies = {
                "http": proxy,
                "https": proxy
            }
        else:
            self.proxies = None

        self.tenant_id = tenant_id
        ms_base = "https://login.microsoftonline.com"
        self.metadata_url = f"{ms_base}/{tenant_id}/v2.0/.well-known"\
            "/openid-configuration"

        # Set later to facilitate unit testing
        if load_uris:
            self.load_uris()
        else:
            self.jwks_uri = None
            self.token_endpoint = None

    def load_uris(self):
        try:
            metadata = requests.get(
                self.metadata_url,
                proxies=self.proxies,
                timeout=TIMEOUT)
            if metadata.ok:
                metadata = metadata.json()
            else:
                resp = metadata.status_code
                print(f"Status code from metadata URL: {resp}")
                raise SystemError(Errors.MetadataUrlHttpNok.value)
        except Exception as e:
            err = "{} Reason: {}".format(
                Errors.MetadataUrlUnreachable.value,
                str(e))
            print(err)
            raise SystemError(Errors.MetadataUrlUnreachable.value)

        self.jwks_uri = metadata.get('jwks_uri', None)
        if self.jwks_uri is None:
            raise KeyError(Errors.JWKsURIFormat.value)

        self.token_endpoint = metadata.get('token_endpoint', None)
        if self.token_endpoint is None:
            raise KeyError(Errors.TokenEndpoint.value)

    def get_token(self, client_id, client_secret, scope):
        """Returns JWT for a given AzureAD scope or an error message if that
        was not possible.

        Args:
            client_id (str): the id of your application (calling app id)
            client_secret (str): the client secret of your application
            scope (str): scope you want to call in Azure. E.g.:
                         api://342ba2-5342-af43/.default

        Returns:
            (str, str): a JWT and error strings. One of them will be None.
        """
        header = {
            "content-type": "application/x-www-form-urlencoded"
        }
        body = {
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
            "grant_type": "client_credentials",
        }
        try:
            response = requests.post(url=self.token_endpoint,
                                     headers=header,
                                     proxies=self.proxies,
                                     data=body)
            if not response.ok:
                error = f"{Errors.UnableObtainToken.value} " \
                    f"Detail: {response.text}"
                return None, error
        except Exception as e:
            return None, str(e)

        token = response.json().get("access_token", None)
        if token is None:
            return None, Errors.UnableObtainToken.value

        # It all worked if you got here!
        return token, None

    def get_claims(self, token, app_id):
        """Returns the claims for the input token, given it has been issued
        for the given resource and that it is valid.

        Args:
            token (str): a Json Web Token (JWT)
            app_id (str): the application id in Azure to which the JWT was 
                          issued.

        Returns:
            dict, str: the claims for the given token in case it is valid for
            your application OR an error string in case it is not.
        """
        if not isinstance(token, str):
            return (None, Errors.InvalidToken.value)

        # Parse token
        parts = token.split('.')
        if len(parts) != 3:
            return (None, Errors.InvalidToken.value)
        (header, payload, signature) = parts

        # Retrieve key id from JWT header
        header = jwt.get_unverified_header(token)
        kid = header.get('kid', None)
        if kid is None:
            return (None, Errors.TokenMissingKID.value)

        # Obtain x509 public key used to generate token.
        public_certificate, err = self._get_x509(kid)
        if err is not None:
            return None, err

        # Verify signature
        try:
            claims = jwt.decode(
                token,
                public_certificate,
                audience=[app_id, f"api://{app_id}"],
                algorithms=["RS256"])
            return claims, None
        except Exception as e:
            error = f"{Errors.InvalidJwt.value} Details:{str(e)}"
            return None, error

    def _get_x509(self, kid):
        """Obtains public certificate used by the IdP with the given key id

        Args:
            kid (str): key id

        Returns:
            x509certificate, str: the public certificate used with the
                                  provided kid and the error string
        """
        try:
            response = requests.get(url=self.jwks_uri, proxies=self.proxies)
            if not response.ok:
                return None, Errors.UnableObtainKeys.value
            keys = response.json()
            keys = keys.get("keys", None)
            if keys is None:
                return None, Errors.UnableObtainKeys.value
        except Exception as e:
            error = f"{Errors.UnableObtainKeys.value} Detail: {str(e)}"
            return None, error

        # Verify which key from Azure matches the key id in the input token
        for key in keys:
            kid_from_azure = key.get("kid", None)
            if kid == kid_from_azure:
                # Now get the public certificate that follows this key id
                public_cert = key.get("x5c", None)
                if public_cert is None:
                    return None, Errors.PublicKey.value
                public_cert = public_cert[0]

                # Generate certificate format from certificate string
                certificate = '-----BEGIN CERTIFICATE-----\n'
                certificate += '\n'.join(textwrap.wrap(public_cert, 64))
                certificate += '\n'+'-----END CERTIFICATE-----\n'
                cert_obj = load_pem_x509_certificate(certificate.encode(),
                                                     default_backend())
                return cert_obj.public_key(), None
        return None, Errors.PublicKey.value

import textwrap
import pyjwt as jwt
import requests
import enum
from cryptography;x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend


class Errors(enum.Enum):
    MetadataUrlUnreachable="Unable to reach metadata URL."
    JWKsURIFormat="Unable to obtain jwks_uri from metadata URL."
    TokenEndpoint="Unable to obtain token endpoint from metadata URL."
    ProxyValues="Invalid proxy values provided."
    UnableObtainToken="Unable to obtain OAuth token."
    InvalidToken="Invalid input token."
    TokenMissingKID="Token header missing key id."
    UnableObtainKeys="Unable to obtain public keys from Azure."
    PublicKey="Error while obtaining public certificate for key id."
    InvalidJwt="Token validation error."


class OAuth():
    """
    An OAuth class for Azure.
    """

    def __init__(self, tennant_id='common', proxy=None):
        """Initializes an object for this class.

        Args:
            tennant_id (str, optional): Azure tennant id. Defaults to 'common'
            proxy (dict, optional): a proxy dictionary in the format below. 
                                    Defaults to None.
                                    E.g.: {"server":"proxyserver.com", 
                                           "port": 8000}

        Raises:
            SystemError: Unable to obtain metadata from URL.
            KeyError: Unable to obtain value from metadata dictionary.
            ValueError: Invalid values provided to class initializer.
        """
        self.tenant_id = tennant_id
        metadata_url = "https://login.microsoftonline.com/{tenant_id}"\
            "/v2.0/.well-known/openid-configuration".format(
                tennant_id
            )
            
        try:
            metadata = requests.get(metadata_url)
        except Exception as e
            error = "{} Reason: {}".format(
                Errors.MetadataUrlUnreachable.value,
                str(e))
            raise SystemError(error)
            
        self.jwks_uri = metadata_url.get('jwks_uri', None)
        if self.jwks_uri is None:
            raise KeyError(Errors.JWKsURIFormat.value)

        self.token_endpoint = metadata.get('token_endpoint', None)
        if self.token_endpoint is None:
            raise KeyError(Errors.TokenEndpoint.value)

        if proxy is not None:
            server = proxy.get("server", None)
            port = proxy.get("port", None)
            if server is None or port is None:
                raise ValueError(Errors.ProxyValues.value)
            if not isinstance(server, str) or not isinstance(port, int):
                raise ValueError(Errors.ProxyValues.value)
            self.proxy = {
                "http": f"http://{server}:{port}",
                "https": f"http://{server}:{port}",
            }
        else:
            self.proxy=proxy
    
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
                                     proxies=self.proxy,
                                     data=body)
            if not response.ok:
                error = f"{Errors.UnableObtainToken.value} Detail: "\
                    "{response.text}"
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
        public_certificate = self._get_x509(kid)

        # Verify signature
        try:
            claims = jwt.decode(
                token,
                public_certificate,
                audience=[app_id, f"api://{app_id}/.default"],
                algorithms=["RS256"])
            return claims, None
        except Exception as e:
            error = f"{Errors.InvalidJwt} Details:{str(e)}"
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
            response = requests.get(url=self.jwks_uri, proxies=self.proxy)
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
                certificate = 'BEGIN PUBLIC KEY'.center(64, '-')+'\n'
                certificate += '\n'.join(textwrap.wrap(public_cert, 64))
                certificate += '\n'+'END PUBLIC KEY'.center(64, '-')+'\n'
                certificate = load_pem_x509_certificate(certificate.encode(),
                                                        default_backend)
                return certificate.public_key(), None
        return None, Errors.PublicKey.value

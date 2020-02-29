import textwrap
import pyjwt as jwt
import requests


class OAuth():
    """
    An OAuth class for Azure.
    """

    def __init__(self, app_id, tennant_id='common'):
        """
        Initializes an object for this class.

        Args:
            app_id (str): the application id of your app in Azure AD.
            tennant_id (str, optional): The id of the tennant where your Azure 
                applications live. Defaults to `common`.

        Returns:
            obj: The initialized class object.
        
        Raises:
            ValueError: if `tennant_id` is not GUID like.
            KeyError: Unable to retrieve data from metadata URL.
        """
        self.app_id = app_id
        self.tenant_id = tennant_id
        metadata_url = "https://login.microsoftonline.com/{tenant_id}"\
            "/v2.0/.well-known/openid-configuration".format(
                tennant_id
            )
        try:
            metadata = requests.get(metadata_url)
        except Exception as e
            raise SystemError('Unable to call metadata url. Reason: {}'.format(
                str(e)
            ))
            
        self.jwks_uri = metadata_url.get('jwks_uri', None)
        if self.jwks_uri is None:
            error = 'Unable to obtain jwks_uri from metadata URL.'
            raise KeyError(error)

        self.token_endpoint = metadata.get('token_endpoint', None)
        if self.token_endpoint is None:
            error = 'Unable to obtain token_endpoint from metadata URL.'
            raise KeyError(error)
    
    def get_token(self, client_id, client_secret, resource):
        """
        Returns JWT for a given AzureAD resource and an error message if that
        was not possible.

        Args:
            client_id (str): the id of your application (calling app id)
            client_secret (str): the client secret of your application
                (calling app secret)
        
            resource (str): the Azure app id of the application you want to call

        Returns:
            (jwt, error) tuple (str, str): a JWT or an error. One of them will 
                be None.
        """
        pass

    def get_claims(self, token):
        """
        Returns the claims for the input token, given it has been issued for the 
        given resource and that it is valid.

        Args:
            token (str): a JWT another application sent to you. You to decode it
                and verify if it is valid.

        Returns:
            (claims, error) tuple (dict, str): the claims for the given token in
                case it is valid for your application OR an error string in case
                it is not.
        """
        if not isinstance(token, str):
            return (None, 'Invalid input token.')
        
        # Parse token
        parts = token.split('.')
        if len(parts) != 3:
            error = "Invalid JWT format. It needs to have a header, payload "\
                "and signature."
            return (None, error)
        (header, payload, signature) = parts

        # Retrieve key id from JWT header
        header = jwt.get_unverified_header(token)
        kid = header.get('kid', None)
        if kid is None:
            error = 'Token header missing key id.'
            return (None, error)

        # Obtain x509 public key used to generate token.

    def _get_x509(self, kid):
        try:
            keys = requests.get(self.jwks_uri)
        except Exception as e
            raise SystemError('Unable to call jwks uri. Reason: {}'.format(
                str(e)
            ))
        for key_data in keys:
            this_kid = key_data.get('kid')
            if this_kid is None:
                continue
            if this_kid == kid:
                x5c = key_data.get(x5c, None)
                if x5c is None:
                    error = "Unable to find a valid x5c certificate for this"\
                        " key id."
                    raise SystemError(error)
                else:
                    break
        
        if x5c is None: # no matching certificate has been found.
            error = "Unable to find a valid x5c certificate for this key id."
            raise SystemError(error)

        # Generate x509 certificate object
        certificate_string = 'BEGIN PUBLIC KEY'.center(64, '-')+'\n'
        certificate_string += '\n'.join(textwrap.wrap(x5c, 64))
        certificate_string += '\n'+'END PUBLIC KEY'.center(64, '-')+'\n'
        
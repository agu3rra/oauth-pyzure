import pyjwt


class OAuth():
    """
    An OAuth class for Azure.
    """

    def __init__(self, tennant_id='common'):
        """
        Initializes an object for this class.

        Args:
            tennant_id (str, optional): The id of the tennant where your Azure 
                applications live. Defaults to `common`.

        Returns:
            obj: The initialized class object.
        
        Raises:
            ValueError: if `tennant_id` is not GUID like.
        """
        self.tenant_id = tennant_id
        self.metadata_url = "https://login.microsoftonline.com/{tenant_id}"\
            "/v2.0/.well-known/openid-configuration".format(
                tennant_id
            )
    
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

    def validate(self, token, resource):
        pass
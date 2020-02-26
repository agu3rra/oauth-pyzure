# OAuth Pyzure (Work in progress...)
A Python library for using and validating OAuth's client credentials flow (API to API) in Azure.

## Install
> $ pip install oauth-pyzure

## Usage
```python
from oauth_pyzure import OAuth

"""
Instantiate an object and give it an optional tennant id. 
It uses Azure's default if none is provided.
"""
oa = OAuth(tennant_id='some_tennant_id')

"""
Use this if you already have a registered an app in AzureAD and wish to obtain
a JSON Web Token
"""
jwt = oa.get_token(
    client_id='some_client_id',
    client_secret='some_client_secret_you_wont_commit_to_scm',
    resource='app_id_you_wish_to_call'
)

"""
Use this if you are implementing OAuth in your API and wish to obtain the 
claims and validity of a jwt. 

Upon recognition of a valid token, claims will be a dictionary containing all
the claims in the token and error will be set to None.

If any error occurs, it will be saved to the error
string and claims will be set to None.
"""
(claims, error) = oa.validate(jwt)
```

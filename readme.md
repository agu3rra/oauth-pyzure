# OAuth Pyzure
A Python library for using and validating OAuth's [client credentials](https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/) grant type (API to API) when using [Microsoft Azure](https://azure.microsoft.com/).

![azure-access](docs/azure-access.png)

<!-- TOC -->

- [OAuth Pyzure](#oauth-pyzure)
    - [What does this package do?](#what-does-this-package-do)
    - [Install](#install)
    - [Usage](#usage)
- [Setup your API on Azure](#setup-your-api-on-azure)

<!-- /TOC -->

## What does this package do?
The idea for this package came from the necessity of performing authorization using the modern [OAuth protocol](https://www.oauth.com) on a Flask based application. At the time I implemented it in the form of a [Python decorator](https://realpython.com/primer-on-python-decorators/) which I added to all endpoints that required authorization. This package simply abstracts the implementation details when using [Microsoft Azure](https://azure.microsoft.com/) as the application identity provider. The objective is to offer one method to generate tokens to consume other Azure apps and another one to validate if a token received by your application is indeed valid (not expired, not tempered with, etc).

## Install
> $ pip install oauth-pyzure

## Usage
```python
from oauth_pyzure import OAuth

"""
Instantiate an object and give it the Azure tenant id of your application.
"""
oa = OAuth(tenant_id='some_tenant_id')

"""
Use this if you already have a registered an app in AzureAD and wish to obtain
a JSON Web Token
"""
jwt = oa.get_token(
    client_id='some_client_id',
    client_secret='some_client_secret_you_wont_commit_to_scm',
    scope='api://someappid/.default'
)

"""
Use this if you are implementing OAuth in your API and wish to obtain the 
claims and validity of a jwt. 

Upon recognition of a valid token, claims will be a dictionary containing all
the claims in the token and error will be set to None.

If any error occurs, such as a tempered or expired token it will be saved to 
the error string and claims will be set to None.
"""
(claims, error) = oa.get_claims(jwt, app_id)
```

# Setup your API on Azure
Do not forget that in order for the client-credentials flow to work, a target application needs to be setup in *Azure Active Directory > App Registration* and the appropriate scope needs to be set for it. Example below:

![azure](docs/add-scope.png)

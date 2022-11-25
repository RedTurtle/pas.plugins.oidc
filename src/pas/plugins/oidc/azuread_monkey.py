# https://github.com/OpenIDC/pyoidc/issues/520
import re
from oic.oauth2.message import Message
from oic.oic import Client


class EquivalentIssuer:
    #https://sts.windows.net/2e4146d4-a7f8-45b2-9dd1-bbd74093bee5/
    #https://sts.windows.net/{tenantid}/
    patterns = [
        (re.compile(pattern), replace)
        for pattern, replace
        in [
            (r'https://sts.windows.net/[a-z0-9-]{36}\/', 'https://sts.windows.net/{tenantid}/'),
            (r'https://login.microsoftonline.com/[a-z0-9-]{36}\/', 'https://sts.windows.net/{tenantid}/'),
            (r'https://login.microsoftonline.com/\{tenantid\}\/', 'https://sts.windows.net/{tenantid}/'),
        ]
    ]

    @classmethod
    def rewrite(cls, issuer):
        for pattern, replace in cls.patterns:
            match = pattern.match(issuer)
            if match:
                return replace
        return issuer


def patch_handle_provider_config(function):
    def patched(self, pcr, issuer, *arguments, **keywords):
        if 'issuer' in pcr:
            pcr['issuer'] = EquivalentIssuer.rewrite(pcr['issuer'])
        issuer = EquivalentIssuer.rewrite(issuer)
        return function(self, pcr, issuer, *arguments, **keywords)
    return patched
Client.handle_provider_config = patch_handle_provider_config(Client.handle_provider_config)


def patch_add_key(function):
    def patched(self, keyjar, issuer, key, *arguments, **keywords):
        issuer = EquivalentIssuer.rewrite(issuer)
        return function(self, keyjar, issuer, key, *arguments, **keywords)
    return patched
Message._add_key = patch_add_key(Message._add_key)  # pylint: disable=protected-access


def patch_getitem(function):
    def patched(self, key):
        result = function(self, key)
        if key == 'iss':
            result = EquivalentIssuer.rewrite(result)
        return result
    return patched
Message.__getitem__ = patch_getitem(Message.__getitem__)

import logging
logging.warning("Azure AD Patch applied")

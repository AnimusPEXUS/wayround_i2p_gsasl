
"""
Made by wayround.org
"""

import ctypes

cimport org.wayround.gsasl.gsasl_h

from libc.stdio cimport printf
from libc.stdlib cimport free, malloc

##################### ERRORS

GSASL_OK = org.wayround.gsasl.gsasl_h.GSASL_OK
GSASL_NEEDS_MORE = org.wayround.gsasl.gsasl_h.GSASL_NEEDS_MORE
GSASL_UNKNOWN_MECHANISM = org.wayround.gsasl.gsasl_h.GSASL_UNKNOWN_MECHANISM
GSASL_MECHANISM_CALLED_TOO_MANY_TIMES = org.wayround.gsasl.gsasl_h.GSASL_MECHANISM_CALLED_TOO_MANY_TIMES
GSASL_MALLOC_ERROR = org.wayround.gsasl.gsasl_h.GSASL_MALLOC_ERROR
GSASL_BASE64_ERROR = org.wayround.gsasl.gsasl_h.GSASL_BASE64_ERROR
GSASL_CRYPTO_ERROR = org.wayround.gsasl.gsasl_h.GSASL_CRYPTO_ERROR
GSASL_SASLPREP_ERROR = org.wayround.gsasl.gsasl_h.GSASL_SASLPREP_ERROR
GSASL_MECHANISM_PARSE_ERROR = org.wayround.gsasl.gsasl_h.GSASL_MECHANISM_PARSE_ERROR
GSASL_AUTHENTICATION_ERROR = org.wayround.gsasl.gsasl_h.GSASL_AUTHENTICATION_ERROR
GSASL_INTEGRITY_ERROR = org.wayround.gsasl.gsasl_h.GSASL_INTEGRITY_ERROR
GSASL_NO_CLIENT_CODE = org.wayround.gsasl.gsasl_h.GSASL_NO_CLIENT_CODE
GSASL_NO_SERVER_CODE = org.wayround.gsasl.gsasl_h.GSASL_NO_SERVER_CODE
GSASL_NO_CALLBACK = org.wayround.gsasl.gsasl_h.GSASL_NO_CALLBACK
GSASL_NO_ANONYMOUS_TOKEN = org.wayround.gsasl.gsasl_h.GSASL_NO_ANONYMOUS_TOKEN
GSASL_NO_AUTHID = org.wayround.gsasl.gsasl_h.GSASL_NO_AUTHID
GSASL_NO_AUTHZID = org.wayround.gsasl.gsasl_h.GSASL_NO_AUTHZID
GSASL_NO_PASSWORD = org.wayround.gsasl.gsasl_h.GSASL_NO_PASSWORD
GSASL_NO_PASSCODE = org.wayround.gsasl.gsasl_h.GSASL_NO_PASSCODE
GSASL_NO_PIN = org.wayround.gsasl.gsasl_h.GSASL_NO_PIN
GSASL_NO_SERVICE = org.wayround.gsasl.gsasl_h.GSASL_NO_SERVICE
GSASL_NO_HOSTNAME = org.wayround.gsasl.gsasl_h.GSASL_NO_HOSTNAME
GSASL_NO_CB_TLS_UNIQUE = org.wayround.gsasl.gsasl_h.GSASL_NO_CB_TLS_UNIQUE
GSASL_NO_SAML20_IDP_IDENTIFIER = org.wayround.gsasl.gsasl_h.GSASL_NO_SAML20_IDP_IDENTIFIER
GSASL_NO_SAML20_REDIRECT_URL = org.wayround.gsasl.gsasl_h.GSASL_NO_SAML20_REDIRECT_URL
GSASL_NO_OPENID20_REDIRECT_URL = org.wayround.gsasl.gsasl_h.GSASL_NO_OPENID20_REDIRECT_URL
GSASL_GSSAPI_RELEASE_BUFFER_ERROR = org.wayround.gsasl.gsasl_h.GSASL_GSSAPI_RELEASE_BUFFER_ERROR
GSASL_GSSAPI_IMPORT_NAME_ERROR = org.wayround.gsasl.gsasl_h.GSASL_GSSAPI_IMPORT_NAME_ERROR
GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR = org.wayround.gsasl.gsasl_h.GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR
GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR = org.wayround.gsasl.gsasl_h.GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR
GSASL_GSSAPI_UNWRAP_ERROR = org.wayround.gsasl.gsasl_h.GSASL_GSSAPI_UNWRAP_ERROR
GSASL_GSSAPI_WRAP_ERROR = org.wayround.gsasl.gsasl_h.GSASL_GSSAPI_WRAP_ERROR
GSASL_GSSAPI_ACQUIRE_CRED_ERROR = org.wayround.gsasl.gsasl_h.GSASL_GSSAPI_ACQUIRE_CRED_ERROR
GSASL_GSSAPI_DISPLAY_NAME_ERROR = org.wayround.gsasl.gsasl_h.GSASL_GSSAPI_DISPLAY_NAME_ERROR
GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR = org.wayround.gsasl.gsasl_h.GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR
GSASL_KERBEROS_V5_INIT_ERROR = org.wayround.gsasl.gsasl_h.GSASL_KERBEROS_V5_INIT_ERROR
GSASL_KERBEROS_V5_INTERNAL_ERROR = org.wayround.gsasl.gsasl_h.GSASL_KERBEROS_V5_INTERNAL_ERROR
GSASL_SHISHI_ERROR = org.wayround.gsasl.gsasl_h.GSASL_SHISHI_ERROR
GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE = org.wayround.gsasl.gsasl_h.GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE
GSASL_SECURID_SERVER_NEED_NEW_PIN = org.wayround.gsasl.gsasl_h.GSASL_SECURID_SERVER_NEED_NEW_PIN
GSASL_GSSAPI_ENCAPSULATE_TOKEN_ERROR = org.wayround.gsasl.gsasl_h.GSASL_GSSAPI_ENCAPSULATE_TOKEN_ERROR
GSASL_GSSAPI_DECAPSULATE_TOKEN_ERROR = org.wayround.gsasl.gsasl_h.GSASL_GSSAPI_DECAPSULATE_TOKEN_ERROR
GSASL_GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR = org.wayround.gsasl.gsasl_h.GSASL_GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR
GSASL_GSSAPI_TEST_OID_SET_MEMBER_ERROR = org.wayround.gsasl.gsasl_h.GSASL_GSSAPI_TEST_OID_SET_MEMBER_ERROR
GSASL_GSSAPI_RELEASE_OID_SET_ERROR = org.wayround.gsasl.gsasl_h.GSASL_GSSAPI_RELEASE_OID_SET_ERROR

ERRORS_LIST = {
    'GSASL_OK': GSASL_OK,
    'GSASL_NEEDS_MORE': GSASL_NEEDS_MORE,
    'GSASL_UNKNOWN_MECHANISM': GSASL_UNKNOWN_MECHANISM,
    'GSASL_MECHANISM_CALLED_TOO_MANY_TIMES': GSASL_MECHANISM_CALLED_TOO_MANY_TIMES,
    'GSASL_MALLOC_ERROR': GSASL_MALLOC_ERROR,
    'GSASL_BASE64_ERROR': GSASL_BASE64_ERROR,
    'GSASL_CRYPTO_ERROR': GSASL_CRYPTO_ERROR,
    'GSASL_SASLPREP_ERROR': GSASL_SASLPREP_ERROR,
    'GSASL_MECHANISM_PARSE_ERROR': GSASL_MECHANISM_PARSE_ERROR,
    'GSASL_AUTHENTICATION_ERROR': GSASL_AUTHENTICATION_ERROR,
    'GSASL_INTEGRITY_ERROR': GSASL_INTEGRITY_ERROR,
    'GSASL_NO_CLIENT_CODE': GSASL_NO_CLIENT_CODE,
    'GSASL_NO_SERVER_CODE': GSASL_NO_SERVER_CODE,
    'GSASL_NO_CALLBACK': GSASL_NO_CALLBACK,
    'GSASL_NO_ANONYMOUS_TOKEN': GSASL_NO_ANONYMOUS_TOKEN,
    'GSASL_NO_AUTHID': GSASL_NO_AUTHID,
    'GSASL_NO_AUTHZID': GSASL_NO_AUTHZID,
    'GSASL_NO_PASSWORD': GSASL_NO_PASSWORD,
    'GSASL_NO_PASSCODE': GSASL_NO_PASSCODE,
    'GSASL_NO_PIN': GSASL_NO_PIN,
    'GSASL_NO_SERVICE': GSASL_NO_SERVICE,
    'GSASL_NO_HOSTNAME': GSASL_NO_HOSTNAME,
    'GSASL_NO_CB_TLS_UNIQUE': GSASL_NO_CB_TLS_UNIQUE,
    'GSASL_NO_SAML20_IDP_IDENTIFIER': GSASL_NO_SAML20_IDP_IDENTIFIER,
    'GSASL_NO_SAML20_REDIRECT_URL': GSASL_NO_SAML20_REDIRECT_URL,
    'GSASL_NO_OPENID20_REDIRECT_URL': GSASL_NO_OPENID20_REDIRECT_URL,
    'GSASL_GSSAPI_RELEASE_BUFFER_ERROR': GSASL_GSSAPI_RELEASE_BUFFER_ERROR,
    'GSASL_GSSAPI_IMPORT_NAME_ERROR': GSASL_GSSAPI_IMPORT_NAME_ERROR,
    'GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR': GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR,
    'GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR': GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR,
    'GSASL_GSSAPI_UNWRAP_ERROR': GSASL_GSSAPI_UNWRAP_ERROR,
    'GSASL_GSSAPI_WRAP_ERROR': GSASL_GSSAPI_WRAP_ERROR,
    'GSASL_GSSAPI_ACQUIRE_CRED_ERROR': GSASL_GSSAPI_ACQUIRE_CRED_ERROR,
    'GSASL_GSSAPI_DISPLAY_NAME_ERROR': GSASL_GSSAPI_DISPLAY_NAME_ERROR,
    'GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR': GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR,
    'GSASL_KERBEROS_V5_INIT_ERROR': GSASL_KERBEROS_V5_INIT_ERROR,
    'GSASL_KERBEROS_V5_INTERNAL_ERROR': GSASL_KERBEROS_V5_INTERNAL_ERROR,
    'GSASL_SHISHI_ERROR': GSASL_SHISHI_ERROR,
    'GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE': GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE,
    'GSASL_SECURID_SERVER_NEED_NEW_PIN': GSASL_SECURID_SERVER_NEED_NEW_PIN,
    'GSASL_GSSAPI_ENCAPSULATE_TOKEN_ERROR': GSASL_GSSAPI_ENCAPSULATE_TOKEN_ERROR,
    'GSASL_GSSAPI_DECAPSULATE_TOKEN_ERROR': GSASL_GSSAPI_DECAPSULATE_TOKEN_ERROR,
    'GSASL_GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR': GSASL_GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR,
    'GSASL_GSSAPI_TEST_OID_SET_MEMBER_ERROR': GSASL_GSSAPI_TEST_OID_SET_MEMBER_ERROR,
    'GSASL_GSSAPI_RELEASE_OID_SET_ERROR': GSASL_GSSAPI_RELEASE_OID_SET_ERROR
    }

ERRORS = {
    'GSASL_OK': "Successful return code, guaranteed to be always 0",
    'GSASL_NEEDS_MORE': "Mechanism expects another round-trip",
    'GSASL_UNKNOWN_MECHANISM': "Application requested an unknown mechanism",
    'GSASL_MECHANISM_CALLED_TOO_MANY_TIMES': "Application requested too many round trips from mechanism",
    'GSASL_MALLOC_ERROR': "Memory allocation failed",
    'GSASL_BASE64_ERROR': "Base64 encoding/decoding failed",
    'GSASL_CRYPTO_ERROR': "Cryptographic error",
    'GSASL_SASLPREP_ERROR': "Failed to prepare internationalized string",
    'GSASL_MECHANISM_PARSE_ERROR': "Mechanism could not parse input",
    'GSASL_AUTHENTICATION_ERROR': "Authentication has failed",
    'GSASL_INTEGRITY_ERROR': "Application data integrity check failed",
    'GSASL_NO_CLIENT_CODE': "Library was built without client functionality",
    'GSASL_NO_SERVER_CODE': "Library was built without server functionality",
    'GSASL_NO_CALLBACK': "Application did not provide a callback",
    'GSASL_NO_ANONYMOUS_TOKEN': "Could not get required anonymous token",
    'GSASL_NO_AUTHID': "Could not get required authentication identity (username)",
    'GSASL_NO_AUTHZID': "Could not get required authorization identity",
    'GSASL_NO_PASSWORD': "Could not get required password",
    'GSASL_NO_PASSCODE': "Could not get required SecurID PIN",
    'GSASL_NO_PIN': "Could not get required SecurID PIN",
    'GSASL_NO_SERVICE': "Could not get required service name",
    'GSASL_NO_HOSTNAME': "Could not get required hostname",
    'GSASL_NO_CB_TLS_UNIQUE': "Could not get required tls-unique CB",
    'GSASL_NO_SAML20_IDP_IDENTIFIER': "Could not get required SAML IdP",
    'GSASL_NO_SAML20_REDIRECT_URL': "Could not get required SAML redirect URL",
    'GSASL_NO_OPENID20_REDIRECT_URL': "Could not get required OpenID redirect URL",
    'GSASL_GSSAPI_RELEASE_BUFFER_ERROR': "GSS-API library call error",
    'GSASL_GSSAPI_IMPORT_NAME_ERROR': "GSS-API library call error",
    'GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR': "GSS-API library call error",
    'GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR': "GSS-API library call error",
    'GSASL_GSSAPI_UNWRAP_ERROR': "GSS-API library call error",
    'GSASL_GSSAPI_WRAP_ERROR': "GSS-API library call error",
    'GSASL_GSSAPI_ACQUIRE_CRED_ERROR': "GSS-API library call error",
    'GSASL_GSSAPI_DISPLAY_NAME_ERROR': "GSS-API library call error",
    'GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR': "",
    'GSASL_KERBEROS_V5_INIT_ERROR': "Init error in KERBEROS_V5",
    'GSASL_KERBEROS_V5_INTERNAL_ERROR': "General error in KERBEROS_V5",
    'GSASL_SHISHI_ERROR': "General error in KERBEROS_V5",
    'GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE': "SecurID mechanism needs an additional passcode",
    'GSASL_SECURID_SERVER_NEED_NEW_PIN': "SecurID mechanism needs an new PIN",
    'GSASL_GSSAPI_ENCAPSULATE_TOKEN_ERROR': "GSS-API library call error",
    'GSASL_GSSAPI_DECAPSULATE_TOKEN_ERROR': "GSS-API library call error",
    'GSASL_GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR': "GSS-API library call error",
    'GSASL_GSSAPI_TEST_OID_SET_MEMBER_ERROR': "GSS-API library call error",
    'GSASL_GSSAPI_RELEASE_OID_SET_ERROR': "GSS-API library call error",
    }

##################### RFC 2222 (MECHANISM NAME LENGTH)

GSASL_MIN_MECHANISM_SIZE = org.wayround.gsasl.gsasl_h.GSASL_MIN_MECHANISM_SIZE
GSASL_MAX_MECHANISM_SIZE = org.wayround.gsasl.gsasl_h.GSASL_MAX_MECHANISM_SIZE

##################### QUALITY OF PROTECTION TYPES

GSASL_QOP_AUTH = org.wayround.gsasl.gsasl_h.GSASL_QOP_AUTH
GSASL_QOP_AUTH_INT = org.wayround.gsasl.gsasl_h.GSASL_QOP_AUTH_INT
GSASL_QOP_AUTH_CONF = org.wayround.gsasl.gsasl_h.GSASL_QOP_AUTH_CONF

##################### ENCRYPTION TYPES

GSASL_CIPHER_DES = org.wayround.gsasl.gsasl_h.GSASL_CIPHER_DES
GSASL_CIPHER_3DES = org.wayround.gsasl.gsasl_h.GSASL_CIPHER_3DES
GSASL_CIPHER_RC4 = org.wayround.gsasl.gsasl_h.GSASL_CIPHER_RC4
GSASL_CIPHER_RC4_40 = org.wayround.gsasl.gsasl_h.GSASL_CIPHER_RC4_40
GSASL_CIPHER_RC4_56 = org.wayround.gsasl.gsasl_h.GSASL_CIPHER_RC4_56
GSASL_CIPHER_AES = org.wayround.gsasl.gsasl_h.GSASL_CIPHER_AES

##################### FLAGS FOR THE SASLPREP FUNCTION

GSASL_ALLOW_UNASSIGNED = org.wayround.gsasl.gsasl_h.GSASL_ALLOW_UNASSIGNED

##################### CALLBACK/PROPERTY TYPES

GSASL_AUTHID = org.wayround.gsasl.gsasl_h.GSASL_AUTHID
GSASL_AUTHZID = org.wayround.gsasl.gsasl_h.GSASL_AUTHZID
GSASL_PASSWORD = org.wayround.gsasl.gsasl_h.GSASL_PASSWORD
GSASL_ANONYMOUS_TOKEN = org.wayround.gsasl.gsasl_h.GSASL_ANONYMOUS_TOKEN
GSASL_SERVICE = org.wayround.gsasl.gsasl_h.GSASL_SERVICE
GSASL_HOSTNAME = org.wayround.gsasl.gsasl_h.GSASL_HOSTNAME
GSASL_GSSAPI_DISPLAY_NAME = org.wayround.gsasl.gsasl_h.GSASL_GSSAPI_DISPLAY_NAME
GSASL_PASSCODE = org.wayround.gsasl.gsasl_h.GSASL_PASSCODE
GSASL_SUGGESTED_PIN = org.wayround.gsasl.gsasl_h.GSASL_SUGGESTED_PIN
GSASL_PIN = org.wayround.gsasl.gsasl_h.GSASL_PIN
GSASL_REALM = org.wayround.gsasl.gsasl_h.GSASL_REALM
GSASL_DIGEST_MD5_HASHED_PASSWORD = org.wayround.gsasl.gsasl_h.GSASL_DIGEST_MD5_HASHED_PASSWORD
GSASL_QOPS = org.wayround.gsasl.gsasl_h.GSASL_QOPS
GSASL_QOP = org.wayround.gsasl.gsasl_h.GSASL_QOP
GSASL_SCRAM_ITER = org.wayround.gsasl.gsasl_h.GSASL_SCRAM_ITER
GSASL_SCRAM_SALT = org.wayround.gsasl.gsasl_h.GSASL_SCRAM_SALT
GSASL_SCRAM_SALTED_PASSWORD = org.wayround.gsasl.gsasl_h.GSASL_SCRAM_SALTED_PASSWORD
GSASL_CB_TLS_UNIQUE = org.wayround.gsasl.gsasl_h.GSASL_CB_TLS_UNIQUE
GSASL_SAML20_IDP_IDENTIFIER = org.wayround.gsasl.gsasl_h.GSASL_SAML20_IDP_IDENTIFIER
GSASL_SAML20_REDIRECT_URL = org.wayround.gsasl.gsasl_h.GSASL_SAML20_REDIRECT_URL
GSASL_OPENID20_REDIRECT_URL = org.wayround.gsasl.gsasl_h.GSASL_OPENID20_REDIRECT_URL
GSASL_OPENID20_OUTCOME_DATA = org.wayround.gsasl.gsasl_h.GSASL_OPENID20_OUTCOME_DATA
GSASL_SAML20_AUTHENTICATE_IN_BROWSER = org.wayround.gsasl.gsasl_h.GSASL_SAML20_AUTHENTICATE_IN_BROWSER
GSASL_OPENID20_AUTHENTICATE_IN_BROWSER = org.wayround.gsasl.gsasl_h.GSASL_OPENID20_AUTHENTICATE_IN_BROWSER
GSASL_VALIDATE_SIMPLE = org.wayround.gsasl.gsasl_h.GSASL_VALIDATE_SIMPLE
GSASL_VALIDATE_EXTERNAL = org.wayround.gsasl.gsasl_h.GSASL_VALIDATE_EXTERNAL
GSASL_VALIDATE_ANONYMOUS = org.wayround.gsasl.gsasl_h.GSASL_VALIDATE_ANONYMOUS
GSASL_VALIDATE_GSSAPI = org.wayround.gsasl.gsasl_h.GSASL_VALIDATE_GSSAPI
GSASL_VALIDATE_SECURID = org.wayround.gsasl.gsasl_h.GSASL_VALIDATE_SECURID
GSASL_VALIDATE_SAML20 = org.wayround.gsasl.gsasl_h.GSASL_VALIDATE_SAML20
GSASL_VALIDATE_OPENID20 = org.wayround.gsasl.gsasl_h.GSASL_VALIDATE_OPENID20

# PROPERTIES DICT

PROPERTIES_LIST = {
    'GSASL_AUTHID': GSASL_AUTHID,
    'GSASL_AUTHZID': GSASL_AUTHZID,
    'GSASL_PASSWORD': GSASL_PASSWORD,
    'GSASL_ANONYMOUS_TOKEN': GSASL_ANONYMOUS_TOKEN,
    'GSASL_SERVICE': GSASL_SERVICE,
    'GSASL_HOSTNAME': GSASL_HOSTNAME,
    'GSASL_GSSAPI_DISPLAY_NAME': GSASL_GSSAPI_DISPLAY_NAME,
    'GSASL_PASSCODE': GSASL_PASSCODE,
    'GSASL_SUGGESTED_PIN': GSASL_SUGGESTED_PIN,
    'GSASL_PIN': GSASL_PIN,
    'GSASL_REALM': GSASL_REALM,
    'GSASL_DIGEST_MD5_HASHED_PASSWORD': GSASL_DIGEST_MD5_HASHED_PASSWORD,
    'GSASL_QOPS': GSASL_QOPS,
    'GSASL_QOP': GSASL_QOP,
    'GSASL_SCRAM_ITER': GSASL_SCRAM_ITER,
    'GSASL_SCRAM_SALT': GSASL_SCRAM_SALT,
    'GSASL_SCRAM_SALTED_PASSWORD': GSASL_SCRAM_SALTED_PASSWORD,
    'GSASL_CB_TLS_UNIQUE': GSASL_CB_TLS_UNIQUE,
    'GSASL_SAML20_IDP_IDENTIFIER': GSASL_SAML20_IDP_IDENTIFIER,
    'GSASL_SAML20_REDIRECT_URL': GSASL_SAML20_REDIRECT_URL,
    'GSASL_OPENID20_REDIRECT_URL': GSASL_OPENID20_REDIRECT_URL,
    'GSASL_OPENID20_OUTCOME_DATA': GSASL_OPENID20_OUTCOME_DATA,
    'GSASL_SAML20_AUTHENTICATE_IN_BROWSER': GSASL_SAML20_AUTHENTICATE_IN_BROWSER,
    'GSASL_OPENID20_AUTHENTICATE_IN_BROWSER': GSASL_OPENID20_AUTHENTICATE_IN_BROWSER,
    'GSASL_VALIDATE_SIMPLE': GSASL_VALIDATE_SIMPLE,
    'GSASL_VALIDATE_EXTERNAL': GSASL_VALIDATE_EXTERNAL,
    'GSASL_VALIDATE_ANONYMOUS': GSASL_VALIDATE_ANONYMOUS,
    'GSASL_VALIDATE_GSSAPI': GSASL_VALIDATE_GSSAPI,
    'GSASL_VALIDATE_SECURID': GSASL_VALIDATE_SECURID,
    'GSASL_VALIDATE_SAML20': GSASL_VALIDATE_SAML20,
    'GSASL_VALIDATE_OPENID20': GSASL_VALIDATE_OPENID20
    }

PROPERTIES = {
    'GSASL_AUTHID': "Authentication identity (username)",
    'GSASL_AUTHZID': "Authorization identity",
    'GSASL_PASSWORD': "Password",
    'GSASL_ANONYMOUS_TOKEN': "Anonymous identifier",
    'GSASL_SERVICE': "Service name",
    'GSASL_HOSTNAME': "Host name",
    'GSASL_GSSAPI_DISPLAY_NAME': "GSS-API credential principal name",
    'GSASL_PASSCODE': "SecurID passcode",
    'GSASL_SUGGESTED_PIN': "SecurID suggested PIN",
    'GSASL_PIN': "SecurID PIN",
    'GSASL_REALM': "User realm",
    'GSASL_DIGEST_MD5_HASHED_PASSWORD': "Pre-computed hashed DIGEST-MD5 password, to avoid storing passwords in the clear",
    'GSASL_QOPS': "Set of quality-of-protection values",
    'GSASL_QOP': "Quality-of-protection value",
    'GSASL_SCRAM_ITER': "Number of iterations in password-to-key hashing",
    'GSASL_SCRAM_SALT': "Salt for password-to-key hashing",
    'GSASL_SCRAM_SALTED_PASSWORD': "Pre-computed salted SCRAM key, to avoid re-computation and storing passwords in the clear",
    'GSASL_CB_TLS_UNIQUE': "Base64 encoded tls-unique channel binding",
    'GSASL_SAML20_IDP_IDENTIFIER': "SAML20 user IdP URL",
    'GSASL_SAML20_REDIRECT_URL': "SAML 2.0 URL to access in browser",
    'GSASL_OPENID20_REDIRECT_URL': "OpenID 2.0 URL to access in browser",
    'GSASL_OPENID20_OUTCOME_DATA': "OpenID 2.0 authentication outcome data",
    'GSASL_SAML20_AUTHENTICATE_IN_BROWSER': "Request to perform SAML 2.0 authentication in browser",
    'GSASL_OPENID20_AUTHENTICATE_IN_BROWSER': "Request to perform OpenID 2.0 authentication in browser",
    'GSASL_VALIDATE_SIMPLE': "Request for simple validation",
    'GSASL_VALIDATE_EXTERNAL': "Request for validation of EXTERNAL",
    'GSASL_VALIDATE_ANONYMOUS': "Request for validation of ANONYMOUS",
    'GSASL_VALIDATE_GSSAPI': "Request for validation of GSSAPI/GS2",
    'GSASL_VALIDATE_SECURID': "Reqest for validation of SecurID",
    'GSASL_VALIDATE_SAML20': "Reqest for validation of SAML20",
    'GSASL_VALIDATE_OPENID20': "Reqest for validation of OpenID 2.0 login",
    }

class GSASInitException(Exception): pass

class Gsasl:
    def __init__(self, value):
        self.value = int(value)

class GSASLSessionHook:
    def __init__(self, value):
        self.value = int(value)

class GSASLCallbackHook:
    def __init__(self, value):
        self.value = int(value)

gsasl_session_registry = {}

cdef class GSASLSession:

    cdef org.wayround.gsasl.gsasl_h.Gsasl_session * _c_gsasl_session

    def __cinit__(self):
        self._c_gsasl_session = NULL

    def __init__(self, value):

        self._c_gsasl_session = (
            < org.wayround.gsasl.gsasl_h.Gsasl_session *> < int > int(value)
            )

        if not < int > self._c_gsasl_session in gsasl_session_registry:
            print("adding {} to gsasl_session_registry".format(< int > self._c_gsasl_session))
            gsasl_session_registry[ < int > self._c_gsasl_session] = self

    def __dealloc__(self):
        print("object {} dealloc called".format(self))
        if self._c_gsasl_session != NULL:
            org.wayround.gsasl.gsasl_h.gsasl_finish(
                self._c_gsasl_session
                )

            if < int > self._c_gsasl_session in gsasl_session_registry:
                print("removing {} from gsasl_session_registry".format(< int > self._c_gsasl_session))
                del gsasl_session_registry[ < int > self._c_gsasl_session]


    def close(self):
        if self._c_gsasl_session != NULL:
            if < int > self._c_gsasl_session in gsasl_session_registry:
                print("removing {} from gsasl_session_registry".format(< int > self._c_gsasl_session))
                del gsasl_session_registry[ < int > self._c_gsasl_session]


    def hook_set(self, hook):

        if not isinstance(hook, GSASLSessionHook):
            raise TypeError(
                "Wrong hook parameter type. Must be GSASLSessionHook"
                )

        org.wayround.gsasl.gsasl_h.gsasl_session_hook_set(
            self._c_gsasl_session,
            < void *>< int > hook
            )

        return

    def hook_get(self):

        cdef void * cret

        ret = None

        cret = org.wayround.gsasl.gsasl_h.gsasl_session_hook_get(
            self._c_gsasl_session
            )

        if cret != NULL:
            ret = < int > cret

        return ret

    def property_set(self, prop, data):

        if not isinstance(prop, int):
            raise TypeError("prop must be int")

        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")

        org.wayround.gsasl.gsasl_h.gsasl_property_set(
            self._c_gsasl_session,
            < org.wayround.gsasl.gsasl_h.Gsasl_property >< int > prop,
            < bytes > data
            )

        return

    def property_set_raw(self, prop, data, size):

        if not isinstance(prop, int):
            raise TypeError("prop must be int")

        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")

        if not isinstance(size, int):
            raise TypeError("size must be int")

        org.wayround.gsasl.gsasl_h.gsasl_property_set_raw(
            self._c_gsasl_session,
            < org.wayround.gsasl.gsasl_h.Gsasl_property >< int > prop,
            < bytes > data,
            < int > size
            )

        return

    def property_get(self, prop):

        cdef char * cret = NULL

        ret = None

        if not isinstance(prop, int):
            raise TypeError("prop must be int")

        cret = org.wayround.gsasl.gsasl_h.gsasl_property_get(
            self._c_gsasl_session,
            < org.wayround.gsasl.gsasl_h.Gsasl_property >< int > prop
            )

        if cret != NULL:
            ret = < bytes > cret
        else:
            ret = None

        return ret

    def property_fast(self, prop):

        cdef char * cret = NULL

        ret = None

        if not isinstance(prop, int):
            raise TypeError("prop must be int")

        cret = org.wayround.gsasl.gsasl_h.gsasl_property_fast(
            self._c_gsasl_session,
            < org.wayround.gsasl.gsasl_h.Gsasl_property >< int > prop
            )

        if cret != NULL:
            ret = < bytes > cret
        else:
            ret = None

        return ret

    def step(self, inp):

        cdef size_t input_len
        cdef char * output
        cdef size_t output_len

        cdef int cret

        ret = None

        if not isinstance(inp, bytes):
            raise TypeError("inp must be bytes")

        input_len = len(input)

        cret = org.wayround.gsasl.gsasl_h.gsasl_step(
            self._c_gsasl_session,
            < bytes > bytes(inp[0:input_len]),
            < size_t > input_len,
            & output,
            & output_len
            )

        if cret == GSASL_OK or cret == GSASL_NEEDS_MORE:

            ret = < bytes > bytes(output[0:output_len])

            free(output)

            ret = (< int > cret, ret)

        else:
            ret = (< int > cret, None)

        return ret

    def step64(self, b64input):

        cdef char * b64output

        cdef int cret

        ret = None

        if not isinstance(b64input, str):
            raise TypeError("b64input must be str")

        cret = org.wayround.gsasl.gsasl_h.gsasl_step64(
            self._c_gsasl_session,
            < bytes > bytes(b64input, 'utf-8'),
            & b64output,
            )

        if cret == GSASL_OK or cret == GSASL_NEEDS_MORE:

            ret = < bytes > b64output

            free(b64output)

            ret = (< int > cret, ret)

        else:
            ret = (< int > cret, None)

        return ret

    def encode(self, inp):

        cdef size_t input_len
        cdef char * output
        cdef size_t output_len

        cdef int cret

        ret = None

        if not isinstance(inp, bytes):
            raise TypeError("inp must be bytes")

        input_len = len(inp)

        cret = org.wayround.gsasl.gsasl_h.gsasl_encode(
            self._c_gsasl_session,
            < bytes > bytes(inp[0:input_len]),
            < size_t > input_len,
            & output,
            & output_len
            )

        if cret == GSASL_OK:

            ret = < bytes > bytes(output[0:output_len])

            free(output)

            ret = (< int > cret, ret)

        else:
            ret = (< int > cret, None)

        return ret

    def decode(self, inp):

        cdef size_t input_len
        cdef char * output
        cdef size_t output_len

        cdef int cret

        ret = None

        if not isinstance(inp, bytes):
            raise TypeError("inp must be bytes")

        input_len = len(inp)

        cret = org.wayround.gsasl.gsasl_h.gsasl_decode(
            self._c_gsasl_session,
            < bytes > bytes(inp[0:input_len]),
            < size_t > input_len,
            & output,
            & output_len
            )

        if cret == GSASL_OK:

            ret = < bytes > bytes(output[0:output_len])

            free(output)

            ret = (< int > cret, ret)

        else:
            ret = (< int > cret, None)

        return ret

    def mechanism_name(self):

        return str(
            < str > org.wayround.gsasl.gsasl_h.gsasl_mechanism_name(
                self._c_gsasl_session
                ),
            'utf-8'
            )

gsasl_registry = {}

cdef class GSASL:

    cdef org.wayround.gsasl.gsasl_h.Gsasl * _c_gsasl
    cdef _existed
    cdef _py_callback


    def __cinit__(self):
        self._c_gsasl = NULL

    def __init__(self, initial_gsasl=None):

        self._existed = False
        self._py_callback = None

        if initial_gsasl:
            self._existed = True

            if isinstance(initial_gsasl, int):
                self._c_gsasl = (
                    < org.wayround.gsasl.gsasl_h.Gsasl *> < int > initial_gsasl
                    )

            if isinstance(initial_gsasl, GSASL):
                self._c_gsasl = (
                    < org.wayround.gsasl.gsasl_h.Gsasl *> < int > initial_gsasl.get_c_gsasl()
                    )

        else:

            res = org.wayround.gsasl.gsasl_h.gsasl_init(& self._c_gsasl)

            if res != GSASL_OK:
                raise GSASInitException("Exception {} while init".format(res))

            if not < int > self._c_gsasl in gsasl_registry.keys():
                print("adding {} to gsasl_registry".format(< int > self._c_gsasl))
                gsasl_registry[ < int > self._c_gsasl] = self

        return

    def __dealloc__(self):
        print("object {} dealloc called".format(self))
        if not self._existed:
            if self._c_gsasl != NULL:
                org.wayround.gsasl.gsasl_h.gsasl_done(
                    self._c_gsasl
                    )

        return


    def close(self):

        if not self._existed:
            if < int > self._c_gsasl in gsasl_registry.keys():
                print("removing {} from gsasl_registry".format(< int > self._c_gsasl))
                del gsasl_registry[ < int > self._c_gsasl]
        return


    def get_c_gsasl(self):
        return < int > self._c_gsasl

    @property
    def py_callback(self):
        return self._py_callback

    def set_c_gsasl(self, py_gsasl):
        self._c_gsasl = < org.wayround.gsasl.gsasl_h.Gsasl *> < int > py_gsasl

    def set_callback(self, func):

        self._py_callback = func

        org.wayround.gsasl.gsasl_h.gsasl_callback_set(
            self._c_gsasl,
            < org.wayround.gsasl.gsasl_h.Gsasl_callback_function > callback
            )
        return

    def callback(self, session, prop):

        if not isinstance(session, GSASLSession):
            raise TypeError("session must be of GSASLSession type")

        if not isinstance(prop, int):
            raise TypeError("prop must be of int type")

        org.wayround.gsasl.gsasl_h.gsasl_callback(
            self._c_gsasl,
            < org.wayround.gsasl.gsasl_h.Gsasl_session *> < int > session.value,
            < org.wayround.gsasl.gsasl_h.Gsasl_property >< int > prop
            )

        return

    def callback_hook_set(self, hook):

        if not isinstance(hook, GSASLCallbackHook):
            raise TypeError("hook must be of type GSASLCallbackHook")

        org.wayround.gsasl.gsasl_h.gsasl_callback_hook_set(
            self._c_gsasl,
            < void *> hook.value
            )

        return

    def callback_hook_get(self):

        cdef void * cret = NULL
        ret = None

        cret = org.wayround.gsasl.gsasl_h.gsasl_callback_hook_get(self._c_gsasl)

        if cret != NULL:
            ret = GSASLCallbackHook(< int > cret)

        return ret

    def client_start(self, mech):

        cdef org.wayround.gsasl.gsasl_h.Gsasl_session * sctx
        cdef int cret

        if not isinstance(mech, str):
            raise TypeError("mech must be str")

        ret = None

        cret = org.wayround.gsasl.gsasl_h.gsasl_client_start (
            self._c_gsasl,
            < char *>< bytes > bytes(mech, 'utf-8'),
            & sctx
            )

        if cret == GSASL_OK:
            ret = (< int > cret, GSASLSession(< int > sctx))
        else:
            ret = (< int > cret, None)

        return ret

    def server_start(self, mech):

        cdef org.wayround.gsasl.gsasl_h.Gsasl_session * sctx
        cdef int cret

        if not isinstance(mech, str):
            raise TypeError("mech must be str")

        ret = None

        cret = org.wayround.gsasl.gsasl_h.gsasl_server_start (
            self._c_gsasl,
            < char *>< bytes > bytes(mech, 'utf-8'),
            & sctx
            )

        if cret == GSASL_OK:
            ret = (< int > cret, GSASLSession(< int > sctx))
        else:
            ret = (< int > cret, None)

        return ret

    def client_mechlist(self):

        cdef char * out = NULL
        cdef int cret

        cret = org.wayround.gsasl.gsasl_h.gsasl_client_mechlist(
            self._c_gsasl,
            & out
            )

        ret = None

        if cret == GSASL_OK:
            ts = str(< bytes > out, 'utf-8').split(' ')
            ret = (< int > cret, ts)
        else:
            ret = (< int > cret, None)

        return ret

    def client_support_p(self, name):

        cdef int cret

        if not isinstance(name, str):
            raise TypeError("name must be str")

        cret = org.wayround.gsasl.gsasl_h.gsasl_client_support_p(
            self._c_gsasl,
            < bytes > bytes(name, 'utf-8')
            )

        ret = (< int > cret == 1)

        return ret

    def server_mechlist(self):

        cdef char * out = NULL
        cdef int cret

        cret = org.wayround.gsasl.gsasl_h.gsasl_server_mechlist(
            self._c_gsasl,
            & out
            )

        ret = None

        if cret == GSASL_OK:
            ts = str(< bytes > out, 'utf-8').split(' ')
            ret = (< int > cret, ts)
        else:
            ret = (< int > cret, None)

        return ret

    def server_support_p(self, name):

        cdef int cret

        if not isinstance(name, str):
            raise TypeError("name must be str")

        cret = org.wayround.gsasl.gsasl_h.gsasl_server_support_p(
            self._c_gsasl,
            < bytes > bytes(name, 'utf-8')
            )

        ret = (< int > cret == 1)

        return ret

cdef int callback(
    org.wayround.gsasl.gsasl_h.Gsasl * ctx,
    org.wayround.gsasl.gsasl_h.Gsasl_session * sctx,
    org.wayround.gsasl.gsasl_h.Gsasl_property prop
    ):

    if not < int > ctx in gsasl_registry:
        raise KeyError("{} not registered in gsasl_registry".format(< int > ctx))

    if not < int > sctx in gsasl_session_registry:
        raise KeyError("{} not registered in gsasl_session_registry".format(< int > sctx))

    context = gsasl_registry[ < int > ctx]
    session = gsasl_session_registry[ < int > sctx]

    if not hasattr(context, 'py_callback'):
        raise KeyError("py_callback is absent in context of {}".format(context))

    cdef int ret = GSASL_OK

    t1 = context.py_callback != None

    t2 = callable(context.py_callback)

    if t1 and t2:

        ret = context.py_callback(
            context,
            session,
            < int > prop
            )

    return ret

# TODO: char *gsasl_client_suggest_mechanism (Gsasl * ctx,
#                                      char
#                                     *mechlist)



def check_version(req_version=None):

    """
    Accepts None or str. Returns None or str
    """

    cdef char * req_version2 = NULL
    cdef char * cret = NULL


    ret = None

    if req_version != None and not isinstance(req_version, str):
        raise TypeError("req_version must be None or str")

    else:

        if req_version == None:
            req_version2 = NULL

        if isinstance(req_version, str):
            req_version2 = < bytes > bytes(req_version, 'utf-8')

        cret = org.wayround.gsasl.gsasl_h.gsasl_check_version(req_version2)

        if not cret == NULL:
            ret = str(< bytes > cret, 'utf-8')

    return ret

def strerror(err):
    return str(
        < str > org.wayround.gsasl.gsasl_h.gsasl_strerror(int(err)),
        'utf-8'
        )

def strerror_name(err):
    return str(
        < str > org.wayround.gsasl.gsasl_h.gsasl_strerror_name(int(err)),
        'utf-8'
        )

def strproperty(prop):

    ret = '<Unknown property>'

    for i in list(PROPERTIES_LIST.keys()):
        if PROPERTIES_LIST[i] == prop:
            ret = PROPERTIES[i]
            break

    return ret

def strproperty_name(prop):

    ret = '<Unknown property>'

    for i in list(PROPERTIES_LIST.keys()):
        if PROPERTIES_LIST[i] == prop:
            ret = i
            break

    return ret


def saslprep(inv, flags):

    cdef int cret
    cdef char * out
    cdef int stringpreprc

    if not isinstance(inv, str):
        raise TypeError("inv must be str")

    cret = org.wayround.gsasl.gsasl_h.gsasl_saslprep(
        < bytes > bytes(inv, 'utf-8'),
        < org.wayround.gsasl.gsasl_h.Gsasl_saslprep_flags > flags,
        & out,
        & stringpreprc
        )

    ret = None
    if cret == GSASL_OK:

        ret = (< int > cret, < str > str(out, 'utf-8'), < int > stringpreprc)

        free(out)

    else:

        ret = (< int > cret, None, None)

    return ret

def simple_getpass(filename, username):

    cdef char * key
    cdef int cret

    if not isinstance(filename, str):
        raise TypeError("filename must be str")

    if not isinstance(username, str):
        raise TypeError("username must be str")

    cret = org.wayround.gsasl.gsasl_h.gsasl_simple_getpass(
        < bytes > bytes(filename, 'utf-8'),
        < bytes > bytes(username, 'utf-8'),
        & key
        )

    ret = None
    if cret == GSASL_OK:
        ret = (< int > cret, < bytes > key)
        free(key)
    else:
        ret = (< int > cret, None)

    return ret


def base64_to(inv):

    cdef size_t input_len
    cdef char * output
    cdef size_t output_len

    cdef int cret

    ret = None

    if not isinstance(inv, bytes):
        raise TypeError("inv must be bytes")

    input_len = len(inv)

    cret = org.wayround.gsasl.gsasl_h.gsasl_base64_to(
        < bytes > bytes(inv[0:input_len]),
        < size_t > input_len,
        & output,
        & output_len
        )

    if cret == GSASL_OK:

        ret = < bytes > bytes(output[0:output_len])

        free(output)

        ret = (< int > cret, ret)

    else:
        ret = (< int > cret, None)

    return ret

def base64_from(inv):

    cdef size_t input_len
    cdef char * output
    cdef size_t output_len

    cdef int cret

    ret = None

    if not isinstance(inv, bytes):
        raise TypeError("inv must be bytes")

    input_len = len(inv)

    cret = org.wayround.gsasl.gsasl_h.gsasl_base64_from(
        < bytes > bytes(inv[0:input_len]),
        < size_t > input_len,
        & output,
        & output_len
        )

    if cret == GSASL_OK:

        ret = < bytes > bytes(output[0:output_len])

        free(output)

        ret = (< int > cret, ret)

    else:
        ret = (< int > cret, None)

    return ret


def nonce(datalen):

    cdef char * data
    cdef int cret

    ret = ''

    if not isinstance(datalen, int):
        raise TypeError("datalen must be int")

    data = < char *> malloc(< size_t > datalen)

    cret = org.wayround.gsasl.gsasl_h.gsasl_nonce(data, < size_t > datalen)

    ret = None
    if cret == GSASL_OK:
        ret = < bytes > bytes (data[0:datalen])

    free(data)

    return ret

def random(datalen):

    cdef char * data
    cdef int cret

    ret = ''

    if not isinstance(datalen, int):
        raise TypeError("datalen must be int")

    data = < char *> malloc(< size_t > datalen)

    cret = org.wayround.gsasl.gsasl_h.gsasl_random(data, < size_t > datalen)

    ret = None
    if cret == GSASL_OK:
        ret = < bytes > bytes (data[0:datalen])

    free(data)

    return ret

def md5(inv):

    cdef size_t input_len
    cdef char * output

    cdef int cret

    ret = None

    if not isinstance(inv, bytes):
        raise TypeError("inv must be bytes")

    input_len = len(inv)

    cret = org.wayround.gsasl.gsasl_h.gsasl_md5(
        < bytes > bytes(inv[0:input_len]),
        < size_t > input_len,
        & output
        )

    if cret == GSASL_OK:

        ret = < bytes > bytes(output[0:16])

        free(output)

        ret = (< int > cret, ret)

    else:
        ret = (< int > cret, None)

    return ret

def hmac_md5(key, inv):

    cdef size_t key_len
    cdef size_t input_len
    cdef char * outhash

    cdef int cret

    ret = None

    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")

    if not isinstance(inv, bytes):
        raise TypeError("inv must be bytes")

    input_len = len(inv)
    key_len = len(key)

    cret = org.wayround.gsasl.gsasl_h.gsasl_hmac_md5(
        < bytes > bytes(inv[0:input_len]),
        < size_t > input_len,
        < bytes > bytes(key[0:key_len]),
        < size_t > key_len,
        & outhash
        )

    if cret == GSASL_OK:

        ret = < bytes > bytes(outhash[0:16])

        free(outhash)

        ret = (< int > cret, ret)

    else:
        ret = (< int > cret, None)

    return ret

def sha1(inv):

    cdef size_t input_len
    cdef char * output

    cdef int cret

    ret = None

    if not isinstance(inv, bytes):
        raise TypeError("inv must be bytes")

    input_len = len(inv)

    cret = org.wayround.gsasl.gsasl_h.gsasl_sha1(
        < bytes > bytes(inv[0:input_len]),
        < size_t > input_len,
        & output
        )

    if cret == GSASL_OK:

        ret = < bytes > bytes(output[0:20])

        free(output)

        ret = (< int > cret, ret)

    else:
        ret = (< int > cret, None)

    return ret

def hmac_sha1(key, inv):

    cdef size_t key_len
    cdef size_t input_len
    cdef char * outhash

    cdef int cret

    ret = None

    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")

    if not isinstance(inv, bytes):
        raise TypeError("inv must be bytes")

    input_len = len(inv)
    key_len = len(key)

    cret = org.wayround.gsasl.gsasl_h.gsasl_hmac_sha1(
        < bytes > bytes(inv[0:input_len]),
        < size_t > input_len,
        < bytes > bytes(key[0:key_len]),
        < size_t > key_len,
        & outhash
        )

    if cret == GSASL_OK:

        ret = < bytes > bytes(outhash[0:20])

        free(outhash)

        ret = (< int > cret, ret)

    else:
        ret = (< int > cret, None)

    return ret

cdef extern from "gsasl.h":

    ctypedef enum Gsasl_rc:
       
        GSASL_OK
        GSASL_NEEDS_MORE
        GSASL_UNKNOWN_MECHANISM
        GSASL_MECHANISM_CALLED_TOO_MANY_TIMES
        GSASL_MALLOC_ERROR
        GSASL_BASE64_ERROR
        GSASL_CRYPTO_ERROR
        GSASL_SASLPREP_ERROR
        GSASL_MECHANISM_PARSE_ERROR
        GSASL_AUTHENTICATION_ERROR
        GSASL_INTEGRITY_ERROR
        GSASL_NO_CLIENT_CODE
        GSASL_NO_SERVER_CODE
        GSASL_NO_CALLBACK
        GSASL_NO_ANONYMOUS_TOKEN
        GSASL_NO_AUTHID
        GSASL_NO_AUTHZID
        GSASL_NO_PASSWORD
        GSASL_NO_PASSCODE
        GSASL_NO_PIN
        GSASL_NO_SERVICE
        GSASL_NO_HOSTNAME
        GSASL_NO_CB_TLS_UNIQUE
        GSASL_NO_SAML20_IDP_IDENTIFIER
        GSASL_NO_SAML20_REDIRECT_URL
        GSASL_NO_OPENID20_REDIRECT_URL

        GSASL_GSSAPI_RELEASE_BUFFER_ERROR
        GSASL_GSSAPI_IMPORT_NAME_ERROR
        GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR
        GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR
        GSASL_GSSAPI_UNWRAP_ERROR
        GSASL_GSSAPI_WRAP_ERROR
        GSASL_GSSAPI_ACQUIRE_CRED_ERROR
        GSASL_GSSAPI_DISPLAY_NAME_ERROR
        GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR
        GSASL_KERBEROS_V5_INIT_ERROR
        GSASL_KERBEROS_V5_INTERNAL_ERROR
        GSASL_SHISHI_ERROR
        GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE
        GSASL_SECURID_SERVER_NEED_NEW_PIN
        GSASL_GSSAPI_ENCAPSULATE_TOKEN_ERROR
        GSASL_GSSAPI_DECAPSULATE_TOKEN_ERROR
        GSASL_GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR
        GSASL_GSSAPI_TEST_OID_SET_MEMBER_ERROR
        GSASL_GSSAPI_RELEASE_OID_SET_ERROR

    enum:
        GSASL_MIN_MECHANISM_SIZE
        GSASL_MAX_MECHANISM_SIZE

    ctypedef enum Gsasl_qop:
        GSASL_QOP_AUTH
        GSASL_QOP_AUTH_INT
        GSASL_QOP_AUTH_CONF

    ctypedef enum Gsasl_cipher:
        GSASL_CIPHER_DES
        GSASL_CIPHER_3DES
        GSASL_CIPHER_RC4
        GSASL_CIPHER_RC4_40
        GSASL_CIPHER_RC4_56
        GSASL_CIPHER_AES

    ctypedef enum Gsasl_saslprep_flags:
        GSASL_ALLOW_UNASSIGNED

    ctypedef enum Gsasl_property:
        GSASL_AUTHID 
        GSASL_AUTHZID 
        GSASL_PASSWORD 
        GSASL_ANONYMOUS_TOKEN 
        GSASL_SERVICE 
        GSASL_HOSTNAME 
        GSASL_GSSAPI_DISPLAY_NAME 
        GSASL_PASSCODE 
        GSASL_SUGGESTED_PIN 
        GSASL_PIN 
        GSASL_REALM 
        GSASL_DIGEST_MD5_HASHED_PASSWORD 
        GSASL_QOPS 
        GSASL_QOP 
        GSASL_SCRAM_ITER 
        GSASL_SCRAM_SALT 
        GSASL_SCRAM_SALTED_PASSWORD 
        GSASL_CB_TLS_UNIQUE 
        GSASL_SAML20_IDP_IDENTIFIER 
        GSASL_SAML20_REDIRECT_URL 
        GSASL_OPENID20_REDIRECT_URL 
        GSASL_OPENID20_OUTCOME_DATA 
        # Client callbacks
        GSASL_SAML20_AUTHENTICATE_IN_BROWSER 
        GSASL_OPENID20_AUTHENTICATE_IN_BROWSER 
        # Server validation callback properties
        GSASL_VALIDATE_SIMPLE 
        GSASL_VALIDATE_EXTERNAL 
        GSASL_VALIDATE_ANONYMOUS 
        GSASL_VALIDATE_GSSAPI 
        GSASL_VALIDATE_SECURID 
        GSASL_VALIDATE_SAML20 
        GSASL_VALIDATE_OPENID20 

    ctypedef struct Gsasl
   
    ctypedef struct Gsasl_session

    ctypedef int (*Gsasl_callback_function) (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop)
   
    # Library entry and exit points: version.c, init.c, done.c
    int gsasl_init (Gsasl ** ctx)
    void gsasl_done (Gsasl * ctx)
   
    char *gsasl_check_version ( char *req_version)

    # Callback handling: callback.c
    void gsasl_callback_set (Gsasl * ctx, Gsasl_callback_function cb)
    int gsasl_callback (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop)
   
    void gsasl_callback_hook_set (Gsasl * ctx, void *hook)
    void *gsasl_callback_hook_get (Gsasl * ctx)
   
    void gsasl_session_hook_set (Gsasl_session * sctx,
                          void *hook)
    void *gsasl_session_hook_get (Gsasl_session * sctx)
   
    # Property handling: property.c
    void gsasl_property_set (Gsasl_session * sctx,
                          Gsasl_property prop,
                           char *data)
    void gsasl_property_set_raw (Gsasl_session * sctx,
                          Gsasl_property prop,
                           char *data, size_t len)
    char *gsasl_property_get (Gsasl_session * sctx,
                             Gsasl_property prop)
    char *gsasl_property_fast (Gsasl_session * sctx,
                              Gsasl_property prop)
   
    # Mechanism handling: listmech.c, supportp.c, suggest.c
    int gsasl_client_mechlist (Gsasl * ctx, char **out)
    int gsasl_client_support_p (Gsasl * ctx,  char *name)
    char *gsasl_client_suggest_mechanism (Gsasl * ctx,
                                      char
                                     *mechlist)
   
    int gsasl_server_mechlist (Gsasl * ctx, char **out)
    int gsasl_server_support_p (Gsasl * ctx,  char *name)
   
    # Authentication functions: xstart.c, xstep.c, xfinish.c
    int gsasl_client_start (Gsasl * ctx,  char *mech,
                         Gsasl_session ** sctx)
    int gsasl_server_start (Gsasl * ctx,  char *mech,
                         Gsasl_session ** sctx)
    int gsasl_step (Gsasl_session * sctx,
                      char *input, size_t input_len,
                     char **output, size_t * output_len)
    int gsasl_step64 (Gsasl_session * sctx,
                        char *b64input, char **b64output)
    void gsasl_finish (Gsasl_session * sctx)
   
    # Session functions: xcode.c, mechname.c
    int gsasl_encode (Gsasl_session * sctx,
                        char *input, size_t input_len,
                       char **output, size_t * output_len)
    int gsasl_decode (Gsasl_session * sctx,
                        char *input, size_t input_len,
                       char **output, size_t * output_len)
    char *gsasl_mechanism_name (Gsasl_session * sctx)
   
    # Error handling: error.c
    char *gsasl_strerror (int err)
    char *gsasl_strerror_name (int err)
   
    # Internationalized string processing: stringprep.c
    int gsasl_saslprep ( char *inv, Gsasl_saslprep_flags flags, char **out, int *stringpreprc)
   
    # Utilities: base64.c, md5pwd.c, crypto.c
    int gsasl_simple_getpass ( char *filename,
                            char *username,
                           char **key)
    int gsasl_base64_to ( char *inv, size_t inlen,
                      char **out, size_t * outlen)
    int gsasl_base64_from ( char *inv, size_t inlen,
                        char **out, size_t * outlen)
    int gsasl_nonce (char *data, size_t datalen)
    int gsasl_random (char *data, size_t datalen)
    int gsasl_md5 ( char *inv, size_t inlen,
                    char *out[16])
    int gsasl_hmac_md5 ( char *key, size_t keylen,
                          char *inv, size_t inlen,
                         char *outhash[16])
    int gsasl_sha1 ( char *inv, size_t inlen,
                     char *out[20])
    int gsasl_hmac_sha1 ( char *key, size_t keylen,
                       char *inv, size_t inlen,
                      char *outhash[20])
    void gsasl_free (void *ptr)

import org.wayround.gsasl.gsasl_bin


gs = org.wayround.gsasl.gsasl_bin.GSASL()

print("client_mechlist             : {}".format(gs.client_mechlist()))
print("client_support_p            : {}".format(gs.client_support_p('ANONYMOUS')))
print("server_mechlist             : {}".format(gs.server_mechlist()))
print("server_support_p            : {}".format(gs.server_support_p('ANONYMOUS')))
print("gsasl_strerror              : {}".format(org.wayround.gsasl.gsasl_bin.strerror(0)))
print("gsasl_strerror_name         : {}".format(org.wayround.gsasl.gsasl_bin.strerror_name(0)))

n = org.wayround.gsasl.gsasl_bin.nonce(10)
print("nonce (lenght must be 10)   : {} (length {})".format(n, len(n)))
y = None
while not y in ['y', 'n']:
    y = input('test random?[yn]:')
if y == 'y':
    print("generating random, please wait...")
    n = org.wayround.gsasl.gsasl_bin.random(10)
    print("random (lenght must be 10)  : {} (length {})".format(n, len(n)))
print("md5                         : {}".format(org.wayround.gsasl.gsasl_bin.md5(b'')))

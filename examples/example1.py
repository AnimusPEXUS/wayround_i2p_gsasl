
import gc
import logging

import org.wayround.gsasl.gsasl

def client_authenticate(cli):

    buf = ""
    p = ""

    step = 0
    while True:
        print("step {}".format(step))
        rcr = cli.step64(buf)
        if (rcr[0] == org.wayround.gsasl.gsasl.GSASL_NEEDS_MORE
            or rcr[0] == org.wayround.gsasl.gsasl.GSASL_OK):

            print("Output:\n{}".format(rcr[1]))

        if rcr[0] == org.wayround.gsasl.gsasl.GSASL_NEEDS_MORE:
            print("Input base64 encoded data from server:")
            p = input()

            p.strip()

        if rcr[0] != org.wayround.gsasl.gsasl.GSASL_NEEDS_MORE:
            break

        step += 1

def cb(context, session, prop):

    ret = org.wayround.gsasl.gsasl.GSASL_OK

    print(
        "{}: ({}) {} requested".format(
            org.wayround.gsasl.gsasl.strproperty_name(prop),
            prop,
            org.wayround.gsasl.gsasl.strproperty(prop)
            )
        )

    if prop == org.wayround.gsasl.gsasl.GSASL_AUTHID:
        print("Setting GSASL_AUTHID")
        session.property_set(org.wayround.gsasl.gsasl.GSASL_AUTHID, b'jas')

    if prop == org.wayround.gsasl.gsasl.GSASL_PASSWORD:
        print("Setting GSASL_PASSWORD")
        session.property_set(org.wayround.gsasl.gsasl.GSASL_PASSWORD, b'secret')

    return ret

def client(ctx):

    ctx.set_callback(cb)

    clir = None
    try:
        clir = ctx.client_start('PLAIN')
    except:
        logging.exception("Error while starting client")
    else:
        if clir[0] != org.wayround.gsasl.gsasl.GSASL_OK:
            print("Can't start client session")
        else:

            cli = clir[1]

#
#            cli.property_set(org.wayround.gsasl.gsasl.GSASL_PASSWORD, b'secret')

            client_authenticate(cli)

            cli.close()


def main():

    gc.set_debug(gc.DEBUG_LEAK)

    ctx = None
    try:
        ctx = org.wayround.gsasl.gsasl.GSASL()
    except:
        logging.exception("Error while initiating")
    else:

        try:
            client(ctx)
        except:
            print("Some error in client")

        try:
            client(ctx)
        except:
            print("Some error in client")

        try:
            client(ctx)
        except:
            print("Some error in client")

        ctx.close()

    print("cleaning")

    ctx = None
    del ctx

    gc.collect()

    print("dicts cleaning")

#    for i in list(org.wayround.gsasl.gsasl.gsasl_session_registry.keys()):
#        del org.wayround.gsasl.gsasl.gsasl_session_registry[i]

    print("gsasl_session_registry == {}".format(org.wayround.gsasl.gsasl.gsasl_session_registry))


#    for i in list(org.wayround.gsasl.gsasl.gsasl_registry.keys()):
#        del org.wayround.gsasl.gsasl.gsasl_registry[i]

    print("gsasl_registry == {}".format(org.wayround.gsasl.gsasl.gsasl_registry))

    gc.collect()

    print("garbage {}".format(gc.garbage))

    print("exit")

    return 0

if __name__ == '__main__':
    exit(main())

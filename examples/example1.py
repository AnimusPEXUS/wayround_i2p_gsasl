
import logging

import wayround_org.gsasl.gsasl

def client_authenticate(cli):

    buf = ""
    p = ""

    step = 0
    while True:
        print("step {}".format(step))
        rcr = cli.step64(buf)
        if (rcr[0] == wayround_org.gsasl.gsasl.GSASL_NEEDS_MORE
            or rcr[0] == wayround_org.gsasl.gsasl.GSASL_OK):

            print("Output:\n{}".format(rcr[1]))

        if rcr[0] == wayround_org.gsasl.gsasl.GSASL_NEEDS_MORE:
            print("Input base64 encoded data from server:")
            p = input()

            p.strip()

        if rcr[0] != wayround_org.gsasl.gsasl.GSASL_NEEDS_MORE:
            break

        step += 1

def cb(context, session, prop):

    ret = wayround_org.gsasl.gsasl.GSASL_OK

    print(
        "{}: ({}) {} requested".format(
            wayround_org.gsasl.gsasl.strproperty_name(prop),
            prop,
            wayround_org.gsasl.gsasl.strproperty(prop)
            )
        )

    if prop == wayround_org.gsasl.gsasl.GSASL_AUTHID:
        print("Setting GSASL_AUTHID")
        session.property_set(wayround_org.gsasl.gsasl.GSASL_AUTHID, b'jas')

    if prop == wayround_org.gsasl.gsasl.GSASL_PASSWORD:
        print("Setting GSASL_PASSWORD")
        session.property_set(wayround_org.gsasl.gsasl.GSASL_PASSWORD, b'secret')

    return ret

def client(ctx):

    ctx.set_callback(cb)

    clir = None
    try:
        clir = ctx.client_start('PLAIN')
    except:
        logging.exception("Error while starting client")
    else:
        if clir[0] != wayround_org.gsasl.gsasl.GSASL_OK:
            print("Can't start client session")
        else:

            cli = clir[1]

            client_authenticate(cli)

            cli.close()


def main():

    ctx = None
    try:
        ctx = wayround_org.gsasl.gsasl.GSASL()
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


    del ctx

    print("exit")

    return 0

if __name__ == '__main__':
    exit(main())

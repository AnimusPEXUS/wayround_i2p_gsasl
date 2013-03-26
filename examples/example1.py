
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


def client(ctx):

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

            cli.property_set(org.wayround.gsasl.gsasl.GSASL_AUTHID, b'jas')
            cli.property_set(org.wayround.gsasl.gsasl.GSASL_PASSWORD, b'secret')

            client_authenticate(cli)

def main():

    ctx = None
    try:
        ctx = org.wayround.gsasl.gsasl.GSASL()
    except:
        logging.exception("Error while initiating")
    else:

        client(ctx)

    print("exit")

    return 0

if __name__ == '__main__':
    exit(main())

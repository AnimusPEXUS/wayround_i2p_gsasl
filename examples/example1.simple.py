
import gc
import logging

import org.wayround.gsasl.gsasl


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

s = org.wayround.gsasl.gsasl.GSASLSimple(
    callback=cb
    )

s.start()

while True:
    r = s.step64('')

    print("result: {}".format(r))

    if r[0] != org.wayround.gsasl.gsasl.GSASL_NEEDS_MORE:
        break


import gc
import logging

import wayround_org.gsasl.gsasl


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

s = wayround_org.gsasl.gsasl.GSASLSimple(
    callback=cb
    )

s.start()

while True:
    r = s.step64('')

    print("result: {}".format(r))

    if r[0] != wayround_org.gsasl.gsasl.GSASL_NEEDS_MORE:
        break

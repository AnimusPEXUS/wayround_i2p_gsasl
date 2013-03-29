

import org.wayround.gsasl.gsasl


def cb(context, session, prop):

    ret = org.wayround.gsasl.gsasl.GSASL_OK

    print(
        "requested: {} ({}) {}".format(
            org.wayround.gsasl.gsasl.strproperty_name(prop),
            prop,
            org.wayround.gsasl.gsasl.strproperty(prop)
            )
        )

    if prop == org.wayround.gsasl.gsasl.GSASL_QOP:

        value = ''
        while not value in [
            'qop-auth', 'qop-int', 'qop-conf'
            ]:
            print("""\
Answer with one of the variants:
qop-auth    : Authentication only.
qop-int     : Authentication and integrity.
qop-conf    : Authentication, integrity and confidentiality.

server proposes:
{}
""".format(str(session.property_get(org.wayround.gsasl.gsasl.GSASL_QOPS, 'utf-8').split(','))))
            value = input('input value->')

        session.property_set(
            prop,
            bytes(value, 'utf-8')
            )
    else:
        value = input('input value->')
        session.property_set(prop, bytes(value, 'utf-8'))

    return ret

s = org.wayround.gsasl.gsasl.GSASLSimple(
    mechanism='DIGEST-MD5',
    callback=cb
    )

s.start()

i = input('server step result->')

while True:
    r = s.step64(i)

    print("result: {}".format(r))
    print(
        "codes: {} ({}) {}".format(
            org.wayround.gsasl.gsasl.strerror_name(r[0]),
            r[0],
            org.wayround.gsasl.gsasl.strerror(r[0])
            )
        )

    if r[0] != org.wayround.gsasl.gsasl.GSASL_NEEDS_MORE:
        break

    i = input('server step result->')

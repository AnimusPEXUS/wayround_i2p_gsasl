

import wayround_org.gsasl.gsasl


def cb(context, session, prop):

    ret = wayround_org.gsasl.gsasl.GSASL_OK

    print(
        "requested: {} ({}) {}".format(
            wayround_org.gsasl.gsasl.strproperty_name(prop),
            prop,
            wayround_org.gsasl.gsasl.strproperty(prop)
            )
        )

    if prop == wayround_org.gsasl.gsasl.GSASL_QOP:

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
""".format(str(session.property_get(wayround_org.gsasl.gsasl.GSASL_QOPS, 'utf-8').split(','))))
            value = input('input value->')

        session.property_set(
            prop,
            bytes(value, 'utf-8')
            )
    else:
        value = input('input value->')
        session.property_set(prop, bytes(value, 'utf-8'))

    return ret

s = wayround_org.gsasl.gsasl.GSASLSimple(
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
            wayround_org.gsasl.gsasl.strerror_name(r[0]),
            r[0],
            wayround_org.gsasl.gsasl.strerror(r[0])
            )
        )

    if r[0] != wayround_org.gsasl.gsasl.GSASL_NEEDS_MORE:
        break

    i = input('server step result->')

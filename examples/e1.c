/* client.c --- Example SASL client.
 * Copyright (C) 2004-2012 Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include <config.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gsasl.h>

static void
client_authenticate(Gsasl_session * session)
{
    char buf[BUFSIZ] = "";
    char *p;
    int rc;
    /* This loop mimics a protocol where the client send data first. */
    do
    {
        /* Generate client output. */
        rc = gsasl_step64(session, buf, &p);
        if (rc == GSASL_NEEDS_MORE || rc == GSASL_OK)
        {
            /* If sucessful, print it. */
            printf("Output:\n%s\n", p);
            gsasl_free(p);
        }
        if (rc == GSASL_NEEDS_MORE)
        {
            /* If the client need more data from server, get it here. */
            printf("Input base64 encoded data from server:\n");
            p = fgets(buf, sizeof(buf) - 1, stdin);
            if (p == NULL)
            {
                perror("fgets");
                return;
            }
            if (buf[strlen(buf) - 1] == ’\n’)
                buf[strlen(buf) - 1] = ’\0’;
        }
    }
    while (rc == GSASL_NEEDS_MORE);
    printf("\n");
    if (rc != GSASL_OK)
    {
        printf("Authentication error (%d): %s\n", rc, gsasl_strerror(rc));
        return;
    }
    /* The client is done. Here you would typically check if the server
     let the client in. If not, you could try again. */
    printf("If server accepted us, we’re done.\n");
}
static void
client(Gsasl * ctx)
{
    Gsasl_session *session;
    const char *mech = "PLAIN";
    int rc;
    /* Create new authentication session. */
    if ((rc = gsasl_client_start(ctx, mech, &session)) != GSASL_OK)
    {
        printf("Cannot initialize client (%d): %s\n", rc, gsasl_strerror(rc));
        return;
    }
    /* Set username and password
     lost when this session is
     gsasl_property_set (session,
     gsasl_property_set (session,
     in session handle. This info will be
     deallocated below. */
    GSASL_AUTHID, "jas"
    );
    GSASL_PASSWORD, "secret"
    );
    /* Do it. */
    client_authenticate(session);
    /* Cleanup. */
    gsasl_finish(session);
}
int
main(int argc, char *argv[])
{
    Gsasl *ctx = NULL;
    int rc;
    /* Initialize library. */
    if ((rc = gsasl_init(&ctx)) != GSASL_OK)
    {
        printf("Cannot initialize libgsasl (%d): %s", rc, gsasl_strerror(rc));
        return 1;
    }
    /* Do it. */
    client(ctx);
    /* Cleanup. */
    gsasl_done(ctx);
    return 0;
}

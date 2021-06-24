/*
Child, Internet Relay Chat Services
Copyright (C) 2005-2020  David Lebrun (target0@geeknode.org)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/


#include "channel.h"
#include "child.h"
#include "commands.h"
#include "core.h"
#include "hashmap.h"
#include "mem.h"
#include "net.h"
#include "modules.h"
#include "string_utils.h"
#include "user.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

extern commandlist command_list;

int do_sasl (Nick *, User *, Chan *, char **);

void child_init()
{
    AddHook(HOOK_SASL,&do_sasl,"do_sasl","sasl");
}

void child_cleanup()
{}

int do_sasl (Nick *nptr, User *uptr, Chan *cptr, char *parv[])
{
    /*
    unrealircd:
        sendto_server(NULL, 0, 0, NULL, ":%s SASL %s %s H %s %s",
                me.name, SASL_SERVER, client->id, addr, addr);
        sendto_server(NULL, 0, 0, NULL, ":%s SASL %s %s S %s",
            me.name, SASL_SERVER, client->id, parv[1]);

    from atheme:
    https://github.com/atheme/atheme/blob/4fa0e03bd3ce2cb6041a339f308616580c5aac29/modules/saslserv/main.c#L852
    {
		case 'H':
			// (H)ost information
			(void) sasl_input_hostinfo(smsg, p);
			break;

		case 'S':
			// (S)tart authentication
			ret = sasl_input_startauth(smsg, p);
			break;

		case 'C':
			// (C)lient data
			ret = sasl_input_clientdata(smsg, p);
			break;

		case 'D':
			// (D)one -- when we receive it, means client abort
			(void) sasl_session_destroy(p);
			break;
	}

    from child to unrealircd:
    	sts(":%s SVSLOGIN %s %s %s", saslserv->me->nick, servermask, target, entity(account)->name);

    */
    fprintf(stderr, "do_sasl: %s SASL %s\n", parv[0], parv[1]);

    char *sender = parv[0] + 1; // remove leading :
    char *split[10];
    int i = 0;
    User *user;

    char *pch = strtok(parv[1], " ");

    while (pch != NULL)
    {
        split[i] = pch;
        pch = strtok(NULL, " ");
        i++;
    }

    char *target = split[0];
    char *uid = split[1];
    char *command = split[2]; // H/S/C/D
    int ret;
    char *authzid, *authcid, *password, *pos;

    char *decoded[40];

    // parse
    if (strcmp(command, "S") == 0) {
        SendRaw(":%s SASL %s %s C +", target, sender, uid);
    } else if (strcmp(command, "C") == 0) {
        fprintf(stderr, "%s\n", split[3]);
        ret = b64_decode(split[3], decoded, 400);
        fprintf(stderr, "%s %d %d %d \n", decoded, sizeof(decoded), ret, strlen(split[3]));
        authzid = decoded;
        authcid = memchr(decoded, '\0', ret);
        authcid++;
        password = memchr(authcid, '\0', ret);
        password++;
        fprintf(stderr, "%s (%d) %s (%d) %s (%d)\n", authzid, strlen(authzid), authcid, strlen(authcid), password, strlen(password));

        // check user exists and password matches
        user = find_user(authcid);
        if (!user) {
            fprintf(stderr, "Can't find %s\n", authcid);
            SendRaw(":%s SASL %s %s D F", target, sender, uid);
            return;
        } 

        char *md5pass = md5_hash(password);
        if (Strcmp(md5pass,user->md5_pass)) {
            // wrong password
            fprintf(stderr, "Wrong password for %s\n", user->nick);
            SendRaw(":%s SASL %s %s D F", target, sender, uid);
            return;
        }

        user->authed = 1;
        user->lastseen = time(NULL);
        sync_user(user);

        Nick *nick = find_nick(authcid);
        if (!nick) {
            fprintf(stderr, "Can't find nick %s\n", authcid);
            return;
        }
        fprintf(stderr, "%s", nick);

        SendRaw(":%s SVSLOGIN %s %s %s", target, sender, uid, decoded);
        SendRaw(":%s SASL %s %s D S", target, sender, uid);
    }

    return MOD_CONTINUE;
}

// void sasl_start_session(char *uid) {

// }
/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "agentd.h"
#include "os_net/os_net.h"

#if defined(__FreeBSD__) || defined(__OpenBSD__)
#include <sys/endian.h>
#elif defined(__MACH__)
#include <machine/endian.h>
#endif

/* Attempt to connect to all configured servers */
int connect_server(int initial_id)
{
    int attempts = 2;
    int rc = initial_id;

    /* Checking if the initial is zero, meaning we have to
     * rotate to the beginning
     */
    if (agt->rip[initial_id] == NULL) {
        rc = 0;
    }

    /* Close socket if available */
    if (agt->sock >= 0) {
        sleep(1);
        CloseSocket(agt->sock);
        agt->sock = -1;

        if (agt->rip[1]) {
            minfo("Closing connection to server (%s:%d).",
                    agt->rip[rc],
                    agt->port[rc]);
        }
    }

    while (agt->rip[rc]) {
        char *tmp_str;

        /* Check if we have a hostname */
        tmp_str = strchr(agt->rip[rc], '/');
        if (tmp_str) {
            char *f_ip;
            *tmp_str = '\0';

            f_ip = OS_GetHost(agt->rip[rc], 5);
            if (f_ip) {
                char ip_str[128];
                ip_str[127] = '\0';

                snprintf(ip_str, 127, "%s/%s", agt->rip[rc], f_ip);

                free(f_ip);
                free(agt->rip[rc]);

                os_strdup(ip_str, agt->rip[rc]);
                tmp_str = strchr(agt->rip[rc], '/');
                if (!tmp_str) {
                    mwarn("Invalid hostname format: '%s'.", agt->rip[rc]);
                    return 0;
                }

                tmp_str++;
            } else {
                mwarn("Unable to get hostname for '%s'.",
                       agt->rip[rc]);
                *tmp_str = '/';
                tmp_str++;
            }
        } else {
            tmp_str = agt->rip[rc];
        }

        minfo("Trying to connect to server (%s:%d).",
                agt->rip[rc],
                agt->port[rc]);

        if (agt->protocol[rc] == UDP_PROTO) {
            agt->sock = OS_ConnectUDP(agt->port[rc], tmp_str, strchr(tmp_str, ':') != NULL);
        } else {
            if (agt->sock >= 0) {
                close(agt->sock);
            }

            agt->sock = OS_ConnectTCP(agt->port[rc], tmp_str, strchr(tmp_str, ':') != NULL);
        }

        if (agt->sock < 0) {
            agt->sock = -1;
            merror(CONNS_ERROR, tmp_str);
            rc++;

            if (agt->rip[rc] == NULL) {
                attempts += 10;

                /* Only log that if we have more than 1 server configured */
                if (agt->rip[1]) {
                    merror("Unable to connect to any server.");
                }

                sleep(attempts < agt->notify_time ? attempts : agt->notify_time);
                rc = 0;
            }
        } else {
#ifdef HPUX
            /* Set socket non-blocking on HPUX */
            // fcntl(agt->sock, O_NONBLOCK);
#endif

#ifdef WIN32
            if (agt->protocol[rc] == UDP_PROTO) {
                int bmode = 1;

                /* Set socket to non-blocking */
                ioctlsocket(agt->sock, FIONBIO, (u_long FAR *) &bmode);
            }
#endif

            agt->rip_id = rc;
            return (1);
        }
    }

    return (0);
}

/* Send synchronization message to the server and wait for the ack */
void start_agent(int is_startup)
{
    ssize_t recv_b = 0;
    uint32_t length;
    size_t msg_length;
    int attempts = 0, g_attempts = 1;

    char *tmp_msg;
    char msg[OS_MAXSTR + 2];
    char buffer[OS_MAXSTR + 1];
    char cleartext[OS_MAXSTR + 1];
    char fmsg[OS_MAXSTR + 1];

    memset(msg, '\0', OS_MAXSTR + 2);
    memset(buffer, '\0', OS_MAXSTR + 1);
    memset(cleartext, '\0', OS_MAXSTR + 1);
    memset(fmsg, '\0', OS_MAXSTR + 1);
    snprintf(msg, OS_MAXSTR, "%s%s", CONTROL_HEADER, HC_STARTUP);

#ifdef ONEWAY_ENABLED
    return;
#endif

    while (1) {
        /* Send start up message */
        send_msg(msg, -1);
        attempts = 0;

        /* Read until our reply comes back */
        while (attempts <= 5) {
            if (agt->protocol[agt->rip_id] == TCP_PROTO) {
                recv_b = recv(agt->sock, (char*)&length, sizeof(length), MSG_WAITALL);
                length = wnet_order(length);

                if (recv_b > 0) {
                    recv_b = recv(agt->sock, buffer, length, MSG_WAITALL);

                    if (recv_b != (ssize_t)length) {
                        merror(RECV_ERROR);
                        recv_b = 0;
                    }
                }
            } else {
                recv_b = recv(agt->sock, buffer, OS_MAXSTR, MSG_DONTWAIT);
            }

            if (recv_b <= 0) {
                /* Sleep five seconds before trying to get the reply from
                 * the server again
                 */
                attempts++;
                sleep(attempts);

                /* Send message again (after three attempts) */
                if (attempts >= 3) {
                    if (agt->protocol[agt->rip_id] == TCP_PROTO) {
                        if (!connect_server(agt->rip_id)) {
                            continue;
                        }
                    }

                    send_msg(msg, -1);
                }

                continue;
            }

            /* Id of zero -- only one key allowed */
            tmp_msg = ReadSecMSG(&keys, buffer, cleartext, 0, recv_b - 1, &msg_length, agt->rip[agt->rip_id]);
            if (tmp_msg == NULL) {
                mwarn(MSG_ERROR, agt->rip[agt->rip_id]);
                continue;
            }

            /* Check for commands */
            if (IsValidHeader(tmp_msg)) {
                /* If it is an ack reply */
                if (strcmp(tmp_msg, HC_ACK) == 0) {
                    available_server = time(0);

                    minfo(AG_CONNECTED, agt->rip[agt->rip_id],
                            agt->port[agt->rip_id]);

                    if (is_startup) {
                        /* Send log message about start up */
                        snprintf(msg, OS_MAXSTR, OS_AG_STARTED,
                                 keys.keyentries[0]->name,
                                 keys.keyentries[0]->ip->ip);
                        snprintf(fmsg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ,
                                 "ossec", msg);
                        send_msg(fmsg, -1);
                    }
                    return;
                }
            }
        }

        /* Wait for server reply */
        mwarn(AG_WAIT_SERVER, agt->rip[agt->rip_id]);

        /* If we have more than one server, try all */
        if (agt->rip[1]) {
            int curr_rip = agt->rip_id;
            minfo("Trying next server ip in the line: '%s'.",
                   agt->rip[agt->rip_id + 1] != NULL ? agt->rip[agt->rip_id + 1] : agt->rip[0]);
            connect_server(agt->rip_id + 1);

            if (agt->rip_id == curr_rip) {
                sleep(g_attempts < agt->notify_time ? g_attempts : agt->notify_time);
                g_attempts += (attempts * 3);
            } else {
                g_attempts += 5;
                sleep(g_attempts < agt->notify_time ? g_attempts : agt->notify_time);
            }
        } else {
            sleep(g_attempts < agt->notify_time ? g_attempts : agt->notify_time);
            g_attempts += (attempts * 3);

            connect_server(0);
        }
    }

    return;
}

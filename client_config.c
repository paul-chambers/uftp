/*
 *  UFTP - UDP based FTP with multicast
 *
 *  Copyright (C) 2001-2020   Dennis A. Bush, Jr.   bush@tcnj.edu
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  Additional permission under GNU GPL version 3 section 7
 *
 *  If you modify this program, or any covered work, by linking or
 *  combining it with the OpenSSL project's OpenSSL library (or a
 *  modified version of that library), containing parts covered by the
 *  terms of the OpenSSL or SSLeay licenses, the copyright holder
 *  grants you additional permission to convey the resulting work.
 *  Corresponding Source for a non-source form of such a combination
 *  shall include the source code for the parts of OpenSSL used as well
 *  as that of the covered work.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef WINDOWS

#include "win_func.h"

#else  // if WINDOWS

#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#endif

#include "client.h"
#include "client_config.h"

/**
 * Global command line values and sockets
 */
SOCKET listener;
char tempdir[MAXDIRNAME], destdir[MAXDIR][MAXDIRNAME];
char pidfile[MAXPATHNAME];
char keyfile[MAXPATHNAME], keyinfo[MAXPATHNAME];
char backupdir[MAXDIR][MAXDIRNAME];
char statusfilename[MAXPATHNAME];
FILE *status_file;
int debug, encrypted_only, dscp, destdircnt, tempfile;
int interface_count, pub_multi_count, rcvbuf, backupcnt;
char postreceive[MAXPATHNAME], portname[PORTNAME_LEN];
int port, move_individual, cache_len, noname, user_abort, use_ssm;
uint32_t uid;
union sockaddr_u hb_hosts[MAXLIST];
struct iflist m_interface[MAX_INTERFACES];
union sockaddr_u pub_multi[MAX_INTERFACES];
struct group_list_t group_list[MAXLIST];
struct fp_list_t server_list[MAXLIST], proxy_list[MAXLIST];
struct iflist ifl[MAX_INTERFACES];
struct timeval next_keyreq_time, next_hb_time;
int ifl_len, server_count, proxy_count, has_v4_proxy, sys_keys, priority;
int hbhost_count, hb_interval;
union key_t privkey;
int privkey_type;
struct fp_list_t proxy4_info;
union key_t proxy4_pubkey, proxy4_dhkey;
int proxy4_pubkeytype;

extern char *optarg;
extern int optind;

/**
 * Adds a server/proxy and its fingerprint to the appropriate list
 */
void add_host_to_list(struct fp_list_t *list, int *list_count,
                      const char *uid_str, const char *ip,
                      const char *proxyid_str, const char *fingerprint)
{
    struct addrinfo ai_hints, *ai_rval;
    uint32_t host_uid, proxy_uid;
    int rval;

    host_uid = strtoul(uid_str, NULL, 16);
    if ((host_uid == 0xffffffff) || (host_uid == 0)) {
        fprintf(stderr, "Invalid host UID %s\n", uid_str);
        exit(ERR_PARAM);
    }
    proxy_uid = strtoul(proxyid_str, NULL, 16);
    if (proxy_uid == 0xffffffff) {
        fprintf(stderr, "Invalid proxy UID %s\n", proxyid_str);
        exit(ERR_PARAM);
    }

    memset(&ai_hints, 0, sizeof(ai_hints));
    ai_hints.ai_family = AF_UNSPEC;
    ai_hints.ai_socktype = SOCK_DGRAM;
    ai_hints.ai_protocol = 0;
    ai_hints.ai_flags = 0;
    if ((rval = getaddrinfo(ip, NULL, &ai_hints, &ai_rval)) != 0) {
        fprintf(stderr, "Invalid host name/address %s: %s\n",
                ip, gai_strerror(rval));
        exit(ERR_PARAM);
    }

    list[*list_count].uid = htonl(host_uid);
    list[*list_count].proxy_uid = htonl(proxy_uid);
    memcpy(&list[*list_count].addr, ai_rval->ai_addr,
            ai_rval->ai_addrlen);
    list[*list_count].has_fingerprint =
            parse_fingerprint(list[*list_count].fingerprint,
                              fingerprint);
    (*list_count)++;
    freeaddrinfo(ai_rval);
}

/**
 * Set defaults for all command line arguments
 */
void set_defaults(void)
{
    debug = 0;
    log_level = DEF_LOG_LEVEL;
    encrypted_only = 0;
    uid = 0;
    dscp = DEF_DSCP;
    strncpy(logfile, DEF_LOGFILE, sizeof(logfile)-1);
    logfile[sizeof(logfile)-1] = '\x0';
    strncpy(statusfilename, "", sizeof(statusfilename)-1);
    statusfilename[sizeof(statusfilename)-1] = '\x0';
    status_file = NULL;
    noname = 0;
    memset(pidfile, 0, sizeof(pidfile));
    interface_count = 0;
    strncpy(portname, DEF_PORT, sizeof(portname)-1);
    portname[sizeof(portname)-1] = '\x0';
    port = atoi(portname);
    tempfile = 0;
    strncpy(tempdir, DEF_TEMPDIR, sizeof(tempdir)-1);
    tempdir[sizeof(tempdir)-1] = '\x0';
    destdircnt = 0;
    backupcnt = 0;
    pub_multi_count = 0;
    memset(keyfile, 0, sizeof(keyfile));
    memset(keyinfo, 0, sizeof(keyinfo));
    rcvbuf = 0;
    server_count = 0;
    has_v4_proxy = 0;
    sys_keys = 0;
    memset(hb_hosts, 0, sizeof(hb_hosts));
    hbhost_count = 0;
    hb_interval = DEF_HB_INT;
    priority = 0;
    memset(postreceive, 0, sizeof(postreceive));
    move_individual = 0;
    max_log_size = 0;
    max_log_count = DEF_MAX_LOG_COUNT;
    cache_len = DEF_CACHE;
    proxy4_pubkeytype = 0;
    user_abort = 0;
    use_ssm = 0;
}

/**
 * Set argument defaults, read and validate command line options
 */
void process_args(int argc, char *argv[])
{
    int c, i, listidx, rval;
    long tmpval;
    struct addrinfo ai_hints, *ai_rval;
    char line[1000], *serverid, *proxyid, *ipstr, *fingerprint;
    char *p, *p2, *saveptr, *hoststr, *portstr, pubname[INET6_ADDRSTRLEN];
    FILE *serverfile, *proxyfile;
    const char opts[] =
            "dx:qF:L:P:s:c:I:p:tT:D:A:M:B:Q:EU:oS:R:r:k:K:mN:ig:n:h:H:";

    set_defaults();

    // read lettered arguments
    while ((c = getopt(argc, argv, opts)) != EOF) {
        switch (c) {
        case 'd':
            debug = 1;
            break;
        case 'x':
            log_level = atoi(optarg);
            if (log_level < 0) {
                fprintf(stderr, "Invalid log level\n");
                exit(ERR_PARAM);
            }
            break;
        case 'q':
            noname = 1;
            break;
        case 'F':
            strncpy(statusfilename, optarg, sizeof(statusfilename)-1);
            statusfilename[sizeof(statusfilename)-1] = '\x0';
            break;
        case 'L':
            strncpy(logfile, optarg, sizeof(logfile)-1);
            logfile[sizeof(logfile)-1] = '\x0';
            break;
        case 'P':
            strncpy(pidfile, optarg, sizeof(pidfile)-1);
            pidfile[sizeof(pidfile)-1] = '\x0';
            break;
        case 's':
            strncpy(postreceive, optarg, sizeof(postreceive)-1);
            postreceive[sizeof(postreceive)-1] = '\x0';
            break;
        case 'c':
            cache_len = atoi(optarg);
            if ((cache_len < 10240) || (cache_len > 20971520)) {
                fprintf(stderr, "Invalid cache size\n");
                exit(ERR_PARAM);
            }
            break;
        case 'I':
            p = strtok(optarg, ",");
            while (p != NULL) {
                if ((listidx = getifbyname(p, ifl, ifl_len)) != -1) {
                    m_interface[interface_count++] = ifl[listidx];
                    p = strtok(NULL, ",");
                    continue;
                }
                memset(&ai_hints, 0, sizeof(ai_hints));
                ai_hints.ai_family = AF_UNSPEC;
                ai_hints.ai_socktype = SOCK_DGRAM;
                ai_hints.ai_protocol = 0;
                ai_hints.ai_flags = 0;
                if ((rval = getaddrinfo(p, NULL,
                        &ai_hints, &ai_rval)) != 0) {
                    fprintf(stderr, "Invalid name/address %s: %s\n",
                            p, gai_strerror(rval));
                    exit(ERR_PARAM);
                }
                if ((listidx = getifbyaddr((union sockaddr_u *)ai_rval->ai_addr,
                        ifl, ifl_len)) == -1) {
                    fprintf(stderr, "Interface %s not found\n", p);
                    exit(ERR_PARAM);
                }
                m_interface[interface_count++] = ifl[listidx];
                freeaddrinfo(ai_rval);
                p = strtok(NULL, ",");
            }
            break;
        case 'p':
            strncpy(portname, optarg, sizeof(portname)-1);
            portname[sizeof(portname)-1] = '\x0';
            port = atoi(portname);
            if (port == 0) {
                fprintf(stderr, "Invalid port\n");
                exit(ERR_PARAM);
            }
            break;
        case 't':
            tempfile = 1;
            break;
        case 'T':
            strncpy(tempdir, optarg, sizeof(tempdir)-1);
            tempdir[sizeof(tempdir)-1] = '\x0';
            break;
        case 'D':
            p = strtok(optarg, ",");
            while (p != NULL) {
                strncpy(destdir[destdircnt], p, sizeof(destdir[destdircnt])-1);
                destdir[destdircnt][sizeof(destdir[destdircnt])-1] = '\x0';
                destdircnt++;
                p = strtok(NULL, ",");
            }
            break;
        case 'A':
            p = strtok(optarg, ",");
            while (p != NULL) {
                strncpy(backupdir[backupcnt],p,sizeof(backupdir[backupcnt])-1);
                backupdir[backupcnt][sizeof(backupdir[backupcnt])-1] = '\x0';
                backupcnt++;
                p = strtok(NULL, ",");
            }
            break;
        case 'M':
            p = strtok(optarg, ",");
            while (p != NULL) {
                memset(&ai_hints, 0, sizeof(ai_hints));
                ai_hints.ai_family = AF_UNSPEC;
                ai_hints.ai_socktype = SOCK_DGRAM;
                ai_hints.ai_protocol = 0;
                ai_hints.ai_flags = 0;
                if ((rval = getaddrinfo(p, NULL,
                        &ai_hints, &ai_rval)) != 0) {
                    fprintf(stderr, "Invalid multicast address %s: %s\n",
                            p, gai_strerror(rval));
                    exit(ERR_PARAM);
                }
                memcpy(&pub_multi[pub_multi_count], ai_rval->ai_addr,
                        ai_rval->ai_addrlen);
                pub_multi_count++;
                freeaddrinfo(ai_rval);
                p = strtok(NULL, ",");
            }
            break;
        case 'B':
            rcvbuf = atoi(optarg);
            if ((rcvbuf < 65536) || (rcvbuf > 104857600)) {
                fprintf(stderr, "Invalid buffer size\n");
                exit(ERR_PARAM);
            }
            break;
        case 'Q':
            tmpval = strtol(optarg, NULL, 0);
            if ((tmpval < 0) || (tmpval > 63)) {
                fprintf(stderr, "Invalid dscp\n");
                exit(ERR_PARAM);
            }
            dscp = (tmpval & 0xFF) << 2;
            break;
        case 'E':
            encrypted_only = 1;
            break;
        case 'U':
            errno = 0;
            uid = strtoul(optarg, NULL, 16);
            if (errno) {
                perror("Invalid UID");
                exit(ERR_PARAM);
            }
            uid = htonl(uid);
            break;
        case 'o':
            use_ssm = 1;
            break;
        case 'S':
            if ((serverfile = fopen(optarg, "r")) == NULL) {
                fprintf(stderr, "Couldn't open server list %s: %s\n",
                        optarg, strerror(errno));
                exit(ERR_PARAM);
            }
            while (fgets(line, sizeof(line), serverfile)) {
                if ((line[0] == '#') || (line[0] == '\x0')) {
                    continue;
                }
                saveptr = NULL;
                serverid = strtok_r(line, "|", &saveptr);
                ipstr = strtok_r(NULL, "|", &saveptr);
                if (!ipstr) {
                    fprintf(stderr, "Missing IP in server config");
                    exit(ERR_PARAM);
                }
                proxyid = strtok_r(NULL, "|\r\n", &saveptr);
                if (!proxyid) {
                    fprintf(stderr, "Missing proxy ID in server config");
                    exit(ERR_PARAM);
                }
                fingerprint = strtok_r(NULL, "|\r\n", &saveptr);
                add_host_to_list(server_list, &server_count, serverid, ipstr,
                                 proxyid, fingerprint);
            }
            if (!feof(serverfile) && ferror(serverfile)) {
                perror("Failed to read from server list file");
                exit(ERR_PARAM);
            }
            fclose(serverfile);
            break;
        case 'R':
            if ((proxyfile = fopen(optarg, "r")) == NULL) {
                fprintf(stderr, "Couldn't open proxy list %s: %s\n",
                        optarg, strerror(errno));
                exit(ERR_PARAM);
            }
            while (fgets(line, sizeof(line), proxyfile)) {
                if ((line[0] == '#') || (line[0] == '\x0')) {
                    continue;
                }
                saveptr = NULL;
                proxyid = strtok_r(line, "|", &saveptr);
                ipstr = strtok_r(NULL, "|\r\n", &saveptr);
                if (!ipstr) {
                    fprintf(stderr, "Missing IP in proxy config");
                    exit(ERR_PARAM);
                }
                fingerprint = strtok_r(NULL, "|\r\n", &saveptr);
                add_host_to_list(proxy_list, &proxy_count, proxyid, ipstr,
                                 "0", fingerprint);
            }
            if (!feof(proxyfile) && ferror(proxyfile)) {
                perror("Failed to read from proxy list file");
                exit(ERR_PARAM);
            }
            fclose(proxyfile);
            break;
        case 'r':
            strncpy(line, optarg, sizeof(line));
            line[sizeof(line)-1] = '\x0';
            ipstr = strtok(line, "/");
            if (!ipstr) {
                fprintf(stderr, "Invalid host name\n");
                exit(ERR_PARAM);
            }
            fingerprint = strtok(NULL, "/");
            memset(&ai_hints, 0, sizeof(ai_hints));
            ai_hints.ai_family = AF_UNSPEC;
            ai_hints.ai_socktype = SOCK_DGRAM;
            ai_hints.ai_protocol = 0;
            ai_hints.ai_flags = 0;
            if ((rval = getaddrinfo(ipstr, NULL,
                    &ai_hints, &ai_rval)) != 0) {
                fprintf(stderr, "Invalid proxy address %s: %s\n",
                        ipstr, gai_strerror(rval));
                exit(ERR_PARAM);
            }
            memcpy(&proxy4_info.addr, ai_rval->ai_addr, ai_rval->ai_addrlen);
            proxy4_info.has_fingerprint =
                    parse_fingerprint(proxy4_info.fingerprint, fingerprint);
            has_v4_proxy = 1;
            freeaddrinfo(ai_rval);
            break;
        case 'k':
            strncpy(keyfile, optarg, sizeof(keyfile)-1);
            keyfile[sizeof(keyfile)-1] = '\x0';
            break;
        case 'K':
            strncpy(keyinfo, optarg, sizeof(keyinfo)-1);
            keyinfo[sizeof(keyinfo)-1] = '\x0';
            break;
        case 'm':
            sys_keys = 1;
            break;
        case 'N':
            priority = atoi(optarg);
            if (!valid_priority(priority)) {
                fprintf(stderr, "Invalid priority value\n");
                exit(ERR_PARAM);
            }
            break;
        case 'i':
            move_individual = 1;
            break;
        case 'g':
            max_log_size = atoi(optarg);
            if ((max_log_size < 1) || (max_log_size > 1024)) {
                fprintf(stderr, "Invalid max log size\n");
                exit(ERR_PARAM);
            }
            max_log_size *= 1000000;
            break;
        case 'n':
            max_log_count = atoi(optarg);
            if ((max_log_count < 1) || (max_log_count > 1000)) {
                fprintf(stderr, "Invalid max log count\n");
                exit(ERR_PARAM);
            }
            break;
        case 'H':
            p = strtok(optarg, ",");
            while (p != NULL) {
                p2 = strchr(p, ':');
                if (p2) {
                    hoststr = strdup(p);
                    hoststr[p2 - p] = '\x0';
                    portstr = p2 + 1;
                } else {
                    hoststr = p;
                    portstr = NULL;
                }
                memset(&ai_hints, 0, sizeof(ai_hints));
                ai_hints.ai_family = AF_UNSPEC;
                ai_hints.ai_socktype = SOCK_DGRAM;
                ai_hints.ai_protocol = 0;
                ai_hints.ai_flags = 0;
                if ((rval = getaddrinfo(hoststr, portstr,
                        &ai_hints, &ai_rval)) != 0) {
                    fprintf(stderr, "Invalid heartbeat address %s: %s\n",
                            p, gai_strerror(rval));
                    exit(ERR_PARAM);
                }
                memcpy(&hb_hosts[hbhost_count], ai_rval->ai_addr,
                        ai_rval->ai_addrlen);
                freeaddrinfo(ai_rval);
                if (portstr) {
                    free(hoststr);
                } else {
                    if (hb_hosts[hbhost_count].ss.ss_family == AF_INET6) {
                        hb_hosts[hbhost_count].sin6.sin6_port =
                                htons(atoi(DEF_PORT));
                    } else {
                        hb_hosts[hbhost_count].sin.sin_port =
                                htons(atoi(DEF_PORT));
                    }
                }
                hbhost_count++;
                p = strtok(NULL, ",");
            }
            break;
        case 'h':
            hb_interval = atoi(optarg);
            if ((hb_interval <= 0) || (hb_interval > 3600)) {
                fprintf(stderr, "Invalid heartbeat interval\n");
                exit(ERR_PARAM);
            }
            break;
        case '?':
            fprintf(stderr, USAGE);
            exit(ERR_PARAM);
        }
    }
    if (use_ssm) {
        if (!server_count) {
            fprintf(stderr, "SSM mode enabled but no server list specified\n");
            exit(ERR_PARAM);
        }
        for (i = 0; i < pub_multi_count; i++) {
            if (!is_multicast(&pub_multi[i], 1)) {
                if ((rval = getnameinfo((struct sockaddr *)&pub_multi[i],
                        family_len(pub_multi[i]), pubname, sizeof(pubname),
                        NULL, 0, NI_NUMERICHOST)) != 0) {
                    fprintf(stderr,"getnameinfo failed: %s",gai_strerror(rval));
                }
                fprintf(stderr, "Invalid source specific "
                        "multicast address: %s\n", pubname);
                exit(ERR_PARAM);
            }
        }
        if (pub_multi_count == 0) {
            fprintf(stderr, "Default multicast address %s invalid "
                    "for source specific multicast\n", DEF_PUB_MULTI);
            exit(ERR_PARAM);
        }
        // for SSM, make sure server entry with a proxy has a proxy entry
        for (i = 0; i < server_count; i++) {
            if (server_list[i].proxy_uid) {
                if (!fp_lookup(server_list[i].proxy_uid, proxy_list,
                               proxy_count)) {
                    fprintf(stderr, "Proxy %08x for server %08x"
                            " not in proxy list\n",
                            ntohl(server_list[i].proxy_uid),
                            ntohl(server_list[i].uid));
                    exit(ERR_PARAM);
                }
            }
        }
    }
    if (has_v4_proxy) {
        if (proxy4_info.addr.ss.ss_family == AF_INET6) {
            proxy4_info.addr.sin6.sin6_port = htons(port);
        } else {
            proxy4_info.addr.sin.sin_port = htons(port);
        }
    }
    if (destdircnt == 0) {
        strncpy(destdir[0], DEF_DESTDIR, sizeof(destdir[0])-1);
        destdir[0][sizeof(destdir[0])-1] = '\x0';
        destdircnt++;
    }
    if ((backupcnt > 0) && (backupcnt != destdircnt)) {
        fprintf(stderr, "Must specify same number of backup directories "
                        "as destination directories\n");
        exit(ERR_PARAM);
    }
    if (tempfile && (strcmp(tempdir, ""))) {
        fprintf(stderr, "Cannot specify both -t and -T\n");
        exit(ERR_PARAM);
    }
}


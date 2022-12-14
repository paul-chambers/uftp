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

#ifndef _PROXY_UPSTREAM_H
#define _PROXY_UPSTREAM_H

void handle_announce(struct pr_group_list_t *group,
                     const union sockaddr_u *src, unsigned char *packet,
                     unsigned packetlen);
void handle_regconf(struct pr_group_list_t *group, const unsigned char *message,
                    unsigned meslen);
void handle_v4_keyinfo(struct pr_group_list_t *group, unsigned char *message,
                       unsigned meslen, uint32_t src_id);
void handle_keyinfo(struct pr_group_list_t *group, unsigned char *packet,
                    unsigned packetlen);
void send_register(struct pr_group_list_t *group, int pendidx);
void send_clientkey(struct pr_group_list_t *group);
void send_keyinfo_ack(struct pr_group_list_t *group);
void send_fileinfo_ack(struct pr_group_list_t *group, int pendidx);

void send_status(struct pr_group_list_t *group, int pendidx);
void send_complete(struct pr_group_list_t *group, int pendidx);

#endif  // _PROXY_UPSTREAM_H

/*
 *  UFTP - UDP based FTP with multicast
 *
 *  Copyright (C) 2001-2022   Dennis A. Bush, Jr.   bush@tcnj.edu
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

#ifndef _SERVER_COMMON_H
#define _SERVER_COMMON_H

#include "server.h"

void set_uftp_header(struct uftp_h *header, int func, uint32_t group_id,
                     uint8_t group_inst, double l_grtt, int l_gsize);

void send_abort(const struct finfo_t *finfo, const char *message,
                const union sockaddr_u *destaddr,
                uint32_t dest, int encrypt, int current);

int send_multiple(const struct finfo_t *finfo, unsigned char *packet,
                  int message, int attempt, uint32_t *idlist, int state,
                  int encrypt, const union sockaddr_u *destaddr, int regconf);

int validate_packet(const unsigned char *packet, int len,
                    const struct finfo_t *finfo);

int sign_announce(const struct finfo_t *finfo, unsigned char *packet, int len);

int find_client(uint32_t addr);

int client_error(int listidx);

void handle_abort(const unsigned char *message, int meslen, int idx,
                  struct finfo_t *finfo, uint32_t src);

int recalculate_grtt(const struct finfo_t *finfo, int grtt_set,
                     int clear_measured);

double get_adv_grtt(double l_grtt);

#endif  // _SERVER_COMMON_H


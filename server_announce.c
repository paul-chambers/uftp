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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>

#ifdef WINDOWS

#include "win_func.h"

#else  // if WINDOWS

#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>

#endif

#include "server.h"
#include "server_common.h"
#include "server_announce.h"

/**
 * Sets the fields in a EXT_ENC_INFO extension for transmission.
 * Returns the number of bytes set, or 0 on error.
 */
int set_enc_info(const struct finfo_t *finfo, struct enc_info_he *encinfo)
{
    uint8_t *keyblob, *dhblob;
    uint16_t bloblen, dhlen;
    int extlen;

    keyblob = ((uint8_t *)encinfo + sizeof(struct enc_info_he));

    encinfo->exttype = EXT_ENC_INFO;
    encinfo->keyextype_sigtype = 0;
    encinfo->keytype = keytype;
    encinfo->hashtype = hashtype;
    if (client_auth) {
        encinfo->flags |= FLAG_CLIENT_AUTH;
    }
    memcpy(encinfo->rand1, rand1, sizeof(rand1));
    if (privkeytype == KEYBLOB_RSA) {
        if (!export_RSA_key(privkey.rsa, keyblob, &bloblen)) {
            glog0(finfo, "Error exporting server public key");
            return 0;
        }
    } else {
        if (!export_EC_key(privkey.ec, keyblob, &bloblen)) {
            glog0(finfo, "Error exporting server public key");
            return 0;
        }
    }
    encinfo->keylen = htons(bloblen);
    dhblob = ((uint8_t *)encinfo + sizeof(struct enc_info_he) +
                                   ntohs(encinfo->keylen));

    if (!export_EC_key(dhkey.ec, dhblob, &dhlen)) {
        glog0(finfo, "Error exporting server ECDH public key");
        return 0;
    }
    encinfo->dhlen = htons(dhlen);
    if (privkeytype == KEYBLOB_RSA) {
        encinfo->siglen = htons(RSA_keylen(privkey.rsa)); 
    } else {
        encinfo->siglen = htons(ECDSA_siglen(privkey.ec)); 
    }
    
    extlen = sizeof(struct enc_info_he) + ntohs(encinfo->keylen) +
             ntohs(encinfo->dhlen) + ntohs(encinfo->siglen);
    encinfo->extlen = extlen / 4;

    if (!servercontext) {
        create_server_context(htonl(finfo->group_id), finfo->group_inst,
                              server_id, encinfo, extlen,
                              &servercontext, &servercontext_len);
        calculate_server_app_keys(hashtype, groupmaster, sizeof(groupmaster),
                servercontext, servercontext_len,
                keylen, ivlen, server_app_key, server_app_iv);
    }

    return extlen;
}

/**
 * Send the ANNOUNCE message
 * For open group membership, just send one.  For closed group membership,
 * list as many destinations as will fit and send multiple packets so that
 * each receiver is listed.
 * Returns 1 on success, 0 on fail.
 */
int send_announce(const struct finfo_t *finfo, int attempt, int open)
{
    int packetlen, rval, iplen, extlen;
    unsigned char *buf;
    struct uftp_h *header;
    struct announce_h *announce;
    unsigned char *publicaddr, *privateaddr;
    struct enc_info_he *encinfo;
    struct timeval tv;
    uint32_t *idlist;
    int64_t time_us;

    buf = safe_calloc(MAXMTU, 1); 
    if (listen_dest.ss.ss_family == AF_INET6) {
        iplen = sizeof(struct in6_addr);
    } else {
        iplen = sizeof(struct in_addr);
    }
    header = (struct uftp_h *)buf;
    announce = (struct announce_h *)(buf + sizeof(struct uftp_h));
    publicaddr = (unsigned char *)announce + sizeof(struct announce_h);
    privateaddr = publicaddr + iplen;
    encinfo = (struct enc_info_he *)(privateaddr + iplen);

    set_uftp_header(header, ANNOUNCE, finfo->group_id, finfo->group_inst,
                    get_adv_grtt(grtt), destcount);
    announce->func = ANNOUNCE;
    if (sync_mode) {
        announce->flags |= FLAG_SYNC_MODE;
        if (sync_preview) {
            announce->flags |= FLAG_SYNC_PREVIEW;
        }
    }
    announce->robust = robust;
    announce->cc_type = cc_type;
    announce->blocksize = htons(blocksize);
    gettimeofday(&tv, NULL);
    time_us = tv_to_usec(tv);
    announce->tstamp_hi = htonl((time_us & 0xFFFFFFFF00000000ULL) >> 32);
    announce->tstamp_lo = htonl(time_us & 0x00000000FFFFFFFFULL);
    if (!is_multicast(&listen_dest, 0)) {
        memset(publicaddr, 0, iplen);
        memset(privateaddr, 0, iplen);
    } else if (listen_dest.ss.ss_family == AF_INET6) {
        memcpy(publicaddr, &listen_dest.sin6.sin6_addr.s6_addr, iplen);
        memcpy(privateaddr, &receive_dest.sin6.sin6_addr.s6_addr, iplen);
    } else {
        memcpy(publicaddr, &listen_dest.sin.sin_addr.s_addr, iplen);
        memcpy(privateaddr, &receive_dest.sin.sin_addr.s_addr, iplen);
    }
    if (listen_dest.ss.ss_family == AF_INET6) {
        announce->flags |= FLAG_IPV6;
    }

    if (keytype != KEY_NONE) {
        extlen = set_enc_info(finfo, encinfo);
        if (extlen == 0) {
            glog0(finfo, "Error setting up EXT_ENC_INFO");
            free(buf);
            return 0;
        }
        announce->hlen = (uint8_t)((sizeof(struct announce_h) +
                          iplen + iplen + extlen) / 4);
    } else {
        announce->hlen = (uint8_t)((sizeof(struct announce_h) +
                         iplen + iplen) / 4);
    }

    idlist = (uint32_t *)((uint8_t *)announce + (announce->hlen * 4));
    if (open) {
        header->seq = htons(send_seq++);
        packetlen = sizeof(struct uftp_h) + (announce->hlen * 4);
        if (!sign_announce(finfo, buf, packetlen)) {
            glog0(finfo, "Error signing ANNOUNCE");
            free(buf);
            return 0;
        }
        glog2(finfo, "Sending ANNOUNCE %d", attempt);
        if (nb_sendto(sock, buf, packetlen, 0, (struct sockaddr *)&listen_dest,
                      family_len(listen_dest)) == SOCKET_ERROR) {
            gsockerror(finfo, "Error sending ANNOUNCE");
            // So we don't spin our wheels...
            sleep(1);
            free(buf);
            return 0;
        }
        free(buf);
        return 1;
    } else {
        rval = send_multiple(finfo, buf, ANNOUNCE, attempt, idlist,
                DEST_MUTE, 0, &listen_dest, 0);
        free(buf);
        return rval;
    }
}

/**
 * Send out REG_CONF messages specifying all registered clients.
 * Sent when encryption is disabled, or if the client is behind a proxy.
 * Returns 1 on success, 0 on fail
 */
int send_regconf(const struct finfo_t *finfo, int attempt, int do_regconf)
{
    int rval;
    unsigned char *buf;
    struct uftp_h *header;
    struct regconf_h *regconf;
    uint32_t *idlist;

    buf = safe_calloc(MAXMTU, 1); 
    header = (struct uftp_h *)buf;
    regconf = (struct regconf_h *)(buf + sizeof(struct uftp_h));

    set_uftp_header(header, REG_CONF, finfo->group_id, finfo->group_inst,
                    get_adv_grtt(grtt), destcount);
    regconf->func = REG_CONF;
    regconf->hlen = sizeof(struct regconf_h) / 4;

    idlist = (uint32_t *)((uint8_t *)regconf + (regconf->hlen * 4));
    rval = send_multiple(finfo, buf, REG_CONF, attempt, idlist, DEST_ACTIVE,
                         0, &receive_dest, do_regconf);
    free(buf);
    return rval;
}

/**
 * Send a KEYINFO message.  Sent during the Announce phase for a group
 * with encryption enabled.
 * Returns 1 on success, 0 on fail.
 */
int send_keyinfo(const struct finfo_t *finfo, int attempt)
{
    unsigned char *buf, *iv;
    struct uftp_h *header;
    struct keyinfo_h *keyinfo;
    unsigned char *sig, *sigcopy, *sigcontext, *aadcontext;
    struct destkey *keylist;
    unsigned int hsize, packetlen, enclen, siglen, _siglen;
    unsigned int basesigcontextlen, sigcontextlen, baseaadlen, aadlen;
    int maxdest, packetcnt, dests, iv_init, i, rval;
    const char *sig_context_str = "UFTP 5, KEYINFO";
    const char *aad_context_str = "UFTP 5, group master";

    buf = safe_calloc(MAXMTU, 1);
    iv = safe_calloc(ivlen, 1);
    header = (struct uftp_h *)buf;
    keyinfo = (struct keyinfo_h *)(buf + sizeof(struct uftp_h));

    if (privkeytype == KEYBLOB_RSA) {
        siglen = RSA_keylen(privkey.rsa);
    } else {
        siglen = ECDSA_siglen(privkey.ec);
    }

    set_uftp_header(header, KEYINFO, finfo->group_id, finfo->group_inst,
                    get_adv_grtt(grtt), destcount);
    keyinfo->func = KEYINFO;
    keyinfo->hlen = (uint8_t)((sizeof(struct keyinfo_h) + siglen) / 4);
    keyinfo->siglen = htons(siglen);
    sig = (uint8_t *)keyinfo + sizeof(struct keyinfo_h);
    keylist = (struct destkey *)(sig + siglen);

    sigcontext = safe_malloc(strlen(sig_context_str) + servercontext_len +
                             MAXMTU);
    aadcontext = safe_malloc(strlen(aad_context_str) + MAXMTU);
    sigcopy = safe_malloc(siglen);
    sigcontextlen = 0;
    memcpy(sigcontext + sigcontextlen, sig_context_str, strlen(sig_context_str)); 
    sigcontextlen += (unsigned)strlen(sig_context_str);
    memcpy(sigcontext + sigcontextlen, servercontext, servercontext_len);
    sigcontextlen += servercontext_len;
    basesigcontextlen = sigcontextlen;
    aadlen = 0;
    memcpy(aadcontext + aadlen, aad_context_str, strlen(aad_context_str)); 
    aadlen += (unsigned)strlen(aad_context_str);
    baseaadlen = aadlen;

    iv_init = 0;
    hsize = sizeof(struct keyinfo_h) + siglen;
    maxdest = blocksize / sizeof(struct destkey);
    packetcnt = 1;
    for (i = 0, dests = 0; i < destcount; i++) {
        if (destlist[i].status == DEST_REGISTERED) {
            if (!iv_init) {
                ivctr++;
                keyinfo->iv_ctr_hi = htonl((ivctr & 0xFFFFFFFF00000000ULL)>>32);
                keyinfo->iv_ctr_lo = htonl(ivctr & 0x00000000FFFFFFFFULL);
                iv_init = 1;
            }
            keylist[dests].dest_id = destlist[i].id;
            build_iv(iv, destlist[i].encinfo->s_hs_iv, ivlen,
                     uftp_htonll(ivctr));
            memcpy(aadcontext + baseaadlen, destlist[i].encinfo->context2,
                    destlist[i].encinfo->context2_len);
            aadlen = baseaadlen + destlist[i].encinfo->context2_len;
            if (!encrypt_block(keytype, iv, destlist[i].encinfo->s_hs_key,
                    aadcontext, aadlen, groupmaster, sizeof(groupmaster),
                    keylist[dests].groupmaster, &enclen)) {
                glog0(finfo, "Error encrypting KEYINFO for %s",
                             destlist[i].name);
                rval = 0;
                goto cleanup;
            }
            dests++;
        }
        if ((dests >= maxdest) || ((i == destcount - 1) && (dests > 0))) {
            header->seq = htons(send_seq++);
            packetlen = sizeof(struct uftp_h) + hsize + 
                        (dests * sizeof(struct destkey));

            memset(sig, 0, siglen);
            memcpy(sigcontext + basesigcontextlen, buf, packetlen);
            sigcontextlen = basesigcontextlen + packetlen;
            if (privkeytype == KEYBLOB_EC) {
                if (!create_ECDSA_sig(privkey.ec, hashtype, sigcontext, 
                                      sigcontextlen, sigcopy, &_siglen)) {
                    // Called function should log
                    rval = 0;
                    goto cleanup;
                }
            } else {
                if (!create_RSA_sig(privkey.rsa, hashtype, sigcontext,
                                    sigcontextlen, sigcopy, &_siglen)) {
                    // Called function should log
                    rval = 0;
                    goto cleanup;
                }
            }
            if (_siglen != siglen) {
                glog0(finfo, "Signature length doesn't match expected length");
                glog1(finfo, "expected %d, got %d", siglen, _siglen);
                rval = 0;
                goto cleanup;
            }
            memcpy(sig, sigcopy, siglen);

            glog2(finfo, "Sending KEYINFO %d.%d", attempt, packetcnt);
            if (nb_sendto(sock, buf, packetlen, 0,
                          (struct sockaddr *)&receive_dest,
                          family_len(receive_dest)) == SOCKET_ERROR) {
                gsockerror(finfo, "Error sending KEYINFO");
                sleep(1);
                rval = 0;
                goto cleanup;
            }
            if (packet_wait) usleep(packet_wait/1000);
            memset(keylist, 0, maxdest * sizeof(struct destkey));
            iv_init = 0;
            dests = 0;
            packetcnt++;
        }
    }
    rval = 1;

cleanup:
    free(sigcontext);
    free(aadcontext);
    free(sigcopy);
    free(buf);
    free(iv);
    return rval;
}

/**
 * Send a FILEINFO message.  Sent for each individual file.
 * Returns 1 on success, 0 on fail.
 */
int send_fileinfo(const struct finfo_t *finfo, int attempt)
{
    int rval;
    unsigned char *buf;
    struct uftp_h *header;
    struct fileinfo_h *fileinfo;
    struct timeval tv;
    uint32_t *idlist;
    int64_t time_us;
    char *filename, *linkname;

    if (strlen(finfo->destfname) > MAXPATHNAME) {
        glog0(finfo, "File name too long: %s", finfo->destfname);
        return 0;
    }

    buf = safe_calloc(MAXMTU, 1); 
    header = (struct uftp_h *)buf;
    fileinfo = (struct fileinfo_h *)(buf + sizeof(struct uftp_h));
    filename = (char *)fileinfo + sizeof(struct fileinfo_h);

    set_uftp_header(header, FILEINFO, finfo->group_id, finfo->group_inst,
                    get_adv_grtt(grtt), destcount);
    fileinfo->func = FILEINFO;
    fileinfo->ftype = finfo->ftype;
    fileinfo->file_id = htons(finfo->file_id);
    fileinfo->namelen = (uint8_t)(0 + ceil(strlen(finfo->destfname) / 4.0));
    fileinfo->lofsize = htonl((finfo->size & 0xFFFFFFFF));
    fileinfo->hifsize = htons((uint16_t)(finfo->size >> 32));
    fileinfo->ftstamp_hi =
        htons((uint16_t)((finfo->tstamp & 0xFFFFFFFF00000000ULL) >> 32));
    fileinfo->ftstamp_lo = htonl(finfo->tstamp & 0x00000000FFFFFFFFULL);
    gettimeofday(&tv, NULL);
    time_us = tv_to_usec(tv);
    fileinfo->tstamp_hi = htonl((time_us & 0xFFFFFFFF00000000ULL) >> 32);
    fileinfo->tstamp_lo = htonl(time_us & 0x00000000FFFFFFFFULL);

    strncpy(filename, finfo->destfname, MAXPATHNAME);
    if (finfo->ftype == FTYPE_LINK) {
        if (strlen(finfo->linkname) > 
                (unsigned)MAXPATHNAME - (fileinfo->namelen * 4)) {
            glog0(finfo, "Link name too long: %s", finfo->linkname);
            free(buf);
            return 0;
        }
        linkname = filename + (fileinfo->namelen * 4);
        strncpy(linkname, finfo->linkname,
                MAXPATHNAME - (fileinfo->namelen * 4));
        fileinfo->linklen = (uint8_t)(0 + ceil(strlen(finfo->linkname) / 4.0));
    }

    fileinfo->hlen = (sizeof(struct fileinfo_h) + (fileinfo->namelen * 4) +
                     (fileinfo->linklen * 4)) / 4;
    idlist = (uint32_t *)((uint8_t *)fileinfo + (fileinfo->hlen * 4));
    rval = send_multiple(finfo, buf, FILEINFO, attempt, idlist,
            DEST_REGISTERED, (keytype != KEY_NONE), &receive_dest, 0);
    free(buf);
    return rval;
}

/**
 * Adds a registered host to the hostlist.  Returns the list index.
 */
int add_dest_by_addr(uint32_t id, struct finfo_t *finfo,
                     int state, int proxyidx, int isproxy)
{
    snprintf(destlist[destcount].name, sizeof(destlist[destcount].name),
             "0x%08X", ntohl(id));
    destlist[destcount].id = id;
    destlist[destcount].status = state;
    destlist[destcount].proxyidx = proxyidx;
    destlist[destcount].isproxy = isproxy;
    return destcount++;
}

/**
 * When a proxy registers, process the clients the proxy is serving
 */
void add_proxy_dests(struct finfo_t *finfo, const uint32_t *idlist,
                     const union sockaddr_u *su, int clientcnt,
                     int proxyidx, int open, double rtt)
{
    int hostidx, i, dupmsg;

    if (!destlist[proxyidx].isproxy) {
        // True when using open group membership and
        // we get a CLIENT_KEY before the REGSITER for a proxy
        destlist[proxyidx].isproxy = 1;
    }
    for (i = 0; i < clientcnt; i++) {
        dupmsg = 0;
        hostidx = find_client(idlist[i]);
        if (hostidx == -1) {
            if (open) {
                if (destcount == MAXDEST) {
                    glog1(finfo, "Rejecting client %08X: "
                                 "max destinations exceeded", ntohl(idlist[i]));
                    send_abort(finfo, "Max destinations exceeded",
                               su, idlist[i], 0, 0);
                    continue;
                }
                hostidx = add_dest_by_addr(idlist[i], finfo, DEST_ACTIVE,
                                           proxyidx, 0);
            } else {
                glog1(finfo, "Host %08X not in host list", idlist[i]);
                send_abort(finfo, "Not in host list", su, idlist[i], 0, 0);
                continue;
            }
        } else {
            dupmsg = (destlist[hostidx].status == DEST_ACTIVE);
            destlist[hostidx].status = DEST_ACTIVE;
            destlist[hostidx].proxyidx = proxyidx;
        }
        destlist[hostidx].rtt = rtt;
        finfo->deststate[hostidx].conf_sent = 0;
        glog1(finfo, "  For client%s %s", dupmsg ? "+" : "",
                destlist[hostidx].name);
    }
}

/**
 * Verifies the data in a CLIENT_KEY message signed by the client's public key
 */
int verify_client_key(struct finfo_t *finfo, int hostidx, 
                      uint8_t *sig, struct client_key_h *clientkey)
{
    uint8_t *verifydata;
    int verifylen;
    const char *context_str = "UFTP 5, CLIENT_KEY";
    struct encinfo_t *encinfo = destlist[hostidx].encinfo;

    verifydata = safe_calloc(strlen(context_str) + 
            encinfo->context1_len, 1);
    verifylen = 0;
    memcpy(verifydata + verifylen, context_str, strlen(context_str));
    verifylen += (int)strlen(context_str);
    memcpy(verifydata + verifylen, encinfo->context1,
            encinfo->context1_len);
    verifylen += encinfo->context1_len;

    if (encinfo->pubkeytype == KEYBLOB_RSA) {
        if (!verify_RSA_sig(encinfo->pubkey.rsa, hashtype, verifydata,
                verifylen, sig, ntohs(clientkey->siglen))) {
            glog1(finfo, "Rejecting CLIENT_KEY from %s: verify data mismatch",
                         destlist[hostidx].name);
            goto err_exit;
        }
    } else {
        if (!verify_ECDSA_sig(encinfo->pubkey.ec, hashtype, verifydata,
                              verifylen, sig, ntohs(clientkey->siglen))) {
            glog1(finfo, "Rejecting CLIENT_KEY from %s: verify data mismatch",
                         destlist[hostidx].name);
            goto err_exit;
        }
    }

    // sig should point to the signature field in clientkey
    memset(sig, 0, ntohs(clientkey->siglen));
    create_client_context_2(encinfo->context1, encinfo->context1_len,
                            clientkey, clientkey->hlen * 4,
                            &encinfo->context2, &encinfo->context2_len);
    calculate_client_app_keys(hashtype, groupmaster, sizeof(groupmaster),
            encinfo->context2, encinfo->context2_len, keylen, ivlen, 
            encinfo->c_app_key, encinfo->c_app_iv,
            encinfo->finished_key, encinfo->verify_data);

    destlist[hostidx].status = DEST_REGISTERED;
    free(verifydata);
    return 1;

err_exit:
    if (destlist[hostidx].encinfo->pubkeytype == KEYBLOB_RSA) {
        free_RSA_key(destlist[hostidx].encinfo->pubkey.rsa);
    } else {
        free_EC_key(destlist[hostidx].encinfo->pubkey.ec);
    }
    destlist[hostidx].encinfo->pubkey.key = 0;
    destlist[hostidx].encinfo->pubkeytype = 0;
    free(verifydata);
    return 0;
}

/**
 * Processes encryption key information received in a REGISTER message
 */
int handle_register_keys(const struct register_h *reg,
                         const unsigned char *keyinfo, struct finfo_t *finfo,
                         int hostidx)
{
    struct encinfo_t *encinfo = safe_calloc(1, sizeof(struct encinfo_t));
    memcpy(encinfo->rand2, reg->rand2, sizeof(encinfo->rand2));
    if (!import_EC_key(&encinfo->dhkey.ec, keyinfo,
                       ntohs(reg->dhlen), 1)) {
        glog1(finfo, "Rejecting REGISTER from %s: failed to import ECDH key",
                     destlist[hostidx].name);
        free(encinfo);
        return 0;
    }
    if (get_EC_curve(encinfo->dhkey.ec) != ecdh_curve) {
        glog1(finfo, "Rejecting REGISTER from %s: " "invalid curve for ECDH",
                     destlist[hostidx].name);
        free_EC_key(encinfo->dhkey.ec);
        free(encinfo);
        return 0;
    }
    if (!get_ECDH_key(encinfo->dhkey.ec, dhkey.ec, encinfo->premaster,
                      &encinfo->premaster_len, HASH_SHA256)) {
        glog1(finfo, "Rejecting REGISTER from %s: failed to calculate "
                     "premaster secret", destlist[hostidx].name);
        free_EC_key(encinfo->dhkey.ec);
        free(encinfo);
        return 0;
    }

    create_client_context_1(servercontext, servercontext_len, NULL, 0,
            destlist[hostidx].id, keyinfo, ntohs(reg->dhlen), reg->rand2,
            &encinfo->context1, &encinfo->context1_len);
    calculate_hs_keys(hashtype, encinfo->premaster, encinfo->premaster_len,
                      encinfo->context1, encinfo->context1_len, keylen, ivlen,
                      encinfo->s_hs_key, encinfo->s_hs_iv,
                      encinfo->c_hs_key, encinfo->c_hs_iv);
    if (!client_auth) {
        create_client_context_2(encinfo->context1, encinfo->context1_len,
                NULL, 0, &encinfo->context2, &encinfo->context2_len);
        calculate_client_app_keys(hashtype, groupmaster, sizeof(groupmaster),
                encinfo->context2, encinfo->context2_len, keylen, ivlen, 
                encinfo->c_app_key, encinfo->c_app_iv,
                encinfo->finished_key, encinfo->verify_data);
    }

    destlist[hostidx].encinfo = encinfo;
    return 1;
}

/**
 * Process an expected REGISTER with open group membership
 */
void handle_open_register(const unsigned char *message, unsigned meslen,
                          struct finfo_t *finfo, const union sockaddr_u *su,
                          uint32_t src, int regconf)
{
    const struct register_h *reg;
    const uint32_t *idlist;
    const unsigned char *enckey;
    int clientcnt, hostidx;
    struct timeval tv;
    int64_t t1, t2;

    reg = (const struct register_h *)message;
    enckey = (const unsigned char *)reg + sizeof(struct register_h);
    gettimeofday(&tv, NULL);
    t2 = tv_to_usec(tv);

    if (destcount == MAXDEST) {
        glog1(finfo, "Rejecting REGISTER from %08X: "
                     "max destinations exceeded", ntohl(src));
        send_abort(finfo, "Max destinations exceeded", su, src, 0, 0);
        return;
    }
    if ((meslen < (reg->hlen * 4U)) || ((reg->hlen * 4U) <
            sizeof(struct register_h) + ntohs(reg->dhlen))) {
        glog1(finfo, "Rejecting REGISTER from %08X: "
                     "invalid message size", ntohl(src));
        send_abort(finfo, "Invalid message size", su, src, 0, 0);
        return;
    }

    clientcnt = (meslen - (reg->hlen * 4)) / 4;
    hostidx = add_dest_by_addr(src, finfo, DEST_MUTE, -1, (clientcnt > 0));
    if (keytype != KEY_NONE) {
        if (!handle_register_keys(reg, enckey, finfo, hostidx)) {
            return;
        }
    }
    if (regconf) {
        finfo->deststate[hostidx].conf_sent = 0;
    }
    t1 = (int64_t)ntohl(reg->tstamp_hi) << 32;
    t1 |= ntohl(reg->tstamp_lo);
    destlist[hostidx].rtt = (t2 - t1) / 1000000.0;
    if (destlist[hostidx].rtt < CLIENT_RTT_MIN) {
        destlist[hostidx].rtt = CLIENT_RTT_MIN;
    }
    destlist[hostidx].rtt_measured = 1;
    destlist[hostidx].registered = 1;
    destlist[hostidx].status =
            regconf ? DEST_ACTIVE : (client_auth ? DEST_MUTE : DEST_REGISTERED);
    glog2(finfo, "Received REGISTER from %s %s",
              (clientcnt > 0) ? "proxy" : "client", destlist[hostidx].name);
    if (clientcnt > 0) {
        idlist = (const uint32_t *)(message + (reg->hlen * 4));
        add_proxy_dests(finfo, idlist, su, clientcnt, hostidx, 1,
                        destlist[hostidx].rtt);
    }
    glog3(finfo, "send time = " F_i64 ".%06d", t1/1000000, (int)(t1%1000000));
    glog3(finfo, "rx time = " F_i64 ".%06d", t2/1000000, (int)(t2%1000000));
    glog3(finfo, "  rtt = %.6f", destlist[hostidx].rtt);
}

/**
 * Process an expected REGISTER with closed group membership
 */
void handle_register(const unsigned char *message, unsigned meslen,
                     struct finfo_t *finfo, const union sockaddr_u *su,
                     int hostidx, int regconf, int open)
{
    const struct register_h *reg;
    const uint32_t *idlist;
    const unsigned char *enckey;
    int clientcnt, dupmsg, isproxy;
    struct timeval tv;
    int64_t t1, t2;

    reg = (const struct register_h *)message;
    enckey = (const unsigned char *)reg + sizeof(struct register_h);
    gettimeofday(&tv, NULL);
    t2 = tv_to_usec(tv);

    if ((meslen < (reg->hlen * 4U)) || ((reg->hlen * 4U) <
            sizeof(struct register_h) + ntohs(reg->dhlen))) {
        glog1(finfo, "Rejecting REGISTER from %s: "
                     "invalid message size", destlist[hostidx].name);
        send_abort(finfo, "Invalid message size", su, destlist[hostidx].id,0,0);
        return;
    }
    clientcnt = (meslen - (reg->hlen * 4)) / 4;
    if ((clientcnt > 0) && (!destlist[hostidx].isproxy) && (!open)) {
        glog1(finfo, "Rejecting REGISTER from %s: specified multiple clients "
                     "but not a proxy", destlist[hostidx].name);
        send_abort(finfo, "specified multiple clients but not a proxy", su,
                   destlist[hostidx].id, 0, 0);
        destlist[hostidx].status = DEST_ABORT;
        return;
    }    
    if (finfo->file_id != 0) {
        glog2(finfo, "Received REGISTER+ from %s", destlist[hostidx].name);
        return;
    }

    if (destlist[hostidx].status == DEST_MUTE) {
        if ((keytype != KEY_NONE) && !destlist[hostidx].encinfo) {
            if (!handle_register_keys(reg, enckey, finfo, hostidx)) {
                return;
            }
        }
        destlist[hostidx].status = regconf ? DEST_ACTIVE : 
                ((client_auth && (!destlist[hostidx].encinfo->pubkey.key))
                    ? DEST_MUTE : DEST_REGISTERED);
    }
    dupmsg = (destlist[hostidx].registered);
    t1 = (int64_t)ntohl(reg->tstamp_hi) << 32;
    t1 |= ntohl(reg->tstamp_lo);
    destlist[hostidx].rtt = (t2 - t1) / 1000000.0;
    if (destlist[hostidx].rtt < CLIENT_RTT_MIN) {
        destlist[hostidx].rtt = CLIENT_RTT_MIN;
    }
    destlist[hostidx].rtt_measured = 1;
    destlist[hostidx].registered = 1;
    if (regconf) {
        finfo->deststate[hostidx].conf_sent = 0;
    }
    isproxy = destlist[hostidx].isproxy;
    glog2(finfo, "Received REGISTER%s from %s %s",
            (dupmsg && !isproxy) ? "+" : "",
            (isproxy) ? "proxy" : "client", destlist[hostidx].name);
    if (clientcnt > 0) {
        idlist = (const uint32_t *)(message + (reg->hlen * 4));
        add_proxy_dests(finfo, idlist, su, clientcnt, hostidx, open,
                        destlist[hostidx].rtt);
    }
    glog3(finfo, "send time = " F_i64 ".%06d", t1/1000000, (int)(t1%1000000));
    glog3(finfo, "rx time = " F_i64 ".%06d", t2/1000000, (int)(t2%1000000));
    glog3(finfo, "  rtt = %.6f", destlist[hostidx].rtt);
}

/**
 * Verifies a client's public key fingerprint
 */
int verify_client_fingerprint(const struct finfo_t *finfo,
                              const unsigned char *keyblob,
                              uint16_t bloblen, int hostidx)
{
    unsigned char fingerprint[HMAC_LEN];
    unsigned int fplen;

    if (keyblob[0] == KEYBLOB_RSA) {
        if (!import_RSA_key(&destlist[hostidx].encinfo->pubkey.rsa,
                            keyblob, bloblen)) {
            glog1(finfo, "Rejecting CLIENT_KEY from %s: "
                         "failed to import key", destlist[hostidx].name);
            destlist[hostidx].encinfo->pubkey.key = 0;
            return 0;
        }
        destlist[hostidx].encinfo->pubkeytype = KEYBLOB_RSA;
    } else {
        if (!import_EC_key(&destlist[hostidx].encinfo->pubkey.ec,
                           keyblob, bloblen, 0)) {
            glog1(finfo, "Rejecting CLIENT_KEY from %s: "
                         "failed to import key", destlist[hostidx].name);
            destlist[hostidx].encinfo->pubkey.key = 0;
            return 0;
        }
        destlist[hostidx].encinfo->pubkeytype = KEYBLOB_EC;
    }

    if (destlist[hostidx].has_fingerprint) {
        hash(HASH_SHA1, keyblob, bloblen, fingerprint, &fplen);
        if (memcmp(destlist[hostidx].keyfingerprint, fingerprint, fplen)) {
            glog1(finfo, "Rejecting CLIENT_KEY from %s: "
                         "key fingerprint mismatch", destlist[hostidx].name);
            if (keyblob[0] == KEYBLOB_RSA) {
                free_RSA_key(destlist[hostidx].encinfo->pubkey.rsa);
            } else {
                free_EC_key(destlist[hostidx].encinfo->pubkey.ec);
            }
            destlist[hostidx].encinfo->pubkey.key = 0;
            destlist[hostidx].encinfo->pubkeytype = 0;
            return 0;
        }
    }

    return 1;
}

/**
 * Process an expected CLIENT_KEY
 */
void handle_clientkey(unsigned char *message, unsigned meslen,
                      struct finfo_t *finfo, const union sockaddr_u *su,
                      int hostidx)
{
    struct client_key_h *clientkey;
    unsigned char *keyblob, *verify;

    clientkey = (struct client_key_h *)message;
    keyblob = (unsigned char *)clientkey + sizeof(struct client_key_h);
    verify = keyblob + ntohs(clientkey->bloblen);

    if ((meslen < (clientkey->hlen * 4U)) ||
            ((clientkey->hlen * 4U) < sizeof(struct client_key_h) +
                ntohs(clientkey->bloblen) + ntohs(clientkey->siglen))) {
        glog1(finfo, "Rejecting CLIENT_KEY from %s: "
                     "invalid message size", destlist[hostidx].name);
        send_abort(finfo, "Invalid message size", su, destlist[hostidx].id,0,0);
        return;
    }
    if (finfo->file_id != 0) {
        glog2(finfo, "Received CLIENT_KEY+ from %s", destlist[hostidx].name);
        return;
    }

    if (!verify_client_fingerprint(finfo, keyblob, ntohs(clientkey->bloblen),
                                   hostidx)) {
        return;
    }
    if (!verify_client_key(finfo, hostidx, verify, clientkey)) {
        return;
    }
    glog2(finfo, "Received CLIENT_KEY from %s", destlist[hostidx].name);
}

/**
 * Process an expected KEYINFO_ACK and validate the verify_data field.
 */
void handle_keyinfo_ack(const unsigned char *message, unsigned meslen,
                        struct finfo_t *finfo, const union sockaddr_u *su,
                        int hostidx)
{
    const struct keyinfoack_h *keyinfoack;
    const uint8_t *verify_data;
    int dupmsg;

    keyinfoack = (const struct keyinfoack_h *)message;
    verify_data = (const uint8_t *)message + sizeof(struct keyinfoack_h);

    if ((meslen < (keyinfoack->hlen * 4U)) ||
           ((keyinfoack->hlen * 4U) < (sizeof(struct keyinfoack_h) + hashlen))){
        glog1(finfo, "Rejecting KEYINFO_ACK from %s: "
                     "invalid message size", destlist[hostidx].name);
        send_abort(finfo, "Invalid message size", su, destlist[hostidx].id,0,0);
        return;
    }

    if (keytype == KEY_NONE) {
        glog1(finfo, "Rejecting KEYINFO_ACK from %s: "
                     "encryption not enabled", destlist[hostidx].name);
        send_abort(finfo, "Encryption not enabled", su, destlist[hostidx].id,
                   0, 0);
        return;
    }

    if (memcmp(verify_data, destlist[hostidx].encinfo->verify_data, hashlen)) {
        glog1(finfo, "Rejecting KEYINFO_ACK from %s: "
                     "verify data mismatch", destlist[hostidx].name);
        return;
    }

    dupmsg = (destlist[hostidx].status == DEST_ACTIVE);
    glog2(finfo, "Received KEYINFO_ACK%s from %s", dupmsg ? "+" : "",
                 destlist[hostidx].name);
    destlist[hostidx].status = DEST_ACTIVE;
}

/**
 * Process an expected FILEINFO_ACK.
 */
void handle_fileinfo_ack(const unsigned char *message, unsigned meslen,
                         struct finfo_t *finfo, int hostidx)
{
    const struct fileinfoack_h *fileinfoack;
    struct timeval tv;
    int64_t t1, t2;
    const uint32_t *addr;
    int clientcnt, dupmsg, isproxy, clientidx, i;

    fileinfoack = (const struct fileinfoack_h *)message;
    gettimeofday(&tv, NULL);
    t2 = tv_to_usec(tv);

    if ((meslen < (fileinfoack->hlen * 4U)) ||
            ((fileinfoack->hlen * 4U) < sizeof(struct fileinfoack_h))) {
        glog1(finfo, "Rejecting FILEINFO_ACK from %s: "
                     "invalid message size", destlist[hostidx].name);
        return;
    }
    clientcnt = (meslen - (fileinfoack->hlen * 4)) / 4;
    if ((clientcnt > 0) && (!destlist[hostidx].isproxy)) {
        glog1(finfo, "Rejecting FILEINFO_ACK from %s: "
                     "specified multiple clients but not a proxy",
                destlist[hostidx].name);
        return;
    }    

    if (ntohs(fileinfoack->file_id) != finfo->file_id) {
        glog1(finfo, "Rejecting FILEINFO_ACK from %s: "
                "invalid file ID %04X, expected %04X ", destlist[hostidx].name,
                ntohs(fileinfoack->file_id), finfo->file_id);
        return;
    }
    finfo->partial = finfo->partial &&
            ((fileinfoack->flags & FLAG_PARTIAL) != 0);

    t1 = (int64_t)ntohl(fileinfoack->tstamp_hi) << 32;
    t1 |= ntohl(fileinfoack->tstamp_lo);
    destlist[hostidx].rtt = (t2 - t1) / 1000000.0;
    if (destlist[hostidx].rtt < CLIENT_RTT_MIN) {
        destlist[hostidx].rtt = CLIENT_RTT_MIN;
    }
    destlist[hostidx].rtt_measured = 1;
    destlist[hostidx].rtt_sent = 0;
    isproxy = destlist[hostidx].isproxy;
    dupmsg = (destlist[hostidx].status == DEST_ACTIVE);
    destlist[hostidx].status = DEST_ACTIVE;
    glog2(finfo, "Received FILEINFO_ACK%s from %s %s",
                 (dupmsg && !isproxy) ? "+" : "",
                 (isproxy) ? "proxy" : "client", destlist[hostidx].name);
    if (clientcnt > 0) {
        addr = (const uint32_t *)(message + (fileinfoack->hlen * 4));
        for (i = 0; i < clientcnt; i++) {
            dupmsg = 0;
            clientidx = find_client(addr[i]);
            if (clientidx == -1) {
                glog2(finfo, "Host %08X not in host list", ntohl(addr[i]));
                continue;
            } else {
                dupmsg = (destlist[clientidx].status == DEST_ACTIVE);
                destlist[clientidx].status = DEST_ACTIVE;
                destlist[clientidx].rtt = destlist[hostidx].rtt;
            }
            glog2(finfo, "  For client%s %s", dupmsg ? "+" : "",
                         destlist[clientidx].name);
        }
    }
    glog3(finfo, "send time = " F_i64 ".%06d", t1/1000000, (int)(t1%1000000));
    glog3(finfo, "rx time = " F_i64 ".%06d", t2/1000000, (int)(t2%1000000));
    glog3(finfo, "  rtt = %.6f", destlist[hostidx].rtt);
}

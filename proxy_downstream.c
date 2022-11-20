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

#else

#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#endif

#include "proxy.h"
#include "proxy_common.h"
#include "proxy_downstream.h"

/**
 * Adds a client to the given group
 */
int add_client(uint32_t id, struct pr_group_list_t *group)
{
    struct pr_destinfo_t *dest;

    dest = &group->destinfo[group->destcount];
    snprintf(dest->name, sizeof(dest->name), "0x%08X", ntohl(id));
    dest->id = id;
    dest->pending = -1;
    return group->destcount++;
}

/**
 * For a given client, calculate the master key and do key expansion
 * to determine the symmetric cypher key and IV salt, and hash key
 */
void calculate_v4_client_keys(struct pr_group_list_t *group, int hostidx)
{
    unsigned char *seed, *prf_buf;
    unsigned char master[MASTER4_LEN];
    int explen, len, seedlen;
    struct pr_destinfo_t *dest;

    dest = &group->destinfo[hostidx];

    explen = group->keylen + group->ivlen +
             group->hashlen;
    seedlen = sizeof(group->rand1) * 2;
    seed = safe_calloc(seedlen, 1);
    prf_buf = safe_calloc(MASTER4_LEN + explen + group->hashlen, 1);

    memcpy(seed, group->rand1, sizeof(group->rand1));
    memcpy(seed + sizeof(group->rand1), dest->rand2,
            sizeof(dest->rand2));
    PRF(group->hashtype, MASTER4_LEN, dest->premaster, dest->premaster_len,
            "master secret", seed, seedlen, prf_buf, &len);
    memcpy(master, prf_buf, sizeof(master));

    PRF(group->hashtype, explen, master, sizeof(master),
            "key expansion", seed, seedlen, prf_buf, &len);
    // bypass hmac key since it isn't being used
    // v4 uses same key for both client and server
    memcpy(dest->c_hs_key, prf_buf + group->hashlen, group->keylen);
    memcpy(dest->s_hs_key, prf_buf + group->hashlen, group->keylen);
    memcpy(dest->c_hs_iv, prf_buf + group->hashlen + group->keylen, SALT_LEN);
    memcpy(dest->s_hs_iv, prf_buf + group->hashlen + group->keylen, SALT_LEN);

    free(seed);
    free(prf_buf);
}

/**
 * Creates the context for a CLIENT_KEY signature
 */
uint8_t *build_ds_client_key_sig(struct pr_group_list_t *group, int hostidx,
                                 int *verifylen)
{
    uint8_t *verifydata;
    const char *context_str = "UFTP 5, CLIENT_KEY";
    struct pr_destinfo_t *dest;

    dest = &group->destinfo[hostidx];

    verifydata = safe_calloc(strlen(context_str) + dest->c_context1_len, 1);
    *verifylen = 0;
    memcpy(verifydata + *verifylen, context_str, strlen(context_str));
    *verifylen += (int)strlen(context_str);
    memcpy(verifydata + *verifylen, dest->c_context1, dest->c_context1_len);
    *verifylen += dest->c_context1_len;
    return verifydata;
}

/**
 * Verifies the data in a CLIENT_KEY message signed by the client's public key
 */
int verify_client_key(struct pr_group_list_t *group, int hostidx,
                      unsigned char *sig, struct client_key_h *clientkey)
{
    uint8_t *verifydata;
    int verifylen;
    struct pr_destinfo_t *dest;

    dest = &group->destinfo[hostidx];

    if (group->version == UFTP4_VER_NUM) {
        verifydata = build_v4_verify_data(group, hostidx, &verifylen, 0);
    } else {
        verifydata = build_ds_client_key_sig(group, hostidx, &verifylen);
    }
    if (!verifydata) {
        glog1(group, "Rejecting CLIENT_KEY from %s: "
                     "error exporting client public key", dest->name);
        goto err_exit;
    }

    if (dest->client_pubkeytype == KEYBLOB_RSA) {
        if (!verify_RSA_sig(dest->client_pubkey.rsa, group->hashtype,verifydata,
                verifylen, sig, ntohs(clientkey->siglen))) {
            glog1(group, "Rejecting CLIENT_KEY from %s: verify data mismatch",
                         dest->name);
            goto err_exit;
        }
    } else {
        if (!verify_ECDSA_sig(dest->client_pubkey.ec,group->hashtype,verifydata,
                verifylen, sig, ntohs(clientkey->siglen))) {
            glog1(group, "Rejecting CLIENT_KEY from %s: verify data mismatch",
                         dest->name);
            goto err_exit;
        }
    }
    memset(sig, 0, ntohs(clientkey->siglen));
    create_client_context_2(dest->c_context1, dest->c_context1_len,
                            clientkey, clientkey->hlen * 4,
                            &dest->c_context2, &dest->c_context2_len);

    free(verifydata);
    return 1;

err_exit:
    if (dest->client_pubkeytype == KEYBLOB_RSA) {
        free_RSA_key(dest->client_pubkey.rsa);
    } else {
        free_EC_key(dest->client_pubkey.ec);
    }
    dest->client_pubkey.key = 0;
    dest->client_pubkeytype = 0;
    free(verifydata);
    return 0;
}

/**
 * Processes encryption key information received in a REGISTER message
 */
int handle_register_keys(const struct register_h *reg,
                         const unsigned char *enckey,
                         struct pr_group_list_t *group, int hostidx,
                         uint32_t src)
{
    struct pr_destinfo_t *dest;
    int dh_hash;
    union key_t dh_key;

    dest = &group->destinfo[hostidx];
    memcpy(dest->rand2, reg->rand2, sizeof(dest->rand2));
    if (!import_EC_key(&dest->client_dhkey.ec, enckey,
                       ntohs(reg->dhlen), 1)) {
        glog1(group, "Rejecting REGISTER from %s: "
                     "failed to import ECDH key", dest->name);
        return 0;
    }
    if (get_EC_curve(dest->client_dhkey.ec) !=
            get_EC_curve(group->proxy_d_dhkey.ec)) {
        glog1(group, "Rejecting REGISTER from %s: "
                     "invalid curve for ECDH", dest->name);
        free_EC_key(dest->client_dhkey.ec);
        return 0;
    }
    if (group->version == UFTP4_VER_NUM) {
        dh_hash = HASH_SHA1;
        if (proxy_type == RESPONSE_PROXY) {
            dh_key = v4_dhkey;
        } else {
            dh_key = group->proxy_d_dhkey;
        }
    } else {
        dh_hash = HASH_SHA256;
        dh_key = group->proxy_d_dhkey;
    }
    if (!get_ECDH_key(dest->client_dhkey.ec, dh_key.ec,
                      dest->premaster, &dest->premaster_len, dh_hash)) {
        glog1(group, "Rejecting REGISTER from %s: "
                     "failed to calculate premaster secret", dest->name);
        free_EC_key(dest->client_dhkey.ec);
        return 0;
    }

    if (group->version == UFTP4_VER_NUM) {
        calculate_v4_client_keys(group, hostidx);
    } else {
        create_client_context_1(group->s_context, group->s_context_len,
                group->p_context, group->p_context_len,
                dest->id, enckey, ntohs(reg->dhlen), reg->rand2,
                &dest->c_context1, &dest->c_context1_len);
        calculate_hs_keys(group->hashtype, dest->premaster, dest->premaster_len,
                          dest->c_context1, dest->c_context1_len, group->keylen,
                          group->ivlen, dest->s_hs_key, dest->s_hs_iv,
                          dest->c_hs_key, dest->c_hs_iv);
        if (!group->client_auth) {
            create_client_context_2(dest->c_context1, dest->c_context1_len,
                    NULL, 0, &dest->c_context2, &dest->c_context2_len);
        }
    }

    return 1;
}

/**
 * Handles an incoming REGSITER message from a client.
 */
void handle_register(struct pr_group_list_t *group, int hostidx,
                     const unsigned char *message, unsigned meslen,
                     uint32_t src)
{
    const struct register_h *reg;
    const unsigned char *enckey;
    struct pr_destinfo_t *dest;
    int dupmsg;
    int64_t regtime_usec;

    reg = (const struct register_h *)message;
    enckey = (const unsigned char *)reg + sizeof(struct register_h);

    if (group->destcount == MAXPROXYDEST) {
        glog1(group, "Rejecting REGISTER from %08X: max destinations exceeded",
                     ntohl(src));
        send_downstream_abort(group, src, "Max destinations exceeded", 0);
        return;
    }
    if ((meslen < (reg->hlen * 4U)) || ((reg->hlen * 4U) <
            sizeof(struct register_h) + ntohs(reg->dhlen))) {
        glog1(group, "Rejecting REGISTER from %08X: invalid message size",
                     ntohl(src));
        send_downstream_abort(group, src, "Invalid message size", 0);
        return;
    }

    if (hostidx == -1) {
        hostidx = add_client(src, group);
    }
    dest = &group->destinfo[hostidx];
    dupmsg = (dest->registered == 1);
    dest->registered = 1;
    if (group->version == UFTP4_VER_NUM) {
        dest->regtime.tv_sec = ntohl(reg->tstamp_hi);
        dest->regtime.tv_usec = ntohl(reg->tstamp_lo);
    } else {
        regtime_usec = (int64_t)ntohl(reg->tstamp_hi) << 32;
        regtime_usec |= ntohl(reg->tstamp_lo);
        dest->regtime = usec_to_tv(regtime_usec);
    }

    if (dest->state != PR_CLIENT_REGISTERED) {
        if ((group->keytype != KEY_NONE) && !dest->client_dhkey.ec) {
            if (!handle_register_keys(reg, enckey, group, hostidx, src)) {
                return;
            }
        }
        if (!group->client_auth || dest->client_pubkey.key) {
            dest->state = PR_CLIENT_REGISTERED;
        }
    }

    glog2(group, "Received REGISTER%s from %s", dupmsg ? "+" : "", dest->name);

    if (dest->state == PR_CLIENT_REGISTERED) {
        check_pending(group, hostidx, message);
    }
}

/**
 * Handles an incoming CLIENT_KEY message from a client.
 */
void handle_clientkey(struct pr_group_list_t *group, int hostidx,
                      unsigned char *message, unsigned meslen,
                      uint32_t src)
{
    struct client_key_h *clientkey;
    unsigned char *keyblob, *sig;
    struct pr_destinfo_t *dest;
    int dupmsg;
    struct register_h reg;

    if ((hostidx == -1) || (group->destinfo[hostidx].registered == 0)) {
        // We haven't gotten a REGISTER yet, so silently drop and wait for it
        // Can only happen under V4, since V5 CLIENT_KEY couldn't be decrypted
        return;
    }

    clientkey = (struct client_key_h *)message;
    keyblob = (unsigned char *)clientkey + sizeof(struct client_key_h);
    sig = keyblob + ntohs(clientkey->bloblen);

    if ((meslen < (clientkey->hlen * 4U)) ||
            ((clientkey->hlen * 4U) < sizeof(struct client_key_h) +
                ntohs(clientkey->bloblen) + ntohs(clientkey->siglen))) {
        glog1(group, "Rejecting CLIENT_KEY from %08X: invalid message size",
                     ntohl(src));
        send_downstream_abort(group, src, "Invalid message size", 0);
        return;
    }

    dest = &group->destinfo[hostidx];
    dupmsg = (dest->client_pubkey.key != 0);

    if (!dupmsg) {
        dest->client_pubkeytype = keyblob[0];
        if (dest->client_pubkeytype == KEYBLOB_RSA) {
            if (!import_RSA_key(&dest->client_pubkey.rsa, keyblob,
                                ntohs(clientkey->bloblen))) {
                glog1(group, "Failed to load client public key");
                send_downstream_abort(group, src,
                                      "Failed to load client public key", 0);
                return;
            }
        } else {
            if (!import_EC_key(&dest->client_pubkey.ec, keyblob,
                               ntohs(clientkey->bloblen), 0)) {
                glog1(group, "Failed to load client public key");
                send_downstream_abort(group, src,
                                      "Failed to load client public key", 0);
                return;
            }
        }
        if (!verify_fingerprint(client_fp, client_fp_count, keyblob,
                                ntohs(clientkey->bloblen), group, src)) {
            glog1(group, "Failed to verify client key fingerprint");
            if (dest->client_pubkeytype == KEYBLOB_RSA) {
                free_RSA_key(dest->client_pubkey.rsa);
            } else {
                free_EC_key(dest->client_pubkey.ec);
            }
            dest->client_pubkey.key = 0;
            dest->client_pubkeytype = 0;
            send_downstream_abort(group, src, 
                                  "Failed to verify client key fingerprint", 0);
            return;
        }

        if (!verify_client_key(group, hostidx, sig, clientkey)) {
            return;
        }
        dest->state = PR_CLIENT_REGISTERED;
    }

    glog2(group,"Received CLIENT_KEY%s from %s", dupmsg ? "+" : "", dest->name);

    // Pass in a dummy REGISTER message to check_pending, since
    // CLIENT_KEY is basically an extension of REGISTER.
    reg.func = REGISTER;
    check_pending(group, hostidx, (unsigned char *)&reg);
}

/**
 * Handles an incoming KEYINFO_ACK message from a client
 */
void handle_keyinfo_ack(struct pr_group_list_t *group, int hostidx,
                        const unsigned char *message, unsigned meslen)
{
    const struct keyinfoack_h *keyinfoack;
    const unsigned char *h_verify;
    unsigned char *verifydata, *verify_hash, *verify_test;
    int verifylen, len, dupmsg;
    unsigned int hashlen;
    struct pr_destinfo_t *dest;

    keyinfoack = (const struct keyinfoack_h *)message;
    h_verify = message + sizeof(struct keyinfoack_h);
    dest = &group->destinfo[hostidx];

    if ((meslen < (keyinfoack->hlen * 4U)) ||
            ((keyinfoack->hlen * 4U) < sizeof(struct keyinfoack_h))) {
        glog1(group, "Rejecting KEYINFO_ACK from %s: invalid message size",
                     dest->name);
        send_downstream_abort(group, dest->id, "Invalid message size", 0);
        return;
    }

    if (group->version == UFTP4_VER_NUM) {
        if (!(verifydata = build_v4_verify_data(group, hostidx,&verifylen,1))) {
            glog1(group, "Rejecting KEYINFO_ACK from %s: "
                         "error exporting client public key", dest->name);
            return;
        }
        verify_hash = safe_calloc(group->hashlen, 1);
        verify_test = safe_calloc(VERIFY4_LEN + group->hashlen, 1);
        hash(group->hashtype, verifydata, verifylen, verify_hash, &hashlen);
        PRF(group->hashtype, VERIFY4_LEN, group->groupmaster,
                sizeof(group->groupmaster), "client finished",
                verify_hash, group->hashlen, verify_test, &len);
        if (memcmp(h_verify, verify_test, VERIFY4_LEN)) {
            glog1(group, "Rejecting KEYINFO_ACK from %s: verify data mismatch",
                         dest->name);
            free(verifydata);
            free(verify_hash);
            free(verify_test);
            return;
        }

        free(verifydata);
        free(verify_hash);
        free(verify_test);
    } else {
        if (memcmp(h_verify, dest->verify_data, group->hashlen)) {
            glog1(group, "Rejecting KEYINFO_ACK from %s: verify data mismatch",
                         dest->name);
            return;
        }
    }

    dupmsg = (dest->state == PR_CLIENT_READY);
    glog2(group, "Received KEYINFO_ACK%s from %s", dupmsg ? "+" : "",
                 dest->name);
    dest->state = PR_CLIENT_READY;
    if (!check_unfinished_clients(group, 0)) {
        group->phase = PR_PHASE_RECEIVING;
    }
}

/**
 * Handles an incoming FILEINFO_ACK message from a client
 */
void handle_fileinfo_ack(struct pr_group_list_t *group, int hostidx,
                         const unsigned char *message, unsigned meslen)
{
    const struct fileinfoack_h *fileinfoack;
    struct pr_destinfo_t *dest;

    fileinfoack = (const struct fileinfoack_h *)message;
    dest = &group->destinfo[hostidx];

    if ((meslen < (fileinfoack->hlen * 4U)) ||
            ((fileinfoack->hlen * 4U) < sizeof(struct fileinfoack_h))) {
        log1(group->group_id, group->group_inst, ntohs(fileinfoack->file_id),
                "Rejecting FILEINFO_ACK from %s: invalid message size",
                dest->name);
        return;
    }

    log2(group->group_id, group->group_inst, ntohs(fileinfoack->file_id),
            "Received FILEINFO_ACK from %s", dest->name);
    check_pending(group, hostidx, message);
}

/**
 * Sends a PROXY_KEY from a response proxy when an ANNOUNCE is received
 */
void send_proxy_key(struct pr_group_list_t *group)
{
    unsigned char *packet, *keyblob, *dhblob, *sig, *sigcontext;
    struct uftp_h *header;
    struct proxy_key_h *proxykey;
    unsigned int meslen, siglen, sigcontextlen;
    uint16_t bloblen, dhlen;
    const char *sig_context_str = "UFTP 5, PROXY_KEY";

    packet = safe_calloc(MAXMTU, 1);

    header = (struct uftp_h *)packet;
    proxykey = (struct proxy_key_h *)(packet + sizeof(struct uftp_h));
    keyblob = (unsigned char *)proxykey + sizeof(struct proxy_key_h);

    set_uftp_header(header, PROXY_KEY, group);
    proxykey->func = PROXY_KEY;

    if (group->keytype != KEY_NONE) {
        if (group->proxy_privkeytype == KEYBLOB_RSA) {
            if (!export_RSA_key(group->proxy_privkey.rsa, keyblob, &bloblen)) {
                glog0(group, "Error exporting public key");
                free(packet);
                return;
            }
        } else {
            if (!export_EC_key(group->proxy_privkey.ec, keyblob, &bloblen)) {
                glog0(group, "Error exporting public key");
                free(packet);
                return;
            }
        }
        dhblob = keyblob + bloblen;
        if (!export_EC_key(group->proxy_d_dhkey.ec, dhblob, &dhlen)) {
            glog0(group, "Error exporting DH public key");
            free(packet);
            return;
        }
        sig = dhblob + dhlen;

        proxykey->bloblen = htons(bloblen);
        proxykey->dhlen = htons(dhlen);
        if (group->proxy_privkeytype == KEYBLOB_RSA) {
            proxykey->siglen = htons(RSA_keylen(group->proxy_privkey.rsa));
        } else {
            proxykey->siglen = htons(ECDSA_siglen(group->proxy_privkey.ec));
        }
        proxykey->hlen = (uint8_t)((sizeof(struct proxy_key_h) +
                            bloblen + dhlen + ntohs(proxykey->siglen)) / 4);

        if (!group->p_context) {
            create_proxy_context(uid, proxykey, &group->p_context,
                                 &group->p_context_len);
        }

        sigcontext = safe_malloc(strlen(sig_context_str) + group->s_context_len+
                                 group->p_context_len);
        sigcontextlen = 0;
        memcpy(sigcontext + sigcontextlen, sig_context_str,
                strlen(sig_context_str));
        sigcontextlen += (unsigned)strlen(sig_context_str);
        memcpy(sigcontext + sigcontextlen, group->s_context,
                group->s_context_len);
        sigcontextlen += group->s_context_len;
        memcpy(sigcontext + sigcontextlen, group->p_context,
                group->p_context_len);
        sigcontextlen += group->p_context_len;

        if (group->proxy_privkeytype == KEYBLOB_RSA) {
            if (!create_RSA_sig(group->proxy_privkey.rsa, group->hashtype,
                        sigcontext, sigcontextlen, sig, &siglen)) {
                glog0(group, "Error signing context");
                free(packet);
                free(sigcontext);
                return;
            }
        } else {
            if (!create_ECDSA_sig(group->proxy_privkey.ec, group->hashtype,
                    sigcontext, sigcontextlen, sig, &siglen)) {
                glog0(group, "Error signing context");
                free(packet);
                free(sigcontext);
                return;
            }
        }
        free(sigcontext);
        if (siglen != ntohs(proxykey->siglen)) {
            glog0(group, "Signature length doesn't match expected length");
            glog1(group, "expected %d, got %d", ntohs(proxykey->siglen),siglen);
            free(packet);
            return;
        }
    } else {
        proxykey->hlen = (uint8_t)sizeof(struct proxy_key_h) / 4;
        proxykey->bloblen = 0;
        proxykey->dhlen = 0;
        proxykey->siglen = 0;
    }

    meslen = sizeof(struct uftp_h) + (proxykey->hlen * 4);
    glog2(group, "Sending PROXY_KEY");
    if (nb_sendto(listener, packet, meslen, 0,
               (struct sockaddr *)&group->publicmcast,
                family_len(group->publicmcast)) == SOCKET_ERROR) {
        gsockerror(group, "Error sending PROXY_KEY");
    }

    free(packet);
}

/**
 * Sends a KEYINFO to each client that the server sent a REG_CONF for.
 */
void send_keyinfo(struct pr_group_list_t *group, const uint32_t *addrlist,
                  int addrlen)
{
    unsigned char *buf, *iv;
    struct uftp_h *header;
    struct keyinfo_h *keyinfo_hdr;
    struct destkey *keylist;
    unsigned int packetlen, enclen, siglen, _siglen;
    int maxdest, packetcnt, dests, iv_init, foundaddr, i, j;
    int local_keytype, local_keylen, local_ivlen, local_groupmasterlen;
    unsigned char *local_groupmaster;
    struct pr_destinfo_t *dest;
    unsigned char *sig, *sigcopy, *sigcontext, *aadcontext;
    unsigned int basesigcontextlen, sigcontextlen, baseaadlen, aadlen;
    const char *sig_context_str = "UFTP 5, KEYINFO";
    const char *aad_context_str = "UFTP 5, group master";

    if (group->version == UFTP4_VER_NUM) {
        // Don't use a cipher in an authentication mode to encrypt the group master
        local_keytype = unauth_key(group->keytype);
        get_key_info(local_keytype, &local_keylen, &local_ivlen);
        siglen = 0; 
        sigcontext = NULL;
        aadcontext = NULL;
        sigcontextlen = 0;
        aadlen = 0;
        sigcopy = NULL;
    } else {
        local_keytype = group->keytype;
        local_keylen = group->keylen;
        local_ivlen = group->ivlen;
        if (group->proxy_privkeytype == KEYBLOB_RSA) {
            siglen = RSA_keylen(group->proxy_privkey.rsa);
        } else {
            siglen = ECDSA_siglen(group->proxy_privkey.ec);
        }

        sigcontext = safe_malloc(strlen(sig_context_str) +
                        group->s_context_len + group->p_context_len + MAXMTU);
        aadcontext = safe_malloc(strlen(aad_context_str) + MAXMTU);
        sigcopy = safe_malloc(siglen);
        sigcontextlen = 0;
        memcpy(sigcontext + sigcontextlen, sig_context_str,
                strlen(sig_context_str));
        sigcontextlen += (unsigned)strlen(sig_context_str);
        memcpy(sigcontext + sigcontextlen, group->s_context,
                group->s_context_len);
        sigcontextlen += group->s_context_len;
        memcpy(sigcontext + sigcontextlen, group->p_context,
                group->p_context_len);
        sigcontextlen += group->p_context_len;
        basesigcontextlen = sigcontextlen;
        aadlen = 0;
        memcpy(aadcontext + aadlen, aad_context_str, strlen(aad_context_str));
        aadlen += (unsigned)strlen(aad_context_str);
        baseaadlen = aadlen;
    }

    buf = safe_calloc(MAXMTU, 1);
    iv = safe_calloc(local_ivlen, 1);
    header = (struct uftp_h *)buf;
    keyinfo_hdr = (struct keyinfo_h *)(buf + sizeof(struct uftp_h));

    set_uftp_header(header, KEYINFO, group);
    if (group->version == UFTP4_VER_NUM) {
        header->src_id = group->src_id;
    }
    keyinfo_hdr->func = KEYINFO;
    keyinfo_hdr->hlen = (uint8_t)((sizeof(struct keyinfo_h) + siglen) / 4);
    keyinfo_hdr->siglen = htons(siglen);
    sig = (uint8_t *)keyinfo_hdr + sizeof(struct keyinfo_h);
    keylist = (struct destkey *)(sig + siglen);

    iv_init = 0;
    maxdest = max_msg_dest(group, KEYINFO, keyinfo_hdr->hlen * 4);
    packetcnt = 1;
    for (i = 0, dests = 0; i < group->destcount; i++) {
        dest = &group->destinfo[i];
        if (dest->state == PR_CLIENT_CONF) {
            if (addrlist) {
                // We just got a REG_CONF, so only send to listed hosts
                for (j = 0, foundaddr = 0; (j < addrlen) && (!foundaddr); j++) {
                    if (dest->id == addrlist[j]) {
                        foundaddr = 1;
                    }
                }
            } else {
                foundaddr = 1;
            }
            if (foundaddr) {
                if (!iv_init) {
                    group->ivctr++;
                    keyinfo_hdr->iv_ctr_hi =
                            htonl((group->ivctr & 0xFFFFFFFF00000000LL) >> 32);
                    keyinfo_hdr->iv_ctr_lo =
                            htonl(group->ivctr & 0x00000000FFFFFFFFLL);
                    iv_init = 1;
                }
                keylist[dests].dest_id = dest->id;
                if (header->version == UFTP4_VER_NUM) {
                    build_iv4(iv, dest->s_hs_iv, local_ivlen,
                              uftp_htonll(group->ivctr), header->src_id);
                    local_groupmaster = &group->groupmaster[1];
                    local_groupmasterlen = MASTER4_LEN - 1;
                    if (!dest->has_app_keys) {
                        memcpy(dest->c_app_key, group->c_app_key,group->keylen);
                        memcpy(dest->c_app_iv, group->c_app_iv, SALT_LEN);
                        dest->has_app_keys = 1;
                    }
                } else {
                    build_iv(iv, dest->s_hs_iv, local_ivlen,
                             uftp_htonll(group->ivctr));
                    local_groupmaster = group->groupmaster;
                    local_groupmasterlen = MASTER_LEN;
                    memcpy(aadcontext + baseaadlen, dest->c_context2,
                            dest->c_context2_len);
                    aadlen = baseaadlen + dest->c_context2_len;
                    if (!dest->has_app_keys) {
                        calculate_client_app_keys(group->hashtype, 
                                group->groupmaster, MASTER_LEN,
                                dest->c_context2, dest->c_context2_len,
                                group->keylen, group->ivlen,
                                dest->c_app_key, dest->c_app_iv,
                                dest->finished_key, dest->verify_data);
                        dest->has_app_keys = 1;
                    }
                }
                if (!encrypt_block(local_keytype, iv, dest->s_hs_key,
                                   aadcontext, aadlen, local_groupmaster,
                                   local_groupmasterlen,
                                   keylist[dests].groupmaster, &enclen)) {
                    glog0(group, "Error encrypting KEYINFO for %s", dest->name);
                    goto cleanup;
                }
                dests++;
            }
        }
        if ((dests >= maxdest) ||
                ((i == group->destcount - 1) && (dests > 0))) {
            packetlen = sizeof(struct uftp_h) + sizeof(struct keyinfo_h) +
                         siglen + (dests * sizeof(struct destkey));

            if (group->version != UFTP4_VER_NUM) {
                memset(sig, 0, siglen);
                memcpy(sigcontext + basesigcontextlen, buf, packetlen);
                sigcontextlen = basesigcontextlen + packetlen;
                if (group->proxy_privkeytype == KEYBLOB_EC) {
                    if (!create_ECDSA_sig(group->proxy_privkey.ec,
                                          group->hashtype, sigcontext,
                                          sigcontextlen, sigcopy, &_siglen)) {
                        // Called function should log
                        goto cleanup;
                    }
                } else {
                    if (!create_RSA_sig(group->proxy_privkey.rsa,
                                        group->hashtype, sigcontext,
                                        sigcontextlen, sigcopy, &_siglen)) {
                        // Called function should log
                        goto cleanup;
                    }
                }
                if (_siglen != siglen) {
                    glog0(group, "Signature length doesn't match expected length");
                    glog1(group, "expected %d, got %d", siglen, _siglen);
                    goto cleanup;
                }
                memcpy(sig, sigcopy, siglen);
            }

            glog2(group,"Sending KEYINFO %d.%d", group->keyinfo_cnt, packetcnt);
            if (nb_sendto(listener, buf, packetlen, 0,
                       (struct sockaddr *)&group->privatemcast,
                        family_len(group->privatemcast)) == SOCKET_ERROR) {
                gsockerror(group, "Error sending KEYINFO");
                goto cleanup;
            }
            // TODO: This value is good for around 100Mbps.  This is under the
            // assumption that the client proxy is local to the clients
            // it serves.  This should probably be a parameter.
            usleep(120);
            memset(keylist, 0, maxdest * sizeof(struct destkey));
            iv_init = 0;
            dests = 0;
            packetcnt++;
        }
    }
    group->keyinfo_cnt++;
    set_timeout(group, 0, 0);

cleanup:
    free(sigcontext);
    free(aadcontext);
    free(sigcopy);
    free(buf);
    free(iv);
}

/**
 * Handles an incoming STATUS message from a client
 */
void handle_status(struct pr_group_list_t *group, int hostidx,
                   const unsigned char *message, unsigned meslen)
{
    const struct status_h *status;
    int mes_section;
    struct pr_destinfo_t *dest;

    status = (const struct status_h *)message;
    mes_section = ntohs(status->section);
    dest = &group->destinfo[hostidx];

    if ((meslen < (status->hlen * 4U)) ||
            ((status->hlen * 4U) < sizeof(struct status_h))) {
        log1(group->group_id, group->group_inst, ntohs(status->file_id),
                "Rejecting STATUS from %s: invalid message size", dest->name);
        return;
    }

    log2(group->group_id, group->group_inst, ntohs(status->file_id),
            "Got STATUS for section %d from %s", mes_section, dest->name);

    check_pending(group, hostidx, message);
}

/**
 * Handles an incoming COMPLETE message from a client
 */
void handle_complete(struct pr_group_list_t *group, int hostidx,
                     const unsigned char *message, unsigned meslen)
{
    const struct complete_h *complete;
    struct pr_destinfo_t *dest;
    int alldone, i;
    char status[20];

    complete = (const struct complete_h *)message;
    dest = &group->destinfo[hostidx];

    if ((meslen < (complete->hlen * 4U)) ||
            ((complete->hlen * 4U) < sizeof(struct complete_h))) {
        log1(group->group_id, group->group_inst, ntohs(complete->file_id),
                "Rejecting COMPLETE from %s: invalid message size", dest->name);
        return;
    }

    switch (complete->status) {
    case COMP_STAT_NORMAL:
        strncpy(status, "", sizeof(status));
        break;
    case COMP_STAT_SKIPPED:
        strncpy(status, "(skipped)", sizeof(status));
        break;
    case COMP_STAT_OVERWRITE:
        strncpy(status, "(overwritten)", sizeof(status));
        break;
    case COMP_STAT_REJECTED:
        strncpy(status, "(rejected)", sizeof(status));
        break;
    }
    log2(group->group_id, group->group_inst, ntohs(complete->file_id),
            "Received COMPLETE%s from %s", status, dest->name);

    if (ntohs(complete->file_id) == 0) {
        dest->state = PR_CLIENT_DONE;
        for (alldone = 1, i = 0;
                (i < group->destcount) && alldone; i++) {
            alldone = alldone && (group->destinfo[i].state == PR_CLIENT_DONE);
        }
        if (alldone) {
            group->phase = PR_PHASE_DONE;
        }
    }

    check_pending(group, hostidx, message);
}


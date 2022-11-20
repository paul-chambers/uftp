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
#include <time.h>
#include <errno.h>

#ifdef WINDOWS

#include <ws2tcpip.h>

#include "win_func.h"

#else

#include <unistd.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#endif

#include "proxy.h"
#include "proxy_common.h"
#include "proxy_upstream.h"
#include "proxy_downstream.h"

/**
 * Finds next open slot in the global group list.
 * Returns a pointer to the open slot, or NULL if none found.
 */
struct pr_group_list_t *find_open_slot(void)
{
    int i;

    for (i = 0; i < MAXLIST; i++) {
        if (group_list[i].group_id == 0) {
            memset(&group_list[i], 0, sizeof(group_list[i]));
            return &group_list[i];
        }
    }
    return NULL;
}

/**
 * Calculate the master key and do key expansion to determine the symmetric
 * cypher key and IV salt, and hash key for the server
 */
int calculate_v4_server_keys(struct pr_group_list_t *group,
                             const struct enc_info_he *encinfo)
{
    unsigned char *seed, *prf_buf;
    int explen, len, seedlen;
    time_t t;
    uint32_t t2;
    unsigned char master[MASTER4_LEN];

    memcpy(group->rand1, encinfo->rand1, sizeof(encinfo->rand1));
    if (!get_random_bytes(group->rand2, sizeof(group->rand2))) {
        glog0(group, "Failed to get random bytes for rand2");
        send_upstream_abort(group, 0, "Failed to get random bytes for rand2");
        return 0;
    }
    // Sets the first 4 bytes of rand2 to the current time
    t = time(NULL);
    t2 = (uint32_t)(t & 0xFFFFFFFF);
    memcpy(&group->rand2, &t2, sizeof(t2));
    if (!get_ECDH_key(group->server_dhkey.ec, group->proxy_u_dhkey.ec,
                      group->premaster, &group->premaster_len, HASH_SHA1)) {
        glog0(group, "Failed to calculate ECDH key");
        send_upstream_abort(group, 0, "Failed to calculate ECDH key");
        return 0;
    }

    get_key_info(group->keytype, &group->keylen, &group->ivlen);
    group->hashlen = get_hash_len(group->hashtype);

    explen = group->keylen + SALT_LEN + group->hashlen;
    seedlen = RAND_LEN * 2;
    seed = safe_calloc(seedlen, 1);
    prf_buf = safe_calloc(MASTER4_LEN + explen + group->hashlen, 1);

    memcpy(seed, group->rand1, sizeof(group->rand1));
    memcpy(seed + sizeof(group->rand1), group->rand2, sizeof(group->rand2));
    PRF(group->hashtype, MASTER4_LEN, group->premaster, group->premaster_len,
            "master secret", seed, seedlen, prf_buf, &len);
    memcpy(master, prf_buf, sizeof(master));

    PRF(group->hashtype, explen, master, sizeof(master),
            "key expansion", seed, seedlen, prf_buf, &len);
    // bypass hmac key since it isn't being used
    // v4 uses same key for both client and server
    memcpy(group->c_hs_key, prf_buf + group->hashlen, group->keylen);
    memcpy(group->s_hs_key, prf_buf + group->hashlen, group->keylen);
    memcpy(group->c_hs_iv, prf_buf + group->hashlen + group->keylen, SALT_LEN);
    memcpy(group->s_hs_iv, prf_buf + group->hashlen + group->keylen, SALT_LEN);

    free(seed);
    free(prf_buf);
    return 1;
}

/**
 * Calculate hs_secret and do key expansion to determine the
 * handshake keys for proxy (as client) and server
 */
int calculate_client_keys(struct pr_group_list_t *group)
{
    unsigned char *keydata;
    uint16_t keylen;

    if (!get_ECDH_key(group->server_dhkey.ec, group->proxy_u_dhkey.ec,
            group->premaster, &group->premaster_len, HASH_SHA256)) {
        glog0(group, "Failed to calculate ECDH key");
        send_upstream_abort(group, 0, "Failed to calculate ECDH key");
        return 0;
    }

    keydata = safe_malloc(sizeof(struct ec_blob_t) +
                          EC_keylen(group->proxy_u_dhkey.ec));
    if (!export_EC_key(group->proxy_u_dhkey.ec, keydata, &keylen)) {
        glog0(group, "Error exporting ECDH public key");
        send_upstream_abort(group, 0, "Error exporting ECDH public key");
        free(keydata);
        return 0;
    }
    create_client_context_1(group->s_context, group->s_context_len,
                            NULL, 0, uid, keydata, keylen, group->rand2,
                            &group->c_context1, &group->c_context1_len);
    calculate_hs_keys(group->hashtype, group->premaster, group->premaster_len,
                      group->c_context1, group->c_context1_len, group->keylen,
                      group->ivlen, group->s_hs_key, group->s_hs_iv,
                      group->c_hs_key, group->c_hs_iv);
    free(keydata);
    return 1;
}

/**
 * Calculate server context,
 * calculate hs_secret, and do handshake key expansion
 */
int calculate_server_keys(struct pr_group_list_t *group,
                          const struct enc_info_he *encinfo)
{

    if (!get_random_bytes(group->rand2, sizeof(group->rand2))) {
        glog0(group, "Failed to get random bytes for rand2");
        send_upstream_abort(group, 0, "Failed to get random bytes for rand2");
        return 0;
    }

    get_key_info(group->keytype, &group->keylen, &group->ivlen);
    group->hashlen = get_hash_len(group->hashtype);

    create_server_context(htonl(group->group_id), group->group_inst,
                          group->src_id, encinfo, encinfo->extlen * 4,
                          &group->s_context, &group->s_context_len);
    return calculate_client_keys(group);
}


/**
 * Read encryption related fields from an ANNOUNCE
 */
int read_announce_encryption(struct pr_group_list_t *group,
                             struct enc_info_he *encinfo,
                             const unsigned char *packet, int packetlen)
{
    unsigned char *keys, *dhblob, *sig, *sigcopy;
    int siglen, i, rval;

    keys = (unsigned char *)encinfo + sizeof(struct enc_info_he);
    dhblob = keys + ntohs(encinfo->keylen);
    sig = dhblob + ntohs(encinfo->dhlen);

    // Sanity check the selected encryption parameters
    if (!cipher_supported(encinfo->keytype)) {
        glog1(group, "Keytype invalid or not supported here");
        send_upstream_abort(group, 0, "Keytype invalid or not supported here");
        return 0;
    }
    if (!hash_supported(encinfo->hashtype)) {
        glog1(group, "Hashtype invalid or not supported here");
        send_upstream_abort(group, 0, "Hashtype invalid or not supported here");
        return 0;
    }
    if (group->version == UFTP4_VER_NUM) {
        // only accept ECDH and AEAD ciphers from v4 servers
        int keyextype = (encinfo->keyextype_sigtype & 0xF0) >> 4;
        int sigtype = encinfo->keyextype_sigtype & 0x0F;
        if (sigtype != SIG_AUTHENC) {
            glog1(group, "Invalid sigtype specified");
            send_upstream_abort(group, 0, "Invalid sigtype specified");
            return 0;
        }
        if ((keyextype != KEYEX_ECDH_RSA) && (keyextype != KEYEX_ECDH_ECDSA)) {
            glog1(group, "Invalid keyextype specified");
            send_upstream_abort(group, 0, "Invalid keyextype specified");
            return 0;
        }
    }
    group->keytype = encinfo->keytype;
    group->hashtype = encinfo->hashtype;
    group->client_auth = ((encinfo->flags & FLAG_CLIENT_AUTH) != 0);
    memcpy(group->rand1, encinfo->rand1, sizeof(encinfo->rand1));

    if (!verify_fingerprint(server_fp, server_fp_count, keys,
                            ntohs(encinfo->keylen), group, group->src_id)) {
        glog1(group, "Failed to verify server key fingerprint");
        send_upstream_abort(group,0, "Failed to verify server key fingerprint");
        return 0;
    }

    group->server_pubkeytype = keys[0];
    if (group->server_pubkeytype == KEYBLOB_RSA) {
        if (!import_RSA_key(&group->server_pubkey.rsa, keys,
                            ntohs(encinfo->keylen))) {
            glog1(group, "Failed to load server public key");
            send_upstream_abort(group, 0, "Failed to load server public key");
            return 0;
        }
    } else {
        if (!import_EC_key(&group->server_pubkey.ec, keys,
                           ntohs(encinfo->keylen), 0)) {
            glog1(group, "Failed to load server public key");
            send_upstream_abort(group, 0, "Failed to load server public key");
            return 0;
        }
    }
    if (group->version == UFTP4_VER_NUM) {
        for (i = 0; i < key_count; i++) {
            if (((group->server_pubkeytype == KEYBLOB_RSA) &&
                     (privkey_type[i] == KEYBLOB_RSA) &&
                        RSA_keylen(group->server_pubkey.rsa) ==
                            RSA_keylen(privkey[i].rsa)) ||
                    ((group->server_pubkeytype == KEYBLOB_EC) &&
                     (privkey_type[i] == KEYBLOB_EC) &&
                        get_EC_curve(group->server_pubkey.ec) ==
                            get_EC_curve(privkey[i].ec))) {
                group->proxy_privkey = privkey[i];
                group->proxy_privkeytype = privkey_type[i];
                break;
            }
        }
        if (!group->proxy_privkey.key) {
            glog1(group, "No proxy key compatible with server key");
            send_upstream_abort(group,0, "No proxy key compatible with server key");
            return 0;
        }
    } else {
        group->proxy_privkey = privkey[0];
        group->proxy_privkeytype = privkey_type[0];
    }
    if (!import_EC_key(&group->server_dhkey.ec, dhblob,
                       ntohs(encinfo->dhlen), 1)) {
        glog1(group, "Failed to load server public ECDH key");
        send_upstream_abort(group, 0,
                "Failed to load server public ECDH key");
        return 0;
    }

    group->proxy_u_dhkey.ec =
            gen_EC_key(get_EC_curve(group->server_dhkey.ec), 1, NULL);
    if (!group->proxy_u_dhkey.key) {
        glog0(group, "Failed to generate upstream proxy ECDH key");
        send_upstream_abort(group, 0,
                "Failed to generate upstream proxy ECDH key");
        return 0;
    }
    group->proxy_d_dhkey.ec =
            gen_EC_key(get_EC_curve(group->server_dhkey.ec), 1, NULL);
    if (!group->proxy_d_dhkey.key) {
        glog0(group, "Failed to generate downstream proxy ECDH key");
        send_upstream_abort(group, 0,
                "Failed to generate downstream proxy ECDH key");
        return 0;
    }

    siglen = ntohs(encinfo->siglen);
    sigcopy = safe_calloc(siglen, 1);
    memcpy(sigcopy, sig, siglen);
    memset(sig, 0, siglen);
    if (group->server_pubkeytype == KEYBLOB_RSA) {
        if (!verify_RSA_sig(group->server_pubkey.rsa, group->hashtype,
                            packet, packetlen, sigcopy, siglen)) {
            glog1(group, "Signature verification failed");
            send_upstream_abort(group, 0, "Signature verification failed");
            free(sigcopy);
            return 0;
        }
    } else {
        if (!verify_ECDSA_sig(group->server_pubkey.ec, group->hashtype,
                              packet, packetlen, sigcopy, siglen)) {
            glog1(group, "Signature verification failed");
            send_upstream_abort(group, 0, "Signature verification failed");
            free(sigcopy);
            return 0;
        }
    }

    // Calculate keys
    if (group->version == UFTP4_VER_NUM) {  
        rval = calculate_v4_server_keys(group, encinfo);
    } else {
        rval = calculate_server_keys(group, encinfo);
    }

    memcpy(sig, sigcopy, siglen);
    free(sigcopy);
    return rval;
}

/**
 * Read in the contents of an ANNOUNCE.
 */
int read_announce(struct pr_group_list_t *group, unsigned char *packet,
                  const union sockaddr_u *src, int packetlen)
{
    struct uftp_h *header;
    struct announce_h *announce;
    struct enc_info_he *encinfo;
    uint8_t *publicmcast, *privatemcast;
    uint8_t *he;
    unsigned int iplen, extlen;

    header = (struct uftp_h *)packet;
    announce = (struct announce_h *)(packet + sizeof(struct uftp_h));
    encinfo = NULL;

    group->version = header->version;
    group->group_id = ntohl(header->group_id);
    group->group_inst = header->group_inst;
    group->up_addr = *src;
    group->src_id = header->src_id;
    group->grtt = unquantize_grtt(header->grtt);
    group->robust = announce->robust;
    group->cc_type = announce->cc_type;
    group->gsize = unquantize_gsize(header->gsize);
    group->blocksize = ntohs(announce->blocksize);
    iplen = ((announce->flags & FLAG_IPV6) != 0) ?
                sizeof(struct in6_addr) : sizeof(struct in_addr);
    publicmcast = ((uint8_t *)announce) + sizeof(struct announce_h);
    privatemcast = publicmcast + iplen;
    if ((announce->flags & FLAG_IPV6) != 0) {
        group->publicmcast.sin6.sin6_family = AF_INET6;
        group->privatemcast.sin6.sin6_family = AF_INET6;
        memcpy(&group->publicmcast.sin6.sin6_addr.s6_addr, publicmcast, iplen);
        memcpy(&group->privatemcast.sin6.sin6_addr.s6_addr, privatemcast,iplen);
        group->publicmcast.sin6.sin6_port = htons(out_port);
        group->privatemcast.sin6.sin6_port = htons(out_port);
    } else {
        group->publicmcast.sin.sin_family = AF_INET;
        group->privatemcast.sin.sin_family = AF_INET;
        memcpy(&group->publicmcast.sin.sin_addr.s_addr, publicmcast, iplen);
        memcpy(&group->privatemcast.sin.sin_addr.s_addr, privatemcast, iplen);
        group->publicmcast.sin.sin_port = htons(out_port);
        group->privatemcast.sin.sin_port = htons(out_port);
    }

    if ((announce->hlen * 4U) < sizeof(struct announce_h) + (2U * iplen)) {
        glog1(group, "Rejecting ANNOUNCE from %08X: invalid header size",
                     ntohl(group->src_id));
        send_upstream_abort(group, 0, "Invalid header size");
        return 0;
    }
    if ((announce->hlen * 4U) > sizeof(struct announce_h) + (2U * iplen)) {
        he = (uint8_t *)announce + sizeof(struct announce_h) + (2U * iplen);
        if (*he == EXT_ENC_INFO) {
            encinfo = (struct enc_info_he *)he;
            extlen = encinfo->extlen * 4U;
            if ((extlen > ((announce->hlen * 4U) -
                            sizeof(struct announce_h))) ||
                    (extlen < sizeof(struct enc_info_he)) ||
                    (extlen != (sizeof(struct enc_info_he) +
                                ntohs(encinfo->keylen) + ntohs(encinfo->dhlen) +
                                ntohs(encinfo->siglen)))) {
                glog1(group, "Rejecting ANNOUNCE from %08X: "
                             "invalid extension size", ntohl(group->src_id));
                send_upstream_abort(group, 0, "Invalid extension size");
                return 0;
            }
        }
    }

    if ((encinfo != NULL) && (proxy_type != SERVER_PROXY)) {
        if (!read_announce_encryption(group, encinfo, packet, packetlen)) {
            return 0;
        }
    } else {
        group->keytype = KEY_NONE;
        group->hashtype = HASH_NONE;
        group->client_auth = 0;
    }

    gettimeofday(&group->phase_expire_time, NULL);
    if (group->robust * group->grtt < 1.0) {
        add_timeval_d(&group->phase_expire_time, 1.0);
    } else {
        add_timeval_d(&group->phase_expire_time, group->robust * group->grtt);
    }

    // Size of data packet, used in transmission speed calculations
    group->datapacketsize = group->blocksize + sizeof(struct fileseg_h);
    if (group->cc_type == CC_TFMCC) {
        group->datapacketsize += sizeof(struct tfmcc_data_info_he);
    }
    if (group->keytype != KEY_NONE) {
        group->datapacketsize += KEYBLSIZE + sizeof(struct encrypted_h);
    }
    // 8 = UDP size, 20 = IPv4 size, 40 = IPv6 size
    if ((announce->flags & FLAG_IPV6) != 0) {
        group->datapacketsize += sizeof(struct uftp_h) + 8 + 40;
    } else {
        group->datapacketsize += sizeof(struct uftp_h) + 8 + 20;
    }

    return 1;
}

/**
 * Inserts the proxy's public keys into an ANNOUNCE
 * Returns 1 on success, 0 on fail
 */
int insert_pubkey_in_announce(struct pr_group_list_t *group,
                              unsigned char *packet, int packetlen)
{
    struct announce_h *announce;
    struct enc_info_he *encinfo;
    unsigned char *keyblob, *dhkeyblob;
    uint16_t bloblen;
    unsigned int iplen;

    announce = (struct announce_h *)(packet + sizeof(struct uftp_h));
    iplen = ((announce->flags & FLAG_IPV6) != 0) ? 16 : 4;
    encinfo = (struct enc_info_he *)
            ((uint8_t *)announce + sizeof(struct announce_h) + (2U * iplen));
    keyblob = ((unsigned char *)encinfo + sizeof(struct enc_info_he));
    dhkeyblob = keyblob + ntohs(encinfo->keylen);

    if ((group->version == UFTP4_VER_NUM) && (group->keytype != KEY_NONE) &&
            (proxy_type == CLIENT_PROXY)) {
        // Plug in proxy's public key for server's
        if (group->server_pubkeytype == KEYBLOB_RSA) {
            if (!export_RSA_key(group->proxy_privkey.rsa, keyblob, &bloblen)) {
                glog0(group, "Error exporting proxy public key");
                return 0;
            }
        } else {
            if (!export_EC_key(group->proxy_privkey.ec, keyblob, &bloblen)) {
                glog0(group, "Error exporting proxy public key");
                return 0;
            }
        }
        if (bloblen != ntohs(encinfo->keylen)) {
            glog0(group, "Incorrect exported proxy key size");
            return 0;
        }
        if (!export_EC_key(group->proxy_d_dhkey.ec, dhkeyblob, &bloblen)) {
            glog0(group, "Error exporting proxy ECDH public key");
            return 0;
        }
        if (bloblen != ntohs(encinfo->dhlen)) {
            glog0(group, "Incorrect exported proxy ECDH key size");
            return 0;
        }

    }
    return 1;
}

/**
 * Handles an incoming ANNOUNCE message from a server.
 * Sets up encryption if specified and forwards message.
 */
void handle_announce(struct pr_group_list_t *group,
                     const union sockaddr_u *src, unsigned char *packet,
                     unsigned packetlen)
{
    struct uftp_h *header;
    struct announce_h *announce;
    char pubname[INET6_ADDRSTRLEN], privname[INET6_ADDRSTRLEN];
    int rval;

    header = (struct uftp_h *)packet;
    announce = (struct announce_h *)(packet + sizeof(struct uftp_h));

    if ((packetlen < sizeof(struct uftp_h) + (announce->hlen * 4)) ||
            ((announce->hlen * 4) < sizeof(struct announce_h))) {
        glog1(group, "Rejecting ANNOUNCE from %08X: "
                "invalid message size", ntohl(header->src_id));
        return;
    }

    if (group == NULL) {
        if ((group = find_open_slot()) == NULL ) {
            log1(ntohl(header->group_id), group->group_inst, 0,
                    "Error: maximum number of incoming files exceeded: %d\n",
                    MAXLIST);
            return;
        }
        if (!read_announce(group, packet, src, packetlen)) {
            return;
        }
        if ((rval = getnameinfo((struct sockaddr *)&group->publicmcast,
                family_len(group->publicmcast), pubname, sizeof(pubname),
                NULL, 0, NI_NUMERICHOST)) != 0) {
            glog1(group, "getnameinfo failed: %s", gai_strerror(rval));
        }
        if ((rval = getnameinfo((struct sockaddr *)&group->privatemcast,
                family_len(group->privatemcast), privname, sizeof(privname),
                NULL, 0, NI_NUMERICHOST)) != 0) {
            glog1(group, "getnameinfo failed: %s", gai_strerror(rval));
        }

        glog2(group, "Received request from %08X", ntohl(group->src_id));
        glog2(group, "Using public multicast address %s", pubname);
        glog2(group, "Using private multicast address %s",privname);

        if (!addr_blank(&group->privatemcast) && (proxy_type != CLIENT_PROXY)) {
            if (use_ssm) {
                if (!is_multicast(&group->privatemcast, 1)) {
                    glog1(group,"Invalid source specific multicast address: %s",
                                privname);
                    send_upstream_abort(group, 0,
                            "Invalid source specific multicast address");
                    return;
                }
            } else {
                if (!is_multicast(&group->privatemcast, 0)) {
                    glog1(group, "Invalid multicast address: %s", privname);
                    send_upstream_abort(group, 0, "Invalid multicast address");
                    return;
                }
            }
            if (!other_mcast_users(group)) {
                if (use_ssm) {
                    if (!multicast_join(listener, group->group_id,
                            &group->privatemcast, m_interface, interface_count,
                            server_fp, server_fp_count)) {
                        send_upstream_abort(group, 0,
                                "Error joining multicast group");
                        return;
                    }
                } else {
                    if (!multicast_join(listener, group->group_id,
                            &group->privatemcast, m_interface, interface_count,
                            NULL, 0)) {
                        send_upstream_abort(group, 0,
                                "Error joining multicast group");
                        return;
                    }
                }
            }
            group->multi_join = 1;
        }
        group->phase = PR_PHASE_REGISTERED;
    }

    if (insert_pubkey_in_announce(group, packet, packetlen)) {
        forward_message(group, src, packet, packetlen);
    }
    if ((group->version == UFTP_VER_NUM) &&
            (proxy_type == RESPONSE_PROXY || proxy_type == CLIENT_PROXY)) {
        send_proxy_key(group);
    }
}

/**
 * Handles in incoming REG_CONF from a server when encryption is enabled.
 * Upon receiving this message, mark all clients listed as having received.
 * If we got a KEYINFO from the server, send a KEYINFO to all marked clients.
 */
void handle_regconf(struct pr_group_list_t *group, const unsigned char *message,
                    unsigned meslen)
{
    const struct regconf_h *regconf;
    const uint32_t *addrlist;
    int hostidx, idx, addrcnt;
    struct pr_destinfo_t *dest;

    regconf = (const struct regconf_h *)message;
    addrlist = (const uint32_t *)(message + (regconf->hlen * 4));
    addrcnt = (meslen - (regconf->hlen * 4)) / 4;

    if ((meslen < (regconf->hlen * 4U)) ||
            ((regconf->hlen * 4U) < sizeof(struct regconf_h))) {
        glog1(group, "Rejecting REG_CONF from server: invalid message size");
        return;
    }

    glog2(group, "Received REG_CONF");
    for (idx = 0; idx < addrcnt; idx++) {
        hostidx = find_client(group, addrlist[idx]);
        if (hostidx != -1) {
            dest = &group->destinfo[hostidx];
            glog2(group, "  for %s", dest->name);
            if (dest->state != PR_CLIENT_READY) {
                dest->state = PR_CLIENT_CONF;
            }
        }
    }
    if (group->phase == PR_PHASE_READY) {
        send_keyinfo(group, addrlist, addrcnt);
    }
    set_timeout(group, 0, 0);

}

/**
 * Handles an incoming V4 KEYINFO message from a server.
 * Expected in response to a REGISTER when encryption is enabled.  The proxy
 * itself should be specified, not any clients behind it.
 */
void handle_v4_keyinfo(struct pr_group_list_t *group, unsigned char *message,
                    unsigned meslen, uint32_t src_id)
{
    struct keyinfo_h *keyinfo_hdr;
    struct destkey *keylist;
    unsigned explen, declen;
    int i, keyidx, len, keycount, unauth_keytype, unauth_keylen, unauth_ivlen;
    uint8_t decgroupmaster[MASTER4_LEN], *prf_buf, *iv;
    uint64_t ivctr;

    keyinfo_hdr = (struct keyinfo_h *)message;
    keylist = (struct destkey *)(message + (keyinfo_hdr->hlen * 4));
    keycount = (meslen - (keyinfo_hdr->hlen * 4)) / sizeof(struct destkey);

    if ((meslen < (keyinfo_hdr->hlen * 4U)) ||
            ((keyinfo_hdr->hlen * 4U) < sizeof(struct keyinfo_h))) {
        glog1(group, "Rejecting KEYINFO from server: invalid message size");
        return;
    }
    if (group->keytype == KEY_NONE) {
        glog1(group, "Rejecting KEYINFO from server: encryption not enabled");
        return;
    }

    for (i = 0, keyidx = -1; (i < keycount) && (keyidx == -1); i++) {
        if (uid == keylist[i].dest_id) {
            keyidx = i;
            break;
        }
    }

    // Don't use a cipher in an authentication mode to decrypt the group master
    unauth_keytype = unauth_key(group->keytype);
    get_key_info(unauth_keytype, &unauth_keylen, &unauth_ivlen);
    if (keyidx != -1) {
        glog2(group, "Received KEYINFO");
        if (group->phase != PR_PHASE_REGISTERED) {
            // We already got the KEYINFO, so no need to reprocess.
            // Just resend the INFO_ACK and reset the timeout
            send_keyinfo_ack(group);
            return;
        }
        iv = safe_calloc(unauth_ivlen, 1);
        ivctr = ntohl(keyinfo_hdr->iv_ctr_lo);
        ivctr |= (uint64_t)ntohl(keyinfo_hdr->iv_ctr_hi) << 32;
        build_iv4(iv, group->s_hs_iv, unauth_ivlen, uftp_htonll(ivctr), src_id);
        if (!decrypt_block(unauth_keytype, iv, group->s_hs_key, NULL, 0,
                    keylist[keyidx].groupmaster, MASTER4_LEN,
                    decgroupmaster, &declen) ||
                (declen != MASTER4_LEN - 1)) {
            glog1(group, "Decrypt failed for group master");
            send_upstream_abort(group, 0, "Decrypt failed for group master");
            free(iv);
            return;
        }
        free(iv);
        group->groupmaster[0] = group->version;
        memcpy(&group->groupmaster[1], decgroupmaster, declen);

        explen = group->keylen + SALT_LEN + group->hashlen;
        prf_buf = safe_calloc(explen + group->hashlen, 1);
        PRF(group->hashtype, explen, group->groupmaster,
                sizeof(group->groupmaster), "key expansion",
                group->rand1, sizeof(group->rand1), prf_buf, &len);
        // skip hmac key which isn't used
        // v4 uses same key for both client and server
        memcpy(group->s_app_key, prf_buf + group->hashlen, group->keylen);
        memcpy(group->c_app_key, prf_buf + group->hashlen, group->keylen);
        memcpy(group->s_app_iv, prf_buf + group->hashlen + group->keylen,
                SALT_LEN);
        memcpy(group->c_app_iv, prf_buf + group->hashlen + group->keylen,
                SALT_LEN);

        free(prf_buf);
        group->phase = PR_PHASE_READY;
        // Respond to server, then send any pending REG_CONFs as KEYINFO
        send_keyinfo_ack(group);
        send_keyinfo(group, NULL, 0);
    }
}

/**
 * Handles an incoming KEYINFO message from a server.
 * Expected in response to a REGISTER when encryption is enabled.  The proxy
 * itself should be specified, not any clients behind it.
 */
void handle_keyinfo(struct pr_group_list_t *group, unsigned char *packet,
                    unsigned packetlen)
{
    struct keyinfo_h *keyinfo_hdr;
    struct destkey *keylist;
    int i, keyidx, destkeycnt;
    unsigned char *iv, *sig, *sigcopy, *sigcontext, *aadcontext;
    unsigned int meslen, declen, siglen, sigcontextlen, aadlen;
    uint64_t ivctr;
    const char *sig_context_str = "UFTP 5, KEYINFO";
    const char *aad_context_str = "UFTP 5, group master";

    keyinfo_hdr = (struct keyinfo_h *)(packet + sizeof(struct uftp_h));
    sig = (uint8_t *)keyinfo_hdr + sizeof(struct keyinfo_h);
    keylist = (struct destkey *)((unsigned char *)keyinfo_hdr +
                                  (keyinfo_hdr->hlen * 4));
    meslen = packetlen - sizeof(struct uftp_h);
    siglen = ntohs(keyinfo_hdr->siglen);

    if ((meslen < (keyinfo_hdr->hlen * 4U)) || ((keyinfo_hdr->hlen * 4U) <
            sizeof(struct keyinfo_h) + siglen)) {
        glog1(group, "Rejecting KEYINFO from server: invalid message size");
        return;
    }

    destkeycnt = (meslen - (keyinfo_hdr->hlen * 4)) / sizeof(struct destkey);
    // This duplicates uid_in_list, but here it's addressed in a struct array
    for (i = 0, keyidx = -1; (i < destkeycnt) && (keyidx == -1); i++) {
        if (uid == keylist[i].dest_id) {
            keyidx = i;
        }
    }

    if (keyidx != -1) {
        glog2(group, "Received KEYINFO");
        if (group->phase != PR_PHASE_REGISTERED) {
            // We already got the KEYINFO, so no need to reprocess.
            // Just resend the KEYINFO_ACK and reset the timeout
            send_keyinfo_ack(group);
            return;
        }

        sigcontext = safe_malloc(strlen(sig_context_str) +
                                 group->s_context_len + MAXMTU);
        sigcopy = safe_malloc(siglen);
        memcpy(sigcopy, sig, siglen);
        memset(sig, 0, siglen);
        sigcontextlen = 0;
        memcpy(sigcontext + sigcontextlen, sig_context_str,
                strlen(sig_context_str));
        sigcontextlen += (unsigned)strlen(sig_context_str);
        memcpy(sigcontext + sigcontextlen, group->s_context,
                group->s_context_len);
        sigcontextlen += group->s_context_len;
        memcpy(sigcontext + sigcontextlen, packet, packetlen);
        sigcontextlen += packetlen;
        if (group->server_pubkeytype == KEYBLOB_RSA) {
            if (!verify_RSA_sig(group->server_pubkey.rsa, group->hashtype,
                                sigcontext, sigcontextlen, sigcopy, siglen)) {
                glog1(group, "Signature verification failed");
                send_upstream_abort(group, 0, "Signature verification failed");
                free(sigcontext);
                free(sigcopy);
                return;
            }
        } else {
            if (!verify_ECDSA_sig(group->server_pubkey.ec, group->hashtype,
                                  sigcontext, sigcontextlen, sigcopy, siglen)) {
                glog1(group, "Signature verification failed");
                send_upstream_abort(group, 0, "Signature verification failed");
                free(sigcontext);
                free(sigcopy);
                return;
            }
        }
        free(sigcontext);
        free(sigcopy);

        aadcontext = safe_malloc(strlen(aad_context_str) + MAXMTU);
        aadlen = 0;
        memcpy(aadcontext + aadlen, aad_context_str, strlen(aad_context_str));
        aadlen += (unsigned)strlen(aad_context_str);
        memcpy(aadcontext + aadlen, group->c_context2, group->c_context2_len);
        aadlen += group->c_context2_len;

        iv = safe_malloc(group->ivlen);
        ivctr = ntohl(keyinfo_hdr->iv_ctr_lo);
        ivctr |= (uint64_t)ntohl(keyinfo_hdr->iv_ctr_hi) << 32;
        build_iv(iv, group->s_hs_iv, group->ivlen, uftp_htonll(ivctr));
        if (!decrypt_block(group->keytype, iv, group->s_hs_key, aadcontext,
                    aadlen, keylist[keyidx].groupmaster, ENC_MASTER_LEN,
                    group->groupmaster, &declen) ||
                (declen != MASTER_LEN)) {
            glog1(group, "Decrypt failed for group master");
            send_upstream_abort(group, 0, "Decrypt failed for group master");
            free(iv);
            free(aadcontext);
            return;
        }
        free(iv);
        free(aadcontext);

        calculate_server_app_keys(group->hashtype, group->groupmaster,
                MASTER_LEN, group->s_context, group->s_context_len,
                group->keylen, group->ivlen, group->s_app_key,group->s_app_iv);
        calculate_client_app_keys(group->hashtype, group->groupmaster,
                MASTER_LEN, group->c_context2, group->c_context2_len,
                group->keylen, group->ivlen, group->c_app_key, group->c_app_iv,
                group->finished_key, group->verify_data);

        group->phase = PR_PHASE_READY;
        // Respond to server, then send any pending REG_CONFs as KEYINFO
        send_keyinfo_ack(group);
        send_keyinfo(group, NULL, 0);
    }
}

/**
 * Sends a REGISTER to the server for all pending clients.
 */
void send_register(struct pr_group_list_t *group, int pendidx)
{
    struct uftp_h *header;
    struct register_h *reg;
    unsigned char *buf, *keydata;
    uint32_t *addrlist;
    unsigned int meslen, destcount;
    uint16_t keylen;
    struct timeval now, send_time;
    int64_t send_time_us;

    buf = safe_calloc(MAXMTU, 1);

    header = (struct uftp_h *)buf;
    reg = (struct register_h *)(buf + sizeof(struct uftp_h));
    keydata = (unsigned char *)reg + sizeof(struct register_h);

    set_uftp_header(header, REGISTER, group);
    reg->func = REGISTER;
    if (group->keytype != KEY_NONE) {
        memcpy(reg->rand2, group->rand2, RAND_LEN);
        if (!export_EC_key(group->proxy_u_dhkey.ec, keydata, &keylen)) {
            glog0(group, "Error exporting ECDH public key");
            send_upstream_abort(group,0, "Error exporting ECDH public key");
            free(buf);
            return;
        }
        reg->dhlen = htons(keylen);
    } else {
        keylen = 0;
    }

    gettimeofday(&now, NULL);
    if (cmptimestamp(now, group->pending[pendidx].rx_tstamp) <= 0) {
        send_time = group->pending[pendidx].tstamp;
    } else {
        send_time = add_timeval(group->pending[pendidx].tstamp,
                diff_timeval(now, group->pending[pendidx].rx_tstamp));
    }
    if (group->version == UFTP4_VER_NUM) {
        reg->tstamp_hi = htonl((uint32_t)send_time.tv_sec);
        reg->tstamp_lo = htonl((uint32_t)send_time.tv_usec);
    } else {
        send_time_us = tv_to_usec(send_time);
        reg->tstamp_hi = htonl((send_time_us & 0xFFFFFFFF00000000ULL) >> 32);
        reg->tstamp_lo = htonl(send_time_us & 0x00000000FFFFFFFFULL);
    }

    addrlist = (uint32_t *)(keydata + keylen);
    reg->hlen = (uint8_t)((sizeof(struct register_h) + keylen) / 4);
    destcount = load_pending(group, pendidx, REGISTER, addrlist,
                             max_msg_dest(group, REGISTER, reg->hlen * 4));
    meslen = sizeof(struct uftp_h) + (reg->hlen * 4) + (destcount * 4);

    if (nb_sendto(listener, buf, meslen, 0, (struct sockaddr *)&group->up_addr,
               family_len(group->up_addr)) == SOCKET_ERROR) {
        gsockerror(group, "Error sending REGISTER");
    } else {
        glog2(group, "REGISTER sent");
    }

    if (group->client_auth) {
        send_clientkey(group);
    } else if (!group->c_context2) {
        create_client_context_2(group->c_context1, group->c_context1_len,NULL,0,
                                &group->c_context2, &group->c_context2_len);
    }
    set_timeout(group, 1, 0);
    free(buf);
}

/**
 * Creates the context for a CLIENT_KEY signature
 */
uint8_t *build_us_client_key_sig(struct pr_group_list_t *group, int *verifylen)
{
    uint8_t *verifydata;
    const char *context_str = "UFTP 5, CLIENT_KEY";

    verifydata = safe_calloc(strlen(context_str) + group->c_context1_len, 1);
    *verifylen = 0;
    memcpy(verifydata + *verifylen, context_str, strlen(context_str));
    *verifylen += (int)strlen(context_str);
    memcpy(verifydata + *verifylen, group->c_context1,
            group->c_context1_len);
    *verifylen += group->c_context1_len;
    return verifydata;
}

/**
 * Sends a CLIENT_KEY message to the server if requested.
 */
void send_clientkey(struct pr_group_list_t *group)
{
    struct uftp_h *header;
    struct client_key_h *client_key;
    unsigned char *buf, *keyblob, *verify, *encrypted, *outpacket;
    uint8_t *verifydata;
    unsigned int siglen, _siglen, meslen;
    uint16_t bloblen;
    int verifylen, enclen;

    buf = safe_calloc(MAXMTU, 1);

    header = (struct uftp_h *)buf;
    client_key = (struct client_key_h *)(buf + sizeof(struct uftp_h));
    keyblob = (unsigned char *)client_key + sizeof(struct client_key_h);

    if (group->version == UFTP4_VER_NUM) {
        verifydata = build_v4_verify_data(group, -1, &verifylen, 0);
    } else {
        verifydata = build_us_client_key_sig(group, &verifylen);
    }
    if (!verifydata) {
        glog0(group, "Error getting verify data");
        send_upstream_abort(group, 0, "Error getting verify data");
        goto end;
    }

    set_uftp_header(header, CLIENT_KEY, group);

    client_key->func = CLIENT_KEY;
    if (group->proxy_privkeytype == KEYBLOB_RSA) {
        if (!export_RSA_key(group->proxy_privkey.rsa, keyblob, &bloblen)) {
            glog0(group, "Error exporting public key");
            send_upstream_abort(group, 0, "Error exporting public key");
            goto end;
        }
        siglen = RSA_keylen(group->proxy_privkey.rsa);
    } else {
        if (!export_EC_key(group->proxy_privkey.ec, keyblob, &bloblen)) {
            glog0(group, "Error exporting public key");
            send_upstream_abort(group, 0, "Error exporting public key");
            goto end;
        }
        siglen = ECDSA_siglen(group->proxy_privkey.ec);
    }
    client_key->bloblen = htons(bloblen);
    client_key->siglen = htons(siglen);
    client_key->hlen = (uint8_t)((sizeof(struct client_key_h) +
                        bloblen + siglen) / 4);
    if (!group->c_context2) {
        create_client_context_2(group->c_context1, group->c_context1_len,
                                client_key, client_key->hlen * 4,
                                &group->c_context2, &group->c_context2_len);
    }

    verify = keyblob + bloblen;
    if (group->proxy_privkeytype == KEYBLOB_RSA) {
        if (!create_RSA_sig(group->proxy_privkey.rsa, group->hashtype,
                            verifydata, verifylen, verify, &_siglen)) {
            glog0(group, "Error signing verify data");
            send_upstream_abort(group, 0, "Error signing verify data");
            goto end;
        }
    } else {
        if (!create_ECDSA_sig(group->proxy_privkey.ec, group->hashtype,
                              verifydata, verifylen, verify, &_siglen)) {
            glog0(group, "Error signing verify data");
            send_upstream_abort(group, 0, "Error signing verify data");
            goto end;
        }
    }
    if (siglen != _siglen) {
        glog0(group, "Signature length doesn't match expected length");
        glog1(group, "expected %d, got %d", siglen, _siglen);
        send_upstream_abort(group, 0, "Signature length mismatch");
        goto end;
    }

    meslen = client_key->hlen * 4;
    if (group->version == UFTP_VER_NUM) {
        encrypted = NULL;
        if (!encrypt_and_sign(buf, &encrypted, meslen, &enclen,
                              group->keytype, group->c_hs_key, group->c_hs_iv,
                              &group->ivctr, group->ivlen)) {
            glog0(group, "Error encrypting CLIENT_KEY");
            free(buf);
            return;
        }
        outpacket = encrypted;
        meslen = enclen;
    } else {
        encrypted = NULL;
        outpacket = buf;
    }
    meslen += sizeof(struct uftp_h);
    if (nb_sendto(listener, outpacket, meslen, 0, (struct sockaddr *)&group->up_addr,
               family_len(group->up_addr)) == SOCKET_ERROR) {
        gsockerror(group, "Error sending CLIENT_KEY");
    } else {
        glog2(group, "CLIENT_KEY sent");
    }
    free(encrypted);

end:
    free(verifydata);
    free(buf);
}

/**
 * Sends an KEYINFO_ACK to the server in response to a KEYINFO
 */
void send_keyinfo_ack(struct pr_group_list_t *group)
{
    unsigned char *buf, *encrypted;
    struct uftp_h *header;
    struct keyinfoack_h *keyinfo_ack;
    unsigned char *verifydata, *verify_hash, *verify_val, *h_verifydata;
    unsigned int payloadlen, hashlen;
    int verifylen, len, enclen;

    buf = safe_calloc(MAXMTU, 1);

    header = (struct uftp_h *)buf;
    keyinfo_ack = (struct keyinfoack_h *)(buf + sizeof(struct uftp_h));
    h_verifydata = (uint8_t *)keyinfo_ack + sizeof(struct keyinfoack_h);

    set_uftp_header(header, KEYINFO_ACK, group);
    keyinfo_ack->func = KEYINFO_ACK;

    if (group->version == UFTP4_VER_NUM) {
        keyinfo_ack->hlen = (sizeof(struct keyinfoack_h) + VERIFY4_LEN) / 4;
        verifydata = build_v4_verify_data(group, -1, &verifylen, 1);
        if (!verifydata) {
            glog0(group, "Error getting verify data");
            send_upstream_abort(group, 0, "Error getting verify data");
            free(buf);
            return;
        }

        verify_hash = safe_calloc(group->hashlen, 1);
        verify_val = safe_calloc(VERIFY4_LEN + group->hashlen, 1);
        hash(group->hashtype, verifydata, verifylen, verify_hash, &hashlen);
        PRF(group->hashtype, VERIFY4_LEN, group->groupmaster,
                sizeof(group->groupmaster), "client finished",
                verify_hash, hashlen, verify_val, &len);
        memcpy(h_verifydata, verify_val, VERIFY4_LEN);
        free(verifydata);
        free(verify_hash);
        free(verify_val);
    } else {
        keyinfo_ack->hlen = (uint8_t)((sizeof(struct keyinfoack_h) +
                            group->hashlen) / 4);
        memcpy(h_verifydata, group->verify_data, group->hashlen);
    }

    payloadlen = keyinfo_ack->hlen * 4;
    encrypted = NULL;
    if (!encrypt_and_sign(buf, &encrypted, payloadlen, &enclen, group->keytype,
            group->c_app_key, group->c_app_iv, &group->ivctr, group->ivlen)) {
        glog0(group, "Error encrypting KEYINFO_ACK");
        free(buf);
        return;
    }
    payloadlen = enclen + sizeof(struct uftp_h);

    if (nb_sendto(listener, encrypted, payloadlen, 0,
               (struct sockaddr *)&group->up_addr,
               family_len(group->up_addr)) == SOCKET_ERROR) {
        gsockerror(group, "Error sending KEYINFO_ACK");
    } else {
        glog2(group, "KEYINFO_ACK sent");
    }
    set_timeout(group, 0, 0);
    free(encrypted);
    free(buf);
}

/**
 * Sends a FILEINFO_ACK to the server for all pending clients
 */
void send_fileinfo_ack(struct pr_group_list_t *group, int pendidx)
{
    unsigned char *buf, *encrypted, *outpacket;
    struct uftp_h *header;
    struct fileinfoack_h *fileinfo_ack;
    struct pr_pending_info_t *pending;
    unsigned int payloadlen;
    int destcount, enclen;
    uint32_t *addrlist;
    struct timeval now, send_time;
    int64_t send_time_us;

    buf = safe_calloc(MAXMTU, 1);

    pending = &group->pending[pendidx];

    header = (struct uftp_h *)buf;
    fileinfo_ack = (struct fileinfoack_h *)(buf + sizeof(struct uftp_h));
    addrlist =(uint32_t *)((char *)fileinfo_ack + sizeof(struct fileinfoack_h));

    payloadlen = sizeof(struct fileinfoack_h);
    set_uftp_header(header, FILEINFO_ACK, group);
    fileinfo_ack->func = FILEINFO_ACK;
    fileinfo_ack->hlen = sizeof(struct fileinfoack_h) / 4;
    fileinfo_ack->file_id = htons(pending->file_id);
    if (pending->partial) {
        fileinfo_ack->flags |= FLAG_PARTIAL;
    }

    gettimeofday(&now, NULL);
    if (cmptimestamp(now, group->pending[pendidx].rx_tstamp) <= 0) {
        send_time = group->pending[pendidx].tstamp;
    } else {
        send_time = add_timeval(group->pending[pendidx].tstamp,
                diff_timeval(now, group->pending[pendidx].rx_tstamp));
    }
    if (group->version == UFTP4_VER_NUM) {
        fileinfo_ack->tstamp_hi = htonl((uint32_t)send_time.tv_sec);
        fileinfo_ack->tstamp_lo = htonl((uint32_t)send_time.tv_usec);
    } else {
        send_time_us = tv_to_usec(send_time);
        fileinfo_ack->tstamp_hi =
                htonl((send_time_us & 0xFFFFFFFF00000000ULL) >> 32);
        fileinfo_ack->tstamp_lo = htonl(send_time_us & 0x00000000FFFFFFFFULL);
    }

    destcount = load_pending(group, pendidx, FILEINFO_ACK, addrlist,
                    max_msg_dest(group, FILEINFO_ACK, fileinfo_ack->hlen * 4));
    payloadlen += destcount * sizeof(uint32_t);

    if (group->keytype != KEY_NONE) {
        encrypted = NULL;
        if (!encrypt_and_sign(buf, &encrypted, payloadlen, &enclen,
                              group->keytype, group->c_app_key, group->c_app_iv,
                              &group->ivctr, group->ivlen)) {
            log0(group->group_id, group->group_inst, pending->file_id,
                    "Error encrypting FILEINFO_ACK");
            free(buf);
            return;
        }
        outpacket = encrypted;
        payloadlen = enclen;
    } else {
        encrypted = NULL;
        outpacket = buf;
    }
    payloadlen += sizeof(struct uftp_h);

    if (nb_sendto(listener, outpacket, payloadlen, 0,
               (struct sockaddr *)&group->up_addr,
               family_len(group->up_addr)) == SOCKET_ERROR) {
        sockerror(group->group_id, group->group_inst, pending->file_id,
                  "Error sending FILEINFO_ACK");
    } else {
        log2(group->group_id, group->group_inst, pending->file_id,
                "FILEINFO_ACK sent");
    }
    set_timeout(group, 1, 0);
    free(encrypted);
    free(buf);
}

/**
 * Counts the pending naks for the given group
 */
int count_naks(struct pr_group_list_t *group, int pendidx)
{
    unsigned nak_count, i;

    for (nak_count = 0, i = 0; i < group->blocksize * 8; i++) {
        if ((group->pending[pendidx].naklist[i >> 3] & (1 << (i & 7))) != 0) {
            nak_count++;
        }
    }
    // Highly verbose debugging -- print aggregate NAKs before sending
    if (log_level >= 5) {
        for (i = 0; i < group->blocksize; i++) {
            sclog5("%02X ", group->pending[pendidx].naklist[i]);
            if (i % 25 == 24) slog5(" ");
        }
        slog5(" ");
    }
    return nak_count;
}

/**
 * Sends a STATUS to the server for all pending clients.
 */
void send_status(struct pr_group_list_t *group, int pendidx)
{
    unsigned char *buf, *encrypted, *outpacket;
    struct uftp_h *header;
    struct status_h *status;
    unsigned char *sent_naks;
    struct pr_pending_info_t *pending;
    struct pr_destinfo_t *dest;
    int hostidx, payloadlen, enclen, nak_count;

    buf = safe_calloc(MAXMTU, 1);
    pending = &group->pending[pendidx];

    // Since a STATUS doesn't contain a host list, we do this simplified
    // cleanup instead of calling load_pending
    for (hostidx = 0; hostidx < group->destcount; hostidx++) {
        dest = &group->destinfo[hostidx];
        if (dest->pending == pendidx) {
            dest->pending = -1;
        }
    }
    group->pending[pendidx].count = 0;
    group->pending[pendidx].msg = 0;

    header = (struct uftp_h *)buf;
    status = (struct status_h *)(buf + sizeof(struct uftp_h));

    nak_count = count_naks(group, pendidx);
    set_uftp_header(header, STATUS, group);
    status->func = STATUS;
    status->hlen = sizeof(struct status_h) / 4;
    status->file_id = htons(pending->file_id);
    status->section = htons(pending->section);
    payloadlen = group->blocksize;
    sent_naks = (unsigned char *)status + sizeof(struct status_h);
    memcpy(sent_naks, pending->naklist, payloadlen);
    memset(pending->naklist, 0, payloadlen);

    payloadlen += sizeof(struct status_h);
    if (group->keytype != KEY_NONE) {
        encrypted = NULL;
        if (!encrypt_and_sign(buf, &encrypted, payloadlen, &enclen,
                              group->keytype, group->c_app_key, group->c_app_iv,
                              &group->ivctr, group->ivlen)) {
            log0(group->group_id, group->group_inst, pending->file_id,
                    "Error encrypting STATUS");
            free(buf);
            return;
        }
        outpacket = encrypted;
        payloadlen = enclen;
    } else {
        encrypted = NULL;
        outpacket = buf;
    }
    payloadlen += sizeof(struct uftp_h);

    if (nb_sendto(listener, outpacket, payloadlen, 0,
               (struct sockaddr *)&group->up_addr,
               family_len(group->up_addr)) == SOCKET_ERROR) {
        sockerror(group->group_id, group->group_inst, pending->file_id,
                "Error sending STATUS");
    } else {
        log2(group->group_id, group->group_inst, pending->file_id,
                "Sent %d NAKs for section %d", nak_count, pending->section);
    }
    set_timeout(group, 1, 0);

    free(buf);
    free(encrypted);
}

/**
 * Sends a COMPLETE to the server for all pending clients.
 */
void send_complete(struct pr_group_list_t *group, int pendidx)
{
    unsigned char *buf, *encrypted, *outpacket;
    struct uftp_h *header;
    struct complete_h *complete;
    uint32_t *addrlist;
    struct pr_pending_info_t *pending;
    int payloadlen, destcount, enclen;

    buf = safe_calloc(MAXMTU, 1);
    pending = &group->pending[pendidx];

    header = (struct uftp_h *)buf;
    complete = (struct complete_h *)(buf + sizeof(struct uftp_h));
    addrlist = (uint32_t *)((char *)complete + sizeof(struct complete_h));

    set_uftp_header(header, COMPLETE, group);
    complete->func = COMPLETE;
    complete->hlen = sizeof(struct complete_h) / 4;
    complete->file_id = htons(pending->file_id);
    complete->status = pending->comp_status;

    destcount = load_pending(group, pendidx, COMPLETE, addrlist,
                             max_msg_dest(group, COMPLETE, complete->hlen * 4));
    payloadlen = sizeof(struct complete_h) + (destcount * sizeof(uint32_t));

    if (group->keytype != KEY_NONE) {
        encrypted = NULL;
        if (!encrypt_and_sign(buf, &encrypted, payloadlen, &enclen,
                              group->keytype, group->c_app_key, group->c_app_iv,
                              &group->ivctr, group->ivlen)) {
            log0(group->group_id, group->group_inst, pending->file_id,
                    "Error encrypting COMPLETE");
            free(buf);
            return;
        }
        outpacket = encrypted;
        payloadlen = enclen;
    } else {
        encrypted = NULL;
        outpacket = buf;
    }
    payloadlen += sizeof(struct uftp_h);

    if (nb_sendto(listener, outpacket, payloadlen, 0,
               (struct sockaddr *)&group->up_addr,
               family_len(group->up_addr)) == SOCKET_ERROR) {
        sockerror(group->group_id, group->group_inst, pending->file_id,
                "Error sending COMPLETE");
    } else {
        log2(group->group_id, group->group_inst, pending->file_id,
                "Sent COMPLETE");
    }
    set_timeout(group, 1, 0);

    free(buf);
    free(encrypted);
}


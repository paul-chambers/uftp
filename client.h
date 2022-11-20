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

#ifndef _CLIENT_H
#define _CLIENT_H

#include "uftp_common.h"
#include "encryption.h"

#define MAXLIST 100
#define MAXMISORDER 5
#define KEY_REQ_INT 5

/**
 * Current state of client for a given group
 */
enum client_phase {
    PHASE_PREREGISTER = 1,      /// 
    PHASE_REGISTERED = 2,       /// Registered and awaiting KEYINFO or REG_CONF
    PHASE_RECEIVING = 3,        /// Currently receiving a file
    PHASE_COMPLETE = 4,         /// Completed group and awaiting DONE_CONF
    PHASE_MIDGROUP = 5          /// Registered awaiting next file or group end
};

/**
 * Info pertaining to current file
 */
struct file_t {
    uint32_t blocks;            /// Total blocks
    uint16_t sections;          /// Total sections
    uint16_t big_sections;      /// Number of larger sized sections
    uint32_t secsize_small, secsize_big;  /// Size of sections
    int ftype;                  /// File type (regular, directory, symlink)
    f_offset_t size;            /// Size in bytes
    int64_t tstamp;             /// File timestamp
    char filepath[MAXPATHNAME]; /// Local path to file
    char temppath[MAXPATHNAME]; /// Local path to temp file
    char name[MAXPATHNAME];     /// Path name
    char linkname[MAXPATHNAME]; /// Link name (symlinks only)
    uint8_t *naklist;           /// NAK list
    uint8_t *section_done;      /// Array of done flags for each section
    int fd;                     /// File descriptor for file
    uint32_t last_block;        /// Block number of last block received
    uint16_t last_section;      /// Section number of last block received
    int got_data;               /// True if at least one data packet received
    struct timeval nak_time;    /// Time to send out NAKs
    uint16_t nak_section_first; /// First section number to send NAKs for
    uint16_t nak_section_last;  /// Last section number to send NAKs for
    int got_done;               /// A DONE was received for this client
    f_offset_t curr_offset;     /// Current file pointer offset in fd
    int restart;                /// True if restarting a prior session
    int comp_status;            /// Value for status field of COMPLETE
    int destdiridx;             /// Index of dest dir file is received in
    char *cache;                /// Disk cache, consecutive packets
    uint32_t cache_start;       /// First block in cache
    uint32_t cache_end;         /// Last block in cache
    int cache_len;              /// Length of cache in bytes
    char *cache_status;         /// Receive status of cache entries
};

/**
 * Header of client save state file.
 * Followed in the file by the NAK list and section_done list.
 * The naklist and section_done fields are left blank when the struct is
 * written to a file.  When read back in, memory is allocated and the
 * NAK list and section_done list are written to them.
 */
struct client_restart_t {
    uint32_t blocks;            /// Total blocks
    uint32_t sections;          /// Total sections
    f_offset_t size;            /// Size in bytes
    char name[MAXPATHNAME];     /// Path name
    uint8_t *naklist;           /// NAK list
    uint8_t *section_done;      /// Array of done flags for each section
};

/**
 * Loss history item.
 * These are part of an array where the array index is the sequence number.
 */
struct loss_history_t {
    int found;                  /// True if this packet was received
    struct timeval t;           /// Time received, either actual or inferred
    int size;                   /// Size of received packet, including UDP/IP
};

/**
 * Loss event item.
 */
struct loss_event_t {
    uint32_t start_seq;         /// Seq num of event start, including wraparound
    int len;                    /// Size of loss interval
    struct timeval t;           /// Timestamp of event start
};

/**
 * Info for a particular group
 */
struct group_list_t {
    uint32_t group_id;              /// Group ID
    uint8_t group_inst;             /// Group instance ID (restart number)
    uint16_t file_id;               /// File ID of current file
    uint8_t version;                /// Protocol version number of server
    union sockaddr_u multi;         /// Private multicast address
    int multi_join;                 /// True if we're listening on private addr
    char start_date[10];            /// Date initial ANNOUNCE was received
    char start_time[10];            /// Time initial ANNOUNCE was received
    uint16_t send_seq;              /// Outgoing seq. number for loss detection
    uint32_t src_id;                /// ID of server (network byte order)
    uint32_t proxy_id;              /// ID of proxy (network byte order)
    struct fp_list_t *server_fp;    /// Pointer to server's fingerprint struct
    struct fp_list_t *proxy_fp;     /// Pointer to proxy's fingerprint struct
    union sockaddr_u replyaddr;     /// IP to send responses to
    int phase;                      /// Current client_phase of the group
    int client_auth, restart, sync_mode, sync_preview; /// Flags from ANNOUNCE
    struct client_restart_t *restartinfo; /// Restart file header
    unsigned int blocksize;         /// Size of packet payload
    unsigned int datapacketsize;    /// Max size of UFTP packet
    struct timeval timeout_time, start_timeout_time, expire_time;
    double rtt, grtt;               /// Client's RTT and server's GRTT
    uint16_t start_txseq, max_txseq;  /// Server's starting, max sequence #
    struct loss_history_t *loss_history;  /// Loss history
    struct loss_event_t loss_events[9];   /// Loss event history
    int seq_wrap;                   /// Number of times server seq wrapped
    int ccseq;                      /// Current congestion control sequence #
    int64_t initrate;               /// Cong. control rate at start of fb round
    int isclr;                      /// True if this client is the CLR
    int slowstart;                  /// True if we're in slowstart mode
    uint8_t robust, cc_type;        /// Robust factor, congestion control type
    uint32_t gsize;                 /// Group size estimate
    struct timeval cc_time;         /// Timer for sending CC_ACK
    struct timeval last_server_ts, last_server_rx_ts;
    int keytype, hashtype;          /// Encryption parameters
    union key_t server_pubkey;      /// Server's public key
    union key_t server_dhkey;       /// Server ECDH public key for this group
    union key_t proxy_pubkey;       /// Response proxy public key
    union key_t proxy_dhkey;        /// Respose proxy ECDH key for this group
    union key_t client_dhkey;       /// Client ECDH private key for this group
    unsigned int server_keytype;    /// Type of server key
    unsigned int proxy_keytype;     /// Type of response proxy key
    uint8_t rand1[RAND_LEN];        /// Server's random number
    uint8_t rand2[RAND_LEN];        /// Client's random number
    uint8_t *s_context;             /// Server session context
    uint8_t *p_context;             /// Proxy session context
    uint8_t *c_context1;            /// Client session context 1
    uint8_t *c_context2;            /// Client session context 2
    int s_context_len;              /// Length of server context
    int p_context_len;              /// Length of proxy context
    int c_context1_len;             /// Length of client context 1
    int c_context2_len;             /// Length of client context 2
    uint8_t premaster[MASTER4_LEN]; /// Premaster secret resulting from ECDH
    uint8_t groupmaster[MASTER4_LEN];/// Group master key from server
    unsigned int premaster_len;     /// Length of premaster secret
    uint8_t s_hs_key[MAXKEY];       /// Symmetric handshake key for server
    uint8_t s_hs_iv[MAXIV];         /// Symmetric handshake IV for server
    uint8_t c_hs_key[MAXKEY];       /// Symmetric handshake key for client
    uint8_t c_hs_iv[MAXIV];         /// Symmetric handshake IV for client
    uint8_t s_app_key[MAXKEY];      /// Symmetric application key for server
    uint8_t s_app_iv[MAXIV];        /// Symmetric application IV for server
    uint8_t c_app_key[MAXKEY];      /// Symmetric application key for client
    uint8_t c_app_iv[MAXIV];        /// Symmetric application IV for client
    uint8_t finished_key[HASH_LEN]; /// Key for client finished message
    uint8_t verify_data[HASH_LEN];  /// Client's finished hash
    uint64_t ivctr;                 /// Counter portion of the IV
    int ivlen, keylen, hashlen;     /// Length of hash, symmetric key and iv
    struct file_t fileinfo;         /// Info pertaining to current file
};

/**
 * Global command line values and sockets
 */
extern SOCKET listener;
extern char tempdir[MAXDIRNAME], destdir[MAXDIR][MAXDIRNAME];
extern char pidfile[MAXPATHNAME];
extern char keyfile[MAXPATHNAME], keyinfo[MAXPATHNAME];
extern char backupdir[MAXDIR][MAXDIRNAME];
extern char statusfilename[MAXPATHNAME];
extern FILE *status_file;
extern int debug, encrypted_only, dscp, destdircnt, tempfile;
extern int interface_count, pub_multi_count, rcvbuf, backupcnt;
extern char postreceive[MAXPATHNAME], portname[PORTNAME_LEN];
extern int port, move_individual, cache_len, noname, user_abort, use_ssm;
extern uint32_t uid;
extern union sockaddr_u hb_hosts[MAXLIST];
extern struct iflist m_interface[MAX_INTERFACES];
extern union sockaddr_u pub_multi[MAX_INTERFACES];
extern struct group_list_t group_list[MAXLIST];
extern struct fp_list_t server_list[MAXLIST], proxy_list[MAXLIST];
extern struct iflist ifl[MAX_INTERFACES];
extern struct timeval next_keyreq_time, next_hb_time;
extern int ifl_len, server_count, proxy_count, has_v4_proxy, sys_keys, priority;
extern int hbhost_count, hb_interval;
extern union key_t privkey;
extern int privkey_type;
extern struct fp_list_t proxy4_info;
extern union key_t proxy4_pubkey, proxy4_dhkey;
extern int proxy4_pubkeytype;

#endif  // _CLIENT_H


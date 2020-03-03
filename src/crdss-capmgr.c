/****************************************************************************
 *                                                                          *
 *  crdss-capmgr.c - The client-side capabilty manager for access control   *
 *                                                                          *
 *                    Copyright (c) 2020 Till Miemietz                      *
 *                                                                          *
 ****************************************************************************/



/****************************************************************************
 *                                                                          *
 *                     global definitions and macros                        *
 *                                                                          *
 ****************************************************************************/


/* needed to get struct ucred from sys/socket.h                             */
#define _GNU_SOURCE

/****************************************************************************
 *                                                                          *
 *                           include statements                             *
 *                                                                          *
 ****************************************************************************/

#include <sys/socket.h>                  /* credential passing via dom socks*/
#include <stdio.h>                       /* basic I/O facilities            */
#include <stdlib.h>                      /* allocation, exit, ...           */
#include <unistd.h>                      /* UNIX standard libraries         */
#include <string.h>                      /* string manipulation             */
#include <errno.h>                       /* find reasons for errors         */
#include <limits.h>                      /* system limits                   */
#include <arpa/inet.h>                   /* pretty printing of IP addresses */
#include <pthread.h>                     /* POSIX threads                   */
#include <sys/stat.h>                    /* analyze dom socket candidates   */
#include <sys/poll.h>                    /* listen to multiple servers      */

#include "include/slist.h"               /* header for slist implementation */
#include "include/utils.h"               /* utilities like logging          */
#include "include/confparser.h"          /* configuration parser            */
#include "include/protocol.h"            /* crdss application network prot. */
#include "include/cap.h"                 /* crdss capabilities              */

/****************************************************************************
 *                                                                          *
 *                           type definitions                               *
 *                                                                          *
 ****************************************************************************/


/* represents an open work request issued by a client                       */
struct clt_req {
    uint8_t type;                   /* type of request as in protocol.h     */
    struct crdss_clt_cap *cap;      /* cap associated with this request     */

    struct sockaddr_un clt_addr;    /* clt address to send the answer to    */
    socklen_t addr_len;             /* length of client address             */
};

/* represents storage servers of active connections */
struct server {
    struct sockaddr_in addr;                /* IP and port of server        */
    int                sock_fd;             /* socket connected to the srv  */

    struct slist *requests;                 /* open requests sent to server */
    pthread_mutex_t req_lck;                /* lock for accessing req. list */
};

/****************************************************************************
 *                                                                          *
 *                           global variables                               *
 *                                                                          *
 ****************************************************************************/


struct snic_config capmgr_cfg;              /* global config read from file */
struct slist *active_srvs;                  /* list of struct server with   *
                                             * active connections           */
/* lock for manipulating the server list */
pthread_mutex_t srv_lck = PTHREAD_MUTEX_INITIALIZER;

int clt_sock;                               /* fd for comm. with clients    */

struct slist *active_caps;                  /* list of caps registered via  * 
                                             * this capmgr and not yet rev. */
pthread_mutex_t cap_lck = PTHREAD_MUTEX_INITIALIZER;

pthread_t srv_listener;                     /* thread for the server listn. *
                                             * main thrd becomes clt. listn.*/

/****************************************************************************
 *                                                                          *
 *                          static helper functions                         *
 *                                                                          *
 ****************************************************************************/


/****************************************************************************
 *
 * Prints a usage message to stderr.
 */
static void usage(void) {
    fprintf(stderr, "crdss-capmgr - The Caladan Storage Cap Manager\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "./crdss-capmgr -c <path> [-l path] [-u] [-w] [-h]\n");
    fprintf(stderr, "-c : path to capmgr configuration file\n");
    fprintf(stderr, "-l : path to log file (default: stderr)\n");
    fprintf(stderr, "-u : use a UDP socket for client communication\n");
    fprintf(stderr, "-w : do not run capmgr as a daemon\n");
    fprintf(stderr, "-h : print this help message and exit\n");
}

/****************************************************************************
 *
 * Tries to establish a connection to all servers specified in the config 
 * file. Servers with whom the connection setup and the authentication 
 * succeeds will be added to the list of active servers. After calling this
 * function, the server sockets in the active server list are ready for 
 * communication, no further authentication needs to be done.
 */
void connect_servers(void) {
    struct slist *lptr;                     /* iterate through server list  */
    struct srv_conn *srv_addr;
    int temp_sock;
    struct server *cur_srv;                 /* new active server struct     */

    /* fields for pretty printing */
    char srv_ip[INET_ADDRSTRLEN];
    char clt_ip[INET_ADDRSTRLEN];

    /* message fields for authentication */
    uint16_t msg_type = htons(MTYPE_HELLO);
    uint8_t  clt_type = CLT_CAPMGR;
    uint16_t sec_len;
    uint16_t sec_len_nw;                    /* secret length in network bo */
    uint8_t  res;
    char     *srv_sec;                      /* server secret for auth.      */

    for (lptr = capmgr_cfg.srvs; lptr != NULL; lptr = lptr->next) {
        srv_addr = (struct srv_conn *) lptr->data;
        inet_ntop(AF_INET, &srv_addr->addr.sin_addr, srv_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &capmgr_cfg.addr.sin_addr, clt_ip, INET_ADDRSTRLEN);

        logmsg(INFO, "Connecting to server %s:%u from local address %s:%u...", 
               srv_ip, ntohs(srv_addr->addr.sin_port), 
               clt_ip, ntohs(srv_addr->lport));

        /* first setup local socket (different for each server) */
        if ((temp_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            logmsg(ERROR, "Failed to create local socket. Skipping...");
            continue;
        }

        /* the port field of capmgr_cfg.addr is not used anyway, so we can  *
         * alter the port number in every iteration without problems        */
        capmgr_cfg.addr.sin_port = srv_addr->lport;

        /* even if the capmgr acts as a client, it has to bind to its       *
         * specified IP address to be recognized by the servers             */
        if (bind(temp_sock, (struct sockaddr *) &capmgr_cfg.addr,
            sizeof(struct sockaddr_in)) != 0) {
            logmsg(SEVERE, "Failed to bind to configured address (%s).",
                   strerror(errno));
            close(temp_sock);
            continue;
        }

        /* establish network connection */
        if (connect(temp_sock, (struct sockaddr *) &srv_addr->addr, 
            (socklen_t) sizeof(struct sockaddr_in)) < 0) {
            logmsg(INFO, "Failed to establish connection to server %s:%u...", 
                   srv_ip, ntohs(srv_addr->addr.sin_port));
            close(temp_sock);
            continue; 
        }
        logmsg(DEBUG, "Established connection to server %s:%u...",
               srv_ip, ntohs(srv_addr->addr.sin_port));

        sec_len    = strlen(capmgr_cfg.secret) + 1;
        sec_len_nw = htons(sec_len);
        /* now perform authentication with the secret passphrase */
        if (send(temp_sock, &msg_type, sizeof(uint16_t), 0) < 2 ||
            send(temp_sock, &clt_type, sizeof(uint8_t), 0) < 1 ||
            send(temp_sock, &sec_len_nw, sizeof(uint16_t), 0) < 2 ||
            send(temp_sock, capmgr_cfg.secret, sec_len, 0) < sec_len) {
            
            logmsg(ERROR, "Failed to transmit capmgr credentials. Skipping...");
            close(temp_sock);
            continue;
        }
        logmsg(DEBUG, "Transmitted credentials to server %s.", srv_ip);

        /* read the answer of the server. there will be an answer since we   *
         * followed the protocol                                             */
        if (recv(temp_sock, &res, sizeof(uint8_t), MSG_WAITALL) < 1) {
            logmsg(ERROR, "Unable to receive server answer. Skipping...");
            close(temp_sock);
            continue;
        }

        if (res != R_SUCCESS) {
            logmsg(WARN, "Authentication did not succeed (%u).", res);
            continue;
        }
        logmsg(INFO, "Server %s accepted my credentials.", srv_ip);

        /* check if server provides the right key */
        if (recv(temp_sock, &sec_len_nw, sizeof(uint16_t), MSG_WAITALL) < 2) {
            logmsg(WARN, "Unable to receive secret length from server (%s).",
                   strerror(errno));
            close(temp_sock);
            continue;
        }
        sec_len = ntohs(sec_len_nw);
        logmsg(DEBUG, "server's secret length is %u.", sec_len);

        if ((srv_sec = malloc(sec_len)) == NULL) {
            logmsg(ERROR, "can not allocate memory for server's secret.");
            msg_type = MTYPE_BYE;
            send(temp_sock, &msg_type, sizeof(uint16_t), 0);
            close(temp_sock);
            free(srv_sec);
            continue;
        }

        if (recv(temp_sock, srv_sec, sec_len, MSG_WAITALL) < sec_len) {
            logmsg(WARN, "Unable to receive secret string from server.");
            msg_type = MTYPE_BYE;
            send(temp_sock, &msg_type, sizeof(uint16_t), 0);
            close(temp_sock);
            free(srv_sec);
            continue;
        }

        /* if secret does not match the configuration, close the connection */
        if (strcmp(srv_addr->secret, srv_sec) != 0) {
            logmsg(WARN, "Server provided wrong secret!");
            msg_type = MTYPE_BYE;
            send(temp_sock, &msg_type, sizeof(uint16_t), 0);
            close(temp_sock);
            free(srv_sec);
            continue;
        }

        /* secret is correct, so we can discard the string */
        free(srv_sec);
        cur_srv = calloc(1, sizeof(struct server));
        if (cur_srv == NULL) {
            logmsg(ERROR, "Unable to allocate memory for server struct.");
            continue;
        }

        if (slist_insert(&active_srvs, cur_srv)) {
            logmsg(ERROR, "Failed to allocate memory for server list");
            free(cur_srv);
            continue;
        }

        /* everything is ok, fill struct and leave a log message */
        memcpy(&cur_srv->addr, &srv_addr->addr, sizeof(struct sockaddr_in));
        cur_srv->sock_fd = temp_sock;
        pthread_mutex_init(&cur_srv->req_lck, NULL);
        logmsg(INFO, "Added %s:%u to the list of active servers.", 
               srv_ip, srv_addr->addr.sin_port);
    }
}

/****************************************************************************
 *
 * Queries the server for the size of vslice on behlads of a client. In 
 * order for the function to succeed, there must be at least one capability
 * configured that grants the client access to the server/dev_idx/vslice_idx
 * combination specified in the datagram message.
 *
 * Params: msg_buf  - buffer to data of received datagram.
 *         creds    - credentials of the peer that sent this datagram.
 *         clt_addr - address of the client that sent the request. 
 *         addr_len - length of received client address as returned by recv etc.
 *
 * Returns: 0 on success, 1 on error.
 */
static int relay_vslcinfo(unsigned char *msg_buf, struct ucred *creds, 
    struct sockaddr_un *clt_addr, socklen_t addr_len) {

    uint16_t dev_idx       = 0;                 /* parameters received      */
    uint32_t vslc_idx      = 0;
    unsigned long srv_addr = 0;

    struct server        *srv;                  /* server to send msg to    */
    struct clt_req       *new_req;              /* new client request       */
   
    /* +1 since the first byte is the message type                          */
    unsigned char *msg_ptr = msg_buf + 1;       /* ptr to next elem in buf  */

    uint8_t opcode;                             /* msg type for server      */
    struct slist *lptr;                         /* ptr for list iteration   */

    logmsg(DEBUG, "Client UID is %u.", creds->uid);

    /* read input data from client datagram */
    memcpy(&srv_addr, msg_ptr, sizeof(unsigned long));
    msg_ptr += sizeof(unsigned long);
    memcpy(&dev_idx, msg_ptr, 2);
    msg_ptr += 2;
    memcpy(&vslc_idx, msg_ptr, 4);

    /* check whether a capability as specified by the client was configured */
    for (lptr = capmgr_cfg.caps; lptr != NULL; lptr = lptr->next) {
        struct crdss_clt_cap *cap = (struct crdss_clt_cap *) lptr->data;

        if (cap->uid != creds->uid)
            logmsg(DEBUG, "UID not matching conf: %u, clt %u.", cap->uid, 
                   creds->uid);

        if (cap->dev_idx == dev_idx && cap->vslc_idx == vslc_idx &&
            cap->srv.sin_addr.s_addr == srv_addr &&
            cap->uid == creds->uid) {
            break;
        }
    }

    if (lptr == NULL) {
        /* cap not found */
        logmsg(WARN, "Cap requested by client was not configured.");
        return(1);
    }

    pthread_mutex_lock(&srv_lck);
    logmsg(DEBUG, "Searching server list.");

    /* check whether the requested server is currently active               */
    for (lptr = active_srvs; lptr != NULL; lptr = lptr->next) {
        srv = (struct server *) lptr->data;

        if (srv->addr.sin_addr.s_addr == srv_addr) {
            break;
        }
    }

    if (lptr == NULL) {
        /* server not found */
        pthread_mutex_unlock(&srv_lck);
        logmsg(WARN, "Server for requested capability is not connected.");
        return(1);
    }

    logmsg(DEBUG, "Filling intermediate request struct.");
    if ((new_req = malloc(sizeof(struct clt_req))) == NULL) {
        pthread_mutex_unlock(&srv_lck);
        logmsg(WARN, "Memory allocation for new request failed.");
        return(1);
    }

    new_req->type     = MTYPE_VSLCINFO;
    new_req->cap      = NULL;
    memcpy(&new_req->clt_addr, clt_addr, sizeof(struct sockaddr_un));
    new_req->addr_len = addr_len;
    opcode  = MTYPE_VSLCINFO;

    /* convert parameters to network byte order to comm. with server */
    dev_idx  = htons(dev_idx);
    vslc_idx = htonl(vslc_idx);

    pthread_mutex_lock(&srv->req_lck);

    if (slist_append(&srv->requests, new_req) ||
        send(srv->sock_fd, &opcode, 1, 0) < 1 ||
        send(srv->sock_fd, &dev_idx, 2, 0) < 2 ||
        send(srv->sock_fd, &vslc_idx, 4, 0) < 4) {
        
        logmsg(ERROR, "Failed to register new request.");
        srv->requests = slist_remove(srv->requests, new_req);
        pthread_mutex_unlock(&srv->req_lck);
        pthread_mutex_unlock(&srv_lck);

        free(new_req);
    }
    
    pthread_mutex_unlock(&srv->req_lck);
    pthread_mutex_unlock(&srv_lck);

    return(0);
}

/****************************************************************************
 *
 * Checks whether the parameters inside a buffer received via a datagram 
 * socket / queue pair allow for the creation of a new capability and if
 * so, allocates a new cap and inserts into the global cap list. The 
 * function then transmits the capability information to the appropriate
 * storage server and enqueues a new request object in the server's 
 * handler object.
 *
 * Params: msg_buf  - buffer to data of received datagram.
 *         creds    - credentials of the peer that sent this datagram.
 *         clt_addr - address of the client that sent the request. 
 *         addr_len - length of received client address as returned by recv etc.
 *
 * Returns: 0 on success, 1 on error.
 */
static int relay_mkcap2(unsigned char *msg_buf, struct ucred *creds, 
    struct sockaddr_un *clt_addr, socklen_t addr_len) {

    struct server        *srv;                  /* server to send msg to    */
    struct clt_req       *new_req;              /* new client request       */
    struct crdss_clt_cap *new_cap;              /* new cap to create for clt*/
   
    /* +1 since the first byte is the message type                          */
    unsigned char *msg_ptr = msg_buf + 1;       /* ptr to next elem in buf  */
    uint8_t key_len;                            /* length of cap key        */

    uint8_t opcode;                             /* msg type for server      */
    struct slist *lptr;                         /* ptr for list iteration   */

    if ((new_cap = calloc(1, sizeof(struct crdss_clt_cap))) == NULL) {
        logmsg(ERROR, "Failed to allocate memory for new cap.");
        return(1);
    }

    /* fill cap with data from buffers */
    memcpy(&new_cap->srv.sin_addr.s_addr, msg_buf + 1, 
           sizeof(new_cap->srv.sin_addr.s_addr));
    msg_ptr += sizeof(new_cap->srv.sin_addr.s_addr);
    new_cap->dev_idx = *((uint16_t *) msg_ptr);
    msg_ptr += 2;
    new_cap->vslc_idx = *((uint32_t *) msg_ptr);
    msg_ptr += 4;
    new_cap->start_addr = *((uint64_t *) msg_ptr);
    msg_ptr += 8;
    new_cap->end_addr = *((uint64_t *) msg_ptr);
    msg_ptr += 8;
    new_cap->rights = *((uint16_t *) msg_ptr);
    msg_ptr += 2;

    key_len = *((uint8_t *) msg_ptr);
    msg_ptr++;
    
    new_cap->uid = creds->uid;

    /* check for boguous key length parameter */
    if (key_len > (MAX_MSG_LEN - (msg_ptr - msg_buf))) {
        logmsg(WARN, "Client provided bad key length...");
        free(new_cap);
        return(1);
    }

    /* if no key is given, use the default ("generic") */
    if (key_len == 0) {
        logmsg(DEBUG, "Client uses default cap key...");
        key_len = strlen("generic") + 1;
        memcpy(msg_ptr, "generic", key_len);
    } 
 
    new_cap->key = calloc(key_len, sizeof(char));
    if (new_cap->key == NULL) {
        logmsg(ERROR, "Failed to allocate memory for capability key.");
        free(new_cap);
        return(1);
    }

    memcpy(new_cap->key, msg_ptr, key_len);
    new_cap->key[key_len - 1] = '\0';
    
    logmsg(DEBUG, "Client UID is %u.", creds->uid);
    logmsg(DEBUG, "Req. cap saddr is %lu.", new_cap->start_addr);
    logmsg(DEBUG, "Req. cap eaddr is %lu.", new_cap->end_addr);

    /* check whether a capability as specified by the client was configured */
    for (lptr = capmgr_cfg.caps; lptr != NULL; lptr = lptr->next) {
        struct crdss_clt_cap *cap = (struct crdss_clt_cap *) lptr->data;

        if (clt_cap_is_subset(new_cap, cap))
            logmsg(DEBUG, "Caps not matching.");
        if (cap->uid != creds->uid)
            logmsg(DEBUG, "UID not matching conf: %u, clt %u.", cap->uid, 
                   creds->uid);
        if (strcmp(cap->key, new_cap->key) != 0)
            logmsg(DEBUG, "Cap keys not matching.");

        if (clt_cap_is_subset(new_cap, cap) == 0 &&
            cap->uid == creds->uid &&
            strcmp(cap->key, new_cap->key) == 0) {
            break;
        }
    }

    if (lptr == NULL) {
        /* cap not found */
        logmsg(WARN, "Cap requested by client was not configured.");
        free(new_cap->key);
        free(new_cap);
        return(1);
    }

    pthread_mutex_lock(&srv_lck);
    logmsg(DEBUG, "Searching server list.");

    /* check whether the requested server is currently active               */
    for (lptr = active_srvs; lptr != NULL; lptr = lptr->next) {
        srv = (struct server *) lptr->data;

        if (srv->addr.sin_addr.s_addr == new_cap->srv.sin_addr.s_addr) {
            break;
        }
    }

    if (lptr == NULL) {
        /* server not found */
        pthread_mutex_unlock(&srv_lck);
        logmsg(WARN, "Server for requested capability is not connected.");
        free(new_cap->key);
        free(new_cap);
        return(1);
    }

    logmsg(DEBUG, "Filling intermediate request struct.");
    if ((new_req = malloc(sizeof(struct clt_req))) == NULL) {
        pthread_mutex_unlock(&srv_lck);
        logmsg(WARN, "Memory allocation for new request failed.");
        free(new_cap->key);
        free(new_cap);
        return(1);
    }

    new_req->type     = MTYPE_MKCAP2;
    new_req->cap      = new_cap;
    memcpy(&new_req->clt_addr, clt_addr, sizeof(struct sockaddr_un));
    new_req->addr_len = addr_len;
    opcode = MTYPE_MKCAP2;

    pthread_mutex_lock(&srv->req_lck);

    if (slist_append(&srv->requests, new_req) ||
        send(srv->sock_fd, &opcode, 1, 0) < 1 ||
        send_cap_to_sock(srv->sock_fd, new_cap->dev_idx, new_cap->vslc_idx,
                new_cap->start_addr, new_cap->end_addr, new_cap->rights)) {
        
        logmsg(ERROR, "Failed to register new request.");
        srv->requests = slist_remove(srv->requests, new_req);
        pthread_mutex_unlock(&srv->req_lck);
        pthread_mutex_unlock(&srv_lck);

        free(new_cap->key);
        free(new_cap);
        free(new_req);
    }
    
    pthread_mutex_unlock(&srv->req_lck);
    pthread_mutex_unlock(&srv_lck);

    return(0);
}

/****************************************************************************
 *
 * Removes a server who has hang up or whose connection is faulty from the
 * list of active servers. Mind that the caller of this function must not
 * hold any locks related to the server list or related to the server
 * that should be removed (e.g. the lock on the server's request list).
 *
 * Params: srvfd - the file descriptor through that the capmgr is connected
 *                 with the server.
 *
 * Returns: 0 on success, 1 on error.
 */
static int rm_active_srv(int srvfd) {
    struct slist *lptr    = NULL;       /* ptr for list iteration           */
    struct server *faulty = NULL;       /* ptr to faulty server object      */

    pthread_mutex_lock(&srv_lck);
                
    /* find faulty server object */
    for (lptr = active_srvs; lptr != NULL; lptr = lptr->next) {
        faulty = (struct server *) lptr->data;
                    
        if (faulty->sock_fd == srvfd)
            break;
    }

    if (faulty == NULL) {
        pthread_mutex_unlock(&srv_lck);
        logmsg(WARN, "Did not found server with faulty fd.");
        return(1);
    }

    /* destroy server object */
    close(faulty->sock_fd);
    pthread_mutex_lock(&faulty->req_lck);
    while (faulty->requests != NULL) {
        struct crdss_clt_cap *cap = 
                        (struct crdss_clt_cap *) faulty->requests->data;
        free(cap->key);
        free(cap);
        faulty->requests = slist_remove(faulty->requests, cap);
    }
    pthread_mutex_unlock(&faulty->req_lck);

    active_srvs = slist_remove(active_srvs, faulty);
    free(faulty);

    pthread_mutex_unlock(&srv_lck);
    return(0);
}

/****************************************************************************
 *
 * Reads a server answer from file descriptor fd. The fd is expected to be
 * checked for available data using poll / select beforehand. Via the
 * fd, the corresponding server context for the responding server is 
 * extracted and the answer is forwarded to the client process that 
 * initiated the request.
 *
 * Params: srvfd - file descriptor to server socket.
 *
 * Returns: 0 on success, 1 on error.
 */
static int handle_srv_msg(int srvfd) {
    struct slist   *lptr = NULL;                /* ptr for list iteration   */
    struct server  *srv  = NULL;                /* server behind srvfd      */
    struct clt_req req;                         /* client request worked off*/

    uint8_t op_res;                             /* server status response   */
    unsigned short srv_port = 0;                /* port of server for cap   */
    uint64_t slice_size     = 0;                /* size of vslice           */

    unsigned char ans_buf[MAX_MSG_LEN];         /* buf for answer to client */

    ssize_t read_len;                           /* no of unexpected bytes   */

    req.cap = NULL;              /* suppress warnings, maybe an error here? */

    /* first find out the request object that is served by this answer      */
    pthread_mutex_lock(&srv_lck);

    for (lptr = active_srvs; lptr != NULL; lptr = lptr->next) {
        srv = (struct server *) lptr->data;

        if (srv->sock_fd == srvfd) {
            /* this is the right server, make a copy of the next request    */
            pthread_mutex_lock(&srv->req_lck);
            
            /* abort handler if there is no request registered              */
            if (srv->requests == NULL) {
                lptr = NULL;
                logmsg(ERROR, "Server's request list is empty.");
                
                /* still read data to reset stream position */
                read_len = recv(srvfd, ans_buf, MAX_MSG_LEN, MSG_PEEK);
                if (read_len == 0) {
                    logmsg(WARN, "Connection to server died (read returned 0 "
                           "on fd %d).", srvfd);

                    /* release locks as required by clea-up function */
                    pthread_mutex_unlock(&srv->req_lck);
                    pthread_mutex_unlock(&srv_lck);
                    return(rm_active_srv(srvfd));
                }
                else {
                    logmsg(WARN, "Server offers %d bytes of unexpected data.",
                           read_len);
                
                    /* consume data to reset stream to message boundaries   */
                    while (read_len > 0) {
                        read_len -= recv(srvfd, ans_buf, MAX_MSG_LEN, 0);
                    }
                }
            }
            else {
                /* make a copy of the req. and rm it from the open req list */
                memcpy(&req, srv->requests->data, sizeof(struct clt_req));
                free(srv->requests->data);
                srv->requests = slist_remove(srv->requests, 
                                             srv->requests->data);
                srv_port = srv->addr.sin_port;
            }

            pthread_mutex_unlock(&srv->req_lck);
            break;
        }
    }

    pthread_mutex_unlock(&srv_lck);

    if (lptr == NULL) {
        logmsg(ERROR, "Unable to locate request struct matching server input.");
        return(1);
    }

    /* now read server' status answer, only proceed on successful ops       */
    if (recv(srvfd, &op_res, sizeof(uint8_t), MSG_WAITALL) < 1) {
        logmsg(ERROR, "Unable to obtain request status (%d).", errno);
        free(req.cap);
        return(1);
    }

    if (op_res != R_SUCCESS) {
        logmsg(WARN, "Server responded with error code %u.", op_res);
        free(req.cap);
        sendto(clt_sock, &op_res, 1, 0, (struct sockaddr *) &req.clt_addr,
               (socklen_t) sizeof(req.clt_addr));

        return(1);
    }

    memset(ans_buf, 0, MAX_MSG_LEN);
    ans_buf[0] = op_res;
    switch (req.type) {
        case MTYPE_MKCAP2:
            if (recv(srvfd, req.cap->id, CAP_ID_LEN, MSG_WAITALL) < 
                     CAP_ID_LEN ||
                recv(srvfd, &req.cap->rev_dom, 4, MSG_WAITALL) < 4) {
                logmsg(ERROR, "Failed to read complete server answer.");
                free(req.cap);
                return(1);
            }

            /* copy contents into answer buffer */
            memcpy(ans_buf + 1, req.cap->id, CAP_ID_LEN);
            memcpy(ans_buf + CAP_ID_LEN + 1, &req.cap->rev_dom, 4);
            memcpy(ans_buf + CAP_ID_LEN + 5, &srv_port, sizeof(unsigned short));

            break;
        case MTYPE_VSLCINFO:
            if (recv(srvfd, &slice_size, 8, MSG_WAITALL) < 8) {
                logmsg(ERROR, "Failed to read server answer for VSLCINFO.");
                return(1);
            }

            slice_size = be64toh(slice_size);
            memcpy(ans_buf + 1, &slice_size, 8);
            break;
        default:
            logmsg(ERROR, "Unknown request type found.");
            free(req.cap);
            return(1);
    }

    /* enqueue new cap in cap list and send answer to client */
    pthread_mutex_lock(&cap_lck);
    
    if (slist_insert(&active_caps, req.cap) != 0) {
        logmsg(ERROR, "Failed to insert new cap in cap list.");
        pthread_mutex_unlock(&cap_lck);
        free(req.cap);
        return(1);
    }

    pthread_mutex_unlock(&cap_lck);

    sendto(clt_sock, ans_buf, MAX_MSG_LEN, 0, (struct sockaddr *) &req.clt_addr, 
           req.addr_len);

    return(0);
}

/****************************************************************************
 *
 * This function listens for the answers of crdss-srvs to operations that
 * have been previously triggered by the client service thread. After reading
 * the results, it will forward received capabilites or error messages to the
 * clients that are waiting for an answer of the cap manager.
 *
 * Params: args - pointer to arguments. This thread does not expect args.
 *
 * Returns: this function will always return a NULL pointer as operation
 *          result.
 */
void *server_listener(void *args) {
    unsigned int i;

    unsigned int list_len;                  /* list length                  */
    struct pollfd *fds    = NULL;           /* structures for polling       */

    struct slist *lptr    = NULL;           /* ptr for list iterations      */

    (void) args;

    logmsg(INFO, "Starting server-side handler loop.");
    while (1) {
        pthread_mutex_lock(&srv_lck);
        list_len = slist_length(active_srvs);

        if (list_len == 0 ||  
            (fds = realloc(fds, list_len * sizeof(struct pollfd))) == NULL) {
            logmsg(SEVERE, "No active storage servers left, exiting...");
            exit(0);
        }

        memset(fds, 0, list_len * sizeof(struct pollfd));
        i = 0;
        for (lptr = active_srvs; lptr != NULL; lptr = lptr->next, i++) {
            struct server *srv = (struct server *) lptr->data;
        
            logmsg(DEBUG, "Preparing poll struct for fd %d.", srv->sock_fd);
            fds[i].fd     = srv->sock_fd;
            fds[i].events = POLLIN;
        }
        pthread_mutex_unlock(&srv_lck);
        
        /* now wait for incoming events (infinite timeout) */
        logmsg(DEBUG, "Polling %u server connections.", list_len);
        if (poll(fds, list_len, -1) == -1) {
            logmsg(SEVERE, "Polling server connections failed (%d)!", errno);
            return(NULL);
        }

        /* go through the pollfd list and work on incoming messages */
        for (i = 0; i < list_len; i++) {
            if (fds[i].revents & POLLERR || fds[i].revents & POLLHUP ||
                fds[i].revents & POLLNVAL) {
                /* this server connection is broken, remove server from     *
                 * the list of active servers                               */
                logmsg(INFO, "Removing faulty server with fd %d.", fds[i].fd);
                if (rm_active_srv(fds[i].fd) == 0) {
                    logmsg(INFO, "Removed faulty server.");
                }
                else {
                    logmsg(WARN, "Faulty server object did not exist...");
                }

                continue;
            }

            if (fds[i].revents & POLLIN) {
                logmsg(DEBUG, "Received input on fd %d.", fds[i].fd);
                if (handle_srv_msg(fds[i].fd) != 0) {
                    logmsg(ERROR, "Failed to read server answer on fd %d.",
                           fds[i].fd);
                    continue;
                }
            }
        }
    }

    return(NULL);
}

/****************************************************************************
 *
 * Handles incomding client requests. This means that in case it is 
 * necessary, a control of access rights is performed. In case the 
 * verification was successful, the request is forwarded to the corresponding
 * crdss storage server. The cap manager can either use a domain socket or a 
 * UDP endpoint for communication with its clients. However, this function
 * only uses the pre-configured file descriptor, so its is agnostic to the
 * underlying protocol.
 *
 * Returns: 1 since this function only returns after a severe error.
 */
int client_listener(void) {
    uint8_t opcode;                                 /* type of next message */

    struct sockaddr_un peer_addr;                   /* address of client    */

    unsigned char *cred_buf;                        /* buffer for peer cred.*/
    unsigned char msg_buf[MAX_MSG_LEN];             /* message buffer       */

    struct msghdr hdr;                              /* message header       */
    struct iovec  iov;
    struct ucred  *creds;                           /* peer credentials     */

    struct cmsghdr *hdr_ptr;                        /* iterates over headers*/

    ssize_t bytes_read;                             /* no. of bytes read    *
                                                     * from clt. socket     */

    int ret;                                        /* return value         */

    /* allocate buffer for peer credentials. use malloc to obtain proper    *
     * alignment                                                            */
    if ((cred_buf = malloc(CMSG_SPACE(sizeof(struct ucred)))) == NULL) {
        logmsg(SEVERE, "Failed to allocate credentials buffer.");
        return(1);
    }

    /* handler loop, receive messages and serve the requests                */
    logmsg(INFO, "Starting client-side handler loop.");
    while(1) {
        /* assemble message header, will be reused on each recv operation   */
        /* peer's name is not of interest, just find out its UID            */
        memset(&peer_addr, 0, sizeof(peer_addr));
        peer_addr.sun_family = AF_UNIX; 
        hdr.msg_name         = &peer_addr;
        hdr.msg_namelen      = sizeof(peer_addr);

        hdr.msg_control    = cred_buf;
        hdr.msg_controllen = CMSG_SPACE(sizeof(struct ucred));

        /* assemble I/O vector for actual message payload */
        hdr.msg_iov    = &iov;
        hdr.msg_iovlen = 1;
        iov.iov_base   = msg_buf;
        iov.iov_len    = MAX_MSG_LEN;
   
        logmsg(DEBUG, "clt handler: receiving next message.");
        if ((bytes_read = recvmsg(clt_sock, &hdr, 0)) <= 0) {
            logmsg(SEVERE, "Error while listening on socket: %d", errno);
            return(1);
        }

        /* check whether credentials have been transmitted as requested     */
        hdr_ptr = CMSG_FIRSTHDR(&hdr);

        if (hdr_ptr == NULL ||
            hdr_ptr->cmsg_len != CMSG_LEN(sizeof(struct ucred)) ||
            hdr_ptr->cmsg_level != SOL_SOCKET ||
            hdr_ptr->cmsg_type != SCM_CREDENTIALS) {
            logmsg(ERROR, "Failed to acquire credentials from client.");
            continue;
        }
        creds = (struct ucred *) CMSG_DATA(hdr_ptr);

        opcode = *((uint8_t *) (msg_buf));
        logmsg(DEBUG, "Handling request from client %s.", peer_addr.sun_path + 1);
        logmsg(DEBUG, "Length of stored addr is %u.", hdr.msg_namelen);
        logmsg(DEBUG, "Client requested opcode %u.", opcode);
        switch(opcode) {
            case MTYPE_MKCAP2:
                /* create a cap inside a new revocation domain              */
                if (relay_mkcap2(msg_buf, creds, &peer_addr, 
                    (socklen_t) hdr.msg_namelen) != 0) {
                   
                   logmsg(WARN, "Failed to relay MKCAP2 request.");
                
                   /* Notify the client */
                   memset(msg_buf, 0, MAX_MSG_LEN);
                   msg_buf[0] = R_FAILURE;
                   /* important: only use as much bytes as returned in msghdr *
                    * otherwise the socket address has a different path and   *
                    * hence refers to a different address which is certainly  *
                    * not a socket. In this case, sendto returns -1 with      *
                    * errno set to 111 (connection refused)                   */
                   ret = sendto(clt_sock, msg_buf, MAX_MSG_LEN, 0,
                                (struct sockaddr *) &peer_addr,
                                (socklen_t) hdr.msg_namelen); 
                   if (ret < MAX_MSG_LEN) {
                       logmsg(WARN, "Could not transmit error message to clt "
                              "(returned %d, errno is %d).", ret, errno);
                   }
                }
                else { 
                    logmsg(DEBUG, "MKCAP2 request forwarded to server.");
                }

                break;
            case MTYPE_VSLCINFO:
                /* client queries size of a vslice                          */
                if (relay_vslcinfo(msg_buf, creds, &peer_addr, 
                    (socklen_t) hdr.msg_namelen) != 0) {
                   
                   logmsg(WARN, "Failed to relay VSLCINFO request.");
                
                   /* Notify the client */
                   memset(msg_buf, 0, MAX_MSG_LEN);
                   msg_buf[0] = R_FAILURE;
                   /* important: only use as much bytes as returned in msghdr *
                    * otherwise the socket address has a different path and   *
                    * hence refers to a different address which is certainly  *
                    * not a socket. In this case, sendto returns -1 with      *
                    * errno set to 111 (connection refused)                   */
                   ret = sendto(clt_sock, msg_buf, MAX_MSG_LEN, 0,
                                (struct sockaddr *) &peer_addr,
                                (socklen_t) hdr.msg_namelen); 
                   if (ret < MAX_MSG_LEN) {
                       logmsg(WARN, "Could not transmit error message to clt "
                              "(returned %d, errno is %d).", ret, errno);
                   }
                }
                else { 
                    logmsg(DEBUG, "VSLCINFO request forwarded to server.");
                }

                break;
            default:
                logmsg(WARN, "Clt. provided invalid opcode %u.", opcode);
                continue;
        }
    }

    return(1);
}

/****************************************************************************
 *
 * Sets up a UNIX domain socket for communication with clients. The socket
 * is bound to the path name specified in the configuration file. If the
 * file exists and it is a socket, it will be deleted and re-created, 
 * otherwise this operation fails.
 *
 * Returns: 0 on success, 1 on error.
 */
int init_clt_sock_dom(void) {
    int optval;                         /* value for socket options         */
    struct stat stat_buf;               /* for an analysis of socket file   */

    /* first check if the socket file already exists */
    if (access(capmgr_cfg.clt_sock.dom.sun_path, F_OK) == 0) {
        logmsg(DEBUG, "Designated socket file %s already exists.",
               capmgr_cfg.clt_sock.dom.sun_path);

        if (stat(capmgr_cfg.clt_sock.dom.sun_path, &stat_buf) == -1) {
            logmsg(ERROR, "Failed to stat old socket file (%d).", errno);
            return(1);
        }

        if (S_ISSOCK(stat_buf.st_mode)) {
            logmsg(DEBUG, "Unlinking (old) socket file");
            if (unlink(capmgr_cfg.clt_sock.dom.sun_path) == -1) {
                logmsg(ERROR, "Failed to unlink socket file (%d).", errno);
                return(1);
            }
        }
        else {
            logmsg(ERROR, "The desired domain socket path %s is block by a "
                   "non-socket file.", capmgr_cfg.clt_sock.dom.sun_path);
            return(1);
        }
    }

    if ((clt_sock = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
        logmsg(SEVERE, "Failed to create domain client listener socket (%s).", 
               strerror(errno));
        return(1);
    }

    /* change permissions to 777 to that everyone can write to this socket  */
    if (fchmod(clt_sock, stat_buf.st_mode | S_IRWXO) == -1) {
        logmsg(SEVERE, "Failed to set socket permissions (%d).", errno);
        return(1);
    }

    if (bind(clt_sock, (struct sockaddr *) &capmgr_cfg.clt_sock.dom,
        (socklen_t) sizeof(struct sockaddr_un)) == -1) {
        logmsg(SEVERE, "Failed to bind to UDS client listener socket (%d).",
               errno);
        close(clt_sock);
        return(1);
    }

    /* enable passing of peer credentials as ancillary data                 */
    optval = 1;
    if (setsockopt(clt_sock, SOL_SOCKET, SO_PASSCRED, &optval, 
        sizeof(optval)) == -1) {
        logmsg(ERROR, "Failed to set SO_PASSCRED opt for domain socket (%d).",
               errno);
        return(1);
    }

    return(0);
}

/****************************************************************************
 *
 * Sets up a UDP socket for comunication with clients. The socket is bound to
 * the IP address and the port specified in the configuration file.
 *
 * Returns: 0 on success, 1 on error.
 */
int init_clt_sock_udp(void) {
    if ((clt_sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        logmsg(SEVERE, "Failed to create UDP client listener socket (%s).", 
               strerror(errno));
        return(1);
    }

    if (bind(clt_sock, (struct sockaddr *) &capmgr_cfg.clt_sock.udp,
        (socklen_t) sizeof(struct sockaddr_in)) == -1) {
        logmsg(SEVERE, "Failed to bind to UDP client listener socket (%s).",
               strerror(errno));
        close(clt_sock);
        return(1);
    }

    return(0);
}

/****************************************************************************
 *                                                                          *
 *                          function implementation                         *
 *                                                                          *
 ****************************************************************************/


/****************************************************************************
 ****************************************************************************
 ************************           M A I N           ***********************
 ****************************************************************************
 ****************************************************************************/
int main(int argc, char **argv) {
    int next_opt;                   /* value of next cli option             */
    int wflag = 0;
    int uflag = 0;                  /* use domain sockets for client comm.  */
    int rc;                         /* error code for reporting             */

    char *logdir   = NULL;          /* directory of log file                */
    char *logpath  = NULL;          /* path to log file                     */
    char *confpath = NULL;          /* path to config file                  */

    /* parse command line arguments */
    while ((next_opt = getopt(argc, argv, ":c:l:uwh")) != -1) {
        switch (next_opt) {
            case 'c':
                confpath = optarg;
                continue;
            case 'h':
                usage();
                exit(0);
            case 'l':
                /* make the logpath absolute to open logfile at right spot  *
                 * even after daemonizing which changes wdir to /           */
                if (strncmp(optarg, "/", 1) == 0) {
                    /* input path is abolute       */
                    logpath = malloc(strlen(optarg) + 1);
                    strcpy(logpath, optarg);
                }
                else {
                    /* input path is relative      */
                    logdir = malloc((size_t) PATH_MAX);
                    if ((logdir = getcwd(logdir, PATH_MAX)) == NULL) {
                        fprintf(stderr, "Failed get logging directory.\n");
                        exit(1);
                    }
                    logpath = malloc(strlen(logdir) + strlen(optarg) + 2);
                    /* assemble absolute logpath */
                    strcpy(logpath, logdir);
                    strcpy(logpath + strlen(logdir), "/");
                    strcpy(logpath + strlen(logdir) + 1, optarg);
                }
                continue;
            case 'u':
                uflag = 1;
                continue;
            case 'w':
                wflag = 1;
                continue;
            case ':':
                fprintf(stderr, "Missing argument for option -%c\n", optopt);
                exit(1);
            case '?':
                fprintf(stderr, "Unknown option -%c\n", optopt);
                exit(1);
            default:
                usage();
                exit(1);
        }
    }

    /* check input options for conflicts                                    */
    if (confpath == NULL) {
        /* server can not start without a config file */
        fprintf(stderr, "Missing path to capmgr configuration file!\n\n");
        usage();
        exit(1);
    }

    /* daemon must have a logfile to communicate its sorrow                 */
    if (logpath == NULL && !wflag) {
        fprintf(stderr, "Specify a log file when running the server as a "
                "daemon!\n");
        exit(1);
    }
    /* logfile must be writable. if it does not exist, logdir must be       *
     * writable to create a new file                                        */
    if (logpath != NULL) {
        if (access(logpath, F_OK) == -1) {
            /* file does not exist, check if directory is writable          */
            if (access(logdir, W_OK) == -1) {
                fprintf(stderr, "Log file %s does not exist and there are "
                        "no rights for modifying the target directory.\n",
                        logpath);
                exit(1);
            }
        }
        else {
            /* file exists, check if it can be written                      */
            if (access(logpath, W_OK) == -1) {
                fprintf(stderr, "No write permission for log file %s.\n",
                        logpath);
                exit(1);
            }
        }
    }

    /* parse config file, report errors to stderr before server daemonizes! */
    fprintf(stderr, "Parsing config file %s\n", confpath);
    if (parse_snic_config(confpath, &capmgr_cfg) != 0) {
        fprintf(stderr, "Failed to parse configuration file. Exiting...\n");
        exit(1);
    }

    /* some more semantic input checking... Make sure that the required     *
     * information for the client socket is present                         */
    if (uflag == 0 && strlen(capmgr_cfg.clt_sock.dom.sun_path) == 0) {
        fprintf(stderr, "Cap manager shall run with domain socket for clients "
                "but there is no config info for such a socket!\n");
        exit(1);
    }
    else {
        /* only need to check port or ip address, since the config parser   *
         * makes sure that the other part of the configuration is present   */
       if (capmgr_cfg.clt_sock.udp.sin_port == 0) {
            fprintf(stderr, "Cap manager shall run with a UDP socket for its "
                    "clients but there is no config info for such a socket!\n");
            exit(1);
       }
    }

    fprintf(stderr, "Starting capability manager...\n");

    /* daemonize if wflag is not set                                        */
    if (!wflag) {
        if ((rc = daemon(0, 0))) {
            fprintf(stderr, "Failed to daemonize (%d). Exiting...\n", rc);
            exit(2);
        }
    }

    /* set log path. if logpath == NULL, stderr is used since the server    *
     * won't run as a daemon in this case (see error conditions above)      */
    if (logpath != NULL)
        init_logger(logpath, DEBUG);
    else
        init_logger("/dev/stderr", DEBUG);        

    /* logpath-related memory is no longer needed, free it immediately      */
    if (logdir != NULL)
        free(logdir);
    if (logpath != NULL)
        free(logpath);

    /***       From now on, use the logger for printing messages!!!       ***/
    logmsg(DEBUG, "Hello crdss!");
    logmsg(DEBUG, "server port is %d", ntohs(capmgr_cfg.addr.sin_port));
    logmsg(INFO, "Config file listed %d capabilities.", 
           slist_length(capmgr_cfg.caps));

    /* now, try to connect to the servers specified in the config file      */
    logmsg(INFO, "Connecting to crdss servers.");
    connect_servers();
    logmsg(INFO, "Registered with %d of %d servers configured.",
           slist_length(active_srvs), slist_length(capmgr_cfg.srvs)); 
   
    /* start the two handler threads, start server listener first           */
    if (pthread_create(&srv_listener, NULL, server_listener, NULL) != 0) {
        logmsg(SEVERE, "Failed to create server listener thread.");
        exit(3);
    }

    /* setup socket for communication with clients                          */
    if (uflag == 0) {
        if (init_clt_sock_dom()) {
            logmsg(SEVERE, "Failed to setup domain socket for client comm.");
            exit(4);
        }
        logmsg(INFO, "Set up domain socket for client comm.");
    }
    else if (uflag == 1) {
        if (init_clt_sock_udp()) {
            logmsg(SEVERE, "Failed to setup UDP socket for client comm.");
            exit(4);
        }
        logmsg(INFO, "Set up UDP socket for client comm.");
    }
    else {
        logmsg(SEVERE, "Specified unknown protocol for client comm.");
        exit(4);
    }

    /* return result of client handler function */
    return(client_listener());
}

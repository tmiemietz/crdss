/****************************************************************************
 *                                                                          *
 *    libcrdss.c - Client-side library for accessing the CRDSS service.     *
 *                                                                          *
 *                    Copyright (c) 2020 Till Miemietz                      *
 *                                                                          *
 ****************************************************************************/



/****************************************************************************
 *                                                                          *
 *                           include statements                             *
 *                                                                          *
 ****************************************************************************/


#include <stdio.h>                          /* std. I/O channels            */
#include <string.h>                         /* string manipulation          */
#include <sys/socket.h>                     /* networking API               */
#include <sys/un.h>                         /* UNIX domain sockets          */
#include <sys/stat.h>                       /* check socket files           */
#include <unistd.h>                         /* standard UNIX calls          */

#include "include/libcrdss.h"               /* header for libcrdss impl.    */
#include "include/protocol.h"               /* CRDSS protocol               */

/****************************************************************************   
 *                                                                          *   
 *                           global variables                               *   
 *                                                                          *   
 ****************************************************************************/


/*** fields for communication with the capability manager                 ***/
static int capmgr_fd = -1;             /* fd for socket to cap manager      */
static struct sockaddr_un capmgr_addr; /* domain socket addr of cap manager */

/* lock for serializing access (preliminary limitation)                     */
static pthread_mutex_t capmgr_lck = PTHREAD_MUTEX_INITIALIZER;

/****************************************************************************
 *                                                                          *
 *                          static helper functions                         *
 *                                                                          *
 ****************************************************************************/


/****************************************************************************
 *
 * Destructor function for a TLS key that is invoked when a worker thread
 * dies. Currently the function shall release the worker context structure
 * associated with the respective TLS key.
 * TODO: complete description.
 *
 * Params: ctx - Pointer to the value of the TLS key.
 */
static void wctx_destructor(void *ctx) {
    free(ctx);
}

/****************************************************************************
 *                                                                          *
 *                          function implementation                         *
 *                                                                          *
 ****************************************************************************/


/***                   functions as defined in libcrdss.h                 ***/

/* Allocates and initializes a new server context.                          */
struct crdss_srv_ctx *create_srv_ctx(struct clt_lib_cfg *cfg) {
    struct crdss_srv_ctx *ctx = NULL;           /* newly allocated context  */

    if ((ctx = calloc(1, sizeof(struct crdss_srv_ctx))) == NULL) {
        /* allocation of context structure failed. */
        return(NULL);
    }

    /* initialize some values */
    ctx->srv_addr.sin_family = AF_INET; /* is often forgotten; error source */
    ctx->tcp_fd              = -1;
    pthread_mutex_init(&ctx->tcp_lck, NULL);

    /* set the server connection's InfiniBand buffer settings               */
    if (cfg == NULL || check_libcfg(cfg) != 0) {
        /* no (or bad) config given, try to load it from def. location      */
        fprintf(stderr, "No config passed. Trying default config file %s.\n",
                DEF_LIB_CFG_PATH);

        if (parse_lib_config(DEF_LIB_CFG_PATH, &ctx->buf_cfg) != 0) {
            fprintf(stderr, "Failed to parse configuration file.\n");
            pthread_mutex_destroy(&ctx->tcp_lck);
            free(ctx);
            return(NULL);
        }
    }
    else {
        memcpy(&ctx->buf_cfg, cfg, sizeof(struct clt_lib_cfg));
    }

    /* create TLS key for worker context of the new server connection       */
    if (pthread_key_create(&ctx->tls_key, &wctx_destructor) != 0) {
        /* failed to allocate new TLS key */
        fprintf(stderr, "Failed to allcoate new TLS key.\n");
        pthread_mutex_destroy(&ctx->tcp_lck);
        free(ctx);
        return(NULL);
    }

    return(ctx);
}

/* Opens a connection to a local capability manager.                        */
int connect_capmgr_dom(char *sockpath) {
    struct stat sbuf;                   /* for analysis of socket path      */

    int optval;                         /* option value for setsockopt      */

    /* check if designated cap manager socket exists */
    if (sockpath == NULL)
        return(1);

    if (access(sockpath, F_OK) != 0)
        return(1);                                   /* file does not exist */

    if (stat(sockpath, &sbuf) == -1 || ! S_ISSOCK(sbuf.st_mode)) 
        return(2);                  /* stat failed or file is not a socket  */

    /* grab the lock for accessing the capability manager */
    pthread_mutex_lock(&capmgr_lck);
    
    /* close former socket if it is still active */
    if (capmgr_fd != -1)
        close(capmgr_fd);

    memcpy(&capmgr_addr.sun_path, sockpath, strlen(sockpath) + 1);
    capmgr_addr.sun_family = AF_UNIX;

    if ((capmgr_fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
        pthread_mutex_unlock(&capmgr_lck);
        return(3);                                  /* failed to create sock*/
    }

    /* by enabling the SO_PASSCRED, autobinding of the socket is triggered */
    
    optval = 1;
    if (setsockopt(capmgr_fd, SOL_SOCKET, SO_PASSCRED, &optval, 
        sizeof(optval)) == -1) {
        /* setting of socket option failed */
        pthread_mutex_unlock(&capmgr_lck);
        return(4);
    }

    pthread_mutex_unlock(&capmgr_lck);

    return(0);
}

/* Connects an application to the CRDSS storage server specified            */
int connect_storage_srv(struct crdss_srv_ctx *sctx) {
    uint16_t msg_type;              /* init. server expects 16b type field  */
    uint8_t opcode;                 /* opcode sent to server                */
    uint8_t op_res;                 /* status returned from server          */

    if (sctx->srv_addr.sin_family != AF_INET) {
        /* unknown address family */
        return(1);
    }

    /* lock server context */
    pthread_mutex_lock(&sctx->tcp_lck);

    if (sctx->tcp_fd != -1) {
        /* socket is already initialized */
        pthread_mutex_unlock(&sctx->tcp_lck);
        return(1);
    }

    if ((sctx->tcp_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        /* creation of socket failed */
        pthread_mutex_unlock(&sctx->tcp_lck);
        return(1);
    }
    
    if (connect(sctx->tcp_fd, (struct sockaddr *) &sctx->srv_addr, 
        (socklen_t) sizeof(struct sockaddr_in)) < 0) {
        /* low-level connection of sockets failed */
        pthread_mutex_unlock(&sctx->tcp_lck);
        return(1);
    }

    msg_type = htons(MTYPE_HELLO);
    opcode   = CLT_NORMAL;

    if (send(sctx->tcp_fd, &msg_type, 2, 0) < 2 || 
        send(sctx->tcp_fd, &opcode, 1, 0) < 1) {
        /* could not transmit handshake information to server... */
        pthread_mutex_unlock(&sctx->tcp_lck);
        return(1);
    }

    if (recv(sctx->tcp_fd, &op_res, sizeof(uint8_t), MSG_WAITALL) < 1) {
        /* failed to get handshake answer from server */
        pthread_mutex_unlock(&sctx->tcp_lck);
        return(1);
    }

    pthread_mutex_unlock(&sctx->tcp_lck);

    if (op_res != R_SUCCESS) {
        /* handshake error with server */
        return(1);
    }

    return(0);
}

/* Queries the preconfigured cap manager to issue a new capability          */
int request_new_cap(struct crdss_clt_cap *cap) {
    unsigned char msg_buf[MAX_MSG_LEN];         /* message buffer           */
  
    size_t  addr_sz = sizeof(cap->srv.sin_addr.s_addr);
    uint8_t key_len;                            /* length of cap key string */

    /* prepare message buffer for sending */
    memset(msg_buf, 0, MAX_MSG_LEN);
    msg_buf[0] = MTYPE_MKCAP2;
    memcpy(msg_buf + 1, &cap->srv.sin_addr.s_addr, addr_sz);
    memcpy(msg_buf + 1 + addr_sz, &cap->dev_idx, 2);
    memcpy(msg_buf + 3 + addr_sz, &cap->vslc_idx, 4);
    memcpy(msg_buf + 7 + addr_sz, &cap->start_addr, 8);
    memcpy(msg_buf + 15 + addr_sz, &cap->end_addr, 8);
    memcpy(msg_buf + 23 + addr_sz, &cap->rights, 2);

    /* only copy key if it fits in message bounds */
    key_len = (cap->key != NULL) ? (uint8_t) strlen(cap->key) : 0;
    /* max msg len - size of previous msg content - 1 for string terminator *
     * - 1 for key length field                                             */
    if (key_len != 0 && key_len < (MAX_MSG_LEN - 25 - 2 - addr_sz)) {
        msg_buf[addr_sz + 25] = key_len;
        memcpy(msg_buf + addr_sz + 26, cap->key, key_len);
    }

    /* grab the capmgr lock to ensure that the received answer belongs to   *
     * the request that was just sent                                       */
    pthread_mutex_lock(&capmgr_lck);

    /* send message to cap manager */
    sendto(capmgr_fd, msg_buf, MAX_MSG_LEN, 0, (struct sockaddr *) &capmgr_addr,
           (socklen_t) sizeof(capmgr_addr));
    printf("lib: cap data sent.\n");

    /* reset msg buffer to avoid reading stale data */
    memset(msg_buf, 0, MAX_MSG_LEN);

    /* wait for answer from cap manager (he is the only one that should send *
     * mssages, so we do not care for the sender's address here (TODO))      */
    if (recv(capmgr_fd, msg_buf, MAX_MSG_LEN, 0) < 1) {
        /* read from capmgr failed */
        pthread_mutex_unlock(&capmgr_lck);
        return(1);
    }

    pthread_mutex_unlock(&capmgr_lck);

    if (msg_buf[0] != R_SUCCESS) {
        return(msg_buf[0]);
    }

    /* everything seems to be fine, fill cap with answer from capmgr */
    memcpy(cap->id, msg_buf + 1, CAP_ID_LEN);
    memcpy(&cap->rev_dom, msg_buf + CAP_ID_LEN + 1, sizeof(uint32_t));
    memcpy(&cap->srv.sin_port, msg_buf + CAP_ID_LEN + 5, 
           sizeof(unsigned short));
    printf("server port for cap is %u.\n", ntohs(cap->srv.sin_port));

    return(0);
}

/* Initializes an InfiniBand connection with the CRDSS storage server       */
int init_ib_comm(int srvfd, struct ib_ctx *ibctx, uint64_t guid,
                 unsigned char **msgbuf, unsigned char **rdmabuf,
                 int rdmasz) {
    uint8_t msg_type = MTYPE_IBINIT;            /* message type for server  */
    uint8_t op_res;                             /* result of srv operation  */

    uint16_t lid;                               /* buffering of data        */
    uint32_t qpn;   

    uint64_t srv_addr;                          /* ID of server's RDMA buf  */
    uint32_t srv_rkey;
    uint64_t clt_addr;                          /* ID of client's RDMA buf  */
    uint32_t clt_rkey;

    /* first-phase clt-side qp setup */
    if (init_clt_qp(ibctx, guid, msgbuf, rdmabuf, rdmasz) != 0) {
        /* IB queue pair initialization failed */
        printf("IB queue pair initialization failed\n");
        return(1);
    }

    pthread_mutex_init(&ibctx->mtx, NULL);
    pthread_cond_init(&ibctx->cv, NULL);
    ibctx->is_armed = 0;
    ibctx->next_err = 0;
    ibctx->next_id  = 0;

    lid = htons(ibctx->loc_lid);
    qpn = htonl(ibctx->qp->qp_num);
    if (send(srvfd, &msg_type, 1, 0) < 1 || send(srvfd, &lid, 2, 0) < 2 || 
        send(srvfd, &qpn, 4, 0) < 4 || send(srvfd, &rdmasz, 4, 0) < 4) {
        /* failed to transmit IB connection data to server */
        printf("failed to transmit IB connection data to server\n");
        return(1);
    }

    /* receive server's answer */
    if (recv(srvfd, &op_res, 1, MSG_WAITALL) < 1 || op_res != R_SUCCESS) {
        /* server query was not successful */
        return(1);
    }

    if (recv(srvfd, &lid, 2, MSG_WAITALL) < 2 || 
        recv(srvfd, &qpn, 4, MSG_WAITALL) < 4 ||
        recv(srvfd, &srv_addr, 8, MSG_WAITALL) < 8 ||
        recv(srvfd, &srv_rkey, 4, MSG_WAITALL) < 4) {
        /* can not read connection data from server */
        return(1);
    }

    ibctx->rem_lid     = ntohs(lid);
    ibctx->remote_qpn  = ntohl(qpn);
    ibctx->remote_addr = be64toh(srv_addr);
    ibctx->remote_rkey = ntohl(srv_rkey);

    if (complete_clt_qp(ibctx, *msgbuf) != 0) {
        /* queue pair transition failed */
        return(1);
    }
    
    clt_addr = htobe64((uint64_t) *rdmabuf);
    clt_rkey = htonl(ibctx->rdma_mr->rkey);
    if (send(srvfd, &clt_addr, 8, 0) < 8 || send(srvfd, &clt_rkey, 4, 0) < 4) {
        /* failed to send answer with client memory window to server */
        return(1);
    }

    return(0);
}

/* Closes a connection to a CRDSS storage server.                           */
int close_srv_conn(int srvfd, struct ib_ctx *ibctx) {
    uint8_t opcode = MTYPE_BYE;             /* ID for server operation      */
    unsigned char msg_buf[MAX_MSG_LEN];     /* msg for IB transfer          */

    if (ibctx == NULL) {
        /* send goodbye message via TCP */
        send(srvfd, &opcode, 1, 0);
    }
    else {
        /* send goodbye message via IB */
        memset(msg_buf, 0, MAX_MSG_LEN);
        msg_buf[0] = MTYPE_BYE;

        if (post_msg_sr(ibctx, msg_buf) != 0) {
            /* failed to send goodbye message */
            return(1);
        }

        if (destroy_ibctx(ibctx) != 0) {
            /* failed to destroy IB context */
            return(1);
        }
    }
    
    /* close TCP socket */
    close(srvfd);       

    return(0);
}

/* Registers a capability at the server by specifying the cap ID.           */
int reg_cap(int srvfd, struct ib_ctx *ibctx, unsigned char *capid) {
    uint8_t opcode = MTYPE_REGCAP;          /* ID for server operation      */
    uint8_t op_res;                         /* result of srv operation      */
    unsigned char msg_buf[MAX_MSG_LEN];     /* msg for IB transfer          */

    unsigned char *recv_msg = NULL;         /* msg received from queue pair */

    if (ibctx == NULL) {
        /* TCP path */
        if (send(srvfd, &opcode, 1, 0) < 1 ||
            send(srvfd, capid, CAP_ID_LEN, 0) < CAP_ID_LEN) {
            /* failed to transmit message */
            return(1);
        }

        if (recv(srvfd, &op_res, 1, MSG_WAITALL) < 1 || op_res != R_SUCCESS) {
            /* receive error or error on server side (return error code)    */
            return(op_res);
        }

        return(0);
    }
    else {
        /* IB path */
        memset(msg_buf, 0, MAX_MSG_LEN);
        msg_buf[0] = MTYPE_REGCAP;
        memcpy(msg_buf + 1, capid, CAP_ID_LEN);

        if (post_msg_sr(ibctx, msg_buf) != 0) {
            /* failed to trigger IB send op. */
            return(1);
        }

        if (get_next_ibmsg(ibctx, &recv_msg) != 0 || recv_msg[0] != R_SUCCESS) {
            /* either receive op failed or there was an error on the srv side */
            return(1);
        }

        /* repost receive request */
        if (post_msg_rr(ibctx, recv_msg, 1) != 0) {
            return(1);
        }

        return(0);
    }
}

/* Reads len bytes from the storage location specified.                     */
int fast_read_raw(struct ib_ctx *ibctx, uint16_t didx, uint32_t sidx,
                  uint64_t saddr, uint32_t len, uint64_t rdma_addr,
                  uint64_t poll_field) {
    uint16_t didx_nw;               /* parameters in network byte order     */
    uint32_t sidx_nw;
    uint64_t saddr_nw;
    uint32_t len_nw;
    uint64_t rdma_addr_nw;
    uint64_t poll_field_nw;

    uint8_t *pf_ptr;                /* pointer to poll field                */

    unsigned char msg_buf[MAX_MSG_LEN];     /* message for IB transfer      */

    pf_ptr = (uint8_t *) poll_field;

    /* convert parameters to network byte order */
    didx_nw       = htons(didx);
    sidx_nw       = htonl(sidx);
    saddr_nw      = htobe64(saddr);
    len_nw        = htonl(len);
    rdma_addr_nw  = htobe64(rdma_addr);
    poll_field_nw = htobe64(poll_field);

    /* prepare request buffer */
    memset(msg_buf, 0, MAX_MSG_LEN);
    msg_buf[0] = MTYPE_FASTREAD;
    memcpy(msg_buf + 1, &didx_nw, sizeof(uint16_t));
    memcpy(msg_buf + 3, &sidx_nw, sizeof(uint32_t));
    memcpy(msg_buf + 7, &saddr_nw, sizeof(uint64_t));
    memcpy(msg_buf + 15, &len_nw, sizeof(uint32_t));
    memcpy(msg_buf + 19, &rdma_addr_nw, sizeof(uint64_t));
    memcpy(msg_buf + 27, &poll_field_nw, sizeof(uint64_t));

    /* prepare poll field */
    *pf_ptr = R_UNDEF;

    if (post_msg_sr(ibctx, msg_buf) != 0) {
        /* failed to post send request */
        return(R_FAILURE);
    }

    /* spin in this loop until the result arrived */
    while (*pf_ptr == R_UNDEF)
        ;

    return(*pf_ptr);
}

/* Writes len bytes to the storage location specified                       */
int fast_write_raw(struct ib_ctx *ibctx, uint16_t didx, uint32_t sidx,
                   uint64_t saddr, uint32_t len, uint64_t rdma_addr,
                   uint64_t poll_field) {
    (void) ibctx;
    (void) didx;
    (void) sidx;
    (void) saddr;
    (void) len;
    (void) rdma_addr;
    (void) poll_field;

    return(0);
}

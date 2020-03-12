/****************************************************************************
 *                                                                          *
 *    libcrdss.c - Client-side library for accessing the CRDSS service.     *
 *                                                                          *
 *                    Copyright (c) 2020 Till Miemietz                      *
 *                                                                          *
 ****************************************************************************/



/****************************************************************************
 *                                                                          *
 *                     global definitions and macros                        *
 *                                                                          *
 ****************************************************************************/


#define _GNU_SOURCE

/* worker ID for threads above the no_worker limit of the buffer config     */
#define WORKER_UNREG UINT16_MAX

/* size of a single cache line in Bytes (== size for doorbell fields)       */
#define CL_SIZE 512             /* for alignment of send buffers            */

/* maximum file descriptor that can be used for CRDSS files                 */
#define LIBCRDSS_MAX_FD 1024

/* IB GUID for testing (make variable for release)                          */
#define LIBCRDSS_TEST_GUID "0xf45214030010a4e1"

/* number of retries if send queue is full                                  */
#define LIBCRDSS_SQ_FRT 5

/* interval to wait between checks of doorbell register in us               */
#define LIBCRDSS_POLL_INT 2

/****************************************************************************
 *                                                                          *
 *                           include statements                             *
 *                                                                          *
 ****************************************************************************/


#include <stdio.h>                          /* std. I/O channels            */
#include <string.h>                         /* string manipulation          */
#include <stdarg.h>                         /* for varargs in open64        */
#include <sys/socket.h>                     /* networking API               */
#include <sys/un.h>                         /* UNIX domain sockets          */
#include <sys/stat.h>                       /* check socket files           */
#include <sys/types.h>                      /* as required for open(2)      */
#include <fcntl.h>                          /* get access to the open func. */
#include <unistd.h>                         /* standard UNIX calls          */
#include <sys/syscall.h>                    /* for calling gettid           */
#include <dlfcn.h>                          /* for playing with symbols...  */

#include "include/libcrdss.h"               /* header for libcrdss impl.    */
#include "include/protocol.h"               /* CRDSS protocol               */
#include "include/utils.h"                  /* CRDSS logging facility       */

/****************************************************************************   
 *                                                                          *   
 *                           type definitions                               *   
 *                                                                          *   
 ****************************************************************************/


/* Worker context structure. Each thread has one worker context per storage *
 * server it uses. The reference to worker contexts is kept in TLS          */
struct wctx {
    uint32_t        tid;                /* TID of this worker               */
    uint16_t        wid;                /* libcrdss-internal worker ID for  *
                                         * the server context sctx (below)  */

    pthread_mutex_t mtx;                /* for waking a worker at completion*/
    pthread_cond_t  cv;

    uint32_t next_key;                  /* next completion key to listen for*/
    uint32_t  status;                   /* status of last request listened  */
    unsigned char *msg;                 /* pointer to message buffer (RR)   */

    struct crdss_srv_ctx *sctx;         /* pointer to associated server ctx */
};

/* structure for emulating POSIX files                                      */
struct crdss_posix_file {
    char  *name;                        /* file name                        */
    struct crdss_srv_ctx *sctx;         /* server connection for this file  */
    struct crdss_clt_cap cap;           /* cap for file access              */

    unsigned long int file_ptr;         /* position in file for read/write  */
    int ref_cnt;                        /* number of times the file is open */
};

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

/* indicates whether logger is initialized                                  */
static pthread_once_t log_init = PTHREAD_ONCE_INIT;

/* array for file contexts                                                  */
static struct crdss_posix_file *fd_table[LIBCRDSS_MAX_FD];
static pthread_mutex_t table_lck;
static pthread_once_t table_lck_init = PTHREAD_ONCE_INIT;

/* pointers to functions defined by libc but partially shadowed by the POSIX*
 * emulation of libcrdss.                                                   */
static ssize_t (*libc_pread64)(int, void *, size_t, off_t)        = NULL;
static ssize_t (*libc_pwrite64)(int, const void *, size_t, off_t) = NULL;
static int (*libc_xstat64)(int, const char *, struct stat64 *)    = NULL;
static int (*libc_lxstat64)(int, const char *, struct stat64 *)   = NULL;
static int (*libc_open64)(const char *, int, ...)                 = NULL;
/* static int (*libc_close)(int)                                     = NULL; */

/****************************************************************************
 *                                                                          *
 *                          static helper functions                         *
 *                                                                          *
 ****************************************************************************/


/****************************************************************************
 *
 * Initializes the logging facility of libcrdss. This function is expected
 * to be called through pthread_once during library initialization. It uses
 * stderr as default output. The loglevel displayed can be adjusted by 
 * changing the parameters of init_logger.
 */
static void setup_logger(void) {
    init_logger("/dev/stderr", INFO);
}

/****************************************************************************
 *
 * Initializes the lock for the file descriptor table of the POSIX
 * compatibility layer.
 */
static void setup_tbl_lck(void) {
    pthread_mutexattr_t attr;

    /* we do want to have a re-entrant lock here... */
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&table_lck, &attr);
}

/****************************************************************************
 *
 * Destructor function for a TLS key that is invoked when a worker thread
 * dies. The function deallocates the worker context and destroys the
 * pthread objects in it. However, it does not free the worker ID of ctx
 * at the owning server context (ctx->sctx). If an I/O worker threads exits,
 * the application is responsible for freeing the corresponding entry in
 * the worker ID bitmap of the server. The reason for this behavior is that 
 * an exiting thread currently can not be sure whether the server context
 * that the worker context references still exists. If the server context
 * was freed before this function is called, a SIGSEGV would be a fatal
 * consequence, which should be avoided.
 *
 * TODO: Implement safe deletion of worker contexts when a server context is
 *       destroyed.
 *
 * Params: ctx - Pointer to the value of the TLS key.
 */
static void wctx_destructor(void *ctx) {
    struct wctx *work_ctx       = (struct wctx *) ctx;

    pthread_mutex_destroy(&work_ctx->mtx);
    pthread_cond_destroy(&work_ctx->cv);

    free(work_ctx);
}

/****************************************************************************
 *
 * Gets the worker context for the thread that calls this function. The 
 * worker context contains information about the poll field and the small
 * buffer that a thread may use as a block I/O buffer. It also provides
 * means for waking a thread during blocking InfiniBand completion. If the
 * thread has no worker context yet, a new one will be allocated.
 *
 * Note: This function must not be called when holding the TCP lock of sctx!
 *
 * Params: sctx - The server context for that the worker context is returned.
 *
 * Returns: The calling thread's worker context or NULL on error.
 */
static struct wctx *get_wctx(struct crdss_srv_ctx *sctx) {
    unsigned int i;

    struct wctx *ctx;

    /* return an error if the server context is invalid */
    if (sctx == NULL)
        return(NULL);

    ctx = (struct wctx *) pthread_getspecific(sctx->tls_key);

    /* if a worker context was found, simply return it */
    if (ctx != NULL)
        return(ctx);

    /* before new allocation, check if sctx has an active IB connection     */
    pthread_mutex_lock(&sctx->tcp_lck);
    if (sctx->msg_buf == NULL) {
        pthread_mutex_unlock(&sctx->tcp_lck);
        return(NULL);
    }
    pthread_mutex_unlock(&sctx->tcp_lck);

    /* no worker context is set for this server, allocate one */
    if ((ctx = calloc(1, sizeof(struct wctx))) == NULL)
        return(NULL);

    if (pthread_mutex_init(&ctx->mtx, NULL) != 0)
        goto err_mtx;

    if (pthread_cond_init(&ctx->cv, NULL) != 0)
        goto err_cv;

    ctx->sctx = sctx;
    ctx->tid  = syscall(SYS_gettid);
    ctx->wid  = WORKER_UNREG;    /* mark worker as out-of-bounds by default */

    /* try to find free worker ID in the ID bitmap of sctx */
    pthread_mutex_lock(&sctx->id_lck);

    for (i = 0; i < sctx->buf_cfg.no_workers; i++) {
        unsigned int arr_ind   = i / 8;     /* compute position in bitmap   */
        unsigned int arr_off   = i % 8;
        unsigned char comp_val = 1 << arr_off;

        if (! (sctx->worker_ids[arr_ind] & comp_val)) {
            /* a free ID has been found */
            sctx->worker_ids[arr_ind] |= comp_val;
            ctx->wid = i;
            
            break;
        }
    }

    pthread_mutex_unlock(&sctx->id_lck);

    /* lastly, set the worker context in thread-local storage (TLS)         */
    if (pthread_setspecific(sctx->tls_key, ctx) != 0) {
        wctx_destructor(ctx);
        return(NULL);
    }

    logmsg(DEBUG, "New worker id is: %u.", ctx->wid);
    return(ctx);

err_cv:
    pthread_mutex_destroy(&ctx->mtx);
err_mtx:
    free(ctx);
    return(NULL);
}

/****************************************************************************
 *
 * Entry function for a worker threads that handles the completion events of
 * a server connection. The void pointer passed to ths function is expected
 * to point to a valid struct crdss_srv_ctx. The completion worker thread is
 * responsible for waking threads that have been registered for waiting for
 * an InfiniBand message.
 *
 * Params: ctx - Pointer to server context.
 * 
 * Returns: NULL.
 */
static void *completion_worker(void *ctx) {
    struct crdss_srv_ctx *sctx = (struct crdss_srv_ctx *) ctx;

    unsigned char    *msg;              /* next message to receive          */
    int               ret;              /* return value of get_next_ibmsg   */
    uint32_t          imm;              /* immediate received from message  */

    struct slist *lptr;                 /* ptr for list iteration           */

    while (1) {
        ret = get_next_ibmsg(&sctx->ibctx, &msg, &imm);
        logmsg(DEBUG, "comp worker: got new message (imm = %u)!", imm);

        pthread_mutex_lock(&sctx->wait_lck);
        logmsg(DEBUG, "comp worker: trying %u wait entries.", 
               slist_length(sctx->wait_workers));

        /* try to find worker that wait for imm                             */
        for (lptr = sctx->wait_workers; lptr != NULL; lptr = lptr->next) {
            struct wctx *wcontext = (struct wctx *) lptr->data;

            logmsg(DEBUG, "comp worker: trying entry %p.", (void *) wcontext);
            logmsg(DEBUG, "comp worker: next key of worker is %u.", 
                   wcontext->next_key);
            if (imm == wcontext->next_key) {
                wcontext->status = ret;
                wcontext->msg    = msg;

                sctx->wait_workers = slist_remove(sctx->wait_workers, wcontext);

                pthread_mutex_lock(&wcontext->mtx);
                pthread_cond_signal(&wcontext->cv);
                pthread_mutex_unlock(&wcontext->mtx);

                break;
            }
        }

        /* if no worker was found, insert message into the unknown list     */
        if (lptr == NULL) {
            struct wctx *wcontext = calloc(1, sizeof(struct wctx));

            if (wcontext == NULL) {
                pthread_mutex_unlock(&sctx->wait_lck);
                continue;
            }

            wcontext->next_key = imm;
            wcontext->status   = ret;
            wcontext->msg      = msg;

            if (slist_insert(&sctx->unknown_compl, wcontext) != 0) {
                free(wcontext);
                pthread_mutex_unlock(&sctx->wait_lck);
                continue;
            }
        }

        pthread_mutex_unlock(&sctx->wait_lck);
    }

    return(NULL);
}

/****************************************************************************
 *
 * Waits for an InfiniBand message with the message key specified. This is a
 * blocking operation and should not be used for latency-critical 
 * transmission of small messages. The function will queue the worker context
 * at the server's context. The completion handler thread for this server 
 * will wake the caller upon receiving an InfiniBand completion with the key
 * specified in this function. Upon return, the routine will store a pointer
 * to the message buffer as well as the completion status of the operation
 * in the worker context provided to this function.
 *
 * Params: wcontext - worker context of the calling thread.
 *         key      - message key to wait for.
 *
 * Returns: 0 on success, a negative integer for and internal error and a
 *          positive integer if the transmission of the message failed on IB
 *          level.
 */
static int wait_for_ibmsg(struct wctx *wcontext, uint32_t key) {
    struct slist *lptr;                 /* pointer for list iteration       */

    /* initialize worker context for next completion request */
    wcontext->next_key = key;
    wcontext->status   = -1;
    wcontext->msg      = NULL;

    pthread_mutex_lock(&wcontext->sctx->wait_lck);

    logmsg(DEBUG, "wfibmsg: searching unknown list.");
    for (lptr = wcontext->sctx->unknown_compl; lptr != NULL; lptr = lptr->next){
        struct wctx *unknown = (struct wctx *) lptr->data;
    
        /* check if a completion occured meanwhile calling this function    */
        if (unknown->next_key == key) {
            logmsg(DEBUG, "wfibmsg: matching unknown entry found.");
            wcontext->sctx->unknown_compl = 
                slist_remove(wcontext->sctx->unknown_compl, unknown);

            pthread_mutex_unlock(&wcontext->sctx->wait_lck);

            wcontext->status = unknown->status;
            wcontext->msg    = unknown->msg;

            free(unknown);
            return(wcontext->status);
        }
    }

    logmsg(DEBUG, "wfibmsg: inserting thread in wait list (key = %u ptr = %p).", 
           wcontext->next_key, (void *) wcontext);
    if (slist_insert(&wcontext->sctx->wait_workers, wcontext) != 0) {
        pthread_mutex_unlock(&wcontext->sctx->wait_lck);
        return(-1);
    }

    /* locking order is important to avoid deadlocks or lost wakeups        */
    pthread_mutex_lock(&wcontext->mtx);
    pthread_mutex_unlock(&wcontext->sctx->wait_lck);
    
    /* wait for the completion worker to wake up this thread                */
    pthread_cond_wait(&wcontext->cv, &wcontext->mtx);
    pthread_mutex_unlock(&wcontext->mtx);

    return(wcontext->status);
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
    size_t id_bm_size;                          /* size of ID bitmap (in B) */

    pthread_once(&log_init, &setup_logger);

    if ((ctx = calloc(1, sizeof(struct crdss_srv_ctx))) == NULL) {
        /* allocation of context structure failed. */
        return(NULL);
    }

    /* initialize some values */
    ctx->srv_addr.sin_family = AF_INET; /* is often forgotten; error source */
    ctx->tcp_fd              = -1;
    
    /* init pthread structures */
    if (pthread_mutex_init(&ctx->tcp_lck, NULL) != 0||
        pthread_mutex_init(&ctx->lbuf_lck, NULL) != 0 ||
        pthread_mutex_init(&ctx->id_lck, NULL) != 0 ||
        pthread_cond_init(&ctx->lbuf_cv, NULL) != 0 ||
        pthread_mutex_init(&ctx->wait_lck, NULL) != 0) {
        /* failed to init pthread structures */
        goto lock_err;
    }

    /* set the server connection's InfiniBand buffer settings               */
    if (cfg == NULL || check_libcfg(cfg) != 0) {
        /* no (or bad) config given, try to load it from def. location      */
        logmsg(INFO, "No config passed. Trying default config file %s.",
               DEF_LIB_CFG_PATH);

        if (parse_lib_config(DEF_LIB_CFG_PATH, &ctx->buf_cfg) != 0) {
            logmsg(SEVERE, "Failed to parse configuration file.");
            goto lock_err;
        }
    }
    else {
        memcpy(&ctx->buf_cfg, cfg, sizeof(struct clt_lib_cfg));
    }

    /* create TLS key for worker context of the new server connection       */
    if (pthread_key_create(&ctx->tls_key, &wctx_destructor) != 0) {
        /* failed to allocate new TLS key */
        logmsg(SEVERE, "Failed to allcoate new TLS key.");
        goto lock_err;
    }
    
    /* allocate the ID bitmap */
    id_bm_size = ((ctx->buf_cfg.no_workers % 8) == 0) 
                 ? ctx->buf_cfg.no_workers 
                 : ctx->buf_cfg.no_workers + 1;
    if ((ctx->worker_ids = calloc(1, id_bm_size)) == NULL) {
        logmsg(SEVERE, "Failed to allocate worker ID bitmap.");
        goto lock_err;
    }

    return(ctx);

lock_err:
    pthread_mutex_destroy(&ctx->tcp_lck);
    pthread_mutex_destroy(&ctx->lbuf_lck);
    pthread_mutex_destroy(&ctx->id_lck);
    pthread_cond_destroy(&ctx->lbuf_cv);
    pthread_mutex_destroy(&ctx->wait_lck);
    free(ctx);
    return(NULL);
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
        printf("unknown address family.\n");
        return(1);
    }

    /* lock server context */
    pthread_mutex_lock(&sctx->tcp_lck);

    if (sctx->tcp_fd != -1) {
        /* socket is already initialized */
        pthread_mutex_unlock(&sctx->tcp_lck);
        printf("connection already initialized.\n");
        return(1);
    }

    if ((sctx->tcp_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        /* creation of socket failed */
        pthread_mutex_unlock(&sctx->tcp_lck);
        printf("creation of socket failed.\n");
        return(1);
    }
    
    if (connect(sctx->tcp_fd, (struct sockaddr *) &sctx->srv_addr, 
        (socklen_t) sizeof(struct sockaddr_in)) < 0) {
        /* low-level connection of sockets failed */
        pthread_mutex_unlock(&sctx->tcp_lck);
        printf("low-level connection of sockets failed (errno: %d).\n", errno);
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
    logmsg(DEBUG, "lib: cap data sent.");

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
    logmsg(DEBUG, "server port for cap is %u.", ntohs(cap->srv.sin_port));

    return(0);
}

/* Initializes an InfiniBand connection with the CRDSS storage server       */
int init_ib_comm(struct crdss_srv_ctx *sctx) {
    unsigned int i;
    unsigned char *lbuf_offs;                   /* offset for lbufs in rdma *
                                                 * buffer of server context */

    uint8_t msg_type = MTYPE_IBINIT;            /* message type for server  */
    uint8_t op_res;                             /* result of srv operation  */

    uint32_t max_msg_cnt;                       /* max. no. of inflight msgs*/
    uint32_t rdma_size;                         /* size of RDMA region      */
    uint16_t worker_cnt;                        /* # of worker threads      */

    uint16_t lid;                               /* buffering of data        */
    uint32_t qpn;   

    uint64_t srv_addr;                          /* ID of server's RDMA buf  */
    uint32_t srv_rkey;
    uint64_t clt_addr;                          /* ID of client's RDMA buf  */
    uint32_t clt_rkey;

    /* lock the server context to avoid race conditions for initialization  */
    pthread_mutex_lock(&sctx->tcp_lck);

    /* abort initialization if the IB connection has been setup previously  */
    if (sctx-> msg_buf != NULL || sctx->rdma_buf != NULL) {
        pthread_mutex_unlock(&sctx->tcp_lck);
        logmsg(ERROR, "IB connection was already set up.");
        return(1);
    }

    /* abort initialization if server context has no TCP connection         */
    if (sctx->tcp_fd == -1) {
        pthread_mutex_unlock(&sctx->tcp_lck);
        logmsg(ERROR, "Context is not connected to a storage server.");
        return(1);
    }

    /* compute maximum message count from buffer layout in sctx */
    max_msg_cnt = sctx->buf_cfg.no_workers;             /* registered workers */
    /* also, there could be a message for each large buffer (although this    *
     * is unlikely, we have to take care of this case to avoid IB queue stalls*/
    max_msg_cnt += sctx->buf_cfg.lbuf_cnt;

    /* compute RDMA buffer size from buffer layout in sctx */
    rdma_size = sctx->buf_cfg.no_workers * CL_SIZE;   /* poll fields        */
    /* fast buffers for expected worker threads    */
    rdma_size += sctx->buf_cfg.no_workers * sctx->buf_cfg.sbuf_size;
    /* memory areas for transfer of large messages */
    rdma_size += sctx->buf_cfg.lbuf_cnt * sctx->buf_cfg.lbuf_size;

    logmsg(DEBUG, "Setting up clt qp.");
    /* first-phase clt-side qp setup */
    if (init_clt_qp(&sctx->ibctx, sctx->guid, &sctx->msg_buf, max_msg_cnt, 
                    &sctx->rdma_buf, rdma_size) != 0) {
        /* IB queue pair initialization failed */
        pthread_mutex_unlock(&sctx->tcp_lck);
        logmsg(ERROR, "IB queue pair initialization failed.");
        return(1);
    }
    logmsg(DEBUG, "init qp setup done...");

    lid         = htons(sctx->ibctx.loc_lid);
    qpn         = htonl(sctx->ibctx.qp->qp_num);
    max_msg_cnt = htonl(max_msg_cnt);
    rdma_size   = htonl(rdma_size);
    worker_cnt  = htons(sctx->buf_cfg.no_workers);
    if (send(sctx->tcp_fd, &msg_type, 1, 0) < 1 || 
        send(sctx->tcp_fd, &lid, 2, 0) < 2 || 
        send(sctx->tcp_fd, &qpn, 4, 0) < 4 || 
        send(sctx->tcp_fd, &max_msg_cnt, 4, 0) < 4 ||
        send(sctx->tcp_fd, &rdma_size, 4, 0) < 4 ||
        send(sctx->tcp_fd, &worker_cnt, 2, 0) < 2) {
        /* failed to transmit IB connection data to server */
        pthread_mutex_unlock(&sctx->tcp_lck);
        logmsg(ERROR, "Failed to transmit IB connection data to server.");
        return(1);
    }

    /* receive server's answer */
    if (recv(sctx->tcp_fd, &op_res, 1, MSG_WAITALL) < 1 || op_res != R_SUCCESS) 
    {
        /* server query was not successful */
        pthread_mutex_unlock(&sctx->tcp_lck);
        return(1);
    }

    if (recv(sctx->tcp_fd, &lid, 2, MSG_WAITALL) < 2 || 
        recv(sctx->tcp_fd, &qpn, 4, MSG_WAITALL) < 4 ||
        recv(sctx->tcp_fd, &srv_addr, 8, MSG_WAITALL) < 8 ||
        recv(sctx->tcp_fd, &srv_rkey, 4, MSG_WAITALL) < 4) {
        /* can not read connection data from server */
        pthread_mutex_unlock(&sctx->tcp_lck);
        return(1);
    }

    sctx->ibctx.rem_lid     = ntohs(lid);
    sctx->ibctx.remote_qpn  = ntohl(qpn);
    sctx->ibctx.remote_addr = be64toh(srv_addr);
    sctx->ibctx.remote_rkey = ntohl(srv_rkey);

    if (complete_clt_qp(&sctx->ibctx, sctx->msg_buf) != 0) {
        /* queue pair transition failed */
        pthread_mutex_unlock(&sctx->tcp_lck);
        return(1);
    }
    
    clt_addr = htobe64((uint64_t) sctx->rdma_buf);
    clt_rkey = htonl(sctx->ibctx.rdma_mr->rkey);
    if (send(sctx->tcp_fd, &clt_addr, 8, 0) < 8 || 
        send(sctx->tcp_fd, &clt_rkey, 4, 0) < 4) {
        /* failed to send answer with client memory window to server */
        pthread_mutex_unlock(&sctx->tcp_lck);
        return(1);
    }

    /* insert all new large buffers into the list of available large buffers*/
    lbuf_offs = sctx->rdma_buf + sctx->buf_cfg.no_workers * CL_SIZE + 
                sctx->buf_cfg.no_workers * sctx->buf_cfg.sbuf_size;
    pthread_mutex_lock(&sctx->lbuf_lck);

    for (i = 0; i < sctx->buf_cfg.lbuf_cnt; i++) {
        if (slist_insert(&sctx->avail_lbuf, lbuf_offs) != 0) {
            logmsg(ERROR, "Failed to allocate memory for free lbuf list.");
            pthread_mutex_unlock(&sctx->lbuf_lck);
            pthread_mutex_unlock(&sctx->tcp_lck);
            return(1);
        }

        lbuf_offs += sctx->buf_cfg.lbuf_size;
    }

    /* start the completion worker thread */
    if (pthread_create(&sctx->compl_worker, NULL, completion_worker, sctx) != 0)
    {
        /* unable to start handler thread for completion notification */
        return(1);
    }

    /* notify all threads that may have already blocked in expectation of   *
     * available large buffers                                              */
    pthread_cond_broadcast(&sctx->lbuf_cv);

    pthread_mutex_unlock(&sctx->lbuf_lck);
    pthread_mutex_unlock(&sctx->tcp_lck);

    return(0);
}

/* Closes a connection to a CRDSS storage server.                           */
int close_srv_conn(struct crdss_srv_ctx *sctx) {
    uint8_t opcode = MTYPE_BYE;             /* ID for server operation      */
    void *compl_rc = NULL;                  /* return value of compl. worker*/

    logmsg(DEBUG, "Starting teardown of server connection.");
    pthread_mutex_lock(&sctx->tcp_lck);

    if (sctx->tcp_fd < 0) {
        /* error, there was no active server connection on this context     */
        pthread_mutex_unlock(&sctx->tcp_lck);
        return(1);
    }

    /* always send goodbye message via TCP */
    if (send(sctx->tcp_fd, &opcode, 1, 0) < 1) {
        /* send failed... */
        return(1);
    }
    
    /* if an IB connection was active, close it first */
    if (sctx->msg_buf != NULL) {
        /* cancel the completion worker thread */
        pthread_cancel(sctx->compl_worker);
        pthread_join(sctx->compl_worker, compl_rc);
        logmsg(DEBUG, "Completion worker cancelled.");

        destroy_ibctx(&sctx->ibctx);
        free(sctx->msg_buf);
        free(sctx->rdma_buf);

        sctx->msg_buf  = NULL;
        sctx->rdma_buf = NULL;
    }

    /* close TCP socket */
    close(sctx->tcp_fd);
    sctx->tcp_fd = -1;
    pthread_mutex_unlock(&sctx->tcp_lck);
    
    pthread_mutex_destroy(&sctx->tcp_lck);
    pthread_mutex_destroy(&sctx->lbuf_lck);
    pthread_mutex_destroy(&sctx->id_lck);
    pthread_cond_destroy(&sctx->lbuf_cv);
    pthread_mutex_destroy(&sctx->wait_lck);

    free(sctx->worker_ids);
    free(sctx);

    return(0);
}

/* Registers a capability at the server by specifying the cap ID.           */
int reg_cap(struct crdss_srv_ctx *sctx, unsigned char *capid) {
    uint8_t opcode = MTYPE_REGCAP;          /* ID for server operation      */
    uint8_t op_res = R_FAILURE;             /* result of srv operation      */
    unsigned char msg_buf[MAX_MSG_LEN];     /* msg for IB transfer          */

    struct wctx *work_ctx = NULL;           /* worker context for this thrd */
    
    pthread_mutex_lock(&sctx->tcp_lck);
    
    if (sctx->tcp_fd < 0) {
        /* server is not connected */
        pthread_mutex_unlock(&sctx->tcp_lck);
        return(1);
    }

    if (sctx->msg_buf == NULL) {
        /* TCP path */
        if (send(sctx->tcp_fd, &opcode, 1, 0) < 1 ||
            send(sctx->tcp_fd, capid, CAP_ID_LEN, 0) < CAP_ID_LEN) {
            /* failed to transmit message */
            pthread_mutex_unlock(&sctx->tcp_lck);
            return(1);
        }

        if (recv(sctx->tcp_fd, &op_res, 1, MSG_WAITALL) < 1 || 
            op_res != R_SUCCESS) {
            /* receive error or error on server side (return error code)    */
            pthread_mutex_unlock(&sctx->tcp_lck);
            return(op_res);
        }

        pthread_mutex_unlock(&sctx->tcp_lck);
        return(0);
    }
    else {
        /* IB path */
        pthread_mutex_unlock(&sctx->tcp_lck);
        work_ctx = get_wctx(sctx);

        memset(msg_buf, 0, MAX_MSG_LEN);
        msg_buf[0] = MTYPE_REGCAP;
        memcpy(msg_buf + 1, capid, CAP_ID_LEN);

        logmsg(DEBUG, "reg_cap: sending request to the server.");
        while ((op_res = post_msg_sr(&sctx->ibctx, msg_buf, work_ctx->tid)) == 
               12) {
            logmsg(DEBUG, "delete_rdom: waiting for free send queue.");
        }
        if (op_res != 0) {
            /* failed to trigger IB send op. */
            logmsg(ERROR, "reg_cap: Failed to send request to server.");
            return(1);
        }

        logmsg(DEBUG, "reg_cap: waiting for answer of server.");
        if (wait_for_ibmsg(work_ctx, work_ctx->tid) != 0) {
            /* receive op failed */
            return(1);
        }

        op_res = (uint8_t) work_ctx->msg[0];
        /* repost receive request */
        if (post_msg_rr(&sctx->ibctx, work_ctx->msg, 1) != 0) {
            return(1);
        }

        return(op_res);
    }
}

/* Deletes a revocation domain at the server identified by sctx.            */
int delete_rdom(struct crdss_srv_ctx *sctx, uint32_t rdom) {
    uint8_t opcode = MTYPE_RMDOM;           /* ID for server operation      */
    uint8_t op_res = R_FAILURE;             /* result of srv operation      */
    unsigned char msg_buf[MAX_MSG_LEN];     /* msg for IB transfer          */

    struct wctx *work_ctx = NULL;           /* worker context for this thrd */
    
    pthread_mutex_lock(&sctx->tcp_lck);

    if (sctx->tcp_fd < 0) {
        /* server is not connected */
        pthread_mutex_unlock(&sctx->tcp_lck);
        return(1);
    }

    if (sctx->msg_buf == NULL) {
        /* TCP path */
        if (send(sctx->tcp_fd, &opcode, 1, 0) < 1 ||
            send(sctx->tcp_fd, &rdom, 4, 0) < 4) {
            /* failed to transmit message */
            pthread_mutex_unlock(&sctx->tcp_lck);
            return(1);
        }

        if (recv(sctx->tcp_fd, &op_res, 1, MSG_WAITALL) < 1 || 
            op_res != R_SUCCESS) {
            /* receive error or error on server side (return error code)    */
            pthread_mutex_unlock(&sctx->tcp_lck);
            return(op_res);
        }

        pthread_mutex_unlock(&sctx->tcp_lck);
        return(0);
    }
    else {
        /* IB path */
        pthread_mutex_unlock(&sctx->tcp_lck);
        work_ctx = get_wctx(sctx);

        memset(msg_buf, 0, MAX_MSG_LEN);
        msg_buf[0] = MTYPE_RMDOM;
        memcpy(msg_buf + 1, &rdom, sizeof(uint32_t));

        while ((op_res = post_msg_sr(&sctx->ibctx, msg_buf, work_ctx->tid)) == 
               12) {
            logmsg(DEBUG, "delete_rdom: waiting for free send queue.");
        }
        if (op_res != 0) {
            /* failed to trigger IB send op. */
            logmsg(ERROR, "delete_rdom: Failed to send request to server.");
            return(1);
        }

        if (wait_for_ibmsg(work_ctx, work_ctx->tid) != 0) {
            /* receive op failed */
            return(1);
        }

        op_res = (uint8_t) work_ctx->msg[0];
        /* repost receive request */
        if (post_msg_rr(&sctx->ibctx, work_ctx->msg, 1) != 0) {
            return(1);
        }

        return(op_res);
    }
}

/* Queries the server identified by sctx to switch to polling completion.   */
int query_srv_poll(struct crdss_srv_ctx *sctx) {
    uint8_t op_res       = R_FAILURE;       /* result of server operation   */
    unsigned char msg_buf[MAX_MSG_LEN];     /* msg for IB transfer          */
    struct wctx *work_ctx = NULL;           /* worker context               */

    pthread_mutex_lock(&sctx->tcp_lck);

    if (sctx->msg_buf == NULL) {
        /* operation is only allowed for IB server connections */
        pthread_mutex_unlock(&sctx->tcp_lck);
        return(1);
    }

    pthread_mutex_unlock(&sctx->tcp_lck);

    if ((work_ctx = get_wctx(sctx)) == NULL) {
        /* error while obtaining worker context */
        return(1);
    }

    memset(msg_buf, 0, MAX_MSG_LEN);
    msg_buf[0] = MTYPE_CPOLL;

    if (post_msg_sr(&sctx->ibctx, msg_buf, work_ctx->tid) != 0) {
        logmsg(ERROR, "Can not send request to server.");
        /* failed to trigger IB send op. */
        return(1);
    }

    if (wait_for_ibmsg(work_ctx, work_ctx->tid) != 0) {
        /* receive op failed */
        logmsg(ERROR, "Unable to receive answer from server.");
        post_msg_rr(&sctx->ibctx, work_ctx->msg, 1);
        return(1);
    }

    op_res = (uint8_t) work_ctx->msg[0];
    /* repost receive request */
    if (post_msg_rr(&sctx->ibctx, work_ctx->msg, 1) != 0) {
        logmsg(WARN, "Failed to re-post receive request.");
        return(1);
    }

    return(op_res);
}

/* Queries the server identified by sctx to switch to blocking completion.  */
int query_srv_block(struct crdss_srv_ctx *sctx) {
    uint8_t op_res       = R_FAILURE;       /* result of server operation   */
    unsigned char msg_buf[MAX_MSG_LEN];     /* msg for IB transfer          */
    struct wctx *work_ctx = NULL;           /* worker context               */

    pthread_mutex_lock(&sctx->tcp_lck);

    if (sctx->msg_buf == NULL) {
        /* operation is only allowed for IB server connections */
        pthread_mutex_unlock(&sctx->tcp_lck);
        return(1);
    }

    pthread_mutex_unlock(&sctx->tcp_lck);

    if ((work_ctx = get_wctx(sctx)) == NULL) {
        /* error while obtaining worker context */
        return(1);
    }

    memset(msg_buf, 0, MAX_MSG_LEN);
    msg_buf[0] = MTYPE_CBLOCK;

    if (post_msg_sr(&sctx->ibctx, msg_buf, work_ctx->tid) != 0) {
        /* failed to trigger IB send op. */
        return(1);
    }

    if (wait_for_ibmsg(work_ctx, work_ctx->tid) != 0) {
        /* receive op failed */
        return(1);
    }

    op_res = (uint8_t) work_ctx->msg[0];
    /* repost receive request */
    if (post_msg_rr(&sctx->ibctx, work_ctx->msg, 1) != 0)
        return(1);

    return(op_res);
}

/* Queries the size of the vslice in ccap from the capability manager.      */
int get_vslice_size(struct crdss_clt_cap *ccap, uint64_t *size) {
    size_t addr_sz;                     /* size of server address           */

    unsigned char msg_buf[MAX_MSG_LEN]; /* message buffer sent to capmgr    */

    /* query size of vslice */
    addr_sz = sizeof(ccap->srv.sin_addr.s_addr);
    memset(msg_buf, 0, MAX_MSG_LEN);
    msg_buf[0] = MTYPE_VSLCINFO;
    memcpy(msg_buf + 1, &ccap->srv.sin_addr.s_addr, addr_sz);
    memcpy(msg_buf + 1 + addr_sz, &ccap->dev_idx, 2);
    memcpy(msg_buf + 3 + addr_sz, &ccap->vslc_idx, 4);

    /* grab the capmgr lock to ensure that the received answer belongs to   *
     * the request that was just sent                                       */
    pthread_mutex_lock(&capmgr_lck);

    /* send message to cap manager */
    sendto(capmgr_fd, msg_buf, MAX_MSG_LEN, 0, (struct sockaddr *) &capmgr_addr,
           (socklen_t) sizeof(capmgr_addr));

    /* reset msg buffer to avoid reading stale data */
    memset(msg_buf, 0, MAX_MSG_LEN);

    /* wait for answer from cap manager (he is the only one that should send *
     * mssages, so we do not care for the sender's address here (TODO))      */
    if (recv(capmgr_fd, msg_buf, MAX_MSG_LEN, 0) < 1) {
        /* read from capmgr failed */
        pthread_mutex_unlock(&capmgr_lck);
        return(R_FAILURE);
    }

    pthread_mutex_unlock(&capmgr_lck);

    if (msg_buf[0] != R_SUCCESS) {
        return(R_FAILURE);
    }

    memcpy(size, msg_buf + 1, sizeof(uint64_t));
    return(R_SUCCESS);
}

/* Reads len bytes from the storage location specified.                     */
int fast_read_raw(struct crdss_srv_ctx *sctx, uint16_t didx, uint32_t sidx,
                  uint64_t saddr, void *buf, uint32_t len) {
    int ret;                        /* return value of function calls       */

    uint16_t didx_nw;               /* parameters in network byte order     */
    uint32_t sidx_nw;
    uint64_t saddr_nw;
    uint32_t len_nw;
    uint64_t rdma_addr;             /* address in RDMA buffer (host bo.)    */
    uint64_t rdma_addr_nw;          /* address in RDMA buffer (nw byte ord.)*/
    uint64_t poll_field_nw;         /* doorbell address (network byte ord.) */

    volatile uint8_t *pf_ptr;       /* pointer to poll field                */

    unsigned char msg_buf[MAX_MSG_LEN];     /* message for IB transfer      */
    unsigned char *char_buf;

    uint32_t bytes_read   = 0;      /* number of bytes worked off           */
    struct wctx *work_ctx = NULL;   /* context of this worker thread        */

    /* get worker context. The function will fail if this thread is not reg.*/
    work_ctx = get_wctx(sctx);
    if (work_ctx == NULL || work_ctx->wid == WORKER_UNREG)
        return(1);

    char_buf = (unsigned char *) buf;

    /* compute addresses for small buffers and doorbell addresses           */
    poll_field_nw = (uint64_t) (sctx->rdma_buf + work_ctx->wid * CL_SIZE);
    rdma_addr     = (uint64_t) (sctx->rdma_buf + 
                    sctx->buf_cfg.no_workers * CL_SIZE +
                    work_ctx->wid * sctx->buf_cfg.sbuf_size);

    pf_ptr        = (uint8_t *) poll_field_nw;

    /* convert parameters to network byte order */
    didx_nw       = htons(didx);
    sidx_nw       = htonl(sidx);
    rdma_addr_nw  = htobe64(rdma_addr);
    poll_field_nw = htobe64(poll_field_nw);

    /* read in chunks until request is finished */
    while (len > 0) {
        uint32_t cur_len = (len > sctx->buf_cfg.sbuf_size)
                         ? sctx->buf_cfg.sbuf_size
                         : len;
        
        saddr_nw = htobe64(saddr);
        len_nw   = htonl(cur_len);

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

        /* logmsg(DEBUG, "TID of calling thread is %u.", work_ctx->tid); */
        logmsg(DEBUG, "fast_read_raw: sending request to server.");
        while ((ret = post_msg_sr(&sctx->ibctx, msg_buf, work_ctx->tid)) == 12){
            /* failed to post send request, but retry once SQ is polled     */
            usleep(LIBCRDSS_POLL_INT);
        }

        /* if we left the loop, this indicates either success or a severe err */
        if (ret != 0)
            return(1);

        /* spin in this loop until the result arrived */
        logmsg(DEBUG, "fast_read_raw: spinning on addr %p.", (void *) pf_ptr);
        while (*pf_ptr == R_UNDEF) { 
            usleep(LIBCRDSS_POLL_INT); 
        }

        if (*pf_ptr != R_SUCCESS)
            return(*pf_ptr);

        /* copy data into user buffer and prepare next chunk */
        memcpy(char_buf + bytes_read, (void *) rdma_addr, cur_len);

        len        -= cur_len;
        bytes_read += cur_len;
        saddr      += cur_len;
    }

    return(R_SUCCESS);
}

/* Writes len bytes to the storage location specified                       */
int fast_write_raw(struct crdss_srv_ctx *sctx, uint16_t didx, uint32_t sidx,
                   uint64_t saddr, const void *buf, uint32_t len) {
    int ret;                        /* result of function calls             */

    uint16_t didx_nw;               /* parameters in network byte order     */
    uint32_t sidx_nw;
    uint64_t saddr_nw;
    uint32_t len_nw;
    uint64_t rdma_addr;             /* address in RDMA buffer (host bo.)    */
    uint64_t rdma_addr_nw;          /* address in RDMA buffer (nw byte ord.)*/
    uint64_t rdma_rem_addr;         /* target address in remote buffer      */
    uint64_t poll_field_nw;         /* doorbell address (network byte ord.) */

    volatile uint8_t *pf_ptr;       /* pointer to poll field                */

    unsigned char msg_buf[MAX_MSG_LEN];     /* message for IB transfer      */
    unsigned char *char_buf;

    uint32_t bytes_written = 0;     /* number of bytes worked off           */
    struct wctx *work_ctx  = NULL;  /* context of this worker thread        */

    /* get worker context. The function will fail if this thread is not reg.*/
    work_ctx = get_wctx(sctx);
    if (work_ctx == NULL || work_ctx->wid == WORKER_UNREG)
        return(1);

    char_buf = (unsigned char *) buf;

    /* compute addresses for small buffers and doorbell addresses           */
    poll_field_nw = (uint64_t) (sctx->rdma_buf + work_ctx->wid * CL_SIZE);
    rdma_addr     = (uint64_t) (sctx->rdma_buf + 
                    sctx->buf_cfg.no_workers * CL_SIZE +
                    work_ctx->wid * sctx->buf_cfg.sbuf_size);
    rdma_rem_addr = (uint64_t) (sctx->ibctx.remote_addr +                                
                    sctx->buf_cfg.no_workers * CL_SIZE +                        
                    work_ctx->wid * sctx->buf_cfg.sbuf_size); 

    pf_ptr        = (uint8_t *) poll_field_nw;

    /* convert parameters to network byte order */
    didx_nw       = htons(didx);
    sidx_nw       = htonl(sidx);
    rdma_addr_nw  = htobe64(rdma_addr);
    poll_field_nw = htobe64(poll_field_nw);

    /* read in chunks until request is finished */
    while (len > 0) {
        uint32_t cur_len = (len > sctx->buf_cfg.sbuf_size)
                         ? sctx->buf_cfg.sbuf_size
                         : len;
       
        /* copy data to RDMA buffer */
        memcpy((void *) rdma_addr, char_buf + bytes_written, cur_len);

        saddr_nw = htobe64(saddr);
        len_nw   = htonl(cur_len);

        /* prepare request buffer */
        memset(msg_buf, 0, MAX_MSG_LEN);
        msg_buf[0] = MTYPE_FASTWRITE;
        memcpy(msg_buf + 1, &didx_nw, sizeof(uint16_t));
        memcpy(msg_buf + 3, &sidx_nw, sizeof(uint32_t));
        memcpy(msg_buf + 7, &saddr_nw, sizeof(uint64_t));
        memcpy(msg_buf + 15, &len_nw, sizeof(uint32_t));
        memcpy(msg_buf + 19, &rdma_addr_nw, sizeof(uint64_t));
        memcpy(msg_buf + 27, &poll_field_nw, sizeof(uint64_t));
    
        /* prepare poll field */
        *pf_ptr = R_UNDEF;

        /* transfer data, afterwards send the actual request */
        while ((ret = init_rdma_transfer(&sctx->ibctx, 
                (unsigned char *) rdma_addr, (unsigned char *) rdma_rem_addr, 
                cur_len, 0, 0, 0)) == 12) {
            usleep(LIBCRDSS_POLL_INT);
        }

        if (ret != 0) {
            return(R_FAILURE);
        }

        /* trigger the actual request at the server */
        while ((ret = post_msg_sr(&sctx->ibctx, msg_buf, work_ctx->tid)) == 12){
            /* failed to post send request, but retry once SQ is polled     */
            usleep(LIBCRDSS_POLL_INT);
        }

        /* if we left the loop, this indicates either success or a severe err */
        if (ret != 0) {
            /* failed to post send request */
            return(1);
        }

        /* spin in this loop until the result arrived */
        while (*pf_ptr == R_UNDEF) {
            usleep(LIBCRDSS_POLL_INT);
        }

        if (*pf_ptr != R_SUCCESS)
            return(*pf_ptr);

        /* prepare next chunk */
        len           -= cur_len;
        bytes_written += cur_len;
        saddr         += cur_len;
    }

    return(R_SUCCESS);
}

/* Reads len bytes from the storage location specified (blocking compl.).   */
int read_raw(struct crdss_srv_ctx *sctx, uint16_t didx, uint32_t sidx,
             uint64_t saddr, void *buf, uint32_t len) {
    uint8_t  op_res = R_FAILURE;    /* result of server operation           */

    uint16_t didx_nw;               /* parameters in network byte order     */
    uint32_t sidx_nw;
    uint64_t saddr_nw;
    uint32_t len_nw;
    uint64_t rdma_addr;             /* address in RDMA buffer (host bo.)    */
    uint64_t rdma_addr_nw;          /* address in RDMA buffer (nw byte ord.)*/

    unsigned char msg_buf[MAX_MSG_LEN];     /* message for IB transfer      */
    unsigned char *char_buf;

    uint32_t bytes_read   = 0;      /* number of bytes worked off           */
    struct wctx *work_ctx = NULL;   /* context of this worker thread        */

    /* get worker context. The function will fail if this thread is not reg.*/
    work_ctx = get_wctx(sctx);
    if (work_ctx == NULL)
        return(1);

    char_buf = (unsigned char *) buf;

    /* get buffer from the list of large buffers */
    pthread_mutex_lock(&sctx->lbuf_lck);

    while (slist_empty(sctx->avail_lbuf))
        pthread_cond_wait(&sctx->lbuf_cv, &sctx->lbuf_lck);

    rdma_addr        = (uint64_t) sctx->avail_lbuf->data;
    sctx->avail_lbuf = slist_remove(sctx->avail_lbuf, sctx->avail_lbuf->data); 

    pthread_mutex_unlock(&sctx->lbuf_lck);

    logmsg(DEBUG, "read_raw: acquired RDMA buffer.");

    /* convert parameters to network byte order */
    didx_nw       = htons(didx);
    sidx_nw       = htonl(sidx);
    rdma_addr_nw  = htobe64(rdma_addr);

    /* read in chunks until request is finished */
    while (len > 0) {
        uint32_t cur_len = (len > sctx->buf_cfg.lbuf_size)
                         ? sctx->buf_cfg.lbuf_size
                         : len;
        
        saddr_nw = htobe64(saddr);
        len_nw   = htonl(cur_len);

        /* prepare request buffer */
        memset(msg_buf, 0, MAX_MSG_LEN);
        msg_buf[0] = MTYPE_READ;
        memcpy(msg_buf + 1, &didx_nw, sizeof(uint16_t));
        memcpy(msg_buf + 3, &sidx_nw, sizeof(uint32_t));
        memcpy(msg_buf + 7, &saddr_nw, sizeof(uint64_t));
        memcpy(msg_buf + 15, &len_nw, sizeof(uint32_t));
        memcpy(msg_buf + 19, &rdma_addr_nw, sizeof(uint64_t));
    
        if (post_msg_sr(&sctx->ibctx, msg_buf, work_ctx->tid) != 0) {
            /* failed to post send request */
            return(R_FAILURE);
        }

        logmsg(DEBUG, "read_raw: Waiting for answer of server.");
        /* wait for answer of server */        
        if (wait_for_ibmsg(work_ctx, work_ctx->tid) != 0) {
            /* receive op failed */
            return(1);
        }

        op_res = (work_ctx->status == IBV_WC_SUCCESS) ? R_SUCCESS : R_FAILURE;
        logmsg(DEBUG, "read_raw: server status is %u.", op_res);
        /* repost receive request */
        if (post_msg_rr(&sctx->ibctx, work_ctx->msg, 1) != 0) {
            op_res = R_FAILURE;
            break;
        }

        if (op_res != R_SUCCESS)
            break;

        /* copy data into user buffer and prepare next chunk */
        memcpy(char_buf + bytes_read, (void *) rdma_addr, cur_len);

        len        -= cur_len;
        bytes_read += cur_len;
        saddr      += cur_len;
    }

    /* re-insert lbuf in list */
    pthread_mutex_lock(&sctx->lbuf_lck);

    if (slist_insert(&sctx->avail_lbuf, (void *) rdma_addr) != 0) {
        pthread_mutex_unlock(&sctx->lbuf_lck);
        return(1);
    }

    pthread_cond_signal(&sctx->lbuf_cv);
    pthread_mutex_unlock(&sctx->lbuf_lck);

    return(op_res);
}

/* Writes len bytes to the storage location specified (blocking compl.).    */
int write_raw(struct crdss_srv_ctx *sctx, uint16_t didx, uint32_t sidx,
              uint64_t saddr, const void *buf, uint32_t len) {
    uint8_t  op_res = R_FAILURE;    /* result of server operation           */

    uint16_t didx_nw;               /* parameters in network byte order     */
    uint32_t sidx_nw;
    uint64_t saddr_nw;
    uint32_t len_nw;
    uint64_t rdma_addr;             /* address in RDMA buffer (host bo.)    */
    uint64_t rdma_addr_nw;          /* address in RDMA buffer (nw byte ord.)*/
    uint64_t rdma_rem_addr;         /* target address in remote buffer      */

    unsigned char msg_buf[MAX_MSG_LEN];     /* message for IB transfer      */
    unsigned char *char_buf;

    uint32_t bytes_written = 0;     /* number of bytes worked off           */
    struct wctx *work_ctx  = NULL;  /* context of this worker thread        */

    /* get worker context. The function will fail if this thread is not reg.*/
    work_ctx = get_wctx(sctx);
    if (work_ctx == NULL || work_ctx->wid == WORKER_UNREG)
        return(1);

    char_buf = (unsigned char *) buf;

    /* get buffer from the list of large buffers */
    pthread_mutex_lock(&sctx->lbuf_lck);

    while (slist_empty(sctx->avail_lbuf))
        pthread_cond_wait(&sctx->lbuf_cv, &sctx->lbuf_lck);

    rdma_addr        = (uint64_t) sctx->avail_lbuf->data;
    sctx->avail_lbuf = slist_remove(sctx->avail_lbuf, sctx->avail_lbuf->data); 

    pthread_mutex_unlock(&sctx->lbuf_lck);
    
    /* compute addresses for small buffers and doorbell addresses           */
    rdma_rem_addr = (rdma_addr - (uint64_t) sctx->rdma_buf) + 
                    sctx->ibctx.remote_addr; 

    /* convert parameters to network byte order */
    didx_nw       = htons(didx);
    sidx_nw       = htonl(sidx);
    rdma_addr_nw  = htobe64(rdma_addr);

    /* read in chunks until request is finished */
    while (len > 0) {
        uint32_t cur_len = (len > sctx->buf_cfg.lbuf_size)
                         ? sctx->buf_cfg.lbuf_size
                         : len;
       
        /* copy data to RDMA buffer */
        memcpy((void *) rdma_addr, char_buf + bytes_written, cur_len);

        saddr_nw = htobe64(saddr);
        len_nw   = htonl(cur_len);

        /* prepare request buffer */
        memset(msg_buf, 0, MAX_MSG_LEN);
        msg_buf[0] = MTYPE_WRITE;
        memcpy(msg_buf + 1, &didx_nw, sizeof(uint16_t));
        memcpy(msg_buf + 3, &sidx_nw, sizeof(uint32_t));
        memcpy(msg_buf + 7, &saddr_nw, sizeof(uint64_t));
        memcpy(msg_buf + 15, &len_nw, sizeof(uint32_t));
        memcpy(msg_buf + 19, &rdma_addr_nw, sizeof(uint64_t));
    
        /* transfer data, afterwards send the actual request */
        if (init_rdma_transfer(&sctx->ibctx, (unsigned char *) rdma_addr,
                               (unsigned char *) rdma_rem_addr, cur_len, 
                               0, work_ctx->tid, 1) != 0) {
            return(R_FAILURE);
        }

        /* wait for RDMA transfer to complete */        
        if (wait_for_ibmsg(work_ctx, work_ctx->tid) != 0) {
            /* receive op failed */
            return(1);
        }
        logmsg(DEBUG, "write_raw: data transfer complete, sending msg.");

        op_res = (work_ctx->status == IBV_WC_SUCCESS) ? R_SUCCESS : R_FAILURE;
        /* we do not actually receive a message, hence do not repost an RR  */

        if (op_res != R_SUCCESS)
            break;

        /* send actual request to server */
        if (post_msg_sr(&sctx->ibctx, msg_buf, work_ctx->tid) != 0) {
            /* failed to post send request */
            return(R_FAILURE);
        }

        /* wait for answer of server */        
        if (wait_for_ibmsg(work_ctx, work_ctx->tid) != 0) {
            /* receive op failed */
            return(1);
        }

        op_res = (work_ctx->status == IBV_WC_SUCCESS) ? R_SUCCESS : R_FAILURE;
        /* repost receive request */
        if (post_msg_rr(&sctx->ibctx, work_ctx->msg, 1) != 0) {
            op_res = R_FAILURE;
            break;
        }

        logmsg(DEBUG, "write_raw: got answer from server (%u).", op_res);

        if (op_res != R_SUCCESS)
            break;

        /* prepare next chunk */
        len           -= cur_len;
        bytes_written += cur_len;
        saddr         += cur_len;
    }

    /* re-insert lbuf in list */
    pthread_mutex_lock(&sctx->lbuf_lck);

    if (slist_insert(&sctx->avail_lbuf, (void *) rdma_addr) != 0) {
        pthread_mutex_unlock(&sctx->lbuf_lck);
        return(1);
    }

    pthread_cond_signal(&sctx->lbuf_cv);
    pthread_mutex_unlock(&sctx->lbuf_lck);
    
    return(op_res);
}

/***                     POSIX interface emulation                        ***/

/* Reads up to count bytes from file descriptor fd at offset offset.        */
ssize_t pread64(int fd, void *buf, size_t count, off_t offset) {
    int ret = 0;                    /* return value of calls to read        */

    /* the conversion is necessary since ISO C does not support conversion  *
     * of void * to function pointers                                       */
    if (libc_pread64 == NULL)
        libc_pread64 = dlsym(RTLD_NEXT, "pread64");

    /* printf("Called pread64!\n"); */
    
    if (fd_table[fd] == NULL)
        return(libc_pread64(fd, buf, count, offset));

    /* else: use crdss functions for reading data */
    if (count <= fd_table[fd]->sctx->buf_cfg.sbuf_size && 
        get_wctx(fd_table[fd]->sctx) != NULL) {
        /* use small buffers for data transmission */
        /* logmsg(DEBUG, "starting read op."); */
        ret = fast_read_raw(fd_table[fd]->sctx, fd_table[fd]->cap.dev_idx,
                            fd_table[fd]->cap.vslc_idx, (uint64_t) offset, buf,
                            count);

        logmsg(DEBUG, "finished read op");
        if (ret != 0) {
            errno = EIO;
            return(-1);
        }
        else {
            return(count);
        }
    }

    /* use large buffers for data transmission */
    ret = read_raw(fd_table[fd]->sctx, fd_table[fd]->cap.dev_idx,
                   fd_table[fd]->cap.vslc_idx, (uint64_t) offset, buf,
                   count);
    logmsg(DEBUG, "finished block read op.");

    if (ret != 0) {
        errno = EIO;
        return(-1);
    }
    else {
        return(count);
    }
}

/* wrapper for pwrite64 of libc                                             */
ssize_t pwrite64(int fd, const void *buf, size_t nbyte, off_t offset) {
    int ret = 0;                    /* return values of calls to write      */

    if (libc_pwrite64 == NULL)
        libc_pwrite64 = dlsym(RTLD_NEXT, "pwrite64");

    /* printf("Called pwrite64!\n"); */
    
    if (fd_table[fd] == NULL)
        return(libc_pwrite64(fd, buf, nbyte, offset));

    /* else: use crdss functions for reading data */
    if (nbyte <= fd_table[fd]->sctx->buf_cfg.sbuf_size && 
        get_wctx(fd_table[fd]->sctx) != NULL) {
        /* use small buffers for data transmission */
        ret = fast_write_raw(fd_table[fd]->sctx, fd_table[fd]->cap.dev_idx,
                             fd_table[fd]->cap.vslc_idx, (uint64_t) offset, buf,
                             nbyte);

        if (ret != 0) {
            errno = EIO;
            return(-1);
        }
        else {
            return(nbyte);
        }
    }

    /* use large buffers for data transmission */
    ret = write_raw(fd_table[fd]->sctx, fd_table[fd]->cap.dev_idx,
                    fd_table[fd]->cap.vslc_idx, (uint64_t) offset, buf,
                    nbyte);

    if (ret != 0) {
        errno = EIO;
        return(-1);
    }
    else {
        return(nbyte);
    }
}

/* Linux wrapper for stat system calls                                      */
int __xstat64(int ver, const char *path, struct stat64 * stat_buf) {
    struct crdss_clt_cap ccap;

    uint64_t vslc_size = 0;

    char *basename = NULL;              /* basename of path                 */
    char *last_sep = NULL;              /* last occurence of '/' in path    */

    if (libc_xstat64 == NULL)
        libc_xstat64 = dlsym(RTLD_NEXT, "__xstat64");

    /* printf("Called __xstat64!\n"); */

    /* compute basename */
    last_sep = strrchr(path, '/');
    if (last_sep == NULL)
        basename = strdup(path);
    else
        basename = strdup(last_sep + 1);

    if (strncmp(basename, "crdss", 5) != 0)
        return(libc_xstat64(ver, path, stat_buf));
    
    logmsg(DEBUG, "Entering custom part of __xstat64!\n");
    /* else: provide custom values for the crdss file */
    memset(stat_buf, 0, sizeof(struct stat64));
 
    /* try to derive basic information about requested device from path     */
    if (init_ccap_from_path(basename, &ccap) != 0) {
        printf("error while parsing cap.\n");
        return(-1);
    }
    
    /*
    printf("derived cap from file name. didx = %u, sidx = %u\n", 
          ccap.dev_idx, ccap.vslc_idx);
    */

    /* if not done yet, connect to capability manager */
    if (capmgr_fd == -1 && connect_capmgr_dom(DEF_CAPMGR_SOCK) != 0)
        return(-1);

    /* printf("Getting vslice size...\n"); */
    /* query size of vslice */
    if (get_vslice_size(&ccap, &vslc_size) != R_SUCCESS) 
        return(-1);

    /* printf("vslice size is %lu\n", vslc_size); */
    stat_buf->st_size  = vslc_size;

    stat_buf->st_mode  = S_IFREG;           /* disguise as regular file     */
    stat_buf->st_mode |= S_IRUSR;
    stat_buf->st_mode |= S_IWUSR;

    stat_buf->st_uid = getuid();
    stat_buf->st_gid = getgid();

    free(basename);
    return(0);
}

/* Linux wrapper for stat system calls                                      */
int __lxstat64(int ver, const char *path, struct stat64 * stat_buf) {
    struct crdss_clt_cap ccap;

    uint64_t vslc_size = 0;

    char *basename = NULL;              /* basename of path                 */
    char *last_sep = NULL;              /* last occurence of '/' in path    */

    if (libc_lxstat64 == NULL)
        libc_lxstat64 = dlsym(RTLD_NEXT, "__lxstat64");

    /* printf("Called __lxstat64!\n"); */

    /* compute basename */
    last_sep = strrchr(path, '/');
    if (last_sep == NULL)
        basename = strdup(path);
    else
        basename = strdup(last_sep + 1);

    if (strncmp(basename, "crdss", 5) != 0)
        return(libc_lxstat64(ver, path, stat_buf));
    
    logmsg(DEBUG, "Entering custom part of __lxstat64!\n");
    /* else: provide custom values for the crdss file */
    memset(stat_buf, 0, sizeof(struct stat64));
 
    /* try to derive basic information about requested device from path     */
    if (init_ccap_from_path(basename, &ccap) != 0) {
        printf("error while parsing cap.\n");
        return(-1);
    }
   
    /*
    printf("derived cap from file name. didx = %u, sidx = %u\n", 
          ccap.dev_idx, ccap.vslc_idx);
    */

    /* if not done yet, connect to capability manager */
    if (capmgr_fd == -1 && connect_capmgr_dom(DEF_CAPMGR_SOCK) != 0)
        return(-1);

    /* printf("Getting vslice size...\n"); */
    /* query size of vslice */
    if (get_vslice_size(&ccap, &vslc_size) != R_SUCCESS) 
        return(-1);

    /* printf("vslice size is %lu\n", vslc_size); */
    stat_buf->st_size  = vslc_size;

    stat_buf->st_mode  = S_IFREG;           /* disguise as regular file     */
    stat_buf->st_mode |= S_IRUSR;
    stat_buf->st_mode |= S_IWUSR;

    stat_buf->st_uid = getuid();
    stat_buf->st_gid = getgid();

    free(basename);
    return(0);
}

/* System call wrapper for open.                                            */
int open64(const char *pathname, int flags, ...) {
/* #ifdef REUSE_FNAME */
    int i = 0;
/* #endif */

    char *basename = NULL;              /* basename of path                 */
    char *last_sep = NULL;              /* last occurence of '/' in path    */

    struct crdss_posix_file *pfile = NULL;
    int os_fd;                          /* fd returned from OS              */
    uint64_t slice_size = 0;            /* size of opened vslice            */

    /* if not done yet, initialize the table lock */
    pthread_once(&table_lck_init, &setup_tbl_lck);

    if (libc_open64 == NULL)
        libc_open64 = dlsym(RTLD_NEXT, "open64");

    /* fprintf(stderr, "Called open64!\n"); */

    /* compute basename */
    last_sep = strrchr(pathname, '/');
    if (last_sep == NULL)
        basename = strdup(pathname);
    else
        basename = strdup(last_sep + 1);

    if (strncmp(basename, "crdss", 5) != 0) {
        int ret = -1;                               /* rc of real open64    */
        va_list arglist;
    
        va_start(arglist, flags);
        ret = libc_open64(pathname, flags, arglist);
        va_end(arglist);
        free(basename);
        return(ret);
    }

    /* fprintf(stderr, "Entering custom part of open64 (%s)!\n", basename); */

    /* lock fd table to avoid race conditions */
    pthread_mutex_lock(&table_lck);

/* #ifdef REUSE_FNAME */
    /* check if there is already a session for the file specified */
    for (i = 0; i < LIBCRDSS_MAX_FD; i++) {
        if (fd_table[i] != NULL && strcmp(basename, fd_table[i]->name) == 0) {
            /* file name is already opened */
            /* fprintf(stderr, "Reusing existing CRDSS session.\n"); */
            free(basename);
            fd_table[i]->ref_cnt = fd_table[i]->ref_cnt + 1;
            pthread_mutex_unlock(&table_lck);
            return(i);
        }
    }
/* #endif */

    /* if not done yet, connect to capability manager */
    if (capmgr_fd == -1 && connect_capmgr_dom(DEF_CAPMGR_SOCK) != 0) {
        free(basename);
        return(-1);
    }

    if ((pfile = calloc(1, sizeof(struct crdss_posix_file))) == NULL) {
        errno = ENOMEM;
        goto file_alloc_err;
    }
    pfile->name    = basename;
    pfile->ref_cnt = 1;

    /* try to derive basic information about requested device from path     */
    if (init_ccap_from_path(basename, &pfile->cap) != 0) {
        printf("error while parsing cap.\n");
        return(-1);
    }
   
    
    printf("derived cap from file name. didx = %u, sidx = %u\n", 
          pfile->cap.dev_idx, pfile->cap.vslc_idx);
   

    /* derive rights of capability from flags parameter */
    if ((flags & O_ACCMODE) == O_RDONLY) {
        /* printf("cap is rd only.\n"); */
        pfile->cap.rights |= CAP_READ;
    }
    else if ((flags & O_ACCMODE) == O_WRONLY) {
        /* printf("cap is wr only.\n"); */
        pfile->cap.rights |= CAP_WRITE;
    }
    else if ((flags & O_ACCMODE) == O_RDWR) {
        /* printf("cap is rd/wr\n"); */
        pfile->cap.rights |= CAP_READ;
        pfile->cap.rights |= CAP_WRITE;
    }
    else {
        printf("Error: cap without rights.\n");
        errno = EINVAL;
        goto rights_err;
    }

    /* get cap for full vslice */
    if (get_vslice_size(&pfile->cap, &slice_size) != R_SUCCESS) {
        printf("Failed to determine size of vslice.\n");
        errno = EINVAL;
        goto rights_err;
    }
    /* set cap range to whole slice, end offset of cap is slice size - 1!   */
    pfile->cap.start_addr = 0;
    pfile->cap.end_addr   = slice_size - 1;

    /* get backing fd to /dev/null */
    os_fd = libc_open64("/dev/null", O_WRONLY, 0);
    if (os_fd < 0)
        goto open_err;
    if (os_fd > (LIBCRDSS_MAX_FD - 1)) {
        printf("Number of open files exceeds limit of libcrdss.\n");
        goto fd_err;
    }

    logmsg(INFO, "os_fd is: %d\n", os_fd);
    /* set entry in fd table */
    fd_table[os_fd] = pfile;

    /* allocate a new server context for the file */
    pfile->sctx = create_srv_ctx(NULL);
    if (pfile->sctx == NULL) {
        printf("Unable to allocate new server context.\n");
        goto sctx_err;
    }

    /* request creation of capability */
    if (request_new_cap(&pfile->cap) != 0) {
        printf("Failed to create capability for open() request.\n");
        errno = EPERM;
        goto cap_err;
    }

    /* copy address information of cap and connect to storage server */
    memcpy(&pfile->sctx->srv_addr, &pfile->cap.srv, sizeof(struct sockaddr_in));
    pfile->sctx->guid = (uint64_t) strtoull(LIBCRDSS_TEST_GUID, NULL, 0);
    if (connect_storage_srv(pfile->sctx) != 0) {
        printf("Failed to connect to storage server.\n");
        errno = ENXIO;
        goto cap_err;
    }
    logmsg(INFO, "connected to storage server.");

    /* register cap at server */
    if (reg_cap(pfile->sctx, pfile->cap.id) != 0) {
        printf("Failed to register cap at server.\n");
        errno = EPERM;
        goto reg_err;
    }

    /* setup IB communication for further I/O operations */
    if (init_ib_comm(pfile->sctx) != 0) {
        printf("Failed to setup IB communication with crdss server.\n");
        errno = ENXIO;
        goto reg_err;
    }
    logmsg(INFO, "setup IB comm.");

    /* switch server to polling mode */
    /* query_srv_poll(pfile->sctx); */

    pthread_mutex_unlock(&table_lck);
    return(os_fd);

reg_err:
    close_srv_conn(pfile->sctx);
cap_err:
    if (pfile->sctx != NULL) free(pfile->sctx);
sctx_err:
    fd_table[os_fd] = NULL;
fd_err:
    close(os_fd);
open_err:
    pthread_mutex_unlock(&table_lck);
rights_err:
    free(pfile);
file_alloc_err:
    free(basename);
    return(-1);
}

/* wrapper for the close system call                                        */
/*
int close(int fd) {
    if (libc_close == NULL)
        libc_close = dlsym(RTLD_NEXT, "close");
    fprintf(stderr, "Called close for fd %d!\n", fd);

    pthread_mutex_lock(&table_lck);
    if (fd_table[fd] != NULL) {
        fd_table[fd]->ref_cnt = fd_table[fd]->ref_cnt - 1;
        if (fd_table[fd]->ref_cnt == 0) { */
            /* tear down server connection */
            /*
            fprintf(stderr, "destroying custom data structure (fd = %d).\n", 
                    fd);
            close_srv_conn(fd_table[fd]->sctx);
            if (fd_table[fd]->name != NULL) free(fd_table[fd]->name);
            free(fd_table[fd]);
            fd_table[fd] = NULL;
            fprintf(stderr, "destruction of fd %d done, calling close(2).\n", 
                    fd);
        }
    }
    pthread_mutex_unlock(&table_lck);

    return(libc_close(fd));
} */

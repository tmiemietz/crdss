/****************************************************************************
 *                                                                          *
 *    libcrdss.h - Client-side library for accessing the CRDSS service.     *
 *                                                                          *
 *                    Copyright (c) 2020 Till Miemietz                      *
 *                                                                          *
 ****************************************************************************/


#ifndef LIBCRDSS_H
#define LIBCRDSS_H

/****************************************************************************
 *                                                                          *
 *                     global definitions and macros                        *
 *                                                                          *
 ****************************************************************************/


#define DEF_LIB_CFG_PATH "/home/mt/crdss/libcrdss.cfg"
#define DEF_CAPMGR_SOCK  "/tmp/crdss-capmgr.sock"       /* capmgr dom. sock */

/****************************************************************************   
 *                                                                          *   
 *                           include statements                             *   
 *                                                                          *   
 ****************************************************************************/


#include <stdint.h>                     /* fixed-width integers             */
#include <sys/socket.h>                 /* enables networking API           */
#include <sys/un.h>                     /* for UNIX domain sockets          */

#include "cap.h"                        /* crdss capabilities               */
#include "ibcomm.h"                     /* CRDSS InfiniBand wrappers        */
#include "confparser.h"                 /* parse config files for libcrdss  */

/****************************************************************************
 *                                                                          *
 *                           type definitions                               *
 *                                                                          *
 ****************************************************************************/


/* mantle structure for a connection to a server, seen from the client side */
struct crdss_srv_ctx {
    struct sockaddr_in srv_addr;    /* IP address and port of server        */
    int tcp_fd;                     /* fd for TCP socket to server          */
    pthread_mutex_t tcp_lck;        /* lock for using the TCP connection    */

    unsigned char *msg_buf;         /* pointer to message buffer (send/recv)*/
    unsigned char *rdma_buf;        /* pointer to RDMA buffer               */
    uint64_t guid;                  /* GUID of IB port used                 */
    struct ib_ctx ibctx;            /* InfiniBand context                   */

    struct clt_lib_cfg buf_cfg;     /* config for InfiniBand buffers        */

    pthread_key_t tls_key;          /* TLS ID for workers at this ctx       */

    unsigned char *worker_ids;      /* bitmap to track used worker IDs      */
    pthread_mutex_t id_lck;         /* lock for the worker ID bitmap        */

    struct slist *avail_lbuf;       /* list of free large buffers           */
    pthread_mutex_t lbuf_lck;       /* mutex and cv to wait for free lbufs  */
    pthread_cond_t  lbuf_cv;

    pthread_t compl_worker;         /* pointer to completion worker thread  */
    struct slist *wait_workers;     /* list of workers that wait for a CQE  */
    struct slist *unknown_compl;    /* completion for unknown workers       */
    pthread_mutex_t wait_lck;       /* lock for waiter list                 */
};

/***        forwards declarations for library-internal data types         ***/
struct stat64;

/****************************************************************************
 *                                                                          *
 *                          function prototypes                             *
 *                                                                          *
 ****************************************************************************/


/****************************************************************************
 *
 * Allocates and initializes a new server context. The structure returned by
 * this function shall be destroyed by the corresponding destructor function,
 * e.g. close_server_conn. The server context holds all fields necessary for
 * a connection to a single storage server. When connecting to multiple
 * servers, the application needs to allocate one of the context structures
 * per server session. The config parameter passed to this function contains
 * information about the buffer configuration for InfiniBand data transfer
 * buffers. It might be NULL; in this case a default configuration located
 * in DEF_LIB_CFG_PATH is loaded.
 *
 * Params: cfg - pointer to InfiniBand buffer config structure (may be NULL).
 *
 * Returns: An initialized server context structure (no config parameters
 *          included yet) or NULL on error.
 */
struct crdss_srv_ctx *create_srv_ctx(struct clt_lib_cfg *cfg);

/****************************************************************************
 *
 * Opens a connection to a local capability manager acessible via the domain
 * socket located in sockpath. 
 *
 * Params: sockpath - Path to domain socket of local capability manager.
 *
 * Returns: 0 on success, 1 on error.
 */
int connect_capmgr_dom(char *sockpath);

/****************************************************************************
 *
 * Connects an application to the CRDSS storage server specified in the
 * sockaddr structure. The routine will perform the handshake. Upon success,
 * the file descriptor referecing the new socket to the server is returned.
 * Note that the server context passed to this function shall be allocated
 * by calling create_srv_ctx. Afterwards, in order to successfully call this
 * function, the user has to fill in the srv_addr field of the server context
 * with valid values. The function will initialize the tcp_fd field of sctx
 * to point to the TCP socket connected to the server specified in 
 * sctx->srv_addr. Connecting a storage server will only succeed on server
 * contexts which do not contain a valid TCP socket file descriptor.
 *
 * Params: sctx - The server context for connecting.
 *
 * Returns: 0 on success, a non-zero value on error.
 */
int connect_storage_srv(struct crdss_srv_ctx *sctx);

/****************************************************************************
 *
 * Queries the preconfigured cap manager to issue a new capability with the
 * parameters as defined in cap. Note that in order to complete this
 * operation, the connection to the capability manager has to be set up
 * beforehand by calling connect_capmgr_*. Upon successful completion of
 * this function, the ID and rev_dom fields of cap will be filled with valid
 * values. The key of the input cap may be NULL. In that case, the capmgr will
 * search for a cap with the default key ("generic"). The new cap will be
 * placed in a new revocation domain. The function will also fill the port 
 * of the server in charge for serving the slice encoded by the capability,
 * so that subsequent functions to connect to a storage server succeed.
 *
 * Params: cap - Capability structure that contains the parameters of the
 *               storage region requested.
 *
 * Returns 0 on success, an error code otherwise.
 */
int request_new_cap(struct crdss_clt_cap *cap);

/****************************************************************************
 *
 * Initializes an InfiniBand connection with the CRDSS storage server that
 * can be reached via the socket sctx->tcp_fd. Upon successful completion, 
 * the server context contains a functional InfiniBand connection to the 
 * server that backs sctx. Data and message buffers are allocated by this 
 * function and stored in the respective fields of the server context struct. 
 * They buffer size is determined by the IB buffer layout that was specified
 * during the creation of the server context.
 * Connection data like the server's rkey are stored in the ib_ctx structure
 * inside the server context.
 *
 * Params: sctx - context of server with that an IB connection shall will be
 *                established.
 *
 * Returns: 0 on success, 1 on error.
 */
int init_ib_comm(struct crdss_srv_ctx *sctx);

/****************************************************************************
 *
 * Closes a connection to a CRDSS storage server. This will lead to a
 * teardown of both the TCP connection to the server and (if present) the
 * IB queue pairs associated with this context. All InfiniBand buffers that
 * were used by sctx are freed by this routine. In a multi-threaded program,
 * the user is responsible for coordinating his threads so that the 
 * teardown of the connection does not lead to deadlocks etc.
 *
 * Note: The function will also free sctx, so after calling this function,
 *       sctx is no longer a valid pointer.
 *
 * Params: sctx - context of connection to be closed.
 *
 * Returns: 0 on success, 1 on error.
 */
int close_srv_conn(struct crdss_srv_ctx *sctx);

/****************************************************************************
 *
 * Registers a capability at the server identified by sctx. In order to
 * execute this function, the server context must have been connected to
 * a server. If the IB connection to the server is not active yet, the
 * registration request is sent via TCP.
 * Note that the capability ID passed to this function must contain CAP_ID_LEN
 * characters, otherwise the behavior of this function is undefined.
 *
 * Params: sctx  - server connection context.
 *         capid - pointer to buffer for capability ID.
 *
 * Returns: 0 on success, 1 on error.
 */
int reg_cap(struct crdss_srv_ctx *sctx, unsigned char *capid);

/****************************************************************************
 *
 * Deletes a revocation domain at the server identified by sctx. In order to
 * execute this function, the server context must have been conencted to a 
 * server. If the IB connection is not active, yet, the deletion request
 * will be sent via TCP. In order for the request to succeed, the client 
 * must have registered at least one capability with the server that belongs
 * to the deleted revocation domain.
 *
 * Params: sctx - server connection context.
 *         rdom - ID of revocation domain to delete.
 *
 * Returns: 0 on success, 1 on error.
 */
int delete_rdom(struct crdss_srv_ctx *sctx, uint32_t rdom);

/****************************************************************************
 *
 * Queries the server identified by sctx to switch to polling completion.
 * When using polling completion on the server side, the latency of requests
 * is improved. This however comes at a much higher CPU utilization. The 
 * function will only work if the server context has an active InfiniBand
 * connection.
 *
 * Params: sctx - server connection context.
 * 
 * Returns: 0 on success, 1 on error.
 */
int query_srv_poll(struct crdss_srv_ctx *sctx);

/****************************************************************************
 * 
 * Queries the server identified by sctx to switch to blocking completion.
 * When using blocking completion on the server side, the latency of requests
 * is increased. However, blocking completion significantly lowers the CPU
 * utilization on the server side. The function will only work if the server
 * context has an active InfiniBand connection.
 *
 * Params: sctx - server connection context.
 *
 * Returns: 0 on success, 1 on error.
 */
int query_srv_block(struct crdss_srv_ctx *sctx);

/****************************************************************************
 *
 * Queries the size of the vslice in ccap from the capability manager.
 * The size returned in size is the size of vslice that the capability passed
 * as input parameter refers to (given in Bytes).
 *
 * Params: ccap - capability that specifies the vslice to examine.
 *         size - size of the requested vslice (output parameter).
 *
 * Returns: An error number as defined in src/include/protocol.h
 */
int get_vslice_size(struct crdss_clt_cap *ccap, uint64_t *size);

/****************************************************************************
 *
 * Reads len bytes from the storage location specified by didx, sidx and
 * saddr and stores them in the buffer pointed to by buf. This function uses
 * polling-based I/O completion with a doorbell memory address. For best
 * latency, the server shall be switched to polling completion as well before
 * calling this function. The function will fail if the calling thread can not
 * be registered with a dorbell / sbuf entry.
 *
 * Params: ibctx      - IB context as yielded from the init_ib_comm routine.
 *         didx       - index of device to read from.
 *         sidx       - index of vslice to read from.
 *         saddr      - address inside vslice to read from.
 *         buf        - buffer provided by user for storing the data.
 *         len        - number of bytes to read.
 *
 * Returns: The status of the operation, as defined in include/protocol.h.
 */
int fast_read_raw(struct crdss_srv_ctx *sctx, uint16_t didx, uint32_t sidx,
                  uint64_t saddr, void *buf, uint32_t len);

/****************************************************************************
 *
 * Writes len bytes to the storage location specified by didx, sidx and
 * saddr. Data is taken from the user-provided buffer pointed to by buf.
 * This function uses polling completion in combination with a doorbell 
 * memory address. For lowest latency, the server shall be switched to polling 
 * compltione as well before calling this function.
 * The function will fail if the calling thread can not be registered with a 
 * dorbell / sbuf entry.
 *
 * Params: ibctx      - IB context as yielded from the init_ib_comm routine.
 *         didx       - index of device to write to.
 *         sidx       - index of vslice to write to.
 *         saddr      - address inside vslice to write to.
 *         buf        - buffer provided by user that contains the data to be
 *                      written.
 *         len        - number of bytes to write.
 *
 * Returns: The status of the operation, as defined in include/protocol.h.
 */
int fast_write_raw(struct crdss_srv_ctx *sctx, uint16_t didx, uint32_t sidx,
                   uint64_t saddr, const void *buf, uint32_t len);

/****************************************************************************
 *
 * Reads len bytes from the storage location specified by didx, sidx and
 * saddr and stores them in the buffer pointed to by buf. This function uses 
 * InfiniBand's blocking completion mechanism. The RDMA buffer used for data
 * transmission is allocated from the global list of large buffers. 
 * Consequently, when there are more threads using this function than there
 * are large buffers, the calling threads will have to wait for such a large
 * buffer to become available.
 *
 * Params: ibctx      - IB context as yielded from the init_ib_comm routine.
 *         didx       - index of device to read from.
 *         sidx       - index of vslice to read from.
 *         saddr      - address inside vslice to read from.
 *         buf        - buffer provided by user for storing the data.
 *         len        - number of bytes to read.
 *
 * Returns: The status of the operation, as defined in include/protocol.h.
 */
int read_raw(struct crdss_srv_ctx *sctx, uint16_t didx, uint32_t sidx,    
             uint64_t saddr, void *buf, uint32_t len);

/****************************************************************************
 *
 * Writes len bytes to the storage location specified by didx, sidx and
 * saddr. Data is taken from the user-provided buffer pointed to by buf.
 * This function uses InfiniBand's blocking completion mechanism. 
 * The RDMA buffer used for data transmission is allocated from the global 
 * list of large buffers. Consequently, when there are more threads using 
 * this function than there are large buffers, the calling threads will have
 * to wait for such a large buffer to become available.
 *
 * Params: ibctx      - IB context as yielded from the init_ib_comm routine.
 *         didx       - index of device to write to.
 *         sidx       - index of vslice to write to.
 *         saddr      - address inside vslice to write to.
 *         buf        - buffer provided by user that contains the data to be
 *                      written.
 *         len        - number of bytes to write.
 *
 * Returns: The status of the operation, as defined in include/protocol.h.
 */
int write_raw(struct crdss_srv_ctx *sctx, uint16_t didx, uint32_t sidx,
              uint64_t saddr, const void *buf, uint32_t len);

/***                     POSIX interface emulation                        ***/

/****************************************************************************
 *
 * Linux-specific system call wrapper for stat on systems with large file
 * support.
 */
int __xstat64(int ver, const char *path, struct stat64 *stat_buf);

/****************************************************************************
 *
 * Linux-specific system call wrapper for lstat on systems with large file
 * support.
 */
 int __lxstat64(int ver, const char *path, struct stat64 *stat_buf);

#endif /* LIBCRDSS_H */

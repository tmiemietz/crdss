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

    struct ib_ctx ibctx;            /* InfiniBand context                   */

    struct clt_lib_cfg buf_cfg;     /* config for InfiniBand buffers        */

    pthread_key_t tls_key;          /* TLS ID for workers at this ctx       */
};

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
 * can be reached via the socket srv sock. The user of this function shall
 * allocate an InfiniBand context structure and pass this structure to 
 * this routine. Upon successful completion, the context contains various
 * IB-related structures. Data and message buffers are allocated by this 
 * function and returned via the respective pointers. After calling this
 * function, the queue pair in ibctx shall be ready for communication. 
 * Connection data like the server's rkey are stored in the ib_ctx structure
 * provided to this function.
 *
 * Params: srvfd   - socket for TCP communication with server.
 *         ibctx   - preallocated InfiniBand context.
 *         guid    - identifier of port to use for IB communication.
 *         msgbuf  - message buffer is stored in this ptr (output param).
 *         rdmabuf - RDMA buffer is stored in this ptr (output param).
 *         rdmasz  - size of RDMA buffer to allocate.
 *
 * Returns: 0 on success, 1 on error.
 */
int init_ib_comm(int srvfd, struct ib_ctx *ibctx, uint64_t guid,
                 unsigned char **msgbuf, unsigned char **rdmabuf, int rdmasz);

/****************************************************************************
 *
 * Closes a connection to a CRDSS storage server. The user shall pass both
 * the fd for the TCP socket to the server as well as the IB context if it
 * has been created already. However, the user is still responsible for
 * freeing the data and message buffers of the IB context as well as the
 * context object itself. Note that it is valid to pass NULL for the IB ctx
 * if no queue pair setup has been done yet.
 *
 * Params: srvfd - fd for TCP socket to server.
 *         ibctx - IB context as yielded from the init_ib_comm rountine.
 *
 * Returns: 0 on success, 1 on error.
 */
int close_srv_conn(int srvfd, struct ib_ctx *ibctx);

/****************************************************************************
 *
 * Registers a capability at the server by specifying the cap ID. If the
 * IB context passed to this function is NULL, the TCP socket with fd srvfd
 * will be used, otherwise communication is done via SEND/RECEIVE ops.
 * Note that the capability ID passed to this function must contain CAP_ID_LEN
 * characters, otherwise the behavior of this function is undefined.
 *
 * Params: srvfd - fd for TCP socket to server.
 *         ibctx - IB context as yielded from the init_ib_comm routine.
 *         capid - pointer to buffer for capability ID.
 *
 * Returns: 0 on success, 1 on error.
 */
int reg_cap(int srvfd, struct ib_ctx *ibctx, unsigned char *capid);

/****************************************************************************
 *
 * Reads len bytes from the storage location specified by didx, sidx and
 * saddr and stores them at rdma_addr in the RDMA buffer allocated for
 * the queue pair when the InfiniBand connection has been set up. This function
 * will enter a polling loop until the completion notification has been put
 * at address poll_field by the server.
 *
 * Params: ibctx      - IB context as yielded from the init_ib_comm routine.
 *         didx       - index of device to read from.
 *         sidx       - index of vslice to read from.
 *         saddr      - address inside vslice to read from.
 *         len        - number of bytes to read.
 *         rdma_addr  - location where data shall be written to.
 *         poll_field - memory address used as a status indicator.
 *
 * Returns: The status of the operation, as defined in include/protocol.h.
 */
int fast_read_raw(struct ib_ctx *ibctx, uint16_t didx, uint32_t sidx,
                  uint64_t saddr, uint32_t len, uint64_t rdma_addr, 
                  uint64_t poll_field);

/****************************************************************************
 *
 * Writes len bytes to the storage location specified by didx, sidx and
 * saddr. Data is written from the buffer located at rdma_addr in the RDMA 
 * region allocated for the queue pair when the InfiniBand connection has been 
 * set up. This function will enter a polling loop until the completion 
 * notification has been put at address poll_field by the server.
 *
 * Params: ibctx      - IB context as yielded from the init_ib_comm routine.
 *         didx       - index of device to write to.
 *         sidx       - index of vslice to write to.
 *         saddr      - address inside vslice to write to.
 *         len        - number of bytes to write.
 *         rdma_addr  - location where data shall be taken from.
 *         poll_field - memory address used as a status indicator.
 *
 * Returns: The status of the operation, as defined in include/protocol.h.
 */
int fast_write_raw(struct ib_ctx *ibctx, uint16_t didx, uint32_t sidx,
                   uint64_t saddr, uint32_t len, uint64_t rdma_addr, 
                   uint64_t poll_field);

#endif /* LIBCRDSS_H */

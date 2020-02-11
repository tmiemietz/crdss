/****************************************************************************
 *                                                                          *
 *  ibcomm.h - data types and routines for CRDSS' InfiniBand communication  *
 *                                                                          *
 *                    Copyright (c) 2020 Till Miemietz                      *
 *                                                                          *
 ****************************************************************************/


#ifndef IBCOMM_H
#define IBCOMM_H

/****************************************************************************
 *                                                                          *
 *                           include statements                             *
 *                                                                          *
 ****************************************************************************/


#include <stdint.h>                 /* integers with fixed width            */
#include <pthread.h>                /* POSIX MT interface                   */
#include <infiniband/verbs.h>       /* IB communcation types                */

/****************************************************************************
 *                                                                          *
 *                     global definitions and macros                        *
 *                                                                          *
 ****************************************************************************/


/* size of the control message buffer. The size weill be allocated for both *
 * send and receive buffers. I.e, a value of 10 means that memory for 10    *
 * send requests as well as for 10 receive requests is allocated            */
#define RBUF_MSG_CNT 10

/* max. number of scatter-gather elements per request, to be tuned          */
#define MAX_SGE 10

/***            sizing of both client and server-side RDMA buffers        ***/
#define MAX_SRV_BUF_SZ  1073741824      /* max amount of mem that each clt  *
                                         * may claim on server side for RDMA*
                                         * hard limit is currently 1 GiB    */

/* preliminary, hardcoded values to indicate which pkey to use, change later*/
#define CRDSS_PKEY_IDX 0

/* starting packet sequence number for all queue pairs                      */
#define STARTING_PSN 0

/****************************************************************************
 *                                                                          *
 *                              type definitions                            *
 *                                                                          *
 ****************************************************************************/


/* type that contains all data structures that describe a IB connection     */
struct ib_ctx {
    struct ibv_context *dev_ctx;            /* device context for this QP   */
    
    struct ibv_pd *pdom;                    /* protection domain of this QP */
    struct ibv_cq *cq;                      /* completion queue of this QP  */

    struct ibv_comp_channel *cchannel;      /* for non-polling completion   */

    struct ibv_mr *msg_mr;                  /* mem region for messages      */
    struct ibv_mr *rdma_mr;                 /* mem region for data transfer */

    struct ibv_qp *qp;                      /* the actual queue pair        */

    uint8_t  port_num;                      /* port no. to to use for comm. */
    uint16_t loc_lid;                       /* local LID of used port       */
    uint16_t rem_lid;                       /* LID of peer queue pair       */
    uint32_t remote_qpn;                    /* QPN of peer queue pair       */

    uint64_t remote_addr;                   /* start address of remote RDMA *
                                             * buffer for data transfer     */
    uint32_t remote_rkey;                   /* rkey of remote data buffer   */

    /* client-side fields for coordination of blocking completion           */
    pthread_mutex_t mtx;
    pthread_cond_t  cv;

    int      is_armed;
    int      next_err;
    uint64_t next_id;
};

/****************************************************************************
 *                                                                          *
 *                          function prototypes                             *
 *                                                                          *
 ****************************************************************************/


/****************************************************************************
 *
 * Initiates an InfiniBand RC queue pair on client side. After performing 
 * this step, the local QPN and other config parameters that have to be
 * transmitted to the server will be known. However, the queue pair inside the
 * IB context is not yet operational. This function will also allocate the 
 * RDMA buffers as requested by the application.
 *
 * Params: ibctx   - mantle structure for IB context, must not be NULL.
 *         guid    - InfiniBand GUID of the port used for communication.
 *         msgbuf  - pointer to the location of the control message buffer
 *                   (output parameter).
 *         rdmabuf - pointer to the RDMA buffer region (output parameter).
 *         rdmasz  - size of RDMA buffer to allocate.
 *
 * Returns: 0 on success, 1 on error.
 */
int init_clt_qp(struct ib_ctx *ibctx, uint64_t guid, unsigned char **msgbuf, 
                unsigned char **rdmabuf, int rdmasz);

/****************************************************************************
 *
 * Completes the connection to a server queue pair by transitioning the
 * queue pair in ibctx. The context passed to this structure must be
 * previously handed into the init_clt_qp function. After calling this routine
 * the ctx' queue pair is ready for data transmission and communication
 * channels can be switched. This function also takes a reference to the start
 * of the message buffer and will post RBUF_MSG_CNT receive requests, taken 
 * from the second half of the message buffer.
 *
 * Params: ibctx   - InfiniBand communication context.
 *         msg_buf - poiner to message buffer (must have been passed to
 *                   init qp function previously).
 *
 * Returns: 0 on success, 1 on error.
 */
int complete_clt_qp(struct ib_ctx *ibctx, unsigned char *msg_buf);

/****************************************************************************
 *
 * Sets up a InfiniBand queue pair on the server side. Since this function
 * will also perform queue pair transition, the connection parameters of the
 * client queue pair have ot be known before calling this routine.
 * This function will also allocate message and RDMA buffers needed on the
 * server side to handle the client. The size of these buffers is given by the
 * parameter rdmasz and must be lower than the current maximum on the size
 * of a per-client memory region, currently given by the definition
 * of MAX_SRV_BUF_SZ.
 * 
 * Params: ibctx   - mantle structure for IB context.
 *         guid    - InfiniBand GUID of the port used for communication.
 *         msgbuf  - pointer to control message buffer (output parameter).
 *         databuf - pointer to buffer for sending and RDMA (output parameter).
 *         rdmasz  - size of the server's RDMA region for data transfer.
 *
 * Returns: 0 on success, 1 on any error.
 */
int setup_srv_qp(struct ib_ctx *ibctx, uint64_t guid, unsigned char **msgbuf, 
                 unsigned char **databuf, uint32_t rdmasz);

/****************************************************************************
 *
 * Posts a receive request with the size of MAX_MSG_LEN starting from 
 * the start address given by msg_addr. This receive request will be capable
 * of holding exactly one crdss control command (i.e., the pointer must
 * point to a memory area that is at least MAX_MSG_LEN bytes in size).
 * If the buffer pointed to by msg_addr is a multiple size of MAX_MSG_LEN, 
 * several RRs can be posted at once by specifiying a value greater than 1 for
 * cnt. Also make sure that the memory that msg_addr points to is part of a
 * registered memory region.
 *
 * Params: ibctx    - mantle structure for IB context.
 *         msg_addr - start address of message buffer.
 *         cnt      - number of receive requests to post.
 *
 * Returns: 0 on success, 1 on error.
 */
int post_msg_rr(struct ib_ctx *ibctx, unsigned char *msg_addr, 
                unsigned int cnt);

/***************************************************************************
 *
 * Posts a send request containing a crdss command with size MAX_MSG_LEN.
 * Send operations will be carried out without solicitation etc.
 *
 * Params: ibctx    - mantle structure for IB context.
 *         msg_addr - start address of message buffer.
 *
 * Returns: 0 on success, 1 on error.
 */
int post_msg_sr(struct ib_ctx *ibctx, unsigned char *msg_addr);

/****************************************************************************
 *
 * Initiates an RDMA transfer to the remote side connected to the queue pair
 * in the InfiniBand context structure provided to this function. 
 * The transfer can be used with a immediate value that tells the remote side
 * the memory address where the contents of the local input buffer have been
 * stored.
 *
 * Params: ibctx    - mantle structure for IB context.
 *         loc_addr - address of local buffer.
 *         rem_addr - address of remote buffer.
 *         length   - amount of data to transmit.
 *         use_imm  - if != 0 use an RDMA with immediate operation to tell
 *                    the remote side about this operation.
 *         signaled - if != 0, a completion event for the RDMA op will be
 *                    generated in the sender's CQ.
 *
 * Returns: 0 on success, 1 on error.
 */
int init_rdma_transfer(struct ib_ctx *ibctx, unsigned char *loc_addr, 
                       unsigned char *rem_addr, size_t length, int use_imm,
                       int signaled);

/****************************************************************************
 *
 * Writes a operation status into a remote polling field by using an RDMA
 * operation. Since the stauts code that is transmitted is only 8 bytes in 
 * size, inlining is used. 
 *
 * Params: ibctx    - mantle structure for IB context.
 *         loc_addr - address of local status code (must be registered mem.)
 *         rem_addr - address of remote buffer.
 *         rkey     - rkey of remote poll field.
 *
 * Returns: 0 on success, 1 on error.
 */
int write_poll_field(struct ib_ctx *ibctx, uint64_t loc_addr, 
                     uint64_t rem_addr);

/****************************************************************************
 *
 * Closes an InfiniBand connection and destroys all resources associated
 * with it. After calling this function, the message and data buffers
 * referenced by the ib_ctx structure passed to this routines can be freed
 * safely. This function will discard outstanding completion entries.
 *
 * Params: ibctx - context of InfiniBand connection to close.
 *
 * Returns: 0 on success, 1 if there was an error during teardown.
 */
int destroy_ibctx(struct ib_ctx *ibctx);

/****************************************************************************
 *
 * Reads the next control message from the InfiniBand queue pair contained
 * in ibctx. The InfiniBand context is expected to be fully initialized.
 * To save CPU resources, a blocking completion notification via a completion
 * channel is used. Currently, this channel acknowledges one message at a
 * time in each call to this function, which might be a performance pitfall.
 *
 * Params: ibctx - InfiniBand context of the calling handler thread.
 *         msg   - points to a pointer where the message start shall be saved.
 *
 * Returns: 0 on success, 1 on error.
 */
int get_next_ibmsg(struct ib_ctx *ibctx, unsigned char **msg);

#ifdef bla
/****************************************************************************
 *
 * Waits for the next message whise work request id is wrid. This is a 
 * blocking operation and requires coordination between all threads that
 * are currently waiting on this queue pair.
 *
 * Params: ibctx - InfiniBand context of the calling thread.
 *         wrid  - work request ID to wait for.
 *
 * Returns: 0 on success, 1 on error.
 */
int wait_for_msg_id(struct ibctx *ibctx, uint64_t wrid);
#endif

#endif /* IBCOMM_H */

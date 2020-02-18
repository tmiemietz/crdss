/****************************************************************************
 *                                                                          *
 *  ibcomm.c - data types and routines for CRDSS' InfiniBand communication  *
 *                                                                          *
 *                    Copyright (c) 2020 Till Miemietz                      *
 *                                                                          *
 ****************************************************************************/



/****************************************************************************
 *                                                                          *
 *                           include statements                             *
 *                                                                          *
 ****************************************************************************/


#include <stdlib.h>                         /* memory allocation            */
#include <stdint.h>                         /* fixed-width integers         */
#include <string.h>                         /* memset and friends           */
#include <infiniband/verbs.h>               /* IB communication definitions */
#include <errno.h>                          /* find out reasons for errors  */
#include <arpa/inet.h>                      /* byte order conversion        */
#include <time.h>                           /* for nanosleep                */

#include "include/ibcomm.h"                 /* header for ibcomm impl.      */
#include "include/protocol.h"               /* to compute size of msg bufs  */
#include "include/utils.h"                  /* for log messaging            */

/****************************************************************************
 *                                                                          *
 *                          static helper functions                         *
 *                                                                          *
 ****************************************************************************/


/****************************************************************************
 *
 * Iterates through all IB ports available on the machine and opens the
 * device that bears a port with the GUID guid on it. The reference to the
 * open device as well as the port number to use when configuring queue pairs
 * for use with the port specified by the GUID guid are stored in the
 * ib_ctx structure.
 *
 * Params: ibctx - mantle structure that contains IB data.
 *         guid  - GUID to search for in the system's port list.
 *
 * Returns: 0 on success (device was opened), 1 on error
 */
static int get_ctx_by_guid(struct ib_ctx *ibctx, uint64_t guid) {
    int i;
    int j;
    struct ibv_device  **dev_list;          /* vars for iterating the devlist */
    int dev_cnt;                            /* no. of IB devs in the system   */
    struct ibv_device  *dev;
    struct ibv_context *open_dev;           /* dev currently examined         */

    /* fields for querying device / port information                          */
    struct ibv_device_attr dev_attr;
    struct ibv_port_attr pattr;
    union  ibv_gid port_gid;

    if ((dev_list = ibv_get_device_list(&dev_cnt)) == NULL) {
        logmsg(ERROR, "Failed to open IB device list.");
        return(1);
    }
    
    /* iterate through all devices in the system */
    logmsg(DEBUG, "IB dev count is %d.", dev_cnt);
    for (i = 0; i < dev_cnt; i++) {
        dev = dev_list[i];

        open_dev = ibv_open_device(dev);
        if (open_dev == NULL) {
            logmsg(ERROR, "Failed to open IB device (errno: %d).", errno);
            continue;
        }

        if (ibv_query_device(open_dev, &dev_attr) == -1) {
            logmsg(ERROR, "Failed to query device attributes.");
            ibv_close_device(open_dev);
            continue;
        }

        logmsg(DEBUG, "Dev %d: max. cont. MR is of size %#lx B", i,
               dev_attr.max_mr_size);

        /* iterate over all ports on the device, remember that port nums    *
         * start with 1 in InfiniBand                                       */
        for (j = 1; j <= dev_attr.phys_port_cnt; j++) {
           /* query port's GUID by asking for the GID with index 0 (special *
            * entry containing the GUID                                     */
           if (ibv_query_gid(open_dev, j, 0, &port_gid) == -1) {
                logmsg(ERROR, "Can not query GUID of port %u (errno: %d).",
                       j, errno);
                continue;
           }

           if (ibv_query_port(open_dev, j, &pattr) == -1) {
                logmsg(ERROR, "Failed to query attributes of port %u "
                       "(errno: %d).", j, errno);
                continue;
           }

           logmsg(DEBUG, "Dev %d, port %d: guid is %#lx (hbo %#lx).", i, j, 
                  port_gid.global.interface_id, 
                  be64toh(port_gid.global.interface_id));

           /* GID / GUID is stored in network byte order!                   */
           if (be64toh(port_gid.global.interface_id) == guid) {
                /* guid was found, close all structs and leave */
                ibctx->dev_ctx  = open_dev;
                ibctx->port_num = j;
                ibctx->loc_lid  = pattr.lid;

                ibv_free_device_list(dev_list);
                return(0);
           }
        }

        /* this was not the right device, query the next one */
        ibv_close_device(open_dev);
    }

    /* if this point is reached, the requested GUID has not been found      */
    ibv_free_device_list(dev_list);
    return(1);
}

/****************************************************************************
 *                                                                          *
 *                          function implementation                         *
 *                                                                          *
 ****************************************************************************/


/***                     functions defined in ibcomm.h                    ***/

/* Initiates an InfiniBand RC queue pair on client side.                    */
int init_clt_qp(struct ib_ctx *ibctx, uint64_t guid, unsigned char **msgbuf, 
                uint32_t msg_cnt, unsigned char **rdmabuf, uint32_t rdmasize) {
    struct ibv_qp_init_attr iattr;      /* attributes for initializing a    *
                                         * queue pair                       */

    /* first of all, allocate the message buffers. If this fails, we don't  *
     * even have to bother with any further actions                         */
    /* memory is allocated only for receive / completion messages since     *
     * sending of small messages is always done using inline data           */
    *msgbuf  = malloc(msg_cnt * MAX_MSG_LEN);
    *rdmabuf = malloc(rdmasize);

    if (*msgbuf == NULL || *rdmabuf == NULL) {
        logmsg(ERROR, "Allocation of InfiniBand message buffers failed!");

        if (*msgbuf != NULL)  free(*msgbuf);
        if (*rdmabuf != NULL) free(*rdmabuf);

        return(1);
    }

    /* open the IB device identified by guid and save the port no. in ibctx */
    if (get_ctx_by_guid(ibctx, guid) != 0) {
        logmsg(ERROR, "Failed to open IB device with port GUID %#lx. "
               "Make sure that the GUID is correct...", guid);
        goto err_mem;
    }

    /* allocate completion channel and protection domain                    */
    ibctx->cchannel = ibv_create_comp_channel(ibctx->dev_ctx);
    ibctx->pdom     = ibv_alloc_pd(ibctx->dev_ctx);
    if (ibctx->cchannel == NULL || ibctx->pdom == NULL) {
        logmsg(ERROR, "Failed to allocate completion channel / protection "
               "domain");
        if (ibctx->cchannel != NULL) 
            ibv_destroy_comp_channel(ibctx->cchannel);
        if (ibctx->pdom != NULL)
            ibv_dealloc_pd(ibctx->pdom);

        goto err_pd;
    }

    /* register memory regions for send / receive buffer areas as well as for*
     * the rdma data transfer areas, we will only use RDMA write so nor      *
     * IBV_ACCESS_REMOTE_READ flag has to be set                             */
    ibctx->msg_mr = ibv_reg_mr(ibctx->pdom, *msgbuf, msg_cnt * MAX_MSG_LEN,
                               IBV_ACCESS_LOCAL_WRITE | 
                               IBV_ACCESS_REMOTE_WRITE);
    ibctx->rdma_mr = ibv_reg_mr(ibctx->pdom, *rdmabuf, rdmasize,
                               IBV_ACCESS_LOCAL_WRITE |
                               IBV_ACCESS_REMOTE_WRITE);
    if (ibctx->msg_mr == NULL || ibctx->rdma_mr == NULL) {
        logmsg(ERROR, "Failed to register memory regions (errno %d).", errno);

        if (ibctx->msg_mr == NULL)
            logmsg(ERROR, "Registration of msg region failed.");
        if (ibctx->rdma_mr == NULL)
            logmsg(ERROR, "Registration of data region failed.");

        if (ibctx->msg_mr != NULL)
            ibv_dereg_mr(ibctx->msg_mr);
        if (ibctx->rdma_mr != NULL)
            ibv_dereg_mr(ibctx->rdma_mr);

        goto err_mr;
    }

    /* create a completion queue, maybe investigate on the IRQ vector later */
    ibctx->cq = ibv_create_cq(ibctx->dev_ctx, msg_cnt, NULL,
                              ibctx->cchannel, 0);
    if (ibctx->cq == NULL)
        goto err_cq;

    /* set the init attrs to meaningful values and create the queue pair    */
    iattr.qp_context = NULL;            /* handler-private QP, no ctx needed*/
    iattr.send_cq    = ibctx->cq;       /* for now use the same cq          */
    iattr.recv_cq    = ibctx->cq;
    iattr.srq        = NULL;            /* no SRQ usage for now             */
    
    iattr.cap.max_send_wr  = msg_cnt;   /* max outstanding send reqs.       */
    iattr.cap.max_recv_wr  = msg_cnt;   /* max outstanding recv reqs.       */
    iattr.cap.max_send_sge = MAX_SGE;   /* see ibcomm.h                     */
    iattr.cap.max_recv_sge = MAX_SGE;
    /* ctrl messages are small, so they might be sent inline... */
    iattr.cap.max_inline_data = MAX_MSG_LEN;
    
    iattr.qp_type    = IBV_QPT_RC;      /* we want an RC queue pair         */
    iattr.sq_sig_all = 0;               /* no default CQE for send ops      */
    /* Tumbleweed's IB headers do not contain a member "xrc_domain", even   *
     * stated differently in the documentation...                           */
    /* iattr.xrc_domain = NULL; */      /* we do not use extended RCs       */

    if ((ibctx->qp = ibv_create_qp(ibctx->pdom, &iattr)) == NULL) {
        logmsg(ERROR, "Queue pair creation failed.");
        goto err_qp;
    }

    /* save the number of messages that the message buffer can hold at once *
     * (each of them is MAX_MSG_LEN in size)                                */
    ibctx->msg_cnt = msg_cnt;

    /* we have done the basic (!) setup of an IB connection... */
    return(0);

err_qp:
    ibv_destroy_cq(ibctx->cq);
err_cq:
    ibv_dereg_mr(ibctx->msg_mr);
    ibv_dereg_mr(ibctx->rdma_mr);
err_mr:
    ibv_destroy_comp_channel(ibctx->cchannel);
    ibv_dealloc_pd(ibctx->pdom);
err_pd:
    ibv_close_device(ibctx->dev_ctx);
err_mem:
    free(*msgbuf);
    free(*rdmabuf);

    return(1); 
}

/* Completes the connection to a server queue pair                          */
int complete_clt_qp(struct ib_ctx *ibctx, unsigned char *msg_buf) {
    struct ibv_qp_attr attr;            /* queue pair attributes to modify  */

    /* RESET to INIT */
    memset(&attr, 0, sizeof(struct ibv_qp_attr));
    attr.qp_state   = IBV_QPS_INIT;
    attr.pkey_index = CRDSS_PKEY_IDX;           /* hard-wired to 0 for now  */
    attr.port_num   = ibctx->port_num;
    /* only permit RDMA writes */
    attr.qp_access_flags = IBV_ACCESS_REMOTE_WRITE;

    if (ibv_modify_qp(ibctx->qp, &attr, IBV_QP_STATE | IBV_QP_PKEY_INDEX |
            IBV_QP_PORT | IBV_QP_ACCESS_FLAGS) != 0) {
        logmsg(ERROR, "Transition of QP from RESET to INIT failed.");
        return(1);
    }

    /* INIT to RTR */
    /* second hald of message buffer is reserved for receive requests, need *
     * to post some before switching to RTR state                           */
    if (post_msg_rr(ibctx, msg_buf, ibctx->msg_cnt)){
        logmsg(ERROR, "Unable to register initial receive requests...");
        return(1);
    }

    memset(&attr, 0, sizeof(struct ibv_qp_attr));
    attr.qp_state = IBV_QPS_RTR;
    /* fill in only the basic fields of the address handle */
    attr.ah_attr.dlid      = ibctx->rem_lid;    /* destination LID          */
    attr.ah_attr.is_global = 0;                 /* only LID-based addressing*/
    attr.ah_attr.port_num  = ibctx->port_num;

    attr.path_mtu           = IBV_MTU_4096;
    attr.dest_qp_num        = ibctx->remote_qpn;
    attr.rq_psn             = STARTING_PSN;
    attr.max_dest_rd_atomic = 0;                    /* no atomic / RDMA read*/ 
    attr.min_rnr_timer      = 12;                   /* 0.64 ms, recommended *
                                                     * by the manual        */

    if (ibv_modify_qp(ibctx->qp, &attr, IBV_QP_STATE | IBV_QP_PATH_MTU |
            IBV_QP_AV | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | 
            IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER) != 0) {
        logmsg(ERROR, "Transition of QP from INIT to RTR failed.");
        return(1);
    }

    /* RTR to RTS (values as recommended by the manual) */
    memset(&attr, 0, sizeof(struct ibv_qp_attr));
    attr.qp_state      = IBV_QPS_RTS;
    attr.timeout       = 14;
    attr.retry_cnt     = 7;
    attr.rnr_retry     = 7;
    attr.sq_psn        = STARTING_PSN;
    attr.max_rd_atomic = 0;             /* we don't use atomics/ RDMA read  */

    if (ibv_modify_qp(ibctx->qp, &attr, IBV_QP_STATE | IBV_QP_TIMEOUT |
            IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN |
            IBV_QP_MAX_QP_RD_ATOMIC) != 0) {
        logmsg(ERROR, "Transition of QP from RTR to RTS failed.");
        return(1);
    }

    /* lastly, arm the completion channel */
    if (ibv_req_notify_cq(ibctx->cq, 0) != 0) {
        logmsg(ERROR, "Failed to arm completion notification.");
        return(1);
    }

    return(0);
}

/* Sets up a InfiniBand queue pair on the server side.                      */
int setup_srv_qp(struct ib_ctx *ibctx, uint64_t guid, unsigned char **msgbuf,            
                 uint32_t msg_cnt, unsigned char **databuf, uint32_t rdmasz) {
    
    /* check size of requested memory window for data transfer */
    if (rdmasz > MAX_SRV_BUF_SZ) {
        logmsg(ERROR, "Size of requested RDMA region (%u) exceeds limit (%u).",
               rdmasz, MAX_SRV_BUF_SZ);
        return(1);
    }

    if (msg_cnt > MAX_SRV_MSG_QD) {
        logmsg(ERROR, "SEND/RECV queue depth (%u) exceeds limit (%u).",
              msg_cnt, MAX_SRV_MSG_QD);
        return(1);
    }

    /* fortunately, we can recycle the functions used for client setup...   */
    if (init_clt_qp(ibctx, guid, msgbuf, msg_cnt, databuf, rdmasz) != 0) {
        logmsg(ERROR, "Queue pair initialization failed.");
        return(1);
    }

    if (complete_clt_qp(ibctx, *msgbuf) != 0) {
        logmsg(ERROR, "Queue pair transition failed.");
        return(1);
    }

    return(0);
}

/* Posts a receive request with the size of MAX_MSG_LEN.                    */
int post_msg_rr(struct ib_ctx *ibctx, unsigned char *msg_addr, 
        unsigned int cnt) {
    
    unsigned int i;
    int ret;
    struct ibv_recv_wr *rwrs;               /* receive work request list    */
    struct ibv_sge *sges;                   /* scatter/gather entries for wr*/
    struct ibv_recv_wr *bad;

    /* check if there is something to do */
    if (cnt < 1)
        return(0);

    if ((sges = malloc(sizeof(struct ibv_sge) * cnt)) == NULL) {
        logmsg(ERROR, "Memory allocation error during posting of RRs.");
        return(1);
    }
    
    if ((rwrs = malloc(sizeof(struct ibv_recv_wr) * cnt)) == NULL) {
        logmsg(ERROR, "Memory allocation error during posting of RRs.");
        free(sges);
        return(1);
    }

    /* fill the receive request array */
    for (i = 0; i < cnt; i++) {
        sges[i].addr   = (uint64_t) (msg_addr + i * MAX_MSG_LEN);
        sges[i].length = MAX_MSG_LEN;
        sges[i].lkey   = ibctx->msg_mr->lkey;

        /* WR ID is a pointer to the memory buffer */
        rwrs[i].wr_id   = (uint64_t) (msg_addr + i * MAX_MSG_LEN);
        rwrs[i].sg_list = &sges[i];
        rwrs[i].num_sge = 1;

        if (i == (cnt - 1))
            rwrs[i].next = NULL;
        else
            rwrs[i].next = &rwrs[i + 1];
    }

    ret = ibv_post_recv(ibctx->qp, rwrs, &bad);
    if (ret != 0) {
        logmsg(ERROR, "Failed to post receive requests (%d).", ret);
        free(sges);
        free(rwrs);
        return(1);
    }

    logmsg(DEBUG, "Posted %d RRs.", cnt);
    free(rwrs);
    free(sges);

    return(0);
}

/* Posts a send request containing a crdss command with size MAX_MSG_LEN.   */
int post_msg_sr(struct ib_ctx *ibctx, unsigned char *msg_addr, uint32_t imm) {
    int ret;
    struct ibv_send_wr swr;                 /* send work request            */
    struct ibv_sge sge;                     /* scatter/gather entry for wr  */
    struct ibv_send_wr *bad;

    memset(&swr, 0, sizeof(struct ibv_send_wr));
    memset(&sge, 0, sizeof(struct ibv_sge));

    sge.addr   = (uint64_t) msg_addr;
    sge.length = MAX_MSG_LEN;
    sge.lkey   = ibctx->msg_mr->lkey;

    swr.wr_id      = (uint64_t) msg_addr;   /* address of buf hidden in id  */
    swr.next       = NULL;                  /* only send one msg at a time  */
    swr.sg_list    = &sge;
    swr.num_sge    = 1;
    swr.opcode     = IBV_WR_SEND_WITH_IMM;
    swr.imm_data   = htonl(imm);
    /* since crdss commands are rather small (<64B) we use inline sending   *
     * which provides better latency and simplifies send buffer handling    *
     * since message buffers can be reused immediately after post_recv ret. */
    swr.send_flags = IBV_SEND_INLINE | IBV_SEND_SIGNALED;

    ret = ibv_post_send(ibctx->qp, &swr, &bad);
    if (ret != 0) {
        logmsg(ERROR, "Failed to post send request (%d).", ret);
        return(1);
    }

    return(0);
}

/* Initiates an RDMA transfer to the remote side of ibctx                   */
int init_rdma_transfer(struct ib_ctx *ibctx, unsigned char *loc_addr,
                       unsigned char *rem_addr, size_t length, int use_imm,
                       uint32_t imm, int signaled) {
    
    int ret;
    struct ibv_send_wr swr;                 /* send work request            */
    struct ibv_sge sge;                     /* scatter/gather entry for wr  */
    struct ibv_send_wr *bad;

    memset(&swr, 0, sizeof(struct ibv_send_wr));
    memset(&sge, 0, sizeof(struct ibv_sge));

    sge.addr   = (uint64_t) loc_addr;
    sge.length = length;
    sge.lkey   = ibctx->rdma_mr->lkey;

    /* ID is offset in RDMA buffer or immediate value on signaled send      */
    swr.wr_id      = (signaled == 0)
                   ? (uint64_t) rem_addr - ibctx->remote_addr
                   : imm;
    swr.next       = NULL;                  /* only send one msg at a time  */
    swr.sg_list    = &sge;
    swr.num_sge    = 1;
    swr.opcode     = (use_imm == 0) 
                   ? IBV_WR_RDMA_WRITE 
                   : IBV_WR_RDMA_WRITE_WITH_IMM;
    swr.send_flags = (signaled == 0) ? 0 : IBV_SEND_SIGNALED;

    swr.wr.rdma.remote_addr = (uint64_t) rem_addr;
    swr.wr.rdma.rkey        = ibctx->remote_rkey;

    /* set the immediate value (generates CQE on remote side)               */
    if (use_imm != 0) {
        /* address window is limited to 4 GiB via this constraint           */
        swr.imm_data = htonl(imm);
    }

    ret = ibv_post_send(ibctx->qp, &swr, &bad);
    if (ret != 0) {
        logmsg(ERROR, "Failed to post send request (%d).", ret);
        return(1);
    }

    return(0);
}

/* Writes a operation status into a remote polling field.                   */
int write_poll_field(struct ib_ctx *ibctx, uint64_t loc_addr, uint64_t rem_addr) 
{    
    int ret;
    struct ibv_send_wr swr;                 /* send work request            */
    struct ibv_sge sge;                     /* scatter/gather entry for wr  */
    struct ibv_send_wr *bad;

    memset(&swr, 0, sizeof(struct ibv_send_wr));
    memset(&sge, 0, sizeof(struct ibv_sge));

    sge.addr   = (uint64_t) loc_addr;
    sge.length = 1;
    sge.lkey   = ibctx->rdma_mr->lkey;

    /* ID is offset in RDMA buffer */
    swr.wr_id      = loc_addr;
    swr.next       = NULL;                  /* only send one msg at a time  */
    swr.sg_list    = &sge;
    swr.num_sge    = 1;
    swr.opcode     = IBV_WR_RDMA_WRITE;
    swr.send_flags = IBV_SEND_INLINE;

    swr.wr.rdma.remote_addr = (uint64_t) rem_addr;
    swr.wr.rdma.rkey        = ibctx->remote_rkey;

    ret = ibv_post_send(ibctx->qp, &swr, &bad);
    if (ret != 0) {
        logmsg(ERROR, "Failed to post send request (%d).", ret);
        return(1);
    }

    return(0);
}

/* Closes an InfiniBand connection and destroys all resources hold by it    */
int destroy_ibctx(struct ib_ctx *ibctx) {
    struct ibv_qp_attr attr;                /* for cleanly disabling QP     */

    if (ibctx == NULL)
        return(0);

    memset(&attr, 0, sizeof(struct ibv_qp_attr));
    attr.qp_state = IBV_QPS_RESET;

    if (ibctx->qp != NULL && ibv_modify_qp(ibctx->qp, &attr, IBV_QP_STATE) != 0) 
    {
        logmsg(ERROR, "Failed to reset QP.");
        return(1);
    }

    if (ibctx->qp != NULL && ibv_destroy_qp(ibctx->qp) != 0) {
        logmsg(ERROR, "Failed to destrox QP.");
        return(1);
    }

    if (ibctx->cq != NULL && ibv_destroy_cq(ibctx->cq) != 0) {
        logmsg(ERROR, "Failed to delete completion queue.");
        return(1);
    }

    if (ibctx->cchannel != NULL && 
        ibv_destroy_comp_channel(ibctx->cchannel) != 0) {
        logmsg(ERROR, "Failed to delete completion channel.");
        return(1);
    }

    if ((ibctx->rdma_mr != NULL && ibv_dereg_mr(ibctx->rdma_mr) != 0) || 
        (ibctx->msg_mr != NULL && ibv_dereg_mr(ibctx->msg_mr) != 0)) {
        logmsg(ERROR, "Failed to unregister memory regions.");
        return(1);
    }

    if (ibctx->pdom != NULL)    ibv_dealloc_pd(ibctx->pdom);
    if (ibctx->dev_ctx != NULL) ibv_close_device(ibctx->dev_ctx);

    return(0);
}

/* Reads the next control message from an InfiniBand queue pair.            */
int get_next_ibmsg(struct ib_ctx *ibctx, unsigned char **msg, uint32_t *imm) {
    int poll_res = 0;                       /* result of IB poll operation  */

    struct ibv_cq *cq;
    void *compl_ctx;                        /* completion context (set to   *
                                             * NULL during init)            */
    struct ibv_wc cqe;                      /* completion entry             */

    while (poll_res == 0) {
        if (ibv_get_cq_event(ibctx->cchannel, &cq, &compl_ctx) == -1) {
            logmsg(ERROR, "Failed to get next completion event notification.");
            return(-1);
        }
    
        /* this should be always false, but check for completeness          */
        if (cq != ibctx->cq) {
            logmsg(ERROR, "CChannel delivered event from wrong CQ.");
            return(-1);
        }

        /* acknowledge the event read */
        ibv_ack_cq_events(ibctx->cq, 1);
    
        if (ibv_req_notify_cq(ibctx->cq, 0) == -1) {
            logmsg(ERROR, "Failed to rearm notification mechanism of CQ.");
            return(-1);
        }

        /* get the actual event from the CQ */
        poll_res = ibv_poll_cq(ibctx->cq, 1, &cqe);
        if (poll_res < 0) {
            logmsg(ERROR, "Could not read completion event from CQ.");
            return(-1);
        }

        /* suppress successful send operations */
        if (cqe.opcode == IBV_WC_SEND && cqe.status == IBV_WC_SUCCESS) {
            logmsg(DEBUG, "Skipping send request.");
            poll_res = 0;
        }
    }

    logmsg(DEBUG, "CQE opcode is: %u.", cqe.opcode);
    logmsg(DEBUG, "CQE status is: %u.", cqe.status);
    if (cqe.status != IBV_WC_SUCCESS) {
        logmsg(WARN, "CQE provided error code %u.", cqe.status);
        return((int) cqe.status);
    }

    *msg = (unsigned char *) cqe.wr_id;     /* cast ID back to buffer ptr   */
    if (cqe.opcode == IBV_WC_RDMA_WRITE) {
        /* set buffer to NULL, but fill immediate value with wr ID */
        *msg = NULL;
        *imm = (uint32_t) cqe.wr_id;
        return(0);
    }

    /* if an immediate value was sent, hand it to the receiver */
    if (cqe.wc_flags & IBV_WC_WITH_IMM) {
        *imm = ntohl(cqe.imm_data);
    }

    return(0);
}

/* Reads the next control message from an InfiniBand queue pair (polling).  */
int poll_next_ibmsg(struct ib_ctx *ibctx, unsigned char **msg, uint32_t *imm) {
    unsigned int i = 0;
    struct timespec tspec;                  /* for cancellation purposes    */

    int poll_res = 0;                       /* result of IB poll function   */

    struct ibv_wc cqe;                      /* completion entry             */

    tspec.tv_sec  = 0;                      /* short sleep for cancel check */
    tspec.tv_nsec = 500;

    /* get the actual event from the CQ */
    while (poll_res == 0) {
        poll_res = ibv_poll_cq(ibctx->cq, 1, &cqe);

        if (poll_res < 0) {
            logmsg(ERROR, "Could not read completion event from CQ.");
            return(-1);
        }

        /* suppress successful send operations */
        if (cqe.opcode == IBV_WC_SEND && cqe.status == IBV_WC_SUCCESS) {
            logmsg(DEBUG, "Skpping send request.");
            poll_res = 0;
        }

        /* occasionally visit a cancellation point to make sure that the    *
         * thread is not stuck in the polling routine while the surrounding *
         * context is shut down                                             */
        i++;
        if ((i % 1000) == 0) {
            nanosleep(&tspec, NULL);
        }
    }

    logmsg(DEBUG, "CQE opcode is: %u.", cqe.opcode);
    logmsg(DEBUG, "CQE status is: %u.", cqe.status);
    if (cqe.status != IBV_WC_SUCCESS) {
        logmsg(WARN, "CQE provided error code %u.", cqe.status);
        return((int) cqe.status);
    }

    *msg = (unsigned char *) cqe.wr_id;     /* cast ID back to buffer ptr   */
    if (cqe.opcode == IBV_WC_RDMA_WRITE) {
        /* set buffer to NULL, but fill immediate value with wr ID */
        *msg = NULL;
        *imm = (uint32_t) cqe.wr_id;
        return(0);
    }

    /* if an immediate value was sent, hand it to the receiver */
    if (cqe.wc_flags & IBV_WC_WITH_IMM) {
        *imm = ntohl(cqe.imm_data);
    }

    return(0);
}

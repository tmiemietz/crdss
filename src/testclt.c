/****************************************************************************
 *                                                                          *
 *  testclt.c - A sample client application for testing the CRDSS system.   *
 *                                                                          *
 *                    Copyright (c) 2020 Till Miemietz                      *
 *                                                                          *
 ****************************************************************************/



/****************************************************************************
 *                                                                          *
 *                     global definitions and macros                        *
 *                                                                          *
 ****************************************************************************/


#define CAPMGR_DOMSOCK "/tmp/crdss-capmgr.sock"
#define CLT_GUID "0xf45214030010a4e1"
#define DEFAULT_SRV "10.10.10.1"
#define BUFFER_SIZE 8388608

/****************************************************************************
 *                                                                          *
 *                           include statements                             *
 *                                                                          *
 ****************************************************************************/


#include <stdio.h>                      /* std. I/O facilities              */
#include <arpa/inet.h>                  /* strings to IP addresses and back */
#include <errno.h>                      /* standard error numbers           */

#include "include/libcrdss.h"           /* access to CRDSS service          */

/*** FOR TESTING ONLY; TODO: REMOVE ***/
#include "include/utils.h"

/****************************************************************************
 *                                                                          *
 *                           global variables                               *
 *                                                                          *
 ****************************************************************************/



/****************************************************************************
 *                                                                          *
 *                          static helper functions                         *
 *                                                                          *
 ****************************************************************************/



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
    unsigned int i;

    struct ibv_wc cqe[5];
    struct crdss_clt_cap cap;
    struct crdss_srv_ctx *sctx;

    unsigned char *iobuf;
    size_t buf_len = 4096;

    uint64_t guid = (uint64_t) strtoull(CLT_GUID, NULL, 0);

    (void) argc;
    (void) argv;

    init_logger(NULL, DEBUG);

    printf("I am a testing application!\n");
    printf("IB guid is %#lx\n", guid);

    if ((iobuf = malloc(buf_len)) == NULL) {
        printf("Failed to allocate I/O buffer...\n");
        return(1);
    }
    memset(iobuf, 0, buf_len);

    printf("Connecting to capmgr %s...\n", CAPMGR_DOMSOCK);
    if (connect_capmgr_dom(CAPMGR_DOMSOCK) != 0) {
        printf("Failed to connect to capmgr.\n");
        return(1);
    }
    printf("Done.\n");

    /* prepare cap for request */
    memset(&cap, 0, sizeof(struct crdss_clt_cap));
    cap.srv.sin_family = AF_INET;
    inet_pton(AF_INET, DEFAULT_SRV, &cap.srv.sin_addr);
    cap.dev_idx    = 0;
    cap.vslc_idx   = 0;
    cap.start_addr = 0;
    cap.end_addr   = 4096;
    cap.rights     = CAP_READ | CAP_WRITE;
    cap.key        = NULL;

    printf("Allocating server context...\n");
    if ((sctx = create_srv_ctx(NULL)) == NULL) {
        printf("Failed to allocate new server context.\n");
        return(1);
    }
    printf("Done.\n");


    printf("Requesting capability...\n");
    if (request_new_cap(&cap) != 0) {
        printf("Capability request failed.\n");
        return(1);
    }
    printf("Done.\n");

    /* set server's IP address before proceeding */
    sctx->guid                = guid;
    sctx->srv_addr.sin_family = AF_INET;
    sctx->srv_addr.sin_port   = cap.srv.sin_port;
    inet_pton(AF_INET, DEFAULT_SRV, &sctx->srv_addr.sin_addr);    

    printf("Connecting to storage server (port %u)...\n", 
           ntohs(sctx->srv_addr.sin_port));
    if (connect_storage_srv(sctx) != 0) {
        printf("Unable to connect to storage server.\n");
        return(1);
    }
    printf("Done.\n");

    printf("Registering cap...\n");         /* use TCP */
    if (reg_cap(sctx, cap.id) != 0) {
        printf("Failed to register cap.\n");
        close_srv_conn(sctx);
        return(1);
    }
    printf("Done.\n");
    
    printf("Switching to InfiniBand communication...\n");
    if (init_ib_comm(sctx) != 0) {
        printf("IB setup failed.\n");
        return(1);
    }
    printf("Done.\n");

    printf("Server responded. RDMA region address on server is %#lx, rkey is "
           "%#x.\n", sctx->ibctx.remote_addr, sctx->ibctx.remote_rkey);

    printf("local RDMA base addr is %lu.\n", (uint64_t) sctx->rdma_buf);
    printf("remote RDMA base addr is %lu.\n", 
           (uint64_t) sctx->ibctx.remote_addr);
    printf("Trying read (didx = %u, sidx = %u, saddr = %lu, eaddr = %lu).\n",
           cap.dev_idx, cap.vslc_idx, cap.start_addr, buf_len - 1);

    if (read_raw(sctx, cap.dev_idx, cap.vslc_idx, 0, iobuf, buf_len) != 0) 
    {
        printf("Failed to read from remote device...\n");
        return(1);
    }
    printf("Buffer content after initial read: \"%s\"\n", iobuf);

    printf("Rewriting buffer...\n");
    memset(iobuf, 0, buf_len);
    memcpy(iobuf, "Yeet and greet O_o", strlen("Yeet and greet O_o"));
        
    if (write_raw(sctx, cap.dev_idx, cap.vslc_idx, 0, iobuf, buf_len) 
        != 0) {
        printf("Failed to write to remote device...\n");
        return(1);
    }
    printf("Done.\n");

    printf("Re-reading buffer contents (fast path).\n");
    if (query_srv_poll(sctx) != 0) {
        printf("Failed to switch server to polling mode.\n");
        return(1);
    }
    printf("Switched server to polling mode.\n");

    if (fast_read_raw(sctx, cap.dev_idx, cap.vslc_idx, 0, iobuf, buf_len) != 0){
        printf("Failed to re-read buffer (fast path)...\n");
        return(1);
    }
    printf("Buffer content after second reading: %s\n", iobuf);

    printf("Rewriting buffer a second time (fast path)...\n");
    memset(iobuf, 0, buf_len);
    memcpy(iobuf, "Sample Data 123...", strlen("Sample Data 123..."));
        
    if (fast_write_raw(sctx, cap.dev_idx, cap.vslc_idx, 0, iobuf, buf_len) 
        != 0) {
        printf("Failed to write to remote device...\n");
        return(1);
    }
    printf("Done.\n");

    printf("Executing read /write loop 100000 times.\n");
    for (i = 0; i < 100000; i++) {
        if (fast_read_raw(sctx, cap.dev_idx, cap.vslc_idx, 0, iobuf, buf_len) 
            != 0) {
            printf("Failed to re-read buffer (fast path)...\n");
            return(1);
        }

        memset(iobuf, 0, buf_len);
        memcpy(iobuf, "Sample Data 123...", strlen("Sample Data 123"));
        
        if (fast_write_raw(sctx, cap.dev_idx, cap.vslc_idx, 0, iobuf, buf_len) 
            != 0) {
            printf("Failed to write to remote device...\n");
            return(1);
        }

        printf("r/w cycle %u (%u).\n", i, ibv_poll_cq(sctx->ibctx.cq, 5, cqe));
    }
    printf("Done.\n");

    printf("Closing connection to server...\n");
    if (close_srv_conn(sctx) != 0) {
        printf("Error while closing server connection.\n");
        return(1);
    }
    printf("Done.\n");

    printf("Tests finished successfully.\n");


    return(0);
}

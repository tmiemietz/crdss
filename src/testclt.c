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
    struct crdss_clt_cap cap;
    struct ib_ctx ibctx;
    struct crdss_srv_ctx *sctx;

    unsigned char *msg_buf = NULL;
    unsigned char *rdma_buf = NULL;
    int srv_fd = -1;

    uint64_t guid = (uint64_t) strtoull(CLT_GUID, NULL, 0);

    (void) argc;
    (void) argv;

    init_logger(NULL, DEBUG);

    printf("I am a testing application!\n");
    printf("IB guid is %#lx\n", guid);

    printf("Connecting to capmgr %s...\n", CAPMGR_DOMSOCK);
    if (connect_capmgr_dom(CAPMGR_DOMSOCK) != 0) {
        printf("Failed to connect to capmgr.\n");
        return(1);
    }
    printf("Done.\n");

    /* prepare cap for request */
    memset(&cap, 0, sizeof(struct crdss_clt_cap));
    memset(&ibctx, 0, sizeof(struct ib_ctx));
    cap.srv.sin_family = AF_INET;
    inet_pton(AF_INET, DEFAULT_SRV, &cap.srv.sin_addr);
    cap.dev_idx    = 0;
    cap.vslc_idx   = 0;
    cap.start_addr = 2;
    cap.end_addr   = 9;
    cap.rights     = CAP_READ | CAP_WRITE;
    cap.key        = NULL;

    printf("Allocating server context...\n");
    if ((sctx = create_srv_ctx(NULL)) == NULL) {
        printf("Failed to allocate new server context");
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
    sctx->srv_addr.sin_family = AF_INET;
    sctx->srv_addr.sin_port   = cap.srv.sin_port;
    inet_pton(AF_INET, DEFAULT_SRV, &sctx->srv_addr.sin_addr);    

    printf("Connecting to storage server (port %u)...\n", 
           ntohs(sctx->srv_addr.sin_port));
    if ((srv_fd = connect_storage_srv(sctx)) != 0) {
        printf("Unable to connect to storage server.\n");
        return(1);
    }
    printf("Done.\n");

    printf("Registering cap...\n");         /* use TCP */
    if (reg_cap(srv_fd, NULL, cap.id) != 0) {
        printf("Failed to register cap.\n");
        close_srv_conn(srv_fd, &ibctx);
        return(1);
    }
    printf("Done.\n");
    
    printf("Switching to InfiniBand communication...\n");
    if (init_ib_comm(srv_fd, &ibctx, guid, &msg_buf, &rdma_buf, 
        BUFFER_SIZE) != 0) {
        printf("IB setup failed.\n");
        return(1);
    }
    printf("Done.\n");

    printf("Server responded. RDMA region address on server is %#lx, rkey is "
           "%#x.\n", ibctx.remote_addr, ibctx.remote_rkey);

    printf("Closing connection to server...\n");
    if (close_srv_conn(srv_fd, &ibctx) != 0) {
        printf("Error while closing server connection.\n");
        return(1);
    }
    printf("Done.\n");

    printf("Tests finished successfully.\n");


    return(0);
}

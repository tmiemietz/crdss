/****************************************************************************
 *                                                                          *
 * gap_read_cap.c - Read chunks from a file, leave a read gap, repeat and   *
 * create and revoke capabilities in a seperate thread to stress the server.*
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

#define CHUNKSIZE 4096
#define GAPSIZE 131072
#define MAX_CHUNKS_READ 200000

/****************************************************************************
 *                                                                          *
 *                           include statements                             *
 *                                                                          *
 ****************************************************************************/


#include <stdio.h>                      /* std. I/O facilities              */
#include <arpa/inet.h>                  /* strings to IP addresses and back */
#include <errno.h>                      /* standard error numbers           */
#include <pthread.h>                    /* POSIX threads                    */
#include <unistd.h>                     /* for usleep implementation        */

#include "include/libcrdss.h"           /* access to CRDSS service          */

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


struct crdss_clt_cap cap1;
struct crdss_clt_cap cap2;
struct crdss_srv_ctx *sctx;

unsigned char *iobuf;

int cap_flag;

pthread_t cap_thread;

/****************************************************************************
 *                                                                          *
 *                          function implementation                         *
 *                                                                          *
 ****************************************************************************/


void *cap_worker(void *ptr) {
    struct ibv_wc cqe[5];
    
    (void) ptr;

    fprintf(stderr, "here is the cap worker.\n");

    while (1) {
        if (reg_cap(sctx, cap2.id) != 0) {
            fprintf(stderr, "cap_worker: Failed to register cap.\n");
        }
   
        fprintf(stderr, "reged cap.\n");
        usleep(10);

        if (delete_rdom(sctx, cap2.rev_dom) != 0) {
            fprintf(stderr, "cap_worker: Failed to delete cap.\n");
        }
        fprintf(stderr, "deleted cap.\n");

        if (request_new_cap(&cap2) != 0) {
            fprintf(stderr, "cap_worker: Failed to recreate cap.\n");
        }

        ibv_poll_cq(sctx->ibctx.cq, 5, cqe);
        fprintf(stderr, "Completed one loop.\n");
    }
}

/****************************************************************************
 ****************************************************************************
 ************************           M A I N           ***********************
 ****************************************************************************
 ****************************************************************************/
int main(int argc, char **argv) {
    unsigned int i;
    struct ibv_wc cqe[5];

    struct timespec start;
    struct timespec end;

    unsigned int max_read_cycles = 0;
    size_t file_size      = 0;
    off_t  file_offset    = 0;

    unsigned long nano_diff = 0;
    double sec_diff = 0;

    uint64_t guid = (uint64_t) strtoull(CLT_GUID, NULL, 0);

    memset(&start, 0, sizeof(struct timespec));
    memset(&end, 0, sizeof(struct timespec));

    if (argc < 2) {
        fprintf(stderr, "First arg: 1 with caps, 0 without cap ops.\n");
        return(1);    
    }
    cap_flag = atoi(argv[1]);

    if ((iobuf = malloc(CHUNKSIZE)) == NULL) {
        printf("Failed to allocate I/O buffer...\n");
        return(1);
    }

    printf("Connecting to capmgr %s...\n", CAPMGR_DOMSOCK);
    if (connect_capmgr_dom(CAPMGR_DOMSOCK) != 0) {
        printf("Failed to connect to capmgr.\n");
        return(1);
    }
    printf("Done.\n");

    /* prepare cap for request */
    memset(&cap1, 0, sizeof(struct crdss_clt_cap));
    cap1.srv.sin_family = AF_INET;
    inet_pton(AF_INET, DEFAULT_SRV, &cap1.srv.sin_addr);
    cap1.dev_idx    = 0;
    cap1.vslc_idx   = 0;
    cap1.start_addr = 0;
    cap1.end_addr   = 0;
    cap1.rights     = CAP_READ | CAP_WRITE;
    cap1.key        = NULL;

    memset(&cap2, 0, sizeof(struct crdss_clt_cap));
    cap2.srv.sin_family = AF_INET;
    inet_pton(AF_INET, DEFAULT_SRV, &cap2.srv.sin_addr);
    cap2.dev_idx    = 0;
    cap2.vslc_idx   = 0;
    cap2.start_addr = 0;
    cap2.end_addr   = 1;
    cap2.rights     = CAP_READ | CAP_WRITE;
    cap2.key        = NULL;
   
    if (get_vslice_size(&cap1, &cap1.end_addr) != 0) {
        fprintf(stderr, "Failed to get vslice size.\n");
        return(1);
    }
    file_size = cap1.end_addr;
    cap1.end_addr--;
    fprintf(stderr, "Size of slice is %lu.\n", file_size);

    printf("Allocating server context...\n");
    if ((sctx = create_srv_ctx(NULL)) == NULL) {
        printf("Failed to allocate new server context.\n");
        return(1);
    }
    printf("Done.\n");

    printf("Requesting capability...\n");
    if (request_new_cap(&cap1) != 0 || request_new_cap(&cap2) != 0) {
        printf("Capability request failed.\n");
        return(1);
    }
    printf("Done.\n");

    /* set server's IP address before proceeding */
    sctx->guid                = guid;
    sctx->srv_addr.sin_family = AF_INET;
    sctx->srv_addr.sin_port   = cap1.srv.sin_port;
    inet_pton(AF_INET, DEFAULT_SRV, &sctx->srv_addr.sin_addr);    

    printf("Connecting to storage server (port %u)...\n", 
           ntohs(sctx->srv_addr.sin_port));
    if (connect_storage_srv(sctx) != 0) {
        printf("Unable to connect to storage server.\n");
        return(1);
    }
    printf("Done.\n");

    printf("Registering cap...\n");         /* use TCP */
    if (reg_cap(sctx, cap1.id) != 0) {
        printf("Failed to register cap.\n");
        close_srv_conn(sctx);
        return(1);
    }
    printf("Done.\n");
    
    printf("Switching to InfiniBand communication...\n");
    if (init_ib_comm(sctx) != 0) {
        fprintf(stderr, "IB setup failed.\n");
        return(1);
    }
    printf("Done.\n");

    printf("Server responded. RDMA region address on server is %#lx, rkey is "
           "%#x.\n", sctx->ibctx.remote_addr, sctx->ibctx.remote_rkey);

    if (query_srv_poll(sctx) != 0) {
        fprintf(stderr, "Failed to switch server to polling mode.\n");
        return(1);
    }
    printf("Switched server to polling mode.\n");

    max_read_cycles = file_size / (CHUNKSIZE + GAPSIZE);
    if (max_read_cycles > MAX_CHUNKS_READ)
        max_read_cycles = MAX_CHUNKS_READ;

    if (cap_flag != 0) {
        fprintf(stderr, "Starting cap worker.\n");
        if (pthread_create(&cap_thread, NULL, cap_worker, NULL) != 0) {
            fprintf(stderr, "Failed to create cap worker.\n");
            exit(1);
        }
    }

    fprintf(stderr, "Going to read %u chunks.\n", max_read_cycles);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (i = 0; i < max_read_cycles; i++) {
        if (fast_read_raw(sctx, cap1.dev_idx, cap1.vslc_idx, file_offset, 
            iobuf, CHUNKSIZE) != 0) {
            fprintf(stderr, "Failed to read data from disk...\n");
            return(1);
        }

        ibv_poll_cq(sctx->ibctx.cq, 5, cqe);
        file_offset += GAPSIZE;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    nano_diff = (end.tv_sec * 1000000000 + end.tv_nsec) -
                (start.tv_sec * 1000000000 + start.tv_nsec);
    sec_diff  = (double) nano_diff / 1000000000;

    fprintf(stderr, "\n\nRead %u chunks with a size of %u B (total %u B).\n",
            max_read_cycles, CHUNKSIZE, CHUNKSIZE * max_read_cycles);
    fprintf(stderr, "Total time spent: %f s (%f s per chunk).\n", sec_diff,
            sec_diff / max_read_cycles);

    if (close_srv_conn(sctx) != 0) {
        printf("Error while closing server connection.\n");
        return(1);
    }

    return(0);
}

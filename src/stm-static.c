/****************************************************************************
 *                                                                          *
 *      stm-static.c - A storage manager that uses static partitions.       *
 *                                                                          *
 *                    Copyright (c) 2019 Till Miemietz                      *
 *                                                                          *
 ****************************************************************************/


/****************************************************************************
 *                                                                          *
 *                     global definitions and macros                        *
 *                                                                          *
 ****************************************************************************/


/* maximum size of a vslice table for the static storage manager            */
#define SSTM_VSLC_TBL_SZ 4096

/* offset for vslice allocation bytemap on disk                             */
#define BM_OFFS (2 * sizeof(uint32_t) + 2 * sizeof(uint64_t))

/****************************************************************************
 *                                                                          *
 *                           include statements                             *
 *                                                                          *
 ****************************************************************************/


#include <stdlib.h>                      /* memory allocation etc.          */
#include <stdint.h>                      /* fixed-width integers            */
#include <string.h>                      /* for memcpy                      */
#include <errno.h>                       /* error numbers                   */
#include <unistd.h>                      /* UNIX standard calls             */
#include <sys/ioctl.h>
#include <linux/fs.h>                    /* get bdev size on linux          */

#include "include/stm-common.h"          /* common stm routines             */
#include "include/stm-static.h"          /* definition of the static stm    */
#include "include/utils.h"               /* logging, ...                    */
#include "include/slist.h"               /* single-linked lists             */

/****************************************************************************
 *                                                                          *
 *                          function implementation                         *
 *                                                                          *
 ****************************************************************************/


/***                  functions defined in stm-static.h                   ***/

/* Initializes an opened block device for use with the static stm           */
int sstm_init(struct crdss_bdev *dev, unsigned int vslc_cnt) {
    struct stm_static_ctx *ctx;
    uint8_t               *slc_bm;

    /* buffer for writing vslice table (4096 B), use a buffer instead of    *
     * writing the fields separately in order to support direct I/O         */
    unsigned char table_buf[SSTM_VSLC_TBL_SZ] 
                    __attribute__ ((__aligned__(512)));

    /* buffer for stm type */
    uint32_t stm_type = STM_TYPE_STATIC;

    uint64_t slcsz;                         /* slice size in bytes          */
    uint64_t devsz;                         /* block device size in bytes   */

    if (vslc_cnt > STM_STATIC_MAX_VSLC) {
        logmsg(ERROR, "Requested slice count exceeds stm limits");
        return(-1);
    }

    if (ioctl(dev->fd, BLKGETSIZE64, &devsz) == -1) {
        logmsg(ERROR, "sstm_init: Failed to query size of block device");
        return(-1);
    }

    /* substract 4096 from raw drive size to fit in the vslice table        *
     * make sure to scale this value if STM_STATIC_MAX_VSLC is increased    */
    slcsz = (devsz - 4096) / vslc_cnt;
    logmsg(INFO, "sstm_init: new slice size is %lu B (%lu MiB)", 
           slcsz, slcsz / 1024 / 1024);

    if ((ctx = calloc(1, sizeof(struct stm_static_ctx))) == NULL) {
        logmsg(ERROR, "sstm_init: memory allocation for stm context failed");
        return(-1);
    }
    if ((slc_bm = calloc(vslc_cnt, sizeof(uint8_t))) == NULL) {
        logmsg(ERROR, "sstm_init: memory allocation for stm context failed");
        return(-1);
    }

    /* construct context structure */
    ctx->part_cnt    = vslc_cnt;
    ctx->part_size   = slcsz;
    ctx->vslc_offset = 4096;
    ctx->act_vslc    = slc_bm;

    pthread_mutex_lock(&dev->meta_lck);

    /* fill vslice table buffer */
    memcpy(table_buf, &stm_type, 4);
    memcpy(table_buf + 4, &ctx->part_cnt, 4);
    memcpy(table_buf + 8, &ctx->part_size, 8);
    memcpy(table_buf + 16, &ctx->vslc_offset, 8);
    memcpy(table_buf + 24, slc_bm, vslc_cnt * sizeof(uint8_t));

    /* update context structure and write slice table to disk */
    if (pwrite(dev->fd, table_buf, 4096, 0) < (ssize_t) 4096) {
        logmsg(ERROR, "sstm_init: Failed to write vslice table (%d).", errno);
        goto err; 
    }

    if (fsync(dev->fd) == -1) {
        logmsg(ERROR, "sstm_init: Failed to sync data");
        goto err;
    }

    /* everything is on disk, update in-memory representation */
    dev->stm_ctx = ctx;
    pthread_mutex_unlock(&dev->meta_lck);
    return(0);

err:
    pthread_mutex_unlock(&dev->meta_lck);
    free(slc_bm);
    free(ctx);
    return(-1);
}

/* Reads the vslice table of a static storage manager.                      */
int sstm_rd_vslctbl(struct crdss_bdev *dev) {
    struct stm_static_ctx *ctx;
    uint8_t               *vlsbm;               /* vslice bytemap           */

    /* buffer for writing vslice table (4096 B), use a buffer instead of    *
     * writing the fields separately in order to support direct I/O         */
    unsigned char table_buf[SSTM_VSLC_TBL_SZ] 
                    __attribute__ ((__aligned__(512)));
    
    if ((ctx = malloc(sizeof(struct stm_static_ctx))) == NULL) {
        logmsg(ERROR, "Failed to allocate memory for sstm context");
        return(-1);
    }

    if (pread(dev->fd, table_buf, 4096, 0) < (ssize_t) 4096) {
        logmsg(ERROR, "Failed to read sstm vslice table");
        free(ctx);
        return(-1);
    }

    memcpy(&ctx->part_cnt, table_buf + 4, 4);
    memcpy(&ctx->part_size, table_buf + 8,  8);
    memcpy(&ctx->vslc_offset, table_buf + 16,  8);

    vlsbm = malloc((size_t) ctx->part_cnt);
    if (vlsbm == NULL) {
        logmsg(ERROR, "Failed to allocate memory for sstm context bitmap");            
        free(ctx);
        return(-1);
    }
    memcpy(vlsbm, table_buf + 24, ctx->part_cnt * sizeof(uint8_t));
    
    ctx->act_vslc = vlsbm;
    pthread_mutex_lock(&dev->meta_lck);
    dev->stm_ctx = ctx;
    pthread_mutex_unlock(&dev->meta_lck);
    return(0);
}

/* Creates a new virtual slice.                                             */
int sstm_mkvslc(struct crdss_bdev *dev) {
    unsigned int i;

    int next_slc_idx = -1;              /* index of next free slice         */

    struct stm_static_ctx *ctx = (struct stm_static_ctx *) dev->stm_ctx;

    /* buffer for writing vslice table (4096 B), use a buffer instead of    *
     * writing the fields separately in order to support direct I/O         */
    unsigned char table_buf[SSTM_VSLC_TBL_SZ] 
                __attribute__ ((__aligned__(512)));
    
    pthread_mutex_lock(&dev->meta_lck);
    for (i = 0; i < ctx->part_cnt; i++) {
        if (ctx->act_vslc[i] == 0) {
            next_slc_idx = i;
            break;
        }
    }

    if (next_slc_idx == -1) {
        /* no free slice found, do not forget unlocking */
        logmsg(WARN, "mkvslc: No free slices available");
        pthread_mutex_unlock(&dev->meta_lck);
        return(-1);
    }

    /* read vslice table from disk                                          */
    if (pread(dev->fd, table_buf, SSTM_VSLC_TBL_SZ, 0) < SSTM_VSLC_TBL_SZ) {
        logmsg(ERROR, "mkvslc: Failed to read vslice table (%d).", errno);
        pthread_mutex_unlock(&dev->meta_lck);
        return(-1);
    }
    memset(table_buf + BM_OFFS + next_slc_idx * sizeof(uint8_t), 1, 1);

    /* if a slice is available, update metadata in memory and on disk       */
    if (pwrite(dev->fd, table_buf, SSTM_VSLC_TBL_SZ, 0) < SSTM_VSLC_TBL_SZ) {
        logmsg(ERROR, "mkvslc: Failed to write updated metadata to disk");
        pthread_mutex_unlock(&dev->meta_lck);
        return(-1);
    }

    /* immediately sync data to disk */
    if (fsync(dev->fd) == -1) {
        logmsg(ERROR, "mkvslc: Failed to sync metadata with disk");
        pthread_mutex_unlock(&dev->meta_lck);
        return(-1);
    }

    ctx->act_vslc[next_slc_idx] = 1;
    pthread_mutex_unlock(&dev->meta_lck);
    return(next_slc_idx);
}

/* Deletes the vslice with index idx on device dev.                         */
int sstm_rmvslc(struct crdss_bdev *dev, unsigned int idx) {
    uint8_t write_buf = 0;                  /* data to write on disk        */

    struct stm_static_ctx *ctx = (struct stm_static_ctx *) dev->stm_ctx;

    pthread_mutex_lock(&dev->meta_lck);
    if (idx > (ctx->part_cnt - 1) || ctx->act_vslc[idx] == 0) {        
        /* no free slice found, do not forget unlocking */
        logmsg(WARN, "rmvslc: Attempting to delete invalid slice");
        pthread_mutex_unlock(&dev->meta_lck);
        return(-1);
    }

    /* remove slice by setting its bitmap entry to inactive                 */
    if (pwrite(dev->fd, &write_buf, sizeof(uint8_t), 
        BM_OFFS + idx * sizeof(uint8_t)) < (ssize_t) sizeof(uint8_t)) {
        logmsg(ERROR, "rmvslc: Failed to write updated metadata to disk");
        pthread_mutex_unlock(&dev->meta_lck);
        return(-1);
    }

    /* immediately sync data to disk */
    if (fsync(dev->fd) == -1) {
        logmsg(ERROR, "rmvslc: Failed to sync metadata with disk");
        pthread_mutex_unlock(&dev->meta_lck);
        return(-1);
    }

    ctx->act_vslc[idx] = 0;
    pthread_mutex_unlock(&dev->meta_lck);
    return(0);
}

/* Enlarges the vslice with index idx by nr_blks bytes at offset offs.      */
int sstm_alloc(struct crdss_bdev *dev, unsigned int slc_idx, size_t offs,
               size_t nr_blks) {
    (void) dev;
    (void) slc_idx;
    (void) offs;
    (void) nr_blks;
    logmsg(WARN, "Vslice resizing not supported for static storage manager");
    return(-1);
}

/* Shrinks the vslice with index idx by nr_blks bytes at offset offs.       */
int sstm_release(struct crdss_bdev *dev, unsigned int slc_idx, size_t offs,
                 size_t nr_blks) {
    (void) dev;
    (void) slc_idx;
    (void) offs;
    (void) nr_blks;
    logmsg(WARN, "Vslice resizing not supported for static storage manager");   
    return(-1); 
}

/* Translates a vslice-relative block address into a LBA                    */
int sstm_translate(struct crdss_bdev *dev, unsigned int slc_idx, size_t vsa,
                   size_t *lba, size_t *nr_seq) {
    /* TODO: think again about locking in the translation process           */
    struct stm_static_ctx *ctx = (struct stm_static_ctx *) dev->stm_ctx;

    pthread_mutex_lock(&dev->meta_lck);
    
    /* check if slice-relative address is in bounds                         */
    if (slc_idx > (ctx->part_cnt - 1) || vsa > ctx->part_size) {
        
        logmsg(WARN, "sstm_translate: Tried to access out-of-bounds address");
        pthread_mutex_unlock(&dev->meta_lck);
        return(-1);
    }

    if (ctx->act_vslc[slc_idx] == 0) {
        logmsg(WARN, "sstm-translate: Tried to access inactive slice");
        pthread_mutex_unlock(&dev->meta_lck);
        return(-1);
    }

    *lba    = ctx->vslc_offset + slc_idx * ctx->part_size + vsa;
    *nr_seq = ctx->part_size - vsa;

    pthread_mutex_unlock(&dev->meta_lck);
    return(0);
}

/* Outputs information about existing slices and free disk space            */
struct vslc_info *sstm_info(struct crdss_bdev *dev) {
    unsigned int i;
    int idle_slc_cnt = 0;               /* no. of unused slices             */

    struct vslice    *slice    = NULL;
    struct slist     *slc_list = NULL;  /* list of active vslices           */
    struct vslc_info *info     = NULL;  /* designated return value          */

    struct stm_static_ctx *ctx = (struct stm_static_ctx *) dev->stm_ctx;

    /* iterate through all slices and setup a record if for each active one */
    pthread_mutex_lock(&dev->meta_lck);
    for (i = 0; i < ctx->part_cnt; i++) {
        if (ctx->act_vslc[i] == 1) {
            slice = calloc(1, sizeof(struct vslice));
            if (slice == NULL || slist_insert(&slc_list, slice)) {
                logmsg(WARN, "sstm_info: skipping vslice due to alloc error");
                if (slice != NULL)
                    free(slice);
                continue;
            }

            /* allocation was successful */
            slice->idx  = i;
            slice->size = ctx->part_size;
        }
        else {
            idle_slc_cnt++;
        }
    }
    pthread_mutex_unlock(&dev->meta_lck);

    if ((info = calloc(1, sizeof(struct vslc_info))) == NULL) {
        logmsg(WARN, "Error on memory allocation during sstm_info");
        /* tear down slice list again */
        while (slc_list != NULL) {
            free(slc_list->data);   /* safe since it contains struct vslice */
            slc_list = slist_remove(slc_list, slc_list->data);
        }

        return(NULL);
    }
    
    info->stm_type   = STM_TYPE_STATIC;
    info->free_space = idle_slc_cnt * ctx->part_size;
    info->vslc       = slc_list;

    return(info);
}

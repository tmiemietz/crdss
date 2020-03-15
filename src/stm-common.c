/****************************************************************************
 *                                                                          *
 *          stm-common.c - Common routines for the storage manager          *
 *                                                                          *
 *                    Copyright (c) 2019 Till Miemietz                      *
 *                                                                          *
 ****************************************************************************/


#define _GNU_SOURCE                      /* for the definition of O_DIRECT  */

/****************************************************************************
 *                                                                          *
 *                           include statements                             *
 *                                                                          *
 ****************************************************************************/


#include <stdint.h>                      /* fixed-size integers             */
#include <stdlib.h>                      /* memory allocation               */
#include <string.h>                      /* string manipulation             */
#include <unistd.h>                      /* UNIX standard calls             */
#include <errno.h>                       /* information about errors        */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>                   /* get the block size of a device  */
#include <linux/fs.h>                    /* for ioctl types                 */
#include <fcntl.h>                       /* for bare open                   */
#include <stdarg.h>                      /* for varargs                     */

#include "include/stm-common.h"          /* header for stm implementation   */
#include "include/stm-static.h"          /* implementation of a static stm  */
#include "include/utils.h"               /* logging, ...                    */

/****************************************************************************
 *                                                                          *
 *                          function implementation                         *
 *                                                                          *
 ****************************************************************************/


/***                    functions defined in stm-common.h                 ***/

/* Opens the device located in path and allocates a crdss_bdev structure    */
struct crdss_bdev *stm_open_dev(char *path) {
    struct crdss_bdev *dev;
    int                 fd;
    char         *path_cpy;                 /* copy of path to store in dev */
    unsigned int  block_sz;                 /* block size of device         */

    /* in order to obtain realistic values for testing with the kernel, use *
     * O_DIRECT when opening files                                          */
    if ((fd = open(path, O_RDWR /* | O_DIRECT */)) == -1) {
        logmsg(WARN, "Failed to open dev %s (%s), continuing...", path,
               strerror(errno));
        return(NULL);
    }

    dev      = malloc(sizeof(struct crdss_bdev));
    path_cpy = strdup(path);

    /* check for allocation error, free unused resources if needed  */
    if (dev == NULL || path_cpy == NULL) {
        logmsg(WARN, "stm_open_dev: memory allocation failed");
        if (dev != NULL)      free(dev);
        if (path_cpy != NULL) free(path_cpy);

        return(NULL);
    }

    if (ioctl(fd, BLKSSZGET, &block_sz) == -1) {
        logmsg(ERROR, "Failed to query block size of device (%d).", errno);
        free(path_cpy);
        free(dev);

        return(NULL);
    }
    logmsg(DEBUG, "Block size of device is %u.", block_sz);

    dev->path     = path_cpy;
    dev->fd       = fd;
    dev->block_sz = block_sz;
    pthread_mutex_init(&dev->meta_lck, NULL);       /* use default attrs    */

    return(dev);
}

/* Detects the storage manager type of a device managed by crdss.           */
int stm_detect_type(struct crdss_bdev *dev) {
    /* buffer for writing vslice table (4096 B), use a buffer instead of    *   
     * writing the fields separately in order to support direct I/O         */  
    unsigned char table_buf[4096]                                   
                    __attribute__ ((__aligned__(512)));    

    if (pread(dev->fd, table_buf, 4096, (off_t) 0) < 4) {
        logmsg(WARN, "Failed to read drive label");
        return(STM_TYPE_UNKNWN);
    }
    else {
        /* detect STM type and set proper function implementations          */
        switch (*((uint32_t *) table_buf)) {
            case STM_TYPE_STATIC:
                logmsg(INFO, "Device %s has static vslice layout.", dev->path);
                pthread_mutex_lock(&dev->meta_lck);
                dev->ops.rd_vslctbl = sstm_rd_vslctbl;
                dev->ops.mkvslc     = sstm_mkvslc;
                dev->ops.rmvslc     = sstm_rmvslc;
                dev->ops.alloc      = sstm_alloc;
                dev->ops.release    = sstm_release;
                dev->ops.translate  = sstm_translate;
                dev->ops.info       = sstm_info;
                pthread_mutex_unlock(&dev->meta_lck);
                return(STM_TYPE_STATIC);
            default:
                logmsg(WARN, "Device %s has unknown vslice layout.",
                       dev->path);
                return(STM_TYPE_UNKNWN);
        }
    }
}

/* Formats the disk for use with a new storage manager type                 */
int stm_init(struct crdss_bdev *dev, unsigned int type, ...) {
    va_list arglist;
    unsigned int slc_cnt;           /* to be extracted from varargs         */

    /* actually, we do not care about the first vararg (type), so we will   *
     * call va_arg immediately before retrieving the real var args          */
    va_start(arglist, type);
    switch (type) {
        case STM_TYPE_STATIC:
            slc_cnt = va_arg(arglist, unsigned int);
            if (sstm_init(dev, slc_cnt) == -1) {
                dev->state = DEV_CORRPT;
                va_end(arglist);
                return(-1);
            }

            /* set the function implementation accordingly */
            pthread_mutex_lock(&dev->meta_lck);
            dev->ops.rd_vslctbl = sstm_rd_vslctbl;
            dev->ops.mkvslc     = sstm_mkvslc;
            dev->ops.rmvslc     = sstm_rmvslc;
            dev->ops.alloc      = sstm_alloc;
            dev->ops.release    = sstm_release;
            dev->ops.translate  = sstm_translate;
            dev->ops.info       = sstm_info;
            pthread_mutex_unlock(&dev->meta_lck);

            /* if table was written successfully, device is in a sane state */
            dev->state = DEV_OK;
            break;
        default:
            logmsg(WARN, "stm_init: Unknown stm type requested");
            va_end(arglist);
            return(-1);
    }

    va_end(arglist);

    /* do a call to stm_detect_type to set the new stm operations           */
    (void) stm_detect_type(dev);
    return(0);
}

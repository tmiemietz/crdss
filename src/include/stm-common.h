/****************************************************************************
 *                                                                          *
 *         stm-common.h - Common routines for the storage manager.          *
 *                                                                          *
 *                    Copyright (c) 2019 Till Miemietz                      *
 *                                                                          *
 ****************************************************************************/


#ifndef STM_COMMON_H
#define STM_COMMON_H

/****************************************************************************
 *                                                                          *
 *                           include statements                             *
 *                                                                          *
 ****************************************************************************/


#include <pthread.h>                    /* POSIX MT library                 */

/****************************************************************************
 *                                                                          *
 *                     global definitions and macros                        *
 *                                                                          *
 ****************************************************************************/


/* storage manager implementation identifiers                               */
#define STM_TYPE_UNKNWN 0x00
#define STM_TYPE_STATIC 0x01    /* != 0 to avoid confusion with empty drive */            

/* device states                                                            */
#define DEV_UNKNWN 0x00         /* device has unknown (vslice) layout       */
#define DEV_CORRPT 0x01         /* device has known stm id but corrupt meta */
#define DEV_OK     0x02         /* device slice table is valid              */

/****************************************************************************
 *                                                                          *
 *                           type definitions                               *
 *                                                                          *
 ****************************************************************************/


struct crdss_bdev;

/* common representation of a virtual slice on a SSD                        */
struct vslice {
    unsigned int idx;       /* index of the vslice, used as an identifier   */
    uint64_t     size;      /* size of the vslice in Bytes                  */
};

/* structure that describes existing vslices on a drive in a format common  *
 * for all storage managers                                                 */
struct vslc_info {
    int      stm_type;                  /* type of storage manager used     */
    uint64_t free_space;                /* free space on the drive in Bytes */

    struct slist *vslc;                 /* list of existing vslices, filled *
                                         * with struct vslice               */
};

/* contains pointers to the implementations of storage management routines. *
 * initialization of block devices is not part of these routines and has to *
 * be called separately.                                                    */
struct stm_ops {
    /* read the vslice table from block device dev                          */
    int (*rd_vslctbl) (struct crdss_bdev *dev);

    /* create / remove a virtual slice. mkvlsc returns vslice idx, rmvslc   *
     * only the status of the operation                                     */
    int (*mkvslc) (struct crdss_bdev *dev);
    int (*rmvslc) (struct crdss_bdev *dev, unsigned int idx);

    /* grow / shrink a virtual slice (status of operation is returned)      */
    int (*alloc) (struct crdss_bdev *dev, unsigned int slc_idx, size_t offs, 
                  size_t nr_blks);
    int (*release) (struct crdss_bdev *dev, unsigned int slc_idx, size_t offs,
                    size_t nr_blks);

    /* translates an address used for referencing data in a vslice into a   *
     * LBA that can be used for accessing data in the real file. lba and    *
     * nr_seq are output parameters; operation status is returned. nr_seq   *
     * specifies the number of contiguous bytes, starting from lba, that    *
     * belong to the vslice identified by slc_idx.                          */
    int (*translate) (struct crdss_bdev *dev, unsigned int slc_idx, size_t vsa,
                      size_t *lba, size_t *nr_seq);

    /* output information about existing vslices in a common format         */
    struct vslc_info *(*info) (struct crdss_bdev *dev);
};

/* describes a block device managed by one of crdss' storage managers       */
struct crdss_bdev {
    char *path;                       /* path to device file (may be an ID) */
    int     fd;                       /* file descriptor for open device    */
    int   stm_type;                   /* stm type in charge of this device  */
    void *stm_ctx;                    /* context data of stm implementation */
    
    unsigned int state;               /* state of the device                */

    pthread_mutex_t meta_lck;         /* lock for metadata operations       */

    struct stm_ops ops;               /* fptrs to stm implementation funcs. */
};

/****************************************************************************
 *                                                                          *
 *                          function prototypes                             *
 *                                                                          *
 ****************************************************************************/


/****************************************************************************
 *
 * Opens the device located in path and allocates a crdss_bdev structure to
 * hold the device path and file descriptor. After successfully finishing 
 * this operation, stm_detect_type can be called to detect the type of
 * vslice management for the specified device.
 *
 * Params: dpath - Path name of block device to open.
 *
 * Returns: A pointer to an crdss_bdev struct or NULL on any error.
 */
struct crdss_bdev *stm_open_dev(char *path);

/****************************************************************************
 *
 * Detects the storage manager type of a device managed by crdss. The 
 * crdss_bdev struct passed to this function must contain a valid file 
 * descriptor that can be used for reading and writing. The return value
 * equals one of the storage manager types defined above. If the type is
 * unknown, or on error, STM_TYPE_UNKWN is returned. If the type is not
 * unknown, the functions for dev->ops are set to the implementations of the
 * storage manager used for this device.
 *
 * Params: dev - crdss_bdev structure with valid fd inside.
 *
 * Returns: The type of storage manager used for this device.
 */
int stm_detect_type(struct crdss_bdev *dev);

/****************************************************************************
 *
 * Formats the disk for use with a new storage manager type (a.k.a. vslice
 * block allocator). All data on the device specified are lost. The device
 * passed to this function must contain a valid file descriptor; it is
 * recommended to use stm_open_dev for this purpose. This function will also
 * update the stm operations.
 *
 * Apart from the device and the stm type, the exact parameters depend on the
 * implementation. Consider the respective header files.
 *
 * Params: dev  - The device to operate on, must contain a valid fd.
 *         type - the type of the stm to choose (defined in this header file).
 *         ...  - STM-specific initialization arguments.
 *
 * Returns: 0 on success, -1 on error
 */
int stm_init(struct crdss_bdev *dev, unsigned int type, ...);

#endif /* STM_COMMON_H */

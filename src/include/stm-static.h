/****************************************************************************
 *                                                                          *
 *      stm-static.h - A storage manager that uses static partitions.       *
 *                                                                          *
 *                    Copyright (c) 2019 Till Miemietz                      *
 *                                                                          *
 ****************************************************************************/

#ifndef STM_STATIC_H
#define STM_STATIC_H

/****************************************************************************
 *                                                                          *
 *                           include statements                             *
 *                                                                          *
 ****************************************************************************/


#include <stdint.h>                 /* fixed-width integers                 */

#include "slist.h"                  /* simple singly-linked lists           */

/****************************************************************************
 *                                                                          *
 *                     global definitions and macros                        *
 *                                                                          *
 ****************************************************************************/


#define STM_STATIC_MAX_VSLC 256        /* max. no. of vslices supported     */

/****************************************************************************
 *                                                                          *
 *                           type definitions                               *
 *                                                                          *
 ****************************************************************************/


/* in-memory representation of the static stm vslice table, to be used as   *
 * context in the crdss_bdev struct.                                        */
struct stm_static_ctx {
    uint32_t part_cnt;              /* no. of partitions currently active   */
    uint64_t part_size;             /* size of a single partition           */
    uint64_t vslc_offset;           /* offset of first vslice               */

    uint8_t  *act_vslc;             /* array of chars to indicate which     *
                                     * vslices are active, not using a      *
                                     * bitmap to reduce complexity          *
                                     * (to be changed later)                */
};

/****************************************************************************
 *                                                                          *
 *                          function prototypes                             *
 *                                                                          *
 ****************************************************************************/


/****************************************************************************
 *
 * Initializes an opened block device for use with the static storage manager.
 * This routine will calculate the size of the vslices and write a new 
 * vslice table to the disk. The size of each vslice will be <net disk size> /
 * <vslc_cnt>. Keep in mind that all data from previously used
 * vslice allocators will be lost when calling this function.
 *
 * Params: dev      - The block device to change.
 *         vslc_cnt - Number of static vslices to create on the drive.
 *
 * Returns: 0 on success, -1 on error.
 */
int sstm_init(struct crdss_bdev *dev, unsigned int vslc_cnt);

/****************************************************************************
 *
 * Reads the vslice table of a static storage manager from the drive 
 * represented by dev. A new stm_static_ctx structure containing the content
 * of the vslice table is allocated and assigned to dev. If reading the 
 * partition table fails, a non-zero value is returned and no allocations
 * shall be done. Note that the dev struct needs to be partially initialized,
 * e.g. by a call to stm_open_dev.
 *
 * The vslice table layout for the static allocation manager looks as follows:
 * After the initial stm type field (4 Byte), 8 Bytes represent the number of
 * vslices on the drive, followed by 8 Byte that indicate the size of each
 * partition. After that another 8 Bytes are used to determine the start of
 * the first vslice. Followed by that, a "bitmap" of chars which is 
 * <no. of vslices> Bytes long is used to indicate, which partitions are 
 * currently active, i.e., which contain valid data.
 *
 * Params: dev - Represents the bdev to read the vslice table from.
 *
 * Returns: 0 on success, -1 on error
 */
int sstm_rd_vslctbl(struct crdss_bdev *dev);

/****************************************************************************
 *
 * Creates a new virtual slice. If a non-negative number is returned, the
 * operation has been successful and the return code is the index of the
 * newly allocated slice. With the static allocator, vslices always have a
 * fixed size of (devsize - metadata size) / max vslc number.
 *
 * Params: dev - The device to create a vslice on.
 *
 * Returns: A slice index or a negative value on error.
 */
int sstm_mkvslc(struct crdss_bdev *dev);

/****************************************************************************
 *
 * Deletes the vslice with index idx on device dev.
 *
 * Params: dev - The device on which the vslice should be deleted.
 *         idx - The index of the vslice to delete.
 *
 * Returns: 0 on success, -1 on error (e.g. if the vslice did not exist)
 */
int sstm_rmvslc(struct crdss_bdev *dev, unsigned int idx);

/****************************************************************************
 *
 * Enlarges the vslice with index idx by nr_blks bytes at offset offs. This
 * operation is not supported for the static storage manager and hence
 * always fails.
 * 
 * Params: dev     - The device operated upon.
 *         slc_idx - Index of the slice to grow.
 *         offs    - Location in the vslice where the expansion takes place.
 *         nr_blks - No. of bytes that the vslice should be extended.
 *
 * Returns: -1, operation is not supported.
 */
int sstm_alloc(struct crdss_bdev *dev, unsigned int slc_idx, size_t offs, 
               size_t nr_blks);

/****************************************************************************
 *
 * Shrinks the vslice with index idx by nr_blks bytes at offset offs. This
 * operation is not supported for the static storage manager and hence
 * always fails.
 *
 * Params: dev     - The device operated upon.
 *         slc_idx - Index of the slice to grow.
 *         offs    - Location in the vslice where the expansion takes place.
 *         nr_blks - No. of bytes that the vslice should be extended.
 *
 * Returns: -1, operation is not supported.
 */
int sstm_release(struct crdss_bdev *dev, unsigned int slc_idx, size_t offs,                
                 size_t nr_blks);

/****************************************************************************
 *
 * Translates a vslice-relative block address into a LBA that can be used for
 * accessing the SSD via the pread / pwrite interfaces (or whatever technique
 * the storage backend uses). The LBA for disk access is stored in lba. nr_seq
 * is also an output paramter and indicates how many bytes can be sequentially
 * accessed starting from lba without encountering data that belongs to 
 * different vslices.
 *
 * Params: dev     - The device operated upon.
 *         slc_idx - vslice index used.
 *         vsa     - Address in the virtual address space of a vslice.
 *         lba     - LBA that backs vsa is stored here
 *         nr_seq  - number of bytes following lba that belong to slc_idx
 *
 * Returns: 0 on success, -1 on error
 */
int sstm_translate(struct crdss_bdev *dev, unsigned int slc_idx, size_t vsa, 
                   size_t *lba, size_t *nr_seq);

/****************************************************************************
 *
 * Outputs information about existing slices and free disk space in a format
 * independent of the exact storage manager implementation. See stm-common.h
 * for a description of the output structures. vslc_info structs and 
 * possible children will be allocated by this routine. The caller is 
 * responsible for freeing them after use.
 *
 * Params: dev - The device to query.
 *
 * Returns: a vslc_info struct containing the current vslice layout on the
 *          drive or a NULL pointer on error.
 */
struct vslc_info *sstm_info(struct crdss_bdev *dev);

#endif /* STM_STATIC_H */

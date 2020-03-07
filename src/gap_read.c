/****************************************************************************
 *                                                                          *
 *     gap_read.c - Read chunks from a file, leave a read gap, repeat.      *
 *                                                                          *
 *                    Copyright (c) 2020 Till Miemietz                      *
 *                                                                          *
 ****************************************************************************/



/****************************************************************************
 *                                                                          *
 *                     global definitions and macros                        *
 *                                                                          *
 ****************************************************************************/


#define _GNU_SOURCE
#define CHUNKSIZE 4096
#define GAPSIZE 131072
#define MAX_CHUNKS_READ 200000

/****************************************************************************
 *                                                                          *
 *                           include statements                             *
 *                                                                          *
 ****************************************************************************/


#include <stdio.h>                      /* std. I/O facilities              */
#include <stdlib.h>                     /* memory allocation routines       */
#include <string.h>                     /* routines for handling strings    */
#include <errno.h>                      /* standard error numbers           */
#include <sys/stat.h>                   /* find out things about files      */
#include <time.h>                       /* measure wall time of this program*/
#include <fcntl.h>                      /* for open and O_DIRECT flag       */
#include <unistd.h>                     /* pread / pwrite calls             */
#include <sys/ioctl.h>
#include <linux/fs.h>                   /* for getting the size of a bdev   */

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

    struct timespec start;
    struct timespec end;

    unsigned int max_read_cycles = 0;
    struct stat64 stat_buf;
    char   *path          = NULL;
    size_t file_size      = 0;
    off_t  file_offset    = 0;
    int    file_fd        = -1;
    unsigned char *io_buf = NULL;
    
    unsigned long nano_diff = 0;
    double sec_diff = 0;

    if (argc < 2) {
        fprintf(stderr, "Provide file name as first argument.\n");
        return(1);
    }
    
    if (posix_memalign((void **) &io_buf, CHUNKSIZE, CHUNKSIZE) != 0) {
        fprintf(stderr, "Failed to allocate I/O buffer.\n");
        return(1);
    }

    memset(&start, 0, sizeof(struct timespec));
    memset(&end, 0, sizeof(struct timespec));
    path = strdup(argv[1]);

    if ((file_fd = open64(path, O_RDWR | O_DIRECT)) == -1) {
        fprintf(stderr, "Failed to open file %s.\n", path);
        return(1);
    }

    if (stat64(path, &stat_buf) != 0) {
        fprintf(stderr, "Failed to stat file %s.\n", path);
        return(1);
    }

    if (S_ISREG(stat_buf.st_mode)) {
        file_size = stat_buf.st_size;
    }
    else if (S_ISBLK(stat_buf.st_mode)) {
        if (ioctl(file_fd, BLKGETSIZE64, &file_size) != 0) {
            fprintf(stderr, "Failed to get size of block device.\n");
            return(1);
        }
    }
    else {
        fprintf(stderr, "This program supports regular files and bdevs.\n");
        return(1);
    }

    fprintf(stderr, "Size of file %s is %lu.\n", path, file_size);
    max_read_cycles = file_size / (CHUNKSIZE + GAPSIZE);
    if (max_read_cycles > MAX_CHUNKS_READ)
        max_read_cycles = MAX_CHUNKS_READ;

    fprintf(stderr, "Going to read %u chunks.\n", max_read_cycles);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (i = 0; i < max_read_cycles; i++) {
        /* fprintf(stderr, "Reading chunk %u.\n", i); */
        if (pread64(file_fd, io_buf, CHUNKSIZE, file_offset) < CHUNKSIZE) {
            fprintf(stderr, "Failed to read chunk (%d).\n", errno);
            return(1);
        }

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

    return(0);
}

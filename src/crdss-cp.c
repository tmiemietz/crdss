/****************************************************************************
 *                                                                          *
 *         crdss-cp.c - Copy a file to a CRDSS virtual slice.               *
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
    int res;
    
    struct stat64 stat_buf;
    struct stat64 cstat_buf;
    char   *path          = NULL;
    char   *cpath         = NULL;
    ssize_t file_size     = 0;
    int    file_fd        = -1;
    int    cfile_fd       = -1;
    unsigned char *io_buf = NULL;
    
    if (argc < 3) {
        fprintf(stderr, "Provide file name as first arg, crdss \"file\" as "
                "the second parameter.\n");
        return(1);
    }
    
    path  = strdup(argv[1]);
    cpath = strdup(argv[2]);

    if ((file_fd = open64(path, O_RDWR)) == -1) {
        fprintf(stderr, "Failed to open file %s.\n", path);
        return(1);
    }
    if ((cfile_fd = open64(cpath, O_RDWR)) == -1) {
        fprintf(stderr, "Failed to open file %s.\n", path);
        return(1);
    }

    if (stat64(path, &stat_buf) != 0) {
        fprintf(stderr, "Failed to stat file %s.\n", path);
        return(1);
    }
    if (stat64(cpath, &cstat_buf) != 0) {
        fprintf(stderr, "Failed to stat CRDSS file %s.\n", path);
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

    if (file_size > cstat_buf.st_size) {
        fprintf(stderr, "File %s does not fit in the CRDSS vslice.\n", path);
        return(1);
    }

    res = posix_memalign((void **) &io_buf, 4096, file_size);
    if (res != 0) {
        fprintf(stderr, "Failed to allocate I/O buffer (%d).\n", res);
        return(1);
    }

    fprintf(stderr, "Size of file %s is %lu.\n", path, file_size);

    if (pread64(file_fd, io_buf, file_size, 0) < file_size) {
        fprintf(stderr, "Failed to read contents of file %s (%d).\n", 
                path, errno);
        return(1);
    }

    if (pwrite64(cfile_fd, io_buf, file_size, 0) < file_size) {
        fprintf(stderr, "Failed to write data to CRDSS file.\n");
        return(1);
    }
    fdatasync(cfile_fd);

    return(0);
}

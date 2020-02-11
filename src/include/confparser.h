/****************************************************************************
 *                                                                          *
 *  confparser.h - A parser for the configuration files of crdss servers.   *
 *                                                                          *
 *                    Copyright (c) 2019 Till Miemietz                      *
 *                                                                          *
 ****************************************************************************/

#ifndef CONFPARSER_H
#define CONFPARSER_H

/****************************************************************************
 *                                                                          *
 *                           include statements                             *
 *                                                                          *
 ****************************************************************************/


#include <netinet/ip.h>                /* definitions for sockets, IP, TCP  */
#include <sys/un.h>                    /* domain sockets                    */

#include "slist.h"                     /* single-linked lists               */

/****************************************************************************
 *                                                                          *
 *                           type definitions                               *
 *                                                                          *
 ****************************************************************************/


/* structure that describes a trusted client-side capability manager (SNIC) */
struct clt_capmgr {
    struct sockaddr_in addr;        /* IP address to use                    */
    char *secret;                   /* secret for authentication            */
};

/* structure that describes the configuration of a crdss server             */
struct server_config {
    struct sockaddr_in addr;    /* IP address and port this server should   *
                                 * bind to                                  */
    uint64_t guid;              /* GUID of InfiniBand port that this server *
                                 * shall listen to                          */
    int   loglevel;             /* logging level to choose for execution    */
    char *secret;               /* key for identification                   */

    struct slist *devs;         /* storage devices managed by this server;  *
                                 * contains paths to device files           */
    struct slist *snics;        /* contains clt_capmgr structures for       *
                                 * identifying clt-side cap managers        */   
};

/* structure that contains connection information for a crdss server        */
struct srv_conn {
    struct sockaddr_in addr;    /* IP and port number of the storage server */
    uint16_t           lport;   /* local port number for used for connection*
                                 * stored in network byte order             */
    
    char *secret;               /* identification key of this server        */
};

/* structure that describes the configuration of a crdss SNIC auth. service */
struct snic_config {
    struct sockaddr_in addr;    /* IP address and TCP port this process     *
                                 * should bind to                           */
    int   loglevel;             /* logging level to choose for execution    */

    /* socket for communication with clients. This may either be a UDP or a *
     * UNIX domain socket                                                   */
    union {
        struct sockaddr_in udp;
        struct sockaddr_un dom;
    } clt_sock;

    uint64_t guid;              /* GUID of InfiniBand port that this server *
                                 * should listen to (maybe move to clt conf)*/

    char *secret;               /* secret key for identification with server*/

    struct slist *srvs;         /* list of struct srv_conn with addresses   *
                                 * of crdss server processes                */

    struct slist *caps;         /* list of crdss_clt_cap given in cfg file  */
};

/* structure that describes config of client library (buffer sizes etc.)    */
struct clt_lib_cfg {
    unsigned int no_workers;    /* number of worker threads expected        */

    size_t sbuf_size;           /* size of small buffers in bytes (static   *
                                 * allocation to one worker thread, lib     *
                                 * allocates <worker_cnt> small buffers     */

    size_t lbuf_size;           /* size of large buffers in bytes           */    
    size_t lbuf_cnt;            /* number of large, on-demand allocated bufs*/          
};

/****************************************************************************
 *                                                                          *
 *                          function prototypes                             *
 *                                                                          *
 ****************************************************************************/


/****************************************************************************
 *
 * Parses the server configuration file located at path confpath and  
 * converts its contents to a server_config structure. The mantle object
 * sconf shall be allocated by the caller of this function. Any errors that
 * occur during parsing are reported on stderr.
 *
 * Params: confpath - path to the server configuration file.
 *         sconf    - structure that describes the server configuration.
 *
 * Returns: 0 on success, 1 on error.
 */
int parse_server_config(char *confpath, struct server_config *sconf);

/****************************************************************************
 *
 * Parses the SNIC authproc configuration file located at path confpath and  
 * converts its contents to a snic_config structure. The mantle object
 * sconf shall be allocated by the caller of this function. Any errors that
 * occur during parsing are reported on stderr.
 *
 * Params: confpath - path to the snic configuration file.
 *         sconf    - structure that describes the SNIC configuration.
 *
 * Returns: 0 on success, 1 on error.
 */
int parse_snic_config(char *confpath, struct snic_config *sconf);

/****************************************************************************
 *
 * Parses a configuration file for the client library. The config file is
 * expected to be located at confpath and to contain all elements 
 * necessary for filling a clt_lib_cfg structure. Buffer sizes (i.e., sbuf_size
 * and lbuf_size) in the config file are interpreted with a unit of KiB.
 * The mantle object cconf that shall be filled by this function has to be 
 * allocated by the caller of this routine. Any errors that occur during 
 * parsing are reported on stderr.
 *
 * Params: confpath - path to the library config file.
 *         cconf    - structure that describes the configuration of libcrdss.
 *
 * Returns: 0 on success, 1 on error.
 */
int parse_lib_config(char *confpath, struct clt_lib_cfg *cconf);

/****************************************************************************
 *
 * Checks the sanity of a configuration object for libcrdss.
 * Errors are reported to stderr.
 *
 * Params: cfg - Configuration object to be examined.
 *
 * Returns: 0 if config is properly initialized, an error code that indicates
 *          the reason for the failure else (see implementation).
 */
int check_libcfg(struct clt_lib_cfg *cfg);

#endif /* PARSER_H */

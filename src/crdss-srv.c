/****************************************************************************
 *                                                                          *
 *      crdss-srv.c - The main server of the Caladan Storage System         *
 *                                                                          *
 *                    Copyright (c) 2019 Till Miemietz                      *
 *                                                                          *
 ****************************************************************************/


/****************************************************************************
 *                                                                          *
 *                           include statements                             *
 *                                                                          *
 ****************************************************************************/


#include <stdio.h>                       /* basic I/O facilities            */
#include <stdlib.h>                      /* allocation, exit, ...           */
#include <unistd.h>                      /* UNIX standard libraries         */
#include <limits.h>                      /* system limits                   */
#include <string.h>                      /* string manipulation             */
#include <errno.h>                       /* find reasons for errors         */
#include <sys/types.h>
#include <sys/stat.h>                    /* for both open and stat          */
#include <fcntl.h>                       /* needed for calls to open        */

#include <arpa/inet.h>                   /* pretty printing of IP addresses */

#include <sodium.h>                      /* library for cryptography        */

#include "include/slist.h"               /* header for slist implementation */
#include "include/utils.h"               /* utilities like logging          */
#include "include/confparser.h"          /* configuration parser            */
#include "include/stm-common.h"          /* storage manager common routines */
#include "include/protocol.h"            /* crdss application network prot. */
#include "include/cap.h"                 /* crdss capability implementation */
#include "include/ibcomm.h"              /* IB communication routines       */

/* !!! FOR TESTING ONLY !!! */
#include "include/stm-static.h"

/****************************************************************************
 *                                                                          *
 *                           type definitions                               *
 *                                                                          *
 ****************************************************************************/


struct handler {
    pthread_t tid;                          /* thread id of this handler    */
    
    struct slist *caps;                     /* list of crdss_srv_caps       *
                                             * handled by this thread       */
    pthread_rwlock_t cap_lck;               /* lock for capability list     */

    /*** IP-related fields ****/
    int       sock;                         /* IP socket for control path   */
    struct sockaddr_in clt_addr;            /* IP and port of client        */

    /*** fields for IB communication ***/
    unsigned char *msg_buf;                 /* buffer for send/recv ops     */
    unsigned char *data_buf;                /* buffer for RDMA accesses     */

    struct ib_ctx *ibctx;                   /* wrapper for IB structures    */
    
    unsigned int use_poll;                  /* 1 for completion polling     */
    unsigned int worker_cnt;                /* number of IB workers         */
    pthread_t *ib_workers;                  /* pointers to IB worker threads*/
};

/****************************************************************************
 *                                                                          *
 *                           global variables                               *
 *                                                                          *
 ****************************************************************************/


/* no lock is needed to the dev list itself, since access after             *
 * initialization is always read-only                                       */
struct server_config server_conf;        /* config parsed from conf. file   */
struct slist *devs;                      /* preliminary, list of crdss_bdevs*/
int    srv_sock;                         /* socket for new connections      */

/*** data structures for managing handler threads                         ***/
int act_thrd_cnt = 1;               /* no. of active handler threads. start *
                                     * with 1 since the entry handler thread*
                                     * always exists                        */
pthread_mutex_t thrd_cnt_lck = PTHREAD_MUTEX_INITIALIZER;

pthread_t     entry_handler;        /* thread for initial handling of conns.*/
struct slist *zombies;              /* list of tids of dead threads         */
/* cv for waking up main joiner thread once a new zombie is created         */
pthread_mutex_t zombie_lck = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  zombie_cv  = PTHREAD_COND_INITIALIZER;

struct slist *handlers;             /* list of handler structs              */
/* lock for modifying the handler list, used only by joiner and entry thread*
 * grab after zombie list lock                                              */
pthread_mutex_t handler_lck = PTHREAD_MUTEX_INITIALIZER;

/*** data structures for handling capabilities                            ***/
struct slist *cap_list;             /* list that contains all capabilities  */
struct slist *dom_tree;             /* list of trees of revocation domains  */
struct slist *dom_list;             /* plain list of rdom numbers in use    */

uint32_t max_rdom;                  /* highest rdom id currently in use     */
struct slist *free_dom_ids;         /* rdom ids that are safe to reuse      */

pthread_mutex_t cap_lck = PTHREAD_MUTEX_INITIALIZER;

/****************************************************************************
 *                                                                          *
 *                          static helper functions                         *
 *                                                                          *
 ****************************************************************************/


/****************************************************************************
 *
 * Prints a usage message to stderr.
 */
static void usage(void) {
    fprintf(stderr, "crdss-srv - The Caladan Storage Server\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "./crdss-srv -c <path> [-l path] [-w] [-h]\n");
    fprintf(stderr, "-c : path to server configuration file\n");
    fprintf(stderr, "-l : path to server log file (default: stderr)\n");
    fprintf(stderr, "-w : do not run server as a daemon\n");
    fprintf(stderr, "-h : print this help message and exit\n");
}

/****************************************************************************
 *
 * Checks for availabilty of storage devices passed via the configuration 
 * file, opens them, detects the partition type, configures the appropriate
 * storage manager instance and saves the state information in the device
 * list of this server.
 */
static void open_devs(void) {
    struct slist *lptr;
    struct stat  statbuf;

    /* for each device specified in the config file, peform opening steps   */
    for (lptr = server_conf.devs; lptr != NULL; lptr = lptr->next) {
        logmsg(INFO, "Setting up server structures for device %s",
               (char *) lptr->data);

        if (stat((char *) lptr->data, &statbuf) == -1) {
            logmsg(WARN, "Can not stat file %s (%s). Skipping...", 
                   (char *) lptr->data, strerror(errno));
            continue;
        }
        if (! S_ISBLK(statbuf.st_mode)) {
            logmsg(WARN, "File %s is not a block device. Skipping...",
                   (char *) lptr->data);
        }

        struct crdss_bdev *dev = stm_open_dev((char *) lptr->data);

        if (dev == NULL)
            continue;

        if (slist_insert(&devs, dev)) {
            logmsg(WARN, "open_devs: memory allocation for list failed");
            free(dev->path);
            free(dev);
            continue;
        }
        
        /* if dev could be opened, try to detect a storage manager type     */
        dev->stm_type = stm_detect_type(dev);
        if (dev->stm_type == STM_TYPE_UNKNWN) {
            logmsg(WARN, "Unknown partition type detected for device %s",
                   (char *) lptr->data);
            dev->state = DEV_UNKNWN;
            continue;
        }

        /* if stm type is known, try to read its vslice table               */
        if (dev->ops.rd_vslctbl(dev) == -1) {
            logmsg(WARN, "vslice table for device %s is corrupted, skipping...",
                   (char *) lptr->data);
            dev->state = DEV_CORRPT;
            continue;
        }

        /* everything seems to be fine */
        dev->state = DEV_OK;
    }
}

/***************************************************************************
 *
 * Checks whether a capability with the parameters passed to this function
 * is inside the bound of the storage device infrastructure managed by this
 * server. This means that dev and slice indices as well as the address 
 * bounds within each slice may not be violated.
 *
 * Params: didx  - requested index of device.
 *         sidx  - index of vslice on the device identified by didx.
 *         saddr - requested start address of capability.
 *         eaddr - requested end address of capability.
 *
 * Returns: 0 if the cap will address a valid block range, 1 otherwise.
 */
static int check_cap_bounds(uint16_t didx, uint32_t sidx, uint64_t saddr,
                            uint64_t eaddr) {
    unsigned int i;
    struct slist *lptr = devs;
    struct crdss_bdev *dev;

    struct vslc_info *slc_info;         /* information on active vslices    */
    struct vslice    *slice;

    /* check if dev index is already out of bounds */
    if (slist_empty(devs) || didx > (slist_length(devs) - 1))
        return(1);

    /* move to requested device and get information about its vslices */
    for (i = 0; i < didx; i++)
        lptr = lptr->next;

    dev      = (struct crdss_bdev *) lptr->data;
    slc_info = dev->ops.info(dev);

    if (slc_info == NULL) {
        logmsg(ERROR, "Failed to acquire vslice info...");
        return(1);
    }

    /* check if there exist vslices and if so if slc idx is out of bounds   */
    if (slist_empty(slc_info->vslc) || 
        sidx > (slist_length(slc_info->vslc) - 1)) {
        return(1);
    }

    lptr = slc_info->vslc;
    for (i = 0; i < sidx; i++) 
        lptr = lptr->next;

    /* check if byte addresses are out of bound */
    slice = (struct vslice *) lptr->data;
    if (saddr > (slice->size - 1) || eaddr > (slice->size - 1))
        return(1);
    
    /* clean up vslice info struct before returning */
    while (slc_info->vslc != NULL) {
        free(slc_info->vslc->data);
        slc_info->vslc = slist_remove(slc_info->vslc, slc_info->vslc->data);
    }
    free(slc_info);

    return(0);
}

/****************************************************************************
 *
 * Gets the type of the next message received over InfiniBand. The function 
 * will wait for an incoming completion entry and set the user-provided 
 * message pointer to the buffer containing the request. 
 * The user is responsible for re-queuing the 
 * message after processing it to guaranteee that there is a sufficient
 * number of outstanding receive requests.
 * The message's type will be stored in the integer pointed to by type. This
 * reference must not be NULL. The same holds for the immediate pointer.
 * Whether this routine uses polling or blocking completion depends on the
 * use_poll flag in the handler structure passed to this function.
 *
 * Params: handler - handler structure of the caller.
 *         msg     - pointer for storing the reference to the InfiniBand
 *                   message buffer.
 *         type    - pointer to integer for message type (output parameter).
 *         imm     - pointer to integer for immediate value received along
 *                   with the actual message.
 *
 * Returns 0 on success, 1 on error.
 */
static int get_next_msg_type(struct handler *handler, unsigned char **msg,
        uint8_t *type, uint32_t *imm) {
    if (handler->use_poll == 0) {
        /* blocking completion */
        if (get_next_ibmsg(handler->ibctx, msg, imm) != 0)
            return(1);
    }
    else {
        if (poll_next_ibmsg(handler->ibctx, msg, imm) != 0)
            return(1);
    }

    if (*msg == NULL)
        *type = MTYPE_COMPLETE;
    else
        *type = **msg;

    return(0);
}

/****************************************************************************
 *
 * Retrieves the size of a vslice. Currently, this is the handler method for
 * VSLCINFO requests. If the function succeeds, the size of the vslice 
 * queried will be stored in size, a user-provided pointer that must not be
 * NULL. Reasons for failure are invalid indices vor the device and the 
 * slice or internal errors.
 *
 * Params: didx - index of device that contains the vslice.
 *         sidx - index of the vslice to query.
 *         size - size of the requested vslice (output parameter).
 *
 * Returns: 0 on success, 1 on error.
 */
static int get_vslc_size(uint16_t didx, uint32_t sidx, uint64_t *size) {
    unsigned int i;
    struct slist *lptr = devs;
    struct crdss_bdev *dev;

    struct vslc_info *slc_info = NULL;    /* information on active vslices  */
    struct vslice    *slice    = NULL;

    /* check if size is a null pointer */
    if (size == NULL)
        return(1);

    /* check if dev index is already out of bounds */
    if (slist_empty(devs) || didx > (slist_length(devs) - 1))
        return(1);

    /* move to requested device and get information about its vslices */
    for (i = 0; i < didx; i++)
        lptr = lptr->next;

    dev      = (struct crdss_bdev *) lptr->data;
    slc_info = dev->ops.info(dev);

    if (slc_info == NULL) {
        logmsg(ERROR, "get_vslc_size: Failed to acquire vslice info...");
        return(1);
    }

    /* check if there exist vslices and if so if slc idx is out of bounds   */
    if (slist_empty(slc_info->vslc) || 
        sidx > (slist_length(slc_info->vslc) - 1)) {
        return(1);
    }

    lptr = slc_info->vslc;
    for (i = 0; i < sidx; i++) 
        lptr = lptr->next;

    /* check if byte addresses are out of bound */
    slice = (struct vslice *) lptr->data;
    *size = slice->size;
    
    /* clean up vslice info struct before returning */
    while (slc_info->vslc != NULL) {
        free(slc_info->vslc->data);
        slc_info->vslc = slist_remove(slc_info->vslc, slc_info->vslc->data);
    }
    free(slc_info);

    return(0);
}

/****************************************************************************
 * 
 * Inserts a new capability into the server's management structures. Both
 * new_cap and new_loc_cap are expected to contain the same values.
 * If a parent_id is specified, the new cap pair will be tied to the revdom
 * of the parent cap. However, this operation then will only succeed, iff
 * new_cap is a subset of the parent cap identified by parent_id.
 * If parent_id is NULL, new_cap is expected to contain a valid revdom to 
 * assign the new cap pair to (i.e., the new cap will be a root capability
 * created by a capmgr).
 * On error both new_cap and new_cap_loc will be freed.
 * When entering this function, no locks on capability management structures
 * shall be held.
 *
 * Params: handler     - control structure of the thread executing this request.
 *         new_cap     - the new capability to insert in the global structs
 *         new_cap_loc - copy of new_cap, will be stored thread-local at
 *                       the handler specified.
 *         dom_id      - the revocation domain ID that the new caps shall
 *                       be registered with (ignored if parent_cap is not NULL)
 *
 * Returns: An error number as defined in include/protocol.h.
 */
static int register_cap_with_dom(struct handler *handler, 
        struct crdss_srv_cap *new_cap, struct crdss_srv_cap *new_cap_loc,
        unsigned char *parent_id, uint32_t dom_id) {
    struct slist *lptr;                 /* for iterating through lists      */

    struct crdss_srv_cap *pcap = NULL;  /* pointer to full parent cap       */

    pthread_mutex_lock(&cap_lck);
    if (parent_id == NULL) {
        for (lptr = dom_list; lptr != NULL; lptr = lptr->next) {
            struct rev_dom_node *rdn = (struct rev_dom_node *) lptr->data;
                                                
            if (dom_id == rdn->dom_key)
                 break;
        }

        /* if lptr is NULL, the requested revocation domain does not exist, *
         * hence discard the request                                        */
        if (lptr == NULL) {
            pthread_mutex_unlock(&cap_lck);
            logmsg(WARN, "Handler %lu: Client requested MKCAP for "
                   "invalid revdom %u.", handler->tid, new_cap->rev_dom);
            free(new_cap);
            free(new_cap_loc);
            return(R_INVAL);
        }

        /* set the rdom pointers of the new caps to the proper rdom object  */
        new_cap->rev_dom     = lptr->data;
        new_cap_loc->rev_dom = lptr->data;
    }
    else {
        /* find out whether parent_cap is really a valid parent cap for the *
         * new capabilities                                                 */
        for (lptr = cap_list; lptr != NULL; lptr = lptr->next) {
            pcap = (struct crdss_srv_cap *) lptr->data;

            if (memcmp(parent_id, &pcap->id, CAP_ID_LEN) == 0)
                break;
        }

        /* if lptr is NULL, the requested cap with id parent_id does not    *
         * exist. also check if new_cap is really a subset of a matching    *
         * cap found in the global list                                     */
        if (lptr == NULL || ! srv_cap_is_subset(new_cap, pcap)) {
            pthread_mutex_unlock(&cap_lck);
            logmsg(WARN, "Handler %lu: Client requested DRVCAP for invalid "
                   "parent capability.", handler->tid);
            free(new_cap);
            free(new_cap_loc);
            return(R_INVAL);
        }

        /* set revocation domain of new caps to the one of the parent cap   */
        new_cap->rev_dom     = pcap->rev_dom;
        new_cap_loc->rev_dom = pcap->rev_dom;
    }

    /* now, we still need to find a free cap id...                          */
    find_free_cap_id(new_cap->id, cap_list);
    /* copy final ID to local cap */
    memcpy(&new_cap_loc->id, &new_cap->id, CAP_ID_LEN);

    /* everything is ok, insert the new cap in the global caplist           */
    if (slist_insert(&cap_list, new_cap) ||
        slist_insert(&new_cap->rev_dom->caps, new_cap) ||
        slist_insert(&new_cap_loc->rev_dom->caps, new_cap_loc)) {
        
        cap_list = slist_remove(cap_list, new_cap);
        new_cap->rev_dom->caps = slist_remove(new_cap->rev_dom->caps, new_cap);
        new_cap_loc->rev_dom->caps = slist_remove(new_cap_loc->rev_dom->caps, 
                                                  new_cap_loc);

        pthread_mutex_unlock(&cap_lck);
        logmsg(ERROR, "Handler %lu: Failed to allocate list elem "
              "during cap creation!", handler->tid);
        free(new_cap);
        free(new_cap_loc);
        return(R_FAILURE);
    }
                
    /* insert new capability in local cap list of handler                   */
    pthread_rwlock_rdlock(&handler->cap_lck);
    if (slist_insert(&handler->caps, new_cap_loc)) {
        pthread_rwlock_unlock(&handler->cap_lck);
        cap_list = slist_remove(cap_list, new_cap);
        pthread_mutex_unlock(&cap_lck);

        logmsg(ERROR, "Handler %lu: Failed to allocate list elem "
                      "during cap creation!", handler->tid);
        free(new_cap_loc);
        free(new_cap);
        return(R_FAILURE);
    }

    pthread_rwlock_unlock(&handler->cap_lck);
    pthread_mutex_unlock(&cap_lck);
    return(R_SUCCESS);
}

/****************************************************************************
 *
 * Registers a capability with the specified handler thread. This operation
 * takes the ID of the cap to insert into the handler's local cap list.
 * This function will fail if the global cap list does not contain a cap
 * with the specified ID or if there are memory allcoation errors.
 *
 * Params: handler - handler structure of calling thread.
 *         id_buf  - buffer that contains the ID of the cap to register.
 *
 * Returns: R_SUCCESS on succes or a crdss error number on error.
 */
static int handle_regcap(struct handler *handler, unsigned char *id_buf) {
    struct slist *lptr = NULL;              /* ptr for list iteration       */
    struct crdss_srv_cap *new_cap;          /* ptr to new local cap copy    */
    struct crdss_srv_cap *par_cap;          /* parent cap of requested cap  */

    new_cap = calloc(1, sizeof(struct crdss_srv_cap));
    if (new_cap == NULL) {
        logmsg(ERROR, "Handler %lu: Failed to allocate new cap.", handler->tid);
        return(R_FAILURE);
    }

    /* go through the global cap list and check if a cap with the ID given  *
     * has been registered                                                  */
    pthread_mutex_lock(&cap_lck);
    logmsg(DEBUG, "reg_cap: Acquired cap lock.");

    /* check if cap is globally available                                   */
    logmsg(DEBUG, "reg_cap: global cap list len is %u.", 
           slist_length(cap_list));
    for (lptr = cap_list; lptr != NULL; lptr = lptr->next) {
        par_cap = (struct crdss_srv_cap *) lptr->data;

        if (memcmp(par_cap->id, id_buf, CAP_ID_LEN) == 0) {
            /* make a local copy of the global cap */
            new_cap->dev_idx    = par_cap->dev_idx;
            new_cap->vslc_idx   = par_cap->vslc_idx;
            new_cap->start_addr = par_cap->start_addr;
            new_cap->end_addr   = par_cap->end_addr;

            new_cap->rights  = par_cap->rights;
            new_cap->rev_dom = par_cap->rev_dom;
            memcpy(new_cap->id, par_cap->id, CAP_ID_LEN);

            new_cap->valid   = 1;
            pthread_mutex_init(&new_cap->valid_lck, NULL);
            break;
        }
    }
            
    if (lptr == NULL) {
        pthread_mutex_unlock(&cap_lck);
        logmsg(WARN, "Handler %lu: Clt. specified invalid cap ID "
                     "for registration.", handler->tid);
        free(new_cap);
        return(R_INVAL);
    }

    logmsg(DEBUG, "reg_cap: locking local cap list.");
    pthread_rwlock_wrlock(&handler->cap_lck);
    logmsg(DEBUG, "reg_cap: acquired lock for local cap list.");

    /* first try insertion into handler-local cap list                      */
    if (slist_insert(&handler->caps, new_cap)) {
        pthread_rwlock_unlock(&handler->cap_lck);
        pthread_mutex_unlock(&cap_lck);
        logmsg(ERROR, "Handler %lu: Failed to allocate list elem.",
               handler->tid);
        free(new_cap);
        return(R_FAILURE);
    }

    if (slist_insert(&par_cap->rev_dom->caps, new_cap)) {
        handler->caps = slist_remove(handler->caps, new_cap);
        pthread_rwlock_unlock(&handler->cap_lck);
        pthread_mutex_unlock(&cap_lck);
        logmsg(ERROR, "Handler %lu: Failed to allocate list elem.",
               handler->tid);
        free(new_cap);

        return(R_FAILURE);
    }

    pthread_rwlock_unlock(&handler->cap_lck);
    pthread_mutex_unlock(&cap_lck);

    return(R_SUCCESS);
}

/***************************************************************************
 *
 * Revokes all capabilities in the revocation domain given as a parameter.
 * This also includes deletion of all revocation domains (and the caps 
 * inside them) that are derived from the rdom given. The call will fail if
 * the handler process does not have a cap with the specified rdom 
 * registered.
 *
 * Params: handler - handler structure of the calling thread.
 *         rdom_id - ID of revocation domain to revoke.
 *
 * Returns: One of the error numbers defined in include/protocol.h.
 */
static int handle_rmdom(struct handler *handler, uint32_t rdom_id) {
    struct slist *lptr      = NULL;        /* ptrs for iterating over lists  */
    struct slist *lptr2     = NULL;
    struct slist *inv_rdoms = NULL;        /* contains all doomed rdom nodes */

    struct rev_dom_node *new_node = NULL;  /* ptr to root rdom node to delete*/

    pthread_mutex_lock(&cap_lck);
                
    /* check if rev dom exists and if so, find out all children             */
    for (lptr = dom_list; lptr != NULL; lptr = lptr->next) {
        struct rev_dom_node *rdn = (struct rev_dom_node *) lptr->data;

        /* new_node will be used as the root node for deletion  */
        if (rdn->dom_key == rdom_id) {
            logmsg(INFO, "rmdom: found matching rdom.");
            new_node = rdn;
            break;
        }
    }

    /* check if this handler has a cap with the specified rdom              */
    pthread_rwlock_rdlock(&handler->cap_lck);
    for (lptr2 = handler->caps; lptr2 != NULL; lptr2 = lptr2->next) {
        struct crdss_srv_cap *scap = (struct crdss_srv_cap *) lptr2->data;

        if (scap->rev_dom->dom_key == rdom_id) 
            break;
    }
    pthread_rwlock_unlock(&handler->cap_lck);

    if (lptr == NULL || lptr2 == NULL) {
        pthread_mutex_unlock(&cap_lck);
        logmsg(ERROR, "Handler %lu: Client requested revocation "
                      "of invalid rdom.", handler->tid);
        return(R_INVAL);            
    }
    logmsg(DEBUG, "Handler %lu: Revoking domain %u.", handler->tid, rdom_id);

    /* remove the requested dom node from the list of root rdoms if the     *
     * requested rdom is not a root, this op has no effect                  */
    dom_tree = slist_remove(dom_tree, new_node);
    if (new_node->parent != NULL) {
        new_node->parent->children = slist_remove(new_node->parent->children, 
                                                  new_node);
    }
    delete_rdom_tree(new_node, dom_list, &inv_rdoms);
    logmsg(DEBUG, "Handler %lu: No. of domains revoked (parent + children): "
                  "%u.", handler->tid, slist_length(inv_rdoms));
            
    /* go through all deleted rdoms and mark all their caps as invalid,     *
     * removing them from the global cap list                               */
    for (lptr = inv_rdoms; lptr != NULL; lptr = lptr->next) {
        struct rev_dom_node *rdn = (struct rev_dom_node *) lptr->data;

        for (lptr2 = rdn->caps; lptr2 != NULL; lptr2 = lptr2->next) {
            struct crdss_srv_cap *cap = (struct crdss_srv_cap *) lptr2->data;

            pthread_mutex_lock(&cap->valid_lck);
            cap->valid = 0;
            pthread_mutex_unlock(&cap->valid_lck);

            if (slist_contains(cap_list, cap)) {
                cap_list = slist_remove(cap_list, cap);
                free(cap);
            }
        }
    }
           
    if (slist_insert(&free_dom_ids, (void *) (uint64_t) rdom_id) != 0)
        logmsg(WARN, "Failed to insert rdom ID in free list.");

    pthread_mutex_unlock(&cap_lck);

    /* discard invalid rdoms and send answer */
    while (inv_rdoms != NULL) {
        free(inv_rdoms->data);
        inv_rdoms = slist_remove(inv_rdoms, inv_rdoms->data);
    }

    return(R_SUCCESS);
}

/****************************************************************************
 *
 * Derives a new capability from the cap identified by the ID passed to 
 * this routine. The new capability will be placed in the same revocation
 * domain as its parent cap defined by par_id id. A pointer to
 * the new capability is returned via the parameter ncap. It only contains
 * a valid reference if this function succeeds.
 *
 * Params: handler - handler structure of the calling thread.
 *         par_id  - cap id of parent cap.
 *         didx    - device index of new cap.
 *         sidx    - vslice index of new cap.
 *         saddr   - start address of new cap.
 *         eaddr   - end address of new cap.
 *         rights  - permissions encoded in new capability.
 *         ncap    - pointer to new capability (output parameter).
 *
 * Returns: An error code as defined in include/protocol.h.
 */
static int handle_drvcap(struct handler *handler, unsigned char *par_id,
                         uint16_t didx, uint32_t sidx, uint64_t saddr,
                         uint64_t eaddr, uint16_t rights,
                         struct crdss_srv_cap **ncap) {
    int ret;                                /* return value of functions    */

    struct crdss_srv_cap *new_cap;          /* new global cap               */
    struct crdss_srv_cap *new_cap_cpy;      /* handler-local copy of new_cap*/

    new_cap     = calloc(1, sizeof(struct crdss_srv_cap));
    new_cap_cpy = calloc(1, sizeof(struct crdss_srv_cap));
    if (new_cap == NULL || new_cap_cpy == NULL) {
        logmsg(ERROR, "Handler %lu: Failed to allocate memory for capability.",
               handler->tid);
        
        if (new_cap != NULL)     free(new_cap);
        if (new_cap_cpy != NULL) free(new_cap_cpy);

        return(R_FAILURE);
    }

    /* fill new cap */
    new_cap->dev_idx    = didx;
    new_cap->vslc_idx   = sidx;
    new_cap->start_addr = saddr;
    new_cap->end_addr   = eaddr;
    new_cap->rights     = rights;

    new_cap->valid = 1;
    pthread_mutex_init(&new_cap->valid_lck, NULL);
    
    /* complete the cap copy for our local list */
    new_cap_cpy->dev_idx    = didx;
    new_cap_cpy->vslc_idx   = sidx;
    new_cap_cpy->start_addr = saddr;
    new_cap_cpy->end_addr   = eaddr;
    new_cap_cpy->rights     = rights;

    new_cap->valid = 1;
    pthread_mutex_init(&new_cap_cpy->valid_lck, NULL);

    /* check if the requested revocation domain exists and insert the cap in*
     * all  management structures                                           */
    ret = register_cap_with_dom(handler, new_cap, new_cap_cpy, par_id, 0);
    if (ret != R_SUCCESS) 
        return(ret);

    *ncap = new_cap_cpy;
    return(R_SUCCESS);
}

/****************************************************************************
 *
 * Handles a client's read request. The function checks whether the caps that
 * the client owns are sufficient for the access. If so, the corresponding
 * data is transferred to the location requested by the client.
 *
 * Params: handler   - handler structure of the calling thread.
 *         didx      - device index of data read.
 *         sidx      - vslice index of data read.
 *         addr      - starting virtual LBA for reading data.
 *         len       - length of data to read.
 *         rdma_offs - offset in rdma buffers.
 *         signaled  - create a local cqe for completion of RDMA operation.
 *
 * Returns: An error code as defined in src/include/protocol.h
 */
static int handle_read(struct handler *handler, uint16_t didx, uint32_t sidx,
                       uint64_t addr, uint32_t len, uint64_t rdma_offs) {
    unsigned int i;
    size_t offset = 0;                      /* offset in RDMA buffer        */

    struct slist *lptr     = NULL;          /* ptr for list iteration       */
    struct crdss_bdev *dev = NULL;          /* device to read from          */

    if (rdma_offs > handler->ibctx->rdma_mr->length - 1) {
        logmsg(ERROR, "Handler %lu: RDMA offset is out of bounds (read).",
               handler->tid);
        return(1);
    }

    logmsg(DEBUG, "Read input params: didx = %u, sidx = %u, addr = %lu, "
           "len = %u.", didx, sidx, addr, len);

    /* check whether access is allowed */
    pthread_rwlock_rdlock(&handler->cap_lck);

    for (lptr = handler->caps; lptr != NULL;) {
        struct crdss_srv_cap *cap = (struct crdss_srv_cap *) lptr->data;

        logmsg(DEBUG, "handle_read: acquiring valid lock.");
        pthread_mutex_lock(&cap->valid_lck);
        if (cap->valid == 0) {
            /* cap became void, destruction is not scheduled; destroy it    */
            cap->valid = -1;
            pthread_mutex_unlock(&cap->valid_lck);
            pthread_rwlock_unlock(&handler->cap_lck);

            logmsg(DEBUG, "Handler %lu: Removing expired capability.",
                   handler->tid);
            pthread_rwlock_wrlock(&handler->cap_lck);
            logmsg(DEBUG, "handle_read: acquired local cap list lock.");
            pthread_mutex_destroy(&cap->valid_lck);
            free(cap);

            /* restart iteration since other threads may have already       *
             * deleted the successor of cap                                 */
            handler->caps = slist_remove(handler->caps, cap);
            lptr = handler->caps;

            logmsg(DEBUG, "handle_read: relocking lists after deletion.");
            /* return writer's lock and take reader's lock again (perf.)    */
            pthread_rwlock_unlock(&handler->cap_lck);
            pthread_rwlock_rdlock(&handler->cap_lck);
    
            continue;
        }

        if (cap->valid < 0) {
            /* cap is invalid and scheduled for removal, simply continue    */
            pthread_mutex_unlock(&cap->valid_lck);
            lptr = lptr->next;
            continue;
        }
        pthread_mutex_unlock(&cap->valid_lck);
    
        logmsg(DEBUG, "Cap params: didx = %u, sidx = %u, saddr = %lu, "
               "eaddr = %lu.", cap->dev_idx, cap->vslc_idx, cap->start_addr,
               cap->end_addr);

        if (cap->dev_idx == didx && 
            cap->vslc_idx == sidx &&
            addr >= cap->start_addr && 
            (addr + len) <= cap->end_addr &&
            (cap->rights & CAP_READ)) {
            break;
        }

        lptr = lptr->next;
    }

    pthread_rwlock_unlock(&handler->cap_lck);

    if (lptr == NULL) {
        /* No suitable capability was found */
        logmsg(ERROR, "Handler %lu: Read operation failed due to insufficient "
               "permissions.", handler->tid);
        return(R_PERM);
    }

    lptr = devs;
    for (i = 0; i < didx; i++)
        lptr = lptr->next;

    dev = (struct crdss_bdev *) lptr->data;

    /* load disk data into the rdma buffer, mind the STM translation process*/
    while (len != 0) {
        size_t lba;                     /* LBA for this translation step    */
        size_t nr_seq;                  /* number of bytes with seq. access */
        size_t rlen;                    /* number of bytes to read from disk*/

        if (dev->ops.translate(dev, sidx, addr + offset, &lba, &nr_seq)) {
            logmsg(ERROR, "Handler %lu: Error during STM translation.",
                   handler->tid);
            return(R_FAILURE);
        }

        rlen = (nr_seq > len) ? len : nr_seq;
        if (pread(dev->fd, handler->data_buf + rdma_offs + offset, rlen, 
            (off_t) lba) == -1) {
            logmsg(ERROR, "Handler %lu: Failed to read data from device (%d).",
                   handler->tid, errno);
            return(R_FAILURE);
        }

        offset += rlen;
        len    -= rlen;
    }

    return(R_SUCCESS);
}

/****************************************************************************
 *
 * Handles a client's write request. The function checks whether the caps that
 * the client owns are sufficient for the access. If so, the corresponding
 * data from the local rdma buffer is written to the disk. The client is 
 * responsible for setting the content of the server's RDMA buffer region
 * correctly.
 *
 * Params: handler   - handler structure of the calling thread.
 *         didx      - device index of data read.
 *         sidx      - vslice index of data read.
 *         addr      - starting virtual LBA for reading data.
 *         len       - length of data to read.
 *         rdma_offs - offset in rdma buffers.
 *
 * Returns: An error code as defined in src/include/protocol.h
 */
static int handle_write(struct handler *handler, uint16_t didx, uint32_t sidx,
                        uint64_t addr, uint32_t len, uint64_t rdma_offs) {
    unsigned int i;
    size_t offset = 0;                      /* offset in RDMA buffer        */

    struct slist *lptr     = NULL;          /* ptr for list iteration       */
    struct crdss_bdev *dev = NULL;          /* device to read from          */
    
    if (rdma_offs > handler->ibctx->rdma_mr->length - 1) {
        logmsg(ERROR, "Handler %lu: RDMA offset is out of bounds (write).",
               handler->tid);
        return(1);
    }

    /* check whether access is allowed */
    pthread_rwlock_rdlock(&handler->cap_lck);

    for (lptr = handler->caps; lptr != NULL;) {
        struct crdss_srv_cap *cap = (struct crdss_srv_cap *) lptr->data;

        pthread_mutex_lock(&cap->valid_lck);
        if (cap->valid == 0) {
            /* cap became void, destruction is not scheduled; destroy it    */
            cap->valid = -1;
            pthread_mutex_unlock(&cap->valid_lck);
            pthread_rwlock_unlock(&handler->cap_lck);

            logmsg(DEBUG, "Handler %lu: Removing expired capability.",
                   handler->tid);
            pthread_rwlock_wrlock(&handler->cap_lck);
            pthread_mutex_destroy(&cap->valid_lck);
            free(cap);

            /* restart iteration since other threads may have already       *
             * deleted the successor of cap                                 */
            handler->caps = slist_remove(handler->caps, cap);
            lptr = handler->caps;

            /* return writer's lock and take reader's lock again (perf.)    */
            pthread_rwlock_unlock(&handler->cap_lck);
            pthread_rwlock_rdlock(&handler->cap_lck);

            continue;
        }

        if (cap->valid < 0) {
            /* cap is invalid and scheduled for removal, simply continue    */
            pthread_mutex_unlock(&cap->valid_lck);
            lptr = lptr->next;
            continue;
        }
        pthread_mutex_unlock(&cap->valid_lck);

        if (cap->dev_idx == didx && 
            cap->vslc_idx == sidx &&
            addr >= cap->start_addr && 
            (addr + len) <= cap->end_addr &&
            (cap->rights & CAP_WRITE)) {
            break;
        }

        lptr = lptr->next;
    }

    pthread_rwlock_unlock(&handler->cap_lck);

    if (lptr == NULL) {
        /* No suitable capability was found */
        logmsg(ERROR, "Handler %lu: Write operation failed due to insufficient "
               "permissions of client.", handler->tid);
        return(R_PERM);
    }

    lptr = devs;
    for (i = 0; i < didx; i++)
        lptr = lptr->next;

    dev = (struct crdss_bdev *) lptr->data;

    /* write data from buffer to the disk                                   */
    while (len != 0) {
        size_t lba;                     /* LBA for this translation step    */
        size_t nr_seq;                  /* number of bytes with seq. access */
        size_t rlen;                    /* number of bytes to write to disk */

        if (dev->ops.translate(dev, sidx, addr + offset, &lba, &nr_seq)) {
            logmsg(ERROR, "Handler %lu: Error during STM translation.",
                   handler->tid);
            return(R_FAILURE);
        }

        rlen = (nr_seq > len) ? len : nr_seq;
        if (pwrite(dev->fd, handler->data_buf + rdma_offs + offset, rlen, 
            (off_t) lba) == -1) {
            logmsg(ERROR, "Handler %lu: Failed to read data from device (%d).",
                   handler->tid, errno);
            return(R_FAILURE);
        }

        offset += rlen;
        len    -= rlen;
    }

    return(R_SUCCESS);
}

/****************************************************************************
 *
 * Derives a new capability from the cap identified by the ID passed to 
 * this routine. The new capability will be placed inside a new revocation
 * domain which will be a child of the rdom of the parent cap. A pointer to
 * the new capability is returned via the parameter ncap. It only contains
 * a valid reference if this function succeeds.
 *
 * Params: handler - handler structure of the calling thread.
 *         par_id  - cap id of parent cap.
 *         didx    - device index of new cap.
 *         sidx    - vslice index of new cap.
 *         saddr   - start address of new cap.
 *         eaddr   - end address of new cap.
 *         rights  - permissions encoded in new capability.
 *         ncap    - pointer to new capability (output parameter).
 *
 * Returns: An error code as defined in include/protocol.h.
 */
static int handle_drvcap2(struct handler *handler, unsigned char *par_id,
                          uint16_t didx, uint32_t sidx, uint64_t saddr,
                          uint64_t eaddr, uint16_t rights,
                          struct crdss_srv_cap **ncap) {
    struct crdss_srv_cap *new_cap;          /* new capability to create     */
    struct crdss_srv_cap *new_cap_cpy;      /* handler-local copy of new_cap*/
    struct crdss_srv_cap *par_cap;          /* cap identified by par_id     */
    struct rev_dom_node  *new_node;         /* new rdom node                */

    struct slist *lptr;                     /* list iteration pointer       */

    /* firstly, try allocation of required data structures */
    new_cap     = calloc(1, sizeof(struct crdss_srv_cap));
    new_cap_cpy = calloc(1, sizeof(struct crdss_srv_cap));
    new_node    = calloc(1, sizeof(struct rev_dom_node));
    if (new_cap_cpy == NULL || new_cap_cpy == NULL || new_node == NULL) {
        logmsg(ERROR, "Failed to allocate memory for capability.");
        
        if (new_cap != NULL)     free(new_cap);
        if (new_cap_cpy != NULL) free(new_cap_cpy);
        if (new_node != NULL)    free(new_node);
    
        return(R_FAILURE);
    }

    /* fill new cap */
    new_cap->dev_idx    = didx;
    new_cap->vslc_idx   = sidx;
    new_cap->start_addr = saddr;
    new_cap->end_addr   = eaddr;
    new_cap->rights     = rights;

    new_cap->valid = 1;
    pthread_mutex_init(&new_cap->valid_lck, NULL);
    
    /* complete the cap copy for our local list                 */
    new_cap_cpy->dev_idx    = didx;
    new_cap_cpy->vslc_idx   = sidx;
    new_cap_cpy->start_addr = saddr;
    new_cap_cpy->end_addr   = eaddr;
    new_cap_cpy->rights     = rights;

    new_cap_cpy->valid = 1;
    pthread_mutex_init(&new_cap_cpy->valid_lck, NULL);

    /* check if the requested revocation domain exists and insert the cap in*
     * both management structures                                           */
    pthread_mutex_lock(&cap_lck);

    /* check if there actually is a capability with the ID given            */
    for (lptr = cap_list; lptr != NULL; lptr = lptr->next) {
        par_cap = (struct crdss_srv_cap *) lptr->data;

        if (memcmp(par_cap->id, par_id, CAP_ID_LEN) == 0)
            break;
    }

    if (lptr == NULL || srv_cap_is_subset(new_cap, par_cap) != 0) {
        pthread_mutex_unlock(&cap_lck);
        logmsg(ERROR, "Handler %lu: Client specified invalid parent cap.", 
               handler->tid);
        free(new_cap);
        free(new_cap_cpy);
        free(new_node);

        return(R_INVAL);
    }

    /* now, we still need to find a free cap id and a new domid             */
    find_free_cap_id(new_cap->id, cap_list);
    if (find_free_rdom_id(&new_node->dom_key, &max_rdom, &free_dom_ids)) {
        pthread_mutex_unlock(&cap_lck);
        logmsg(ERROR, "Failed to allocate memory for capability.");
        free(new_cap);
        free(new_cap_cpy);
        free(new_node);

        return(R_FAILURE);
    }

    /* copy final IDs to local cap */
    memcpy(&new_cap_cpy->id, &new_cap->id, CAP_ID_LEN);
    new_cap_cpy->rev_dom = new_node;
    new_cap->rev_dom     = new_node;
    new_node->parent     = par_cap->rev_dom;

    /* everything is ok, insert the new cap in the global caplist           */
    /* insert new revdom node in list of root rdoms                         */
    if (slist_insert(&par_cap->rev_dom->children, new_node) ||
        slist_insert(&dom_list, new_node) ||
        slist_insert(&cap_list, new_cap)  ||
        slist_insert(&new_node->caps, new_cap) ||
        slist_insert(&new_node->caps, new_cap_cpy)) {
        
        /* return id, we do not care if its lost here */
        slist_insert(&free_dom_ids, (void *) (uint64_t) new_cap->rev_dom);

        /* remove items from list, they remain unchanged if item wasn't found*/
        par_cap->rev_dom->children = slist_remove(par_cap->rev_dom->children, 
                                                  new_node);
        dom_list = slist_remove(dom_list, new_node);
        cap_list = slist_remove(cap_list, new_cap);
        new_node->caps = slist_remove(new_node->caps, new_cap);
        new_node->caps = slist_remove(new_node->caps, new_cap_cpy);

        pthread_mutex_unlock(&cap_lck);

        logmsg(ERROR, "Handler %lu: Failed to insert cap in global data "
                      "structures.", handler->tid);
        free(new_cap);
        free(new_cap_cpy);
        free(new_node);
                
        return(R_FAILURE);
    }

    /* insert new capability in local cap list of handler                   */
    pthread_rwlock_rdlock(&handler->cap_lck);
    if (slist_insert(&handler->caps, new_cap_cpy)) {
        pthread_rwlock_unlock(&handler->cap_lck);
        
        slist_insert(&free_dom_ids, (void *) (uint64_t) new_cap->rev_dom);
        par_cap->rev_dom->children = slist_remove(par_cap->rev_dom->children, 
                                                  new_node);
        dom_list = slist_remove(dom_list, new_node);
        cap_list = slist_remove(cap_list, new_cap);
        new_node->caps = slist_remove(new_node->caps, new_cap);
        new_node->caps = slist_remove(new_node->caps, new_cap_cpy);
        
        pthread_mutex_unlock(&cap_lck);

        logmsg(ERROR, "Handler %lu: Failed to insert new cap into handler's "
                      "cap list.", handler->tid);
        free(new_cap_cpy);
        free(new_cap);
        free(new_node);
    
        return(R_FAILURE);
    }

    pthread_rwlock_unlock(&handler->cap_lck);
    pthread_mutex_unlock(&cap_lck);

    *ncap = new_cap;
    return(R_SUCCESS);
}

/****************************************************************************
 *
 * Handles requests of a capability manager. 
 * handler will be aborted if client does not follow the crdss protocol.
 *
 * TODO: add documentation.
 */
static void handle_capmgr(struct handler *handler) {
    struct crdss_srv_cap *new_cap     = NULL; /* pointer to new capability  */
    struct crdss_srv_cap *new_cap_cpy = NULL; /* pointer to local copy of a *
                                               * newly created capability   */
    struct rev_dom_node *new_node;            /* new revocation domain      */

    uint8_t op_res;                         /* result of server operations  */

    unsigned char cap_buf[CAP_ID_LEN];      /* buffer for receiving cap ids */

    /* fields for reading data from network */
    uint8_t msg_type;

    uint16_t device_idx;
    uint32_t slice_idx;
    uint64_t saddr;                             /* start address of cap     */
    uint64_t eaddr;                             /* end address of cap       */
    uint16_t cap_rights;
    uint32_t rdom_id;                           /* id of revocation domain  */

    logmsg(DEBUG, "Handler %lu: entering capmgr handler.", handler->tid);
    while (1) {
        /* every message starts with the type field */
        if (recv(handler->sock, &msg_type, sizeof(uint8_t), MSG_WAITALL) < 1) {
            logmsg(ERROR, "Handler %lu: Connection terminated (status: %s).", 
                   handler->tid, strerror(errno));
            return;
        }
        
        switch (msg_type) {
            case MTYPE_MKCAP:
                /* make a new cap from scratch. The revdom this cap shall   *
                 * belong to is given by the client                         */
                if (read_cap_from_sock(handler->sock, &device_idx, &slice_idx,
                    &saddr, &eaddr, &cap_rights) != 0) {
                    logmsg(ERROR, "Failed to read capability as requested.");
                    return;
                }

                if (recv(handler->sock, &rdom_id,  sizeof(uint32_t), 
                    MSG_WAITALL) < 2) {
                    logmsg(ERROR, "Failed to read rdom id as requested.");
                    return;
                }
    
                /* since the client followed the protocol so far, from now on*
                 * he deserves an answer to his requests                     */
                if (check_cap_bounds(device_idx, slice_idx, saddr, eaddr)) {
                    logmsg(WARN, "Handler %lu: Client requested out-of-bounds "
                           "capability.", handler->tid);
                    op_res = R_INVAL;
                    send(handler->sock, &op_res, sizeof(uint8_t), 0);
                    continue;
                }

                if ((new_cap = malloc(sizeof(struct crdss_srv_cap))) == NULL) {
                    logmsg(ERROR, "Failed to allocate memory for capability.");
                    op_res = R_FAILURE;
                    send(handler->sock, &op_res, sizeof(uint8_t), 0);
                    continue;
                }

                new_cap_cpy = malloc(sizeof(struct crdss_srv_cap));
                if (new_cap_cpy == NULL) {
                    logmsg(ERROR, "Failed to allocate memory for capability.");
                    free(new_cap);
                    op_res = R_FAILURE;
                    send(handler->sock, &op_res, sizeof(uint8_t), 0);
                    continue;
                }

                /* fill new cap */
                new_cap->dev_idx    = device_idx;
                new_cap->vslc_idx   = slice_idx;
                new_cap->start_addr = saddr;
                new_cap->end_addr   = eaddr;
                new_cap->rights     = cap_rights;

                new_cap->valid = 1;
                pthread_mutex_init(&new_cap->valid_lck, NULL);
    
                /* complete the cap copy for our local list                 */
                new_cap_cpy->dev_idx    = device_idx;
                new_cap_cpy->vslc_idx   = slice_idx;
                new_cap_cpy->start_addr = saddr;
                new_cap_cpy->end_addr   = eaddr;
                new_cap_cpy->rights     = cap_rights;

                new_cap_cpy->valid = 1;
                pthread_mutex_init(&new_cap_cpy->valid_lck, NULL);

                /* check if the requested revocation domain exists and      *
                 * insert the cap in all  management structures             */
                op_res = register_cap_with_dom(handler, new_cap, new_cap_cpy,
                                               NULL, rdom_id);
                if (op_res != R_SUCCESS) {
                    logmsg(ERROR, "Handler %lu: Cap registration failed.",
                           handler->tid);
                    send(handler->sock, &op_res, 1, 0);
                    continue;
                }

                logmsg(DEBUG, "Handler %lu: registered new cap %p.", 
                       handler->tid, new_cap);

                /* lastly, send the id of the new cap to the capmgr         */
                send(handler->sock, &op_res, sizeof(uint8_t), 0);
                send(handler->sock, &new_cap->id, CAP_ID_LEN, 0);
                break;
            case MTYPE_MKCAP2:
                logmsg(INFO, "Handler %lu: Handling MKCAP2.", handler->tid);
                /* create a new cap from scratch. this cap will be member of *
                 * a new revocation domain                                   */
                if (read_cap_from_sock(handler->sock, &device_idx, &slice_idx,
                    &saddr, &eaddr, &cap_rights) != 0) {
                    logmsg(ERROR, "Failed to read capability as requested.");
                    return;
                }
                logmsg(DEBUG, "Handler %lu: MKCAP2 read data.", handler->tid);

                if (check_cap_bounds(device_idx, slice_idx, saddr, eaddr)) {
                    logmsg(WARN, "Handler %lu: Client requested out-of-bounds "
                           "capability.", handler->tid);
                    op_res = R_INVAL;
                    send(handler->sock, &op_res, sizeof(uint8_t), 0);
                    continue;
                }
                logmsg(DEBUG, "Handler %lu: Cap check ok.", handler->tid);

                /* since the client followed the protocol so far, from now on*
                 * he deserves an answer to his requests                     */
                new_cap     = calloc(1, sizeof(struct crdss_srv_cap));
                new_cap_cpy = calloc(1, sizeof(struct crdss_srv_cap));
                new_node    = calloc(1, sizeof(struct rev_dom_node));
                if (new_cap_cpy == NULL || new_cap_cpy == NULL || 
                    new_node == NULL) {
                    
                    logmsg(ERROR, "Failed to allocate memory for capability.");
                    if (new_cap != NULL)     free(new_cap);
                    if (new_cap_cpy != NULL) free(new_cap_cpy);
                    if (new_node != NULL)    free(new_node);
                    
                    op_res = R_FAILURE;
                    send(handler->sock, &op_res, sizeof(uint8_t), 0);
                    continue;
                }

                /* fill new cap */
                new_cap->dev_idx    = device_idx;
                new_cap->vslc_idx   = slice_idx;
                new_cap->start_addr = saddr;
                new_cap->end_addr   = eaddr;
                new_cap->rights     = cap_rights;

                new_cap->valid = 1;
                pthread_mutex_init(&new_cap->valid_lck, NULL);
    
                /* complete the cap copy for our local list                 */
                new_cap_cpy->dev_idx    = device_idx;
                new_cap_cpy->vslc_idx   = slice_idx;
                new_cap_cpy->start_addr = saddr;
                new_cap_cpy->end_addr   = eaddr;
                new_cap_cpy->rights     = cap_rights;

                new_cap_cpy->valid = 1;
                pthread_mutex_init(&new_cap_cpy->valid_lck, NULL);

                /* check if the requested revocation domain exists and      *
                 * insert the cap in both management structures             */
                pthread_mutex_lock(&cap_lck);

                /* now, we still need to find a free cap id and a new domid */
                find_free_cap_id(new_cap->id, cap_list);
                if (find_free_rdom_id(&new_node->dom_key, &max_rdom, 
                    &free_dom_ids)) {
                    pthread_mutex_unlock(&cap_lck);
                    logmsg(ERROR, "Handler %lu: No free rdom domain available.",
                           handler->tid);
                    free(new_cap);
                    free(new_cap_cpy);
                    free(new_node);

                    op_res = R_FAILURE;
                    send(handler->sock, &op_res, sizeof(uint8_t), 0);
                    continue;
                }

                /* copy final IDs to local cap */
                memcpy(&new_cap_cpy->id, &new_cap->id, CAP_ID_LEN);
                new_cap->rev_dom     = new_node;
                new_cap_cpy->rev_dom = new_node;

                /* everything is ok, insert the new cap in the global caplist */
                /* insert new revdom node in list of root rdoms               */
                if (slist_insert(&dom_tree, new_node) ||
                    slist_insert(&dom_list, new_node) ||
                    slist_insert(&cap_list, new_cap) ||
                    slist_insert(&new_node->caps, new_cap) ||
                    slist_insert(&new_node->caps, new_cap_cpy)) {
                    /* return id, we do not care if its lost here */
                    slist_insert(&free_dom_ids,
                        (void *) (uint64_t) new_cap->rev_dom);

                    /* remove items from lists, lists remain unchanged if   *
                     * item was not found                                   */
                    dom_tree = slist_remove(dom_tree, new_node);
                    dom_list = slist_remove(dom_list, new_node);
                    cap_list = slist_remove(cap_list, new_cap);
                    new_node->caps = slist_remove(new_node->caps, new_cap);
                    new_node->caps = slist_remove(new_node->caps, new_cap_cpy);

                    pthread_mutex_unlock(&cap_lck);

                    logmsg(ERROR, "Handler %lu: Failed to allocate list elem "
                           "during cap creation!", handler->tid);
                    free(new_cap);
                    free(new_cap_cpy);
                    free(new_node);
                    op_res = R_FAILURE;
                    send(handler->sock, &op_res, sizeof(uint8_t), 0);
                    continue;
                }

                /* insert new capability in local cap list of handler       */
                pthread_rwlock_rdlock(&handler->cap_lck);
                if (slist_insert(&handler->caps, new_cap_cpy)) {
                    pthread_rwlock_unlock(&handler->cap_lck);
                    slist_insert(&free_dom_ids, 
                        (void *) (uint64_t) new_cap->rev_dom);
                    cap_list = slist_remove(cap_list, new_cap);
                    pthread_mutex_unlock(&cap_lck);

                    logmsg(ERROR, "Handler %lu: Failed to allocate list elem "
                           "during cap creation!", handler->tid);
                    free(new_cap_cpy);
                    free(new_cap);
                    free(new_node);
                    op_res = R_FAILURE;
                    send(handler->sock, &op_res, sizeof(uint8_t), 0);
                    continue;
                }

                pthread_rwlock_unlock(&handler->cap_lck);
                pthread_mutex_unlock(&cap_lck);

                logmsg(DEBUG, "Handler %lu: registered new cap %p.", 
                       handler->tid, new_cap);

                /* lastly, send the id of the new cap to the capmgr         */
                op_res  = R_SUCCESS;
                rdom_id = htonl(new_cap->rev_dom->dom_key);
                send(handler->sock, &op_res, sizeof(uint8_t), 0);
                send(handler->sock, &new_cap->id, CAP_ID_LEN, 0);
                send(handler->sock, &rdom_id, sizeof(uint32_t), 0);
                logmsg(DEBUG, "Handler %lu: transferred new cap %p.",
                       handler->tid, new_cap);
                break;
            case MTYPE_DRVCAP:
                /* derive a cap from one of the caps that are already       *
                 * registered with this thread. the new cap will have the   *
                 * same revocation domain as its parent                     */
                if (recv(handler->sock, cap_buf, CAP_ID_LEN, 
                         MSG_WAITALL) < CAP_ID_LEN) {
                    logmsg(ERROR, "Handler %lu: Failed to read parent cap id.",
                           handler->tid);
                    return;
                }

                if (read_cap_from_sock(handler->sock, &device_idx, &slice_idx,
                    &saddr, &eaddr, &cap_rights) != 0) {
                    logmsg(ERROR, "Handler %lu: Failed to read capability as " 
                           "requested.", handler->tid);
                    return;
                }
   
                /* since the client followed the protocol so far, from now on*
                 * he deserves an answer to his requests                     */
                op_res = handle_drvcap(handler, cap_buf, device_idx, slice_idx,
                                       saddr, eaddr, cap_rights, &new_cap);
                if (op_res != R_SUCCESS) {
                    logmsg(ERROR, "Handler %lu: Cap derivation failed (%u).",
                           handler->tid, op_res);
                    send(handler->sock, &op_res, 1, 0);
                    continue;
                }
                else {
                    logmsg(DEBUG, "Handler %lu: derived new cap %p.", 
                           handler->tid, new_cap);

                    /* lastly, send the cap id to the capmgr */
                    send(handler->sock, &op_res, sizeof(uint8_t), 0);
                    send(handler->sock, &new_cap->id, CAP_ID_LEN, 0);
                }

                break;
            case MTYPE_DRVCAP2:
                /* derive a cap from one of the caps that are already       *
                 * registered with this thread. a new revocation domain     *
                 * will be created with the new cap being the first member. *
                 * this new revocation domain will be a descendant of the   *
                 * rdom the parent cap was assigned to.                     */
                logmsg(DEBUG, "Handler %lu: Processing DRVCAP2 request.",
                       handler->tid);
                if (recv(handler->sock, cap_buf, CAP_ID_LEN, 
                         MSG_WAITALL) < CAP_ID_LEN) {
                    logmsg(ERROR, "Handler %lu: Failed to read parent cap id.",
                           handler->tid);
                    return;
                }

                if (read_cap_from_sock(handler->sock, &device_idx, &slice_idx,
                    &saddr, &eaddr, &cap_rights) != 0) {
                    logmsg(ERROR, "Handler %lu: Failed to read capability as " 
                           "requested.", handler->tid);
                    return;
                }

                op_res = handle_drvcap2(handler, cap_buf, device_idx, slice_idx,
                                        saddr, eaddr, cap_rights, &new_cap);

                if (op_res != R_SUCCESS) {
                    logmsg(ERROR, "Handler %lu: Cap derivation failed.",
                           handler->tid);
                    send(handler->sock, &op_res, 1, 0);
                }
                else {
                    logmsg(DEBUG, "Handler %lu: registered new cap %p.", 
                           handler->tid, new_cap);

                     /* lastly, send the id of the new cap to the capmgr    */
                     rdom_id = htonl(new_cap->rev_dom->dom_key);
                     send(handler->sock, &op_res, sizeof(uint8_t), 0);
                     send(handler->sock, &new_cap->id, CAP_ID_LEN, 0);
                     send(handler->sock, &rdom_id, sizeof(uint32_t), 0);
                     logmsg(DEBUG, "Handler %lu: transferred new cap %p.",
                            handler->tid, new_cap);
                }

                break;
            case MTYPE_RMDOM:
                /* removes all caps of a certain rev dom from the global cap*
                 * list, destroys the rdoms and renders handler's local     *
                 * copies of caps invalid                                   */
                if (recv(handler->sock, &rdom_id,  sizeof(uint32_t), 
                    MSG_WAITALL) < 4) {
                    logmsg(ERROR, "Failed to read rdom id as requested.");
                    return;
                }
               
                rdom_id = ntohl(rdom_id);
                op_res = handle_rmdom(handler, rdom_id);
                if (op_res != R_SUCCESS) {
                    logmsg(WARN, "Handler %lu: Failed to revoke domain %u.",
                           handler->tid, rdom_id);
                }

                send(handler->sock, &op_res, sizeof(uint8_t), 0);
                break;
            case MTYPE_REGCAP:
                /* register cap with this handler thread                    */
                logmsg(DEBUG, "Handler %lu: Handling REGCAP request.", 
                       handler->tid);
                if (recv(handler->sock, cap_buf, CAP_ID_LEN, 
                         MSG_WAITALL) < CAP_ID_LEN) {
                    logmsg(ERROR, "Handler %lu: Failed to read cap id.",
                           handler->tid);
                    return;
                }

                op_res = handle_regcap(handler, cap_buf);
                if (op_res == R_SUCCESS) {
                    logmsg(INFO, "Handler %lu: Registered new cap.", 
                           handler->tid);
                }
                else {
                    logmsg(INFO, "Handler %lu: Cap registration failed (%u).",
                           handler->tid, op_res);
                }

                /* finally send a status answer to the client */
                send(handler->sock, &op_res, 1, 0);

                break;
            case MTYPE_VSLCINFO:
                if (recv(handler->sock, &device_idx,  2, MSG_WAITALL) < 2) {
                    logmsg(ERROR, "Failed to read dev index as requested.");
                    return;
                }
                if (recv(handler->sock, &slice_idx,  4, MSG_WAITALL) < 4) {
                    logmsg(ERROR, "Failed to read slice index as requested.");
                    return;
                }

                device_idx = ntohs(device_idx);
                slice_idx  = ntohl(slice_idx);

                /* reuse saddr as variable for storing the vslice's size    */
                if (get_vslc_size(device_idx, slice_idx, &saddr) != 0) {
                    op_res = R_FAILURE;
                    send(handler->sock, &op_res, 1, 0);
                    break;
                }

                logmsg(DEBUG, "Handler %lu: Reporting vslice (didx %u, "
                       "sidx %u) with a size of %lu bytes.", handler->tid,
                       device_idx, slice_idx, saddr);

                saddr  = htobe64(saddr);
                op_res = R_SUCCESS;

                send(handler->sock, &op_res, 1, 0);
                send(handler->sock, &saddr, 8, 0);

                break;
            default:
                logmsg(WARN, "Handler %lu: Received unknown message type %u.",
                       handler->tid, msg_type);
                return;
        }
    }
}

/****************************************************************************
 *
 * Handles InfiniBand requests of a normal client.
 *
 * Params: ctx - pionts to a handler structure.
 *
 * Returns: NULL
 */
static void *ib_worker(void *ctx) {
    struct handler *handler = (struct handler *) ctx;

    struct crdss_srv_cap *new_cap;          /* pointer to new capability    */

    uint8_t op_res;                         /* result of server operations  */

    unsigned char send_buf[MAX_MSG_LEN];    /* send buffer for ctrl messages*/

    /* fields for reading data from network */
    unsigned char *msg;                     /* buffer for IB message        */
    uint8_t  msg_type;                      /* type of next message         */
    uint32_t imm;                           /* imm. received with last msg. */

    uint16_t device_idx;
    uint32_t slice_idx;
    uint64_t saddr;                             /* start address of cap     */
    uint64_t eaddr;                             /* end address of cap       */
    uint16_t cap_rights;
    uint32_t rdom_id;                           /* id of revocation domain  */

    uint32_t length;                            /* length of data operation */
    uint64_t rdma_offs;                         /* offset in RDMA buffer    */
    uint64_t poll_field;                        /* doorbell address offset  */

    logmsg(DEBUG, "Handler %lu: Started IB worker thread.", handler->tid);
    while (1) {
        if (get_next_msg_type(handler, &msg, &msg_type, &imm) != 0) {
            logmsg(ERROR, "Handler %lu: IB Worker: Error in InfiniBand "
                   "communication.", handler->tid);
            return(NULL); 
        }

        switch (msg_type) {
            case MTYPE_REGCAP:
                /* register cap with this handler thread                    */
                logmsg(INFO, "Handler %lu (IBW): Handling REGCAP request.", 
                       handler->tid);
                    
                /* IB path, cap ID has one byte offset */
                op_res = handle_regcap(handler, msg + 1);

                if (op_res == R_SUCCESS) {
                    logmsg(INFO, "Handler %lu (IBW): Registered new cap.", 
                           handler->tid);
                }
                else {
                    logmsg(INFO, "Handler %lu (IBW): Cap registration failed "
                           "(%u).", handler->tid, op_res);
                }

                /* send a status answer to the client (via IB message)      */
                memset(send_buf, 0, MAX_MSG_LEN);
                memcpy(send_buf, &op_res, sizeof(uint8_t));
                post_msg_sr(handler->ibctx, send_buf, imm);

                /* requeue receive request */
                post_msg_rr(handler->ibctx, msg, 1);

                break;
            case MTYPE_DRVCAP:
                /* derive a cap from one of the caps that are already       *
                 * registered with this thread. the new cap will have the   *
                 * same revocation domain as its parent                     */
                /* I know that this way of unmarshalling a message is   *
                 * obnoxious and it nests the protocol deeply into the  *
                 * code, but for now, this must suffice                 */
                device_idx = ntohs(*((uint16_t *) (msg + 1 + CAP_ID_LEN)));
                slice_idx  = ntohl(*((uint32_t *) (msg + 3 + CAP_ID_LEN)));
                saddr      = be64toh(*((uint64_t *) (msg + 7 + CAP_ID_LEN)));
                eaddr      = be64toh(*((uint64_t *) (msg + 15 + CAP_ID_LEN)));
                cap_rights = ntohs(*((uint16_t *) (msg + 23 + CAP_ID_LEN)));

                op_res = handle_drvcap(handler, msg + 1, device_idx, slice_idx, 
                                saddr, eaddr, cap_rights, &new_cap);
                
                if (op_res != R_SUCCESS) {
                    logmsg(ERROR, "Handler %lu: Cap derivation failed (%u).",
                           handler->tid, op_res);

                    memset(send_buf, 0, MAX_MSG_LEN);
                    memcpy(send_buf, &op_res, sizeof(uint8_t));
                    post_msg_sr(handler->ibctx, send_buf, imm);

                    /* requeue receive request */
                    post_msg_rr(handler->ibctx, msg, 1);
                    
                    continue;
                }
                else {
                    logmsg(DEBUG, "Handler %lu: derived new cap %p.", 
                           handler->tid, new_cap);

                    /* lastly, send the cap id to the capmgr */
                    memset(send_buf, 0, MAX_MSG_LEN);
                    memcpy(send_buf, &op_res, sizeof(uint8_t));
                    memcpy(send_buf + 1, &new_cap->id, CAP_ID_LEN);
                    post_msg_sr(handler->ibctx, send_buf, imm);

                    /* requeue receive request */
                    post_msg_rr(handler->ibctx, msg, 1);
                }

                break;
            case MTYPE_DRVCAP2:
                /* derive a cap from one of the caps that are already       *
                 * registered with this thread. a new revocation domain     *
                 * will be created with the new cap being the first member. *
                 * this new revocation domain will be a descendant of the   *
                 * rdom the parent cap was assigned to.                     */
                logmsg(DEBUG, "Handler %lu: Processing DRVCAP2 request.",
                       handler->tid);
                /* I know that this way of unmarshalling a message is   *
                 * obnoxious and it nests the protocol deeply into the  *
                 * code, but for now, this must suffice                 */
                device_idx = ntohs(*((uint16_t *) (msg + 1 + CAP_ID_LEN)));
                slice_idx  = ntohl(*((uint32_t *) (msg + 3 + CAP_ID_LEN)));
                saddr      = be64toh(*((uint64_t *) (msg + 7 + CAP_ID_LEN)));
                eaddr      = be64toh(*((uint64_t *) (msg + 15 + CAP_ID_LEN)));
                cap_rights = ntohs(*((uint16_t *) (msg + 23 + CAP_ID_LEN)));

                op_res = handle_drvcap(handler, msg + 1, device_idx, slice_idx, 
                                saddr, eaddr, cap_rights, &new_cap);

                if (op_res != R_SUCCESS) {
                    logmsg(ERROR, "Handler %lu: Cap derivation failed (%u).",
                           handler->tid, op_res);
                        
                    memset(send_buf, 0, MAX_MSG_LEN);
                    memcpy(send_buf, &op_res, sizeof(uint8_t));
                    post_msg_sr(handler->ibctx, send_buf, imm);

                    /* requeue receive request */
                    post_msg_rr(handler->ibctx, msg, 1);
                    
                    continue;
                }
                else {
                    logmsg(DEBUG, "Handler %lu: registered new cap %p.", 
                           handler->tid, new_cap);

                    /* lastly, send the id of the new cap to the capmgr    */
                    rdom_id = htonl(new_cap->rev_dom->dom_key);
                    
                    memset(send_buf, 0, MAX_MSG_LEN);
                    memcpy(send_buf, &op_res, sizeof(uint8_t));
                    memcpy(send_buf + 1, &new_cap->id, CAP_ID_LEN);
                    memcpy(send_buf + 1 + CAP_ID_LEN, &rdom_id,
                           sizeof(uint32_t));
                    post_msg_sr(handler->ibctx, send_buf, imm);
                        
                    /* requeue receive request */
                    post_msg_rr(handler->ibctx, msg, 1);
                }

                logmsg(DEBUG, "Handler %lu: transferred new cap %p.",
                       handler->tid, new_cap);
                break;
            case MTYPE_RMDOM:
                /* removes all caps of a certain rev dom from the global cap*
                 * list, destroys the rdoms and renders handler's local     *
                 * copies of caps invalid                                   */
                rdom_id = ntohl(*((uint32_t *) (msg + 1)));
                logmsg(INFO, "Handler %lu: Client requests deletion of domain "
                       "%u.", handler->tid, rdom_id);

                op_res = handle_rmdom(handler, rdom_id);
                if (op_res != R_SUCCESS) {
                    logmsg(WARN, "Handler %lu: Failed to revoke domain %u.",
                           handler->tid, rdom_id);
                }
                else {
                    logmsg(INFO, "Handler %lu: Deleted domain %u.", 
                           handler->tid, rdom_id);
                }

                memset(send_buf, 0, MAX_MSG_LEN);
                memcpy(send_buf, &op_res, sizeof(uint8_t));
                post_msg_sr(handler->ibctx, send_buf, imm);
                        
                /* requeue receive request */
                post_msg_rr(handler->ibctx, msg, 1);
                
                break;
            case MTYPE_READ:
                /* transfer data to the client                              */
                logmsg(DEBUG, "Handler %lu: Received READ request.", 
                       handler->tid);

                device_idx = ntohs(*((uint16_t *) (msg + 1)));
                slice_idx  = ntohl(*((uint32_t *) (msg + 3)));
                saddr      = be64toh(*((uint64_t *) (msg + 7)));
                length     = ntohl(*((uint32_t *) (msg + 15)));
                rdma_offs  = be64toh(*((uint64_t *) (msg + 19))) -
                             (uint64_t) handler->ibctx->remote_addr;

                logmsg(DEBUG, "Handler %lu: RDMA offset is %lu, remote addr "
                       "is %lu.", handler->tid, rdma_offs, 
                       handler->ibctx->remote_addr);

                op_res = handle_read(handler, device_idx, slice_idx, saddr,
                                     length, rdma_offs);

                if (op_res != R_SUCCESS) {
                    /* send error message as an answer */
                    memcpy(send_buf, &op_res, sizeof(uint8_t));
                    post_msg_sr(handler->ibctx, send_buf, imm);
                }

                /* data loaded, send RDMA request */
                logmsg(DEBUG, "Handler %lu (IBW): Data of read loaded, "
                       "starting RDMA transfer.", handler->tid);
                if (init_rdma_transfer(handler->ibctx, 
                    handler->data_buf + rdma_offs, 
                    (unsigned char *) (handler->ibctx->remote_addr + rdma_offs), 
                    length, 1, imm, 2) != 0) {
                    logmsg(ERROR, "Handler %lu: Sending RDMA request failed.",
                            handler->tid);
                    
                    op_res = R_FAILURE;
                    memcpy(send_buf, &op_res, sizeof(uint8_t));
                    post_msg_sr(handler->ibctx, send_buf, imm);

                    break;
                }

                /* recycle recv request */
                logmsg(DEBUG, "Handler %lu (IBW): Read request done.",
                       handler->tid);
                post_msg_rr(handler->ibctx, msg, 1);

                break;
            case MTYPE_FASTREAD:
                /* transfer data to the client (polling completion at clt)  */
                device_idx = ntohs(*((uint16_t *) (msg + 1)));
                slice_idx  = ntohl(*((uint32_t *) (msg + 3)));
                saddr      = be64toh(*((uint64_t *) (msg + 7)));
                length     = ntohl(*((uint32_t *) (msg + 15)));
                rdma_offs  = be64toh(*((uint64_t *) (msg + 19))) - 
                             (uint64_t) handler->ibctx->remote_addr;
                poll_field = be64toh(*((uint64_t *) (msg + 27))) -
                             (uint64_t) handler->ibctx->remote_addr;

                if (poll_field > (handler->ibctx->rdma_mr->length - 1)) {
                    logmsg(ERROR, "Handler %lu: Unable to set up poll field", 
                           handler->tid);
                    break;
                }

                op_res = handle_read(handler, device_idx, slice_idx, saddr,
                                     length, rdma_offs);

                if (op_res != R_SUCCESS) {
                    /* write error number to client-side doorbell */
                    logmsg(ERROR, "Handler %lu: Read request failed.", 
                           handler->tid);
                    memcpy((unsigned char *) handler->data_buf + poll_field, 
                           &op_res, sizeof(uint8_t));
                    
                    if (write_poll_field(handler->ibctx, 
                        (uint64_t) handler->data_buf + poll_field,
                        (uint64_t) handler->ibctx->remote_addr + poll_field) != 0){
                        logmsg(ERROR, "Handler %lu: Failed to write poll field.",
                               handler->tid);
                    }
                    post_msg_rr(handler->ibctx, msg, 1);
                    break;
                }

                if (init_rdma_transfer(handler->ibctx, 
                    handler->data_buf + rdma_offs, 
                    (unsigned char *) (handler->ibctx->remote_addr + rdma_offs), 
                    length, 0, (uint32_t) poll_field, 1) != 0) {
                    logmsg(ERROR, "Handler %lu: Sending RDMA request failed.",
                            handler->tid);
                    
                    if (write_poll_field(handler->ibctx, 
                        (uint64_t) handler->data_buf + poll_field,
                        (uint64_t) handler->ibctx->remote_addr + poll_field) != 0){
                        logmsg(ERROR, "Handler %lu: Failed to write poll field.",
                               handler->tid);
                    }
                    post_msg_rr(handler->ibctx, msg, 1);
                    break;
                }

                /* recycle recv request */
                post_msg_rr(handler->ibctx, msg, 1);

                break;
            case MTYPE_WRITE:
                /* write data transferred by client to disk                 */
                if (handler->ibctx == NULL) {
                    logmsg(ERROR, "Handler %lu: Received write request without "
                           "active IB connection.", handler->tid);
                    post_msg_rr(handler->ibctx, msg, 1);
                    break;
                }

                device_idx = ntohs(*((uint16_t *) (msg + 1)));
                slice_idx  = ntohl(*((uint32_t *) (msg + 3)));
                saddr      = be64toh(*((uint64_t *) (msg + 7)));
                length     = ntohl(*((uint32_t *) (msg + 15)));
                rdma_offs  = be64toh(*((uint64_t *) (msg + 19))) - 
                             (uint64_t) handler->ibctx->remote_addr;

                op_res = handle_write(handler, device_idx, slice_idx, saddr,
                                      length, rdma_offs);

                /* regardless of the outcome of the operation, send the     *
                 * status and the rdma offset (for identification on clt    *
                 * side) back to the requester                              */
                memcpy(send_buf, &op_res, sizeof(uint8_t));
                memcpy(send_buf + 1, &rdma_offs, sizeof(uint64_t));
                post_msg_sr(handler->ibctx, send_buf, imm);

                /* recycle recv request */
                post_msg_rr(handler->ibctx, msg, 1);
                break;
            case MTYPE_FASTWRITE:
                /* write data transferred by client to disk                 */
                if (handler->ibctx == NULL) {
                    logmsg(ERROR, "Handler %lu: Received write request without "
                           "active IB connection.", handler->tid);
                    post_msg_rr(handler->ibctx, msg, 1);
                    break;
                }

                device_idx = ntohs(*((uint16_t *) (msg + 1)));
                slice_idx  = ntohl(*((uint32_t *) (msg + 3)));
                saddr      = be64toh(*((uint64_t *) (msg + 7)));
                length     = ntohl(*((uint32_t *) (msg + 15)));
                rdma_offs  = be64toh(*((uint64_t *) (msg + 19))) - 
                             (uint64_t) handler->ibctx->remote_addr;

                op_res = handle_write(handler, device_idx, slice_idx, saddr,
                                      length, rdma_offs);

                /* rdma offset now becomes offset for poll field */
                poll_field = be64toh(*((uint64_t *) (msg + 27))) - 
                             (uint64_t) handler->ibctx->remote_addr;
                if (poll_field > (handler->ibctx->rdma_mr->length - 1)) {
                    logmsg(ERROR, "Handler %lu: Invalid poll field in write.",
                           handler->tid);
                    op_res = R_INVAL;
                }

                *((unsigned char *) handler->data_buf + poll_field) = op_res;
                if (write_poll_field(handler->ibctx, 
                    (uint64_t) handler->data_buf + poll_field,
                    (uint64_t) handler->ibctx->remote_addr + poll_field) != 0) {
                    logmsg(ERROR, "Handler %lu: Failed to write poll field.",
                           handler->tid);
                }

                /* recycle recv request */
                post_msg_rr(handler->ibctx, msg, 1);
                break;
            case MTYPE_COMPLETE:
                /* completion request for fast read, now write poll field   */
                logmsg(DEBUG, "Handler %lu: Completed RDMA tansfer for fast "
                       "read request (imm = %u).", handler->tid, imm);

                /* entry found, write poll field of client */
                *((unsigned char *) handler->data_buf + imm) = R_SUCCESS;
                logmsg(DEBUG, "Handler %lu: Writing remote doorbell %p.",
                      handler->tid, 
                      (void *) ((uint64_t) handler->ibctx->remote_addr + imm));

                if (write_poll_field(handler->ibctx, 
                    (uint64_t) handler->data_buf + imm,
                    (uint64_t) handler->ibctx->remote_addr + imm) != 0) {
                    logmsg(ERROR, "Handler %lu: Failed to write poll field "
                           "for fast read completion.", handler->tid);
                }

                logmsg(DEBUG, "Handler %lu: doorbell address written.",
                       handler->tid);

                break;
            case MTYPE_CPOLL:
                handler->use_poll = 1;

                memset(send_buf, 0, MAX_MSG_LEN);
                send_buf[0] = R_SUCCESS;
                post_msg_sr(handler->ibctx, send_buf, imm);
                logmsg(DEBUG, "Handler %lu: switched to polling completion.",
                       handler->tid);

                /* recycle recv request */
                post_msg_rr(handler->ibctx, msg, 1);
                break;
            case MTYPE_CBLOCK:
                handler->use_poll = 0;

                memset(send_buf, 0, MAX_MSG_LEN);
                send_buf[0] = R_SUCCESS;
                post_msg_sr(handler->ibctx, send_buf, imm);
                logmsg(DEBUG, "Handler %lu: switched to blocking completion.",
                       handler->tid);
                
                /* recycle recv request */
                post_msg_rr(handler->ibctx, msg, 1);
                break;
            default:
                logmsg(WARN, "Handler %lu: Received unknown message type %u.",
                       handler->tid, msg_type);
                
                /* recycle recv request */
                post_msg_rr(handler->ibctx, msg, 1);
                break;
        }
    }

    return(NULL);
}

/****************************************************************************
 *
 * Performs the setup of an InfiniBand connection. Data necessary for
 * establishing an RC queue pair is exchanged over the TCP connection of the
 * handler object. The function will spawn the InfiniBand worker threads.
 *
 * Params: handler - context for the client connection.
 *
 * Returns: An error code as specified in src/include/protocol.h
 */
static int handle_ibinit(struct handler *handler) {
    uint16_t rlid;                          /* LID of client queue pair     */
    uint32_t rqpn;                          /* QPN of client queue pair     */
    uint32_t msg_cnt;                       /* capacity of IB message buf.  */
    uint32_t rdmasz;                        /* size of RDMA memory region   */
    uint16_t worker_cnt;                    /* requested no. of IB workers  */
    
    /* always read parameters from socket to retain message bounds */
    if (recv(handler->sock, &rlid, 2, MSG_WAITALL) < 2) {
        logmsg(ERROR, "Handler %lu: Failed to read remote LID.",
               handler->tid);
        return(R_FAILURE);
    }
    if (recv(handler->sock, &rqpn, 4, MSG_WAITALL) < 4) {
        logmsg(ERROR, "Handler %lu: Failed to read remote QPN.",
               handler->tid);
        return(R_FAILURE);
    }
    if (recv(handler->sock, &msg_cnt, 4, MSG_WAITALL) < 4) {
        logmsg(ERROR, "Handler %lu: Failed to read message count.",
               handler->tid);
        return(R_FAILURE);
    }
    if (recv(handler->sock, &rdmasz, 4, MSG_WAITALL) < 4) {
        logmsg(ERROR, "Handler %lu: Failed to read RDMA reg. size.",
               handler->tid);
        return(R_FAILURE);
    }
    if (recv(handler->sock, &worker_cnt, 2, MSG_WAITALL) < 2) {
        logmsg(ERROR, "Handler %lu: Failed to read worker count.",
               handler->tid);
        return(R_FAILURE);
    }

    /* do nothing if this client already has an IB connection  */
    if (handler->ibctx != NULL) {
        logmsg(WARN, "Handler %lu: Client requested IB connection "
              "twice.", handler->tid);
        return(R_INVAL);
    }

    /* client should have at least one capabilitiy registered  */
    if (slist_empty(handler->caps)) {
        logmsg(WARN, "Handler %lu: Client requested IB connection "
               "without specifying capabilities.", handler->tid);
        return(R_PERM);
    }

    /* check if requested number of workers exceeds server limit */
    if (ntohs(worker_cnt) > MAX_SRV_WORKERS) {
        logmsg(ERROR, "Handler %lu: Client requested too many workers (%u). "
               "The limit is %u.", handler->tid, ntohs(worker_cnt), 
               MAX_SRV_WORKERS);
        return(R_PERM);
    }

    /* allocate context and setup data structures */
    if ((handler->ibctx = calloc(1, sizeof(struct ib_ctx))) == NULL) {
        logmsg(ERROR, "Handler %lu: Failed to allocate IB ctx.", handler->tid);
        return(R_FAILURE);
    }

    /* set connection information in context */
    handler->ibctx->rem_lid    = ntohs(rlid);
    handler->ibctx->remote_qpn = ntohl(rqpn);
    msg_cnt                    = ntohl(msg_cnt);
    rdmasz                     = ntohl(rdmasz);
    handler->worker_cnt        = ntohs(worker_cnt);

    handler->ib_workers = calloc(handler->worker_cnt, sizeof(pthread_t));
    if (handler->ib_workers == NULL) {
        logmsg(ERROR, "Handler %lu: Failed to allocate IB worker threads.",
               handler->tid);
        free(handler->ibctx);
        return(R_FAILURE);
    }

    if (setup_srv_qp(handler->ibctx, server_conf.guid, &handler->msg_buf, 
                     msg_cnt, &handler->data_buf, rdmasz) != 0) {
        logmsg(ERROR, "Handler %lu: Failed to setup server QP.", handler->tid);
                   
        /* tear down IB context on error */
        goto setup_error;
    }

    logmsg(DEBUG, "Handler %lu: Setup IB queue pair for client, "
           "RDMA region size is %u.", handler->tid, rdmasz); 


    return(R_SUCCESS);

setup_error:
    destroy_ibctx(handler->ibctx);
    free(handler->ibctx);
    free(handler->ib_workers);
    if (handler->msg_buf != NULL)  free(handler->msg_buf);
    if (handler->data_buf != NULL) free(handler->data_buf);
                  
    return(R_FAILURE);
}

/****************************************************************************
 * 
 * Closes an InfiniBand connection to a client. This will cancel all IB
 * worker threads associated with this handler. Memory regions are 
 * unregostered and deallocated. The InfiniBand context of the handler will
 * be deallocated as well. The function will do nothing if the handler
 * has no active IB connection.
 *
 * Params: handler - context of handler.
 */
static void close_ib_conn(struct handler *handler) {
    unsigned int i;
    void *res;                      /* result of worker threads             */

    if (handler == NULL || handler->ibctx == NULL)
        return;

    /* kill InfiniBand worker threads */
    logmsg(DEBUG, "Handler %lu: Killing %u IB worker threads.", handler->tid,
           handler->worker_cnt);
    for (i = 0; i < handler->worker_cnt; i++) {
        pthread_cancel(handler->ib_workers[i]);
        pthread_join(handler->ib_workers[i], &res);
    }
    free(handler->ib_workers);
    handler->ib_workers = NULL;

    if (destroy_ibctx(handler->ibctx) != 0) {
        logmsg(WARN, "Handler %lu: Teardown of IB conn. failed.", 
               handler->tid);
    }

    if (handler->ibctx != NULL)    free(handler->ibctx);
    if (handler->msg_buf != NULL)  free(handler->msg_buf);
    if (handler->data_buf != NULL) free(handler->data_buf);

    handler->ibctx    = NULL;
    handler->msg_buf  = NULL;
    handler->data_buf = NULL;

    return;
}

/****************************************************************************
 *
 * Handles TCP requests of a normal client. This function is the "father"
 * thread for any InfiniBand worker threads that are created during
 * establishing an IB connection. IB creation and teardown requests can only
 * be sent via TCP.
 *
 * Params: handler - context structure for client connection.
 */
static void handle_normal_clt(struct handler *handler) {
    unsigned int i;

    struct crdss_srv_cap *new_cap;          /* pointer to new capability    */

    uint8_t op_res;                         /* result of server operations  */

    unsigned char cap_buf[CAP_ID_LEN];      /* buffer for receiving cap ids */

    /* fields for reading data from network */
    uint8_t  msg_type;
    uint16_t device_idx;
    uint32_t slice_idx;
    uint64_t saddr;                             /* start address of cap     */
    uint64_t eaddr;                             /* end address of cap       */
    uint16_t cap_rights;
    uint32_t rdom_id;                           /* id of revocation domain  */

    uint16_t rlid;                              /* LID of peer              */
    uint32_t rqpn;                              /* QPN of peer              */
    
    uint64_t clt_rdma_addr;                     /* address of clt RDMA buf  */
    uint32_t clt_rkey;                          /* rkey of clt RDMA buf     */
    uint32_t rkey;                              /* rkey of local RDMA buf.  */

    logmsg(DEBUG, "Handler %lu: Entering client handler.", handler->tid);
    while (1) {
        /* every message starts with the type field */
        if (recv(handler->sock, &msg_type, sizeof(uint8_t), MSG_WAITALL) < 1) {
            logmsg(ERROR, "Handler %lu: Connection terminated (status: %s).", 
                   handler->tid, strerror(errno));
            
            return;
        }
        
        switch (msg_type) {
            case MTYPE_IBINIT:
                /* Initializes an InfiniBand connection, if connection is   *
                 * successful, the server responds with the memory          *
                 * credentials of the designated receive memory window      */
                /* important: read data first to keep track of messages,    *
                 * error handling can be done after reading data from sock  */
                logmsg(DEBUG, "Handler %lu: Client requests InfiniBand "
                       "connection.", handler->tid);

                op_res = handle_ibinit(handler);

                if (op_res != R_SUCCESS) {
                    send(handler->sock, &op_res, 1, 0);
                    continue;
                }       

                /* reuse rlid and rqpn for answer to client */
                rlid = htons(handler->ibctx->loc_lid);
                rqpn = htonl(handler->ibctx->qp->qp_num);
                send(handler->sock, &op_res, 1, 0);       /* sends R_SUCCESS*/
                send(handler->sock, &rlid, 2, 0);
                send(handler->sock, &rqpn, 4, 0);

                /* reuse address variables for transmission of mem conf.    */
                saddr = (uint64_t) handler->data_buf;   /* buf start addr   */
                rkey  = handler->ibctx->rdma_mr->rkey;  /* now rkey         */
                saddr = htobe64(saddr);
                rkey  = htonl(rkey);
                send(handler->sock, &saddr, 8, 0);
                send(handler->sock, &rkey, 4, 0);

                /* receive memory window information of the client          */
                if (recv(handler->sock, &clt_rdma_addr, 8, MSG_WAITALL) < 8 ||
                    recv(handler->sock, &clt_rkey, 4, MSG_WAITALL) < 4) {
                    logmsg(ERROR, "Handler %lu: Failed to read client answer "
                           "for exchange of RDMA keys.", handler->tid);
                    
                    /* maybe just tear down the IB connection without       *
                     * cancelling the whole handler?                        */
                    return;
                }
                logmsg(DEBUG, "Received clt_rdma_addr: %lu", clt_rdma_addr);
                handler->ibctx->remote_addr = be64toh(clt_rdma_addr);
                handler->ibctx->remote_rkey = ntohl(clt_rkey);

                /* start IB worker threads */
                logmsg(INFO, "Handler %lu: Creating %u IB worker threads.",
                    handler->tid, handler->worker_cnt);
                for (i = 0; i < handler->worker_cnt; i++) {
                    if (pthread_create(&handler->ib_workers[i], NULL, ib_worker, 
                        handler) != 0) {
                        logmsg(ERROR, "Handler %lu: Failed to start IB workers.",
                            handler->tid);
                        close_ib_conn(handler);
                    }
                }

                break;
            case MTYPE_REGCAP:
                /* register cap with this handler thread                    */
                logmsg(DEBUG, "Handler %lu: Handling REGCAP request.", 
                       handler->tid);
                    
                /* read cap ID over TCP */
                if (recv(handler->sock, cap_buf, CAP_ID_LEN, 
                         MSG_WAITALL) < CAP_ID_LEN) {
                    logmsg(ERROR, "Handler %lu: Failed to read cap id.",
                           handler->tid);
                    return;
                }

                op_res = handle_regcap(handler, cap_buf);

                if (op_res == R_SUCCESS) {
                    logmsg(INFO, "Handler %lu: Registered new cap.", 
                           handler->tid);
                }
                else {
                    logmsg(INFO, "Handler %lu: Cap registration failed (%u).",
                           handler->tid, op_res);
                }

                /* finally send a status answer to the client */
                send(handler->sock, &op_res, 1, 0);

                break;
            case MTYPE_DRVCAP:
                /* derive a cap from one of the caps that are already       *
                 * registered with this thread. the new cap will have the   *
                 * same revocation domain as its parent                     */
                if (recv(handler->sock, cap_buf, CAP_ID_LEN, 
                         MSG_WAITALL) < CAP_ID_LEN) {
                    logmsg(ERROR, "Handler %lu: Failed to read parent cap "
                           "id.", handler->tid);
                    return;
                }

                if (read_cap_from_sock(handler->sock, &device_idx, 
                        &slice_idx, &saddr, &eaddr, &cap_rights) != 0) {
                    logmsg(ERROR, "Handler %lu: Failed to read capability "
                           "as requested.", handler->tid);
                    return;
                }

                op_res = handle_drvcap(handler, cap_buf, device_idx, slice_idx,
                                saddr, eaddr, cap_rights, &new_cap);
                
                if (op_res != R_SUCCESS) {
                    logmsg(ERROR, "Handler %lu: Cap derivation failed (%u).",
                           handler->tid, op_res);
                    send(handler->sock, &op_res, 1, 0);
                    
                    continue;
                }
                else {
                    logmsg(DEBUG, "Handler %lu: derived new cap %p.", 
                           handler->tid, new_cap);

                    /* lastly, send the cap id to the capmgr */
                    send(handler->sock, &op_res, sizeof(uint8_t), 0);
                    send(handler->sock, &new_cap->id, CAP_ID_LEN, 0);
                }

                break;
            case MTYPE_DRVCAP2:
                /* derive a cap from one of the caps that are already       *
                 * registered with this thread. a new revocation domain     *
                 * will be created with the new cap being the first member. *
                 * this new revocation domain will be a descendant of the   *
                 * rdom the parent cap was assigned to.                     */
                logmsg(DEBUG, "Handler %lu: Processing DRVCAP2 request.",
                       handler->tid);
                if (recv(handler->sock, cap_buf, CAP_ID_LEN, 
                         MSG_WAITALL) < CAP_ID_LEN) {
                    logmsg(ERROR, "Handler %lu: Failed to read parent cap "
                           "id.", handler->tid);
                    return;
                }

                if (read_cap_from_sock(handler->sock, &device_idx, 
                        &slice_idx, &saddr, &eaddr, &cap_rights) != 0) {
                    logmsg(ERROR, "Handler %lu: Failed to read capability "
                           "as requested.", handler->tid);
                    return;
                }

                op_res = handle_drvcap(handler, cap_buf, device_idx, slice_idx,
                                saddr, eaddr, cap_rights, &new_cap);

                if (op_res != R_SUCCESS) {
                    logmsg(ERROR, "Handler %lu: Cap derivation failed (%u).",
                           handler->tid, op_res);
                    send(handler->sock, &op_res, 1, 0);
                    
                    continue;
                }
                else {
                    logmsg(DEBUG, "Handler %lu: registered new cap %p.", 
                           handler->tid, new_cap);

                    /* lastly, send the id of the new cap to the capmgr    */
                    rdom_id = htonl(new_cap->rev_dom->dom_key);
                    send(handler->sock, &op_res, sizeof(uint8_t), 0);
                    send(handler->sock, &new_cap->id, CAP_ID_LEN, 0);
                    send(handler->sock, &rdom_id, sizeof(uint32_t), 0);
                }

                logmsg(DEBUG, "Handler %lu: transferred new cap %p.",
                       handler->tid, new_cap);
                break;
            case MTYPE_RMDOM:
                /* removes all caps of a certain rev dom from the global cap*
                 * list, destroys the rdoms and renders handler's local     *
                 * copies of caps invalid                                   */
                if (recv(handler->sock, &rdom_id,  sizeof(uint32_t), 
                    MSG_WAITALL) < 2) {
                    logmsg(ERROR, "Failed to read rdom id as requested.");
                    return;
                }
                
                op_res = handle_rmdom(handler, rdom_id);
                if (op_res != R_SUCCESS) {
                    logmsg(WARN, "Handler %lu: Failed to revoke domain %u.",
                           handler->tid, rdom_id);
                }

                send(handler->sock, &op_res, sizeof(uint8_t), 0);
                
                break;
            case MTYPE_IBCLOSE:
                logmsg(INFO, "Handler %lu: Client requested teardown of IB "
                       "queue pairs. Keeping TCP connection.", handler->tid);
                close_ib_conn(handler);

                break;
            case MTYPE_BYE:
                logmsg(INFO, "Handler %lu: Client requested shutdown.",
                       handler->tid);
                return;
            default:
                logmsg(WARN, "Handler %lu: Received unknown message type %u.",
                       handler->tid, msg_type);
                return;
        }
    }
}

/****************************************************************************
 * 
 * Performs initial handling of client connections. This function will 
 * process the client's welcome message and thus decides whether the client
 * will be handled as a capability manager (trusted root that can create any
 * capabilities) or as a normal client.
 * 
 * Params: args - contains a pointer to the handler struct for this thread
 *
 * Returns: return status is always NULL.
 */
static void *handle_client(void *args) {
    uint16_t msg_type;
    uint8_t  clt_type;
    uint8_t  res;                           /* operation result send to clt */

    struct handler *this = (struct handler *) args;

    /* fields for pretty printing of IP addresses */
    char clt_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &this->clt_addr.sin_addr, clt_ip, INET_ADDRSTRLEN);
    logmsg(INFO, "Started clt-handler thread %lu for client %s:%d.", this->tid,
           clt_ip, ntohs(this->clt_addr.sin_port));
    
    /* read hello message */
    if (recv(this->sock, &msg_type, sizeof(uint16_t), MSG_WAITALL) < 2 ||
        recv(this->sock, &clt_type, sizeof(uint8_t), MSG_WAITALL) < 1) {
        logmsg(WARN, "Handler %lu: unable to receive welcome msg.", this->tid);
        goto end;
    }

    /* convert from network to host byte order */
    msg_type = ntohs(msg_type);
    if (msg_type != MTYPE_HELLO) {
        logmsg(WARN, "Handler %lu: expected welcome message first, but got %u. "
               "Exiting...", this->tid, msg_type);
        goto end;
    }

    /* check if clt claims to be a cap manager, if so, challenge for secret */
    if (clt_type == CLT_CAPMGR) {
        uint16_t sec_len;                       /* for receiving secret     */
        uint16_t sec_len_nw;                    /* sec_len in network bo    */
        char     *secret;

        struct slist *snic_lptr;                /* iterate through snic list*/

        logmsg(DEBUG, "Handler %lu: clt is capmgr.", this->tid);

        if (recv(this->sock, &sec_len, sizeof(uint16_t), MSG_WAITALL) < 2) {
            logmsg(WARN, "handler %lu: Unable to receive secret length.",
                   this->tid);
            goto end;
        }
        sec_len = ntohs(sec_len);
        logmsg(DEBUG, "Handler %lu: secret length is %u.", this->tid, 
               sec_len);

        if ((secret = malloc(sec_len)) == NULL) {
            logmsg(ERROR, "Handler %lu: can not allocate memory.", this->tid);
            goto end;
        }

        if (recv(this->sock, secret, sec_len, MSG_WAITALL) < sec_len) {
            logmsg(WARN, "Handler %lu: Unable to receive secret string.",
                   this->tid);
            free(secret);
            goto end;
        }

        /* set last character to \0 to avoid overflow situations */
        secret[sec_len - 1] = '\0';

        /* check if a cap mgr with the credentials received is registered   */
        for (snic_lptr = server_conf.snics; snic_lptr != NULL; 
             snic_lptr = snic_lptr->next) {
            struct clt_capmgr *mgr = (struct clt_capmgr *) snic_lptr->data;

            if (memcmp(&mgr->addr.sin_addr, &this->clt_addr.sin_addr, 
                sizeof(struct in_addr)) != 0 ||
                mgr->addr.sin_port != this->clt_addr.sin_port) {
                continue;
            }

            /* address information is equal, check secret */
            if (strcmp(mgr->secret, secret) != 0) {
                logmsg(WARN, "Handler %lu: client provided wrong secret!",
                       this->tid);

                /* at least, clt knew the protocol, so send a refusal msg   */
                res = R_AUTH;
                send(this->sock, &res, sizeof(uint8_t), 0);
                free(secret);
                goto end;
            }

            logmsg(INFO, "Handler %lu: client is a valid capmgr.", this->tid);
            
            /* send answer and start actual handler. the local key of this  *
             * server shall be attached to the answer so that the remote    *
             * side can verify our identity.                                */
            res        = R_SUCCESS;
            sec_len    = strlen(server_conf.secret) + 1;
            sec_len_nw = htons(sec_len);
            if (send(this->sock, &res, sizeof(uint8_t), 0) < 1 ||
                send(this->sock, &sec_len_nw, sizeof(uint16_t), 0) < 2 ||
                send(this->sock, server_conf.secret, sec_len, 0) < sec_len) {
                logmsg(WARN, "Failed to transmit server credentials.");
                /* do nothing, client will certainly close the connection   */
            }

            /* stop the loop if we have found the cap manager */
            break;
        }

        if (snic_lptr == NULL) {
            logmsg(WARN, "Handler %u: client not found in capmgr list.", 
                   this->tid);
        } 
        else {
            handle_capmgr(this);
        }

        free(secret);
    }
    else if (clt_type == CLT_NORMAL) {
        logmsg(DEBUG, "handler %lu: clt is normal client.", this->tid);
        
        /* send answer and start actual handler */
        res = R_SUCCESS;
        send(this->sock, &res, sizeof(uint8_t), 0);
        handle_normal_clt(this);
    }
    else {
        logmsg(WARN, "handler %lu: unknown client type. Exiting...", this->tid);
    }

end:
    logmsg(INFO, "Handler %lu: Starting teardown operatons.", this->tid);
    
    close_ib_conn(this);
    close(this->sock);
    logmsg(DEBUG, "Handler %lu: Connections (IB and TCP) closed.", this->tid);
    
    /* tear down structures and set this thread on the joinable thread list */
    /* delete local references to capabilities, note that global caps still *
     * exist, so clients may register with them!                            */
    pthread_rwlock_wrlock(&this->cap_lck);
    while (this->caps != NULL) {
        free(this->caps->data);
        this->caps = slist_remove(this->caps, this->caps->data);
    }
    pthread_rwlock_unlock(&this->cap_lck);
    pthread_rwlock_destroy(&this->cap_lck);

    logmsg(DEBUG, "Handler %lu: Deleted caps.", this->tid);
    logmsg(INFO, "Handler %lu: Teardown completed.", this->tid);

    /* set this thread on the joinable list */
    pthread_mutex_lock(&zombie_lck);
    slist_insert(&zombies, &this->tid);
    pthread_cond_broadcast(&zombie_cv);
    pthread_mutex_unlock(&zombie_lck);

    return(NULL);
}

/****************************************************************************
 *
 * Accepts new connections on the main server socket and spawns new handler
 * threads for each of the clients. On any severe error, this thread will 
 * exit and only leave remaining handler threads alive thus eventually 
 * leading to a termination of the whole server.
 *
 * Params: args - pointer to the thread's arguments, none expected here.
 *
 * Returns: execution status of this thread, NULL in this case.
 */
static void *entry_listener(void *args) {
    struct sockaddr_in clt_addr;            /* address of new client        */
    int                clt_sock_fd;         /* fd for client socket         */
    socklen_t          clt_len;             /* length of client address str.*/

    struct handler *new_handler;

    /* fields for pretty printing of IP addresses */
    char clt_ip[INET_ADDRSTRLEN];

    (void) args;
    clt_len = sizeof(clt_addr);

    logmsg(DEBUG, "Starting entry handler loop.");
    while (1) {
        /* wait for new incoming connections */
        if ((clt_sock_fd = accept(srv_sock, (struct sockaddr *) &clt_addr,
            &clt_len)) < 0) {
            logmsg(ERROR, "Failed to accept client connection (%s).",
                   strerror(errno));
            continue;
        }
        inet_ntop(AF_INET, &clt_addr.sin_addr, clt_ip, INET_ADDRSTRLEN);
        logmsg(INFO, "Accepted new connection from %s:%u.", clt_ip,
               ntohs(clt_addr.sin_port));

        /* allocate handler struct and fill necessary fields                */
        new_handler = calloc(1, sizeof(struct handler));
        if (new_handler == NULL) {
            logmsg(ERROR, "Failed to allocate memory for new client handler.");
            continue;
        }

        new_handler->sock = clt_sock_fd;
        memcpy(&new_handler->clt_addr, &clt_addr, sizeof(struct sockaddr_in));

        new_handler->ibctx    = NULL;
        new_handler->msg_buf  = NULL;
        new_handler->data_buf = NULL;

        if (pthread_rwlock_init(&new_handler->cap_lck, NULL) != 0) {
            logmsg(ERROR, "Failed to init capability lock for new handler (%d)",
                   errno);
            free(new_handler);
            continue;
        }

        pthread_mutex_lock(&handler_lck);
        if (slist_insert(&handlers, new_handler)) {
            logmsg(ERROR, "Failed to allocate list element for new handler.");
            free(new_handler);
        }
        pthread_mutex_unlock(&handler_lck);

        if (pthread_create(&new_handler->tid, NULL, handle_client, 
            new_handler) != 0) {
            /* clean up of thread start failed */
            logmsg(ERROR, "Failed to start client handler thread.");
            pthread_mutex_lock(&handler_lck);
            handlers = slist_remove(handlers, new_handler);
            pthread_mutex_unlock(&handler_lck);
            free(new_handler);
            continue;
        }

        /* if everything worked out fine, increment no. of running threads  */
        pthread_mutex_lock(&thrd_cnt_lck);
        act_thrd_cnt++;
        pthread_mutex_unlock(&thrd_cnt_lck);
    }

    return(NULL);
}

/****************************************************************************
 *
 * Waits for handler threads to exit (and enter their thread id in the zombie
 * list) and then joins these threads. The function will return once there 
 * are no more active threads to join. Note that this condition shall not
 * occur in normal server operation since there should be at least the entry
 * thread that accepts new connections and spawns new handlers.
 */
static void join_handlers(void) {
    void *result;                       /* result of thread execution       */
    int zombie_cnt = 0;                 /* zombies killed in this round     */

    struct slist *zptr;                 /* iterate over zombie list         */
    struct slist *hptr;                 /* iterate over handler list        */

    int loop_flag = 1;                  /* set to 0 if loop shall end       */

    while (loop_flag) {
        pthread_mutex_lock(&zombie_lck);

        while (slist_empty(zombies))
            pthread_cond_wait(&zombie_cv, &zombie_lck);

        /* there are zombies to join with */
        zombie_cnt = slist_length(zombies);
        logmsg(DEBUG, "Zombie list has %d entries.", zombie_cnt);
        for (zptr = zombies; zptr != NULL; zptr = zptr->next) {
            /* data is a reference to the tid field of the thread's handler *
             * structure contained in handlers                              */
            pthread_t *thread = (pthread_t *) zptr->data;

            /* normally, joining a thread while holding the lock is not a   *
             * good idea. however, since we can be sure that threads will   *
             * exit immediately after setting themselves on the zombie list,*
             * there should not be much waiting here.                       */
            pthread_join(*thread, &result);
            logmsg(INFO, "Handler %lu terminated.", *thread);

            /* if zombie was a normal handler, free the corresponding structs*/
            if (*thread == entry_handler) {
                logmsg(WARN, "Entry handler terminated, server will die soon.");
            }
            else {
                pthread_mutex_lock(&handler_lck);

                /* we assume that the handler has cleaned up everything and *
                 * this thread only needs to free the mantle structure      */
                for (hptr = handlers; hptr != NULL; hptr = hptr->next) {
                    struct handler *h = (struct handler *) hptr->data;
                    if (h->tid == *thread) {
                        handlers = slist_remove(handlers, h);
                        free(h);
                        break;
                    }
                }

                pthread_mutex_unlock(&handler_lck);
            }
        }

        /* clean up the zombie list, all items are worked off */
        while (zombies != NULL)
            zombies = slist_remove(zombies, zombies->data);

        logmsg(DEBUG, "Deleted %d zombie threads.", zombie_cnt);
        pthread_mutex_unlock(&zombie_lck);

        /* update thread count, exit if no threads remain */
        pthread_mutex_lock(&thrd_cnt_lck);
        
        act_thrd_cnt -= zombie_cnt;
        if (act_thrd_cnt == 0) 
            loop_flag = 0;

        pthread_mutex_unlock(&thrd_cnt_lck);
    }
}

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
    int next_opt;                   /* value of next cli option             */
    int wflag = 0;
    int rc;                         /* error code for reporting             */

    char *logdir   = NULL;          /* directory of log file                */
    char *logpath  = NULL;          /* path to log file                     */
    char *confpath = NULL;          /* path to config file                  */

    /* parse command line arguments */
    while ((next_opt = getopt(argc, argv, ":c:l:wh")) != -1) {
        switch (next_opt) {
            case 'c':
                confpath = optarg;
                continue;
            case 'h':
                usage();
                exit(0);
            case 'l':
                /* make the logpath absolute to open logfile at right spot  *
                 * even after daemonizing which changes wdir to /           */
                if (strncmp(optarg, "/", 1) == 0) {
                    /* input path is abolute       */
                    logpath = malloc(strlen(optarg) + 1);
                    strcpy(logpath, optarg);
                }
                else {
                    /* input path is relative      */
                    logdir = malloc((size_t) PATH_MAX);
                    if ((logdir = getcwd(logdir, PATH_MAX)) == NULL) {
                        fprintf(stderr, "Failed get logging directory.\n");
                        exit(1);
                    }
                    logpath = malloc(strlen(logdir) + strlen(optarg) + 2);
                    /* assemble absolute logpath */
                    strcpy(logpath, logdir);
                    strcpy(logpath + strlen(logdir), "/");
                    strcpy(logpath + strlen(logdir) + 1, optarg);
                }
                continue;
            case 'w':
                wflag = 1;
                continue;
            case ':':
                fprintf(stderr, "Missing argument for option -%c\n", optopt);
                exit(1);
            case '?':
                fprintf(stderr, "Unknown option -%c\n", optopt);
                exit(1);
            default:
                usage();
                exit(1);
        }
    }

    /* check input options for conflicts                                    */
    if (confpath == NULL) {
        /* server can not start without a config file */
        fprintf(stderr, "Missing path to server configuration file!\n\n");
        usage();
        exit(1);
    }

    /* daemon must have a logfile to communicate its sorrow                 */
    if (logpath == NULL && !wflag) {
        fprintf(stderr, "Specify a log file when running the server as a "
                "daemon!\n");
        exit(1);
    }
    /* logfile must be writable. if it does not exist, logdir must be       *
     * writable to create a new file                                        */
    if (logpath != NULL) {
        if (access(logpath, F_OK) == -1) {
            /* file does not exist, check if directory is writable          */
            if (access(logdir, W_OK) == -1) {
                fprintf(stderr, "Log file %s does not exist and there are "
                        "no rights for modifying the target directory.\n",
                        logpath);
                exit(1);
            }
        }
        else {
            /* file exists, check if it can be written                      */
            if (access(logpath, W_OK) == -1) {
                fprintf(stderr, "No write permission for log file %s.\n",
                        logpath);
                exit(1);
            }
        }
    }

    /* parse config file, report errors to stderr before server daemonizes! */
    fprintf(stderr, "Parsing config file %s\n", confpath);
    if (parse_server_config(confpath, &server_conf) != 0) {
        fprintf(stderr, "Failed to parse configuration file. Exiting...\n");
        exit(1);
    }

    fprintf(stderr, "Starting server...\n");

    /* daemonize if wflag is not set                                        */
    if (!wflag) {
        if ((rc = daemon(0, 0))) {
            fprintf(stderr, "Failed to daemonize (%d). Exiting...\n", rc);
            exit(2);
        }
    }

    /* set log path. if logpath == NULL, stderr is used since the server    *
     * won't run as a daemon in this case (see error conditions above)      */
    if (logpath != NULL)
        init_logger(logpath, server_conf.loglevel);
    else
        init_logger("/dev/stderr", server_conf.loglevel);        

    /* logpath-related memory is no longer needed, free it immediately      */
    if (logdir != NULL)
        free(logdir);
    if (logpath != NULL)
        free(logpath);

    /***       From now on, use the logger for printing messages!!!       ***/

    logmsg(DEBUG, "Hello crdss!");
    logmsg(DEBUG, "server port is %d", ntohs(server_conf.addr.sin_port));

    /* check out the block devices passed in the config and set up stms     */
    open_devs();

    /*** !!! ONLY TEMPORARILY FOR TESTING !!! ***/
    /* init first block device with a static stm */
    if (devs != NULL) {
        logmsg(WARN, "Destroying data layout for testing...");
        sstm_init((struct crdss_bdev *) devs->data, 2);
        sstm_mkvslc((struct crdss_bdev *) devs->data);
    }

    /* open socket for incoming connections                                 */
    if ((srv_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        logmsg(SEVERE, "Failed to create server socket.");
        exit(3);
    }

    if (bind(srv_sock, (struct sockaddr *) &server_conf.addr, 
        sizeof(struct sockaddr_in)) != 0) {
        logmsg(SEVERE, "Failed to bind server to configured address (%s).",
               strerror(errno));
        exit(3);
    }

    if (listen(srv_sock, 0) != 0 ) {
        logmsg(SEVERE, "Failed to set server socket to listeting state (%s).",
               strerror(errno));
        exit(3);
    }

    /* start initial handler and join zombies in initial thread             */
    if ((rc = pthread_create(&entry_handler, NULL, &entry_listener, NULL)) != 0) 
    {
        logmsg(SEVERE, "Failed to spawn listener thread (%s).", strerror(rc));
        exit(4);
    }

    join_handlers();
    return(0);
}

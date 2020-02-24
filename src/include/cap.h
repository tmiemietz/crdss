/****************************************************************************
 *                                                                          *
 *      cap.h - Capabilities for controlling access to storage devices      *
 *                                                                          *
 *                    Copyright (c) 2020 Till Miemietz                      *
 *                                                                          *
 ****************************************************************************/


#ifndef CAP_H
#define CAP_H

/****************************************************************************
 *                                                                          *
 *                           include statements                             *
 *                                                                          *
 ****************************************************************************/


#include <stdint.h>                     /* fixed-width integers             */
#include <netinet/ip.h>                 /* for server id on client side     */
#include <sys/types.h>                  /* uid in client cap                */

#include <sodium.h>                     /* to determine size of cap id      *
                                         * ciphertext                       */

/****************************************************************************
 *                                                                          *
 *                     global definitions and macros                        *
 *                                                                          *
 ****************************************************************************/


#define CAP_ID_LEN      16                  /* length of cap id in bytes    */

/***              constants that indicate the validity of a cap           ***/
#define CAP_INVALID 0
#define CAP_VALID   1

/***                         rights for capabilities                      ***/
#define CAP_READ    (0x01 << 0)
#define CAP_WRITE   (0x01 << 1)
#define CAP_TRIM    (0x01 << 2)

#define CAP_ALLOC   (0x01 << 3)
#define CAP_RELEASE (0x01 << 4)

/****************************************************************************
 *                                                                          *
 *                           type definitions                               *
 *                                                                          *
 ****************************************************************************/

struct rev_dom_node;

/* a structure that represents a node in the tree of revocation domains     */
struct rev_dom_node {
    uint32_t dom_key;                       /* ID of this revocation domain */

    struct rev_dom_node *parent;            /* parent node of this revdom   */
    struct slist *children;                 /* subordinated rev doms        */
    
    struct slist *caps;                     /* caps that belong to this dom,*
                                             * contains both global and     *
                                             * handler-local caps           */
};

/* a capability as it is represented at the server side                     */
struct crdss_srv_cap {
    uint16_t dev_idx;                       /* index of device              */
    uint32_t vslc_idx;                      /* index of virtual slice       */
    uint64_t start_addr;                    /* first accessible addr in vslc*/
    uint64_t end_addr;                      /* last accessible addr in vslc */

    uint16_t rights;                        /* ops allowed for this cap     *
                                             * (set via single bits)        */
    struct rev_dom_node *rev_dom;           /* revocation domain of this cap*/

    /* 1 if cap is valid, 0 if cap is invalid and destruction is not started*
     * -1 if cap is invalid and its removal is scheduled                    */
    char valid;                             /* indicates whether this cap is*
                                             * still valid                  */
    pthread_mutex_t valid_lck;              /* grab this for making the cap *
                                             * invalid                      */
    unsigned char id[CAP_ID_LEN];           /* random number for identifctn */
};

/* a capability as it is represented at the capmgr / client side            */
struct crdss_clt_cap {
    struct sockaddr_in srv;                 /* server to connect to         */

    uint16_t dev_idx;                       /* index of device              */
    uint32_t vslc_idx;                      /* index of virtual slice       */
    uint64_t start_addr;                    /* first accessible addr in vslc*/
    uint64_t end_addr;                      /* last accessible addr in vslc */

    uint16_t rights;                        /* ops allowed for this cap     *
                                             * (set via single bits)        */

    uint32_t rev_dom;                       /* revocation domain of this cap*/

    uid_t    uid;                           /* uid this cap is bound to     */
    char     *key;                          /* distinguish between multiple *
                                             * procs of the same user       */

    unsigned char id[CAP_ID_LEN];           /* ID returned by server        */
};

/****************************************************************************
 *                                                                          *
 *                          function prototypes                             *
 *                                                                          *
 ****************************************************************************/


/****************************************************************************
 *
 * Reads contents needed for building a capability from the network socket
 * sock and puts their output in the arguments passed to this function.
 * Any input received is converted from network to host byte order. Neither of
 * the pionter parameters must be NULL. Note that information about a desired
 * revocation domain to place the cap in have to be read separately.
 *
 * Params: sock - socket fd to read from.
 *         didx - device index of cap
 *         sidx - vslice index of cap
 *         sadd - start address of cap
 *         eadd - end address of cap
 *         perm - permissions of cap
 *
 * Returns: 0 on success, 1 on error.
 */
int read_cap_from_sock(int sock, uint16_t *didx, uint32_t *sidx, 
                       uint64_t *sadd, uint64_t *eadd, uint16_t *perm);

/****************************************************************************
 *
 * Sends contents needed for building a capability to the network using the
 * socket sock. Any input received by this function will be transformed to
 * network byte order before sending.
 *
 * Params: sock - socket fd to read from.
 *         didx - device index of cap
 *         sidx - vslice index of cap
 *         sadd - start address of cap
 *         eadd - end address of cap
 *         perm - permissions of cap
 *
 * Returns: 0 on success, 1 on error.
 */
int send_cap_to_sock(int sock, uint16_t didx, uint32_t sidx, uint64_t saddr,
                     uint64_t eaddr, uint16_t perm);

/****************************************************************************
 *
 * Finds a free and unique capability ID, i.e., a random number used for the 
 * identification of a cap given a list of capability structures. This list
 * passed to this function is expected to contain crdss_srv_cap 
 * structures. Any locks that protect the cap list must be hold when calling
 * this function.
 *
 * Params: cap_id - ptr to the buffer where the new cap id shall be stored.
 *         clist  - list of caps that are already present in the system.
 */
void find_free_cap_id(unsigned char *cap_id, struct slist *clist);

/****************************************************************************
 * 
 * Finds a free revocation domain id. The list passed to this function is
 * expected to contain uint32_t disguised as a void ptr. Any locks that 
 * protect the cap list must be hold when calling this function. The id  
 * returned in id is will be removed from the id_list.
 *
 * Params: id      - field where the new id shall be placed into.
 *         max_id  - current maximum rdom id in use.
 *         id_list - list of domids ready for reuse.
 *
 * Returns: 0 on success, 1 on error (no rdom ids available).
 */
int find_free_rdom_id(uint32_t *id, uint32_t *max_id, struct slist **id_list);

/****************************************************************************
 *
 * Checks whether cap1 encodes less or equal rights than cap2. The function 
 * fails if both caps are not comparable, e.g., if they refer to different
 * vslices.
 *
 * Params: cap1 - the capability with minor rights.
 *         cap2 - the capability which should include the rights granted by
 *                cap1.
 *
 * Returns: 0 if the rights granted by cap1 are a subset of those granted by
 *          cap2, 1 otherwise
 */
int srv_cap_is_subset(struct crdss_srv_cap *cap1, struct crdss_srv_cap *cap2);

/****************************************************************************
 *
 * Checks whether cap1 encodes less or equal rights than cap2. The function 
 * fails if both caps are not comparable, e.g., if they refer to different
 * vslices. This function does the check for client-side capabilities.
 *
 * Params: cap1 - the capability with minor rights.
 *         cap2 - the capability which should include the rights granted by
 *                cap1.
 *
 * Returns: 0 if the rights granted by cap1 are a subset of those granted by
 *          cap2, 1 otherwise
 */
int clt_cap_is_subset(struct crdss_clt_cap *cap1, struct crdss_clt_cap *cap2);

/****************************************************************************
 *
 * Deletes a tree of revocation domain starting from node root. The rdom  
 * nodes deleted are not freed, but linked in a new list that is returned as 
 * a result of this operation. This list is referenced by rlist.
 * Along with the deletion of the rdoms inside the tree, the domains are also
 * removed from the scalar list dom_list.
 *
 * Params: node  - rdom tree node which shall be deleted.
 *         dlist - scalar list of rev. doms that should be updated too
 */
void delete_rdom_tree(struct rev_dom_node *root, struct slist *dlist,
                      struct slist **rlist);

#endif /* CAP_H */

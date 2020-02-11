/****************************************************************************
 *                                                                          *
 *      cap.c - Capabilities for controlling access to storage devices      *
 *                                                                          *
 *                    Copyright (c) 2020 Till Miemietz                      *
 *                                                                          *
 ****************************************************************************/



/****************************************************************************
 *                                                                          *
 *                           include statements                             *
 *                                                                          *
 ****************************************************************************/

#include <stdint.h>                     /* fixed-width integers             */
#include <sys/socket.h>                 /* to use sockets                   */
#include <arpa/inet.h>                  /* byte order conversion            */
#include <endian.h>                     /* flip byte order of 64bit ints    */
#include <string.h>                     /* comparison of memory areas       */

#include <sodium.h>                     /* crypto library                   */

#include "include/cap.h"                /* definitions to implement         */
#include "include/slist.h"              /* single-linked lists              */

/****************************************************************************
 *                                                                          *
 *                          function implementation                         *
 *                                                                          *
 ****************************************************************************/


/***                       functions defined in cap.h                     ***/

/* Reads contents needed for building a capability from the network         */
int read_cap_from_sock(int sock, uint16_t *didx, uint32_t *sidx,
                       uint64_t *sadd, uint64_t *eadd, uint16_t *perm) {
    if (recv(sock, didx, sizeof(uint16_t), MSG_WAITALL) < 2 ||
        recv(sock, sidx, sizeof(uint32_t), MSG_WAITALL) < 4 ||
        recv(sock, sadd, sizeof(uint64_t), MSG_WAITALL) < 8 ||
        recv(sock, eadd, sizeof(uint64_t), MSG_WAITALL) < 8 ||
        recv(sock, perm, sizeof(uint16_t), MSG_WAITALL) < 2) {
        return(1);
    }

    *didx = ntohs(*didx);
    *sidx = ntohl(*sidx);
    *sadd = be64toh(*sadd);
    *eadd = be64toh(*eadd);
    *perm = ntohs(*perm);

    return(0);
}

/* Sends contents needed for building a capability to the network           */
int send_cap_to_sock(int sock, uint16_t didx, uint32_t sidx, uint64_t saddr,
                     uint64_t eaddr, uint16_t perm) {
    didx  = htons(didx);
    sidx  = htonl(sidx);
    saddr = htobe64(saddr);
    eaddr = htobe64(eaddr);
    perm  = htons(perm);

    if (send(sock, &didx, sizeof(uint16_t), 0) < 2 ||
        send(sock, &sidx, sizeof(uint32_t), 0) < 4 ||
        send(sock, &saddr, sizeof(uint64_t), 0) < 8 ||
        send(sock, &eaddr, sizeof(uint64_t), 0) < 8 ||
        send(sock, &perm, sizeof(uint16_t), 0) < 2) {
        return(1);
    }

    return(0);
}

/* Finds a free and unique capability ID given a list of capability structs */
void find_free_cap_id(unsigned char *cap_id, struct slist *clist) {
    struct slist *lptr = clist;                                                

    randombytes_buf(cap_id, CAP_ID_LEN);
    while (lptr != NULL) {                                          
        struct crdss_srv_cap *cap = (struct crdss_srv_cap *) lptr->data;            
        if (memcmp(&cap->id, cap_id, CAP_ID_LEN) == 0) {      
            /* that ID is already in use... */                      
            randombytes_buf(cap_id, CAP_ID_LEN);              
            lptr = clist;                                        
        }                                                           
        else {                                                      
            lptr = lptr->next;                                      
        }                                                           
    } 
}

/* Finds a free revocation domain id.                                       */
int find_free_rdom_id(uint32_t *id, uint32_t *max_id, struct slist **id_list) {
    /* prefer to take an element from the free list */
    if (! slist_empty(*id_list)) {
        *id      = (uint32_t) (uint64_t) (*id_list)->data;
        *id_list = slist_remove(*id_list, (*id_list)->data);
        return(0);
    }
    else if (*max_id < UINT32_MAX) {
        *id = *max_id;
        (*max_id)++;
        return(0);
    }
    else {
        return(1);
    }
}

/* Checks whether cap1 encodes less or equal rights than cap2.              */
int srv_cap_is_subset(struct crdss_srv_cap *cap1, struct crdss_srv_cap *cap2) {
    if (cap1->dev_idx != cap2->dev_idx)
        return(1);

    if (cap1->vslc_idx != cap2->vslc_idx)
        return(1);

    if (cap1->start_addr < cap2->start_addr || cap1->end_addr > cap2->end_addr)
        return(1);

    /* the union of both right sets has to be equal to cap2->rights (i.e.,  *
     * cap1 has no right bits set that are not present in cap2              */
    if ((cap1->rights | cap2->rights) != cap2->rights)
        return(1);

    return(0);
}

/* Checks whether cap1 encodes less or equal rights than cap2 (clt side).   */
int clt_cap_is_subset(struct crdss_clt_cap *cap1, struct crdss_clt_cap *cap2) {
    if (cap1->dev_idx != cap2->dev_idx)
        return(1);

    if (cap1->vslc_idx != cap2->vslc_idx)
        return(1);

    if (cap1->start_addr < cap2->start_addr || cap1->end_addr > cap2->end_addr)
        return(1);

    /* the union of both right sets has to be equal to cap2->rights (i.e.,  *
     * cap1 has no right bits set that are not present in cap2              */
    if ((cap1->rights | cap2->rights) != cap2->rights)
        return(1);

    return(0);
}

/* Deletes a tree of revocation domain starting from node root.             */
void delete_rdom_tree(struct rev_dom_node *root, struct slist *dlist, 
                     struct slist **rlist) {
   struct slist *lptr;

   for (lptr = root->children; lptr != NULL; lptr = lptr->next) {
        delete_rdom_tree((struct rev_dom_node *) lptr->data, dlist, rlist);
   }

    dlist = slist_remove(dlist, root);
    slist_insert(rlist, root);

    while (root->children != NULL)
        root->children = slist_remove(root->children, root->children->data);
}

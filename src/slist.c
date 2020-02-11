/****************************************************************************
 *                                                                          *
 *           slist.c - A single-linked list for use within crdss.           *
 *                                                                          *
 *                    Copyright (c) 2019 Till Miemietz                      *
 *                                                                          *
 ****************************************************************************/


/****************************************************************************
 *                                                                          *
 *                           include statements                             *
 *                                                                          *
 ****************************************************************************/


#include <stdlib.h>                      /* memory allocation, ...          */

#include "include/slist.h"               /* header for slist implementation */

/****************************************************************************
 *                                                                          *
 *                          function implementation                         *
 *                                                                          *
 ****************************************************************************/


/***                      functions defined in slist.h                    ***/

/* Inserts an element at the head of slist list.                            */
int slist_insert(struct slist **list, void *elem) {
    struct slist *new = calloc((size_t) 1, sizeof(struct slist));
    if (new == NULL) {
        return(1);
    }

    new->data = elem;
    new->next = *list;
    *list     = new;
    return(0);
}

/* Appends an element at the tail of the slist list.                        */
int slist_append(struct slist **list, void *elem) {
    struct slist *iter_ptr;

    struct slist *new = calloc((size_t ) 1, sizeof(struct slist));
    if (new == NULL)
        return(1);

    new->data = elem;
    if (*list == NULL) {
        *list = new;
        return(0);
    }

    /* iterate until the end of the list */
    iter_ptr = *list;
    while (iter_ptr->next != NULL)
        iter_ptr = iter_ptr->next;

    iter_ptr->next = elem;
    return(0);
}

/* Removes the first occurrence of elem from the slist list.                */
struct slist *slist_remove(struct slist *list, void *elem) {
    struct slist *cur  = list;
    struct slist *prev = NULL;

    while (cur != NULL) {
        if (cur->data == elem) {
            if (prev == NULL) {
                list = cur->next;       /* special case: remove list head   */
            }
            else {
                prev->next = cur->next;
            }

            free(cur);
            return(list);
        }

        prev = cur;
        cur  = cur->next;
    }

    return(list);       /* data not found, return unchanged list            */
}

/* Counts the number of elements stored in slist list.                      */
unsigned int slist_length(struct slist *list) {
   int cnt = 0;
   
   while (list != NULL) {
        cnt++;
        list = list->next;
   }

   return(cnt);
}

/* Checks whether the slist list contains any elements.                     */
unsigned int slist_empty(struct slist *list) {
    return(list == NULL);
}

/* Checks whether the slist list contains an element ref'd by ptr           */
unsigned int slist_contains(struct slist *list, void *ptr) {
    struct slist *lptr;

    for (lptr = list; lptr != NULL; lptr = lptr->next) {
        if (lptr->data == ptr)
            return(1);
    }

    return(0);
}

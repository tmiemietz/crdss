/****************************************************************************
 *                                                                          *
 *           slist.h - A single-linked list for use within crdss.           *
 *                                                                          *
 *                    Copyright (c) 2019 Till Miemietz                      *
 *                                                                          *
 ****************************************************************************/

#ifndef SLIST_H
#define SLIST_H

/****************************************************************************
 *                                                                          *
 *                           type definitions                               *
 *                                                                          *
 ****************************************************************************/


/* very simple single-linked list                                           */
struct slist {
    void         *data;     /* data contained by this element */
    struct slist *next;     /* pointer to the next list entry */
};

/****************************************************************************
 *                                                                          *
 *                          function prototypes                             *
 *                                                                          *
 ****************************************************************************/


/****************************************************************************
 *
 * Inserts an element at the head of slist list. A new slist element will be
 * allocated, so passing a reference to a NULL pointer to create a new list is
 * a valid operation.
 *
 * Params: list - pointer to a slist structure.
 *         elem - the data to insert.
 * 
 * Returns: 0 on success, 1 on error (probably due to allocation error).
 */
int slist_insert(struct slist **list, void *elem);

/***************************************************************************
 *
 * Appends an element at the tail of the slist list. A new slist element will
 * be allocated, so passing a reference to a NULL pointer to create a new list
 * is a valid operation.
 *
 * Params: list - pointer to the slist structure to be modified.
 *         elem - the data to append to the list.
 *
 * Returns: 0 on success, 1 on error (likely due to an allocation error)
 */
int slist_append(struct slist **list, void *elem);

/****************************************************************************
 *
 * Removes the first occurrence of an element identified by the pointer data
 * from the slist list. If the element is not found, the list remains 
 * unchanged. While this routine does free the list element itself, it does
 * not take care of tearing down the data hidden behind data, hence the caller
 * is obliged to do so in order to prevent memory leaks. If the list only
 * contains the element searched for, the returned pointer will be NULL.
 *
 * Params: list - pointer to a slist structure
 *         elem - the element to remove
 * 
 * Returns: A pointer to the modified slist. The returned pointer may be NULL.
 */
struct slist *slist_remove(struct slist *list, void *elem);

/****************************************************************************
 *
 * Counts the number of elements stored in slist list.
 *
 * Params: list - pointer to a slist structure
 * 
 * Returns: The number of elements in the list.
 */
unsigned int slist_length(struct slist *list);

/****************************************************************************
 *
 * Checks whether the slist list contains any elements.
 *
 * Params: list - pointer to a slist structure
 * 
 * Returns: 1 if the list is empty, 0 otherwise.
 */
unsigned int slist_empty(struct slist *list);

/****************************************************************************
 *
 * Checks whether the slist list contains an element with a data pointer 
 * equal to ptr.
 *
 * Params: list - pointer to a slist structure.
 *         ptr  - pointer that is checked for existence within the list.
 *
 * Returns: 1 if ptr was found in list, 0 otherwise.
 */
unsigned int slist_contains(struct slist *list, void *ptr);

#endif /* SLIST_H */

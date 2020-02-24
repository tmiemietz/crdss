/****************************************************************************
 *                                                                          *
 * protocol.h - definitions for the network communication protocol of crdss *
 *                                                                          *
 *                    Copyright (c) 2020 Till Miemietz                      *
 *                                                                          *
 ****************************************************************************/


#ifndef PROTOCOL_H
#define PROTOCOL_H

/****************************************************************************
 *                                                                          *
 *                     global definitions and macros                        *
 *                                                                          *
 ****************************************************************************/

/* max length of a control message (excluding MTYPE_HELLO), used for        *
 * sizing of IB receive requests. Currently the MTYPE with the biggest      *
 * payload is MTYPE_DRVCAP2i (41B), is used as a reference; choose 64B (NVMe*
 * command size) for some spare capacity.                                   */
#define MAX_MSG_LEN 64                      /* message length in Bytes      */

/* first 4 bytes of a message is the type field, followed by 4 bytes        *
 * indicating the payload length (hello message only).                      */

/***                           message types                              ***/

/* general messages */
#define MTYPE_HELLO     0x01                /* handshake requested          */
#define MTYPE_BYE       0x02                /* one side terminates the conn *
                                             * shall only be sent by clts   */

/* messages related to capability management */
#define MTYPE_MKCAP     0x03                /* create a new cap, no new rdom*/
#define MTYPE_MKCAP2    0x04                /* create a new cap, this cap   *
                                             * will be placed in a new rdom */
#define MTYPE_DRVCAP    0x05                /* derive cap from another cap  */
#define MTYPE_DRVCAP2   0x06                /* derive cap from another cap, *
                                             * creating a new revdom        */
#define MTYPE_RMDOM     0x07                /* delete a revocation domain   *
                                             * and all caps inside it       */
#define MTYPE_REGCAP    0x08                /* register cap with srv handler*/

/* messages related to InfiniBand */
#define MTYPE_IBINIT    0x09                /* Initialize communication via *
                                             * InfiniBand                   */
#define MTYPE_IBCLOSE   0x10                /* close IB connection          */

/* messages for data exchange */
#define MTYPE_COMPLETE  0x20                /* data transfer is complete    */
#define MTYPE_READ      0x21
#define MTYPE_FASTREAD  0x22                /* read with polling at client  */
#define MTYPE_WRITE     0x23
#define MTYPE_FASTWRITE 0x24                /* write with polling at client */

/* messages for server management */
#define MTYPE_CPOLL     0x50                /* use polling completion       */
#define MTYPE_CBLOCK    0x51                /* use blocking completion      */

/* messages for partitioning operations */
#define MTYPE_VSLCINFO  0x70                /* get info about a vslice      */

/***                           client types                               ***/
#define CLT_CAPMGR 0x01
#define CLT_NORMAL 0x02

/***                           return codes                               ***/
#define R_SUCCESS  0x00                             /* operation successful */
#define R_FAILURE  0x01                             /* generic error        */
#define R_AUTH     0x02                             /* authentication error */
#define R_NOSUPP   0x03                             /* op. is not supported */
#define R_INVAL    0x04                             /* invalid input params */
#define R_PERM     0x05                             /* insufficient perms.  */

#define R_UNDEF    0xff                             /* op result outstanding*/

#endif /* PROTOCOL_H */

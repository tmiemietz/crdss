/****************************************************************************
 *                                                                          *
 *        utils.h - Various utility functions to be used in crdss           *
 *                                                                          *
 *                    Copyright (c) 2019 Till Miemietz                      *
 *                                                                          *
 ****************************************************************************/


#ifndef UTILS_H
#define UTILS_H

/****************************************************************************
 *                                                                          *
 *                     global definitions and macros                        *
 *                                                                          *
 ****************************************************************************/


/***                           logging levels                             ***/
#define SEVERE 0x50000000
#define ERROR  0x40000000
#define WARN   0x30000000
#define INFO   0x20000000
#define DEBUG  0x10000000

#define MAX_LOGMSG_LEN 512      /* max. length of a single logmsg in byte   */

/****************************************************************************
 *                                                                          *
 *                          function prototypes                             *
 *                                                                          *
 ****************************************************************************/


/***                         logging facility                             ***/

/****************************************************************************
 *
 * Sets up the logging facility. A log file location has to be specified. Log 
 * messages will appear on stderr if the logfile can not be opened for 
 * writing. The parameter loglevel specifies the minimal importance that a 
 * log message must have in order to be printed.
 * 
 * NOTE: This function is not threadsafe.
 *
 * Params: logfile   - name of a file used for dumping the log output.
 *         loglevel  - minimum level of log messages printed.
 */
void init_logger(char *lfile, int loglevel);

/****************************************************************************
 *
 * Sets the minimal log level that a message must have in order to appear on 
 * the output channels. The user should use one of the level definitions 
 * offered by this header file as a log level. This function is threadsafe.
 *
 * Params: newlevel - the new minimum log level to apply.
 */
void setloglevel(int newlevel);

/****************************************************************************
 *
 * Prints a log message to the channels configured via init_logger. If the
 * level of a message is below the current global threshold (set via
 * setloglevel), the message is silently dropped. String formatting works as
 * with the flavors of printf. This function is threadsafe.
 *
 * Params: level  - log level for this message.
 *         format - format string of the message to be filled with varargs.
 */
void logmsg(int level, const char *format, ...);

/****************************************************************************
 *
 * Closes the log file passed via init_logger. After a call to this function,
 * subsequent executions of log have undefined behavior.
 */
void close_logfile(void);

#endif /* UTILS_H */

/****************************************************************************
 *                                                                          *
 *        utils.c - Various utility functions to be used in crdss           *
 *                                                                          *
 *                    Copyright (c) 2019 Till Miemietz                      *
 *                                                                          *
 ****************************************************************************/


/****************************************************************************
 *                                                                          *
 *                           include statements                             *
 *                                                                          *
 ****************************************************************************/


#include <stdio.h>
#include <string.h>                      /* string operations               */
#include <stdarg.h>                      /* for var args                    */
#include <pthread.h>                     /* make logging threadsafe         */
#include <time.h>                        
#include <sys/time.h>                    /* for logging with timestamps     */

#include "include/utils.h"               /* header for utils implementation */

/****************************************************************************
 *                                                                          *
 *                        (module) global variables                         *
 *                                                                          *
 ****************************************************************************/


/***                         logging facility                               */

static FILE *logfile = NULL;    /* output stream for logging                */
static int cur_level = WARN;    /* current log level                        */

static pthread_mutex_t log_lck = PTHREAD_MUTEX_INITIALIZER;

/****************************************************************************
 *                                                                          *
 *                          function implementation                         *
 *                                                                          *
 ****************************************************************************/


/***              functions for logging as defined in utils.h             ***/

/* Sets up the logging facility.                                            */
void init_logger(char *lfile, int loglevel) {
    pthread_mutex_lock(&log_lck);

    cur_level = loglevel;
    logfile   = fopen(lfile, "a");
    if (logfile == NULL) {
        fprintf(stderr, "Failed to open log file %s, continuing on stderr.\n", 
                lfile);
        logfile = stderr;
    }

    pthread_mutex_unlock(&log_lck);
}

/* Sets the minmal log level for messages to appear on output.              */
void setloglevel(int newlevel) {
    pthread_mutex_lock(&log_lck);
    cur_level = newlevel;
    pthread_mutex_unlock(&log_lck);
}

/* Prints a log message to the channels configured via init_logger.         */
void logmsg(int level, const char* format, ...) {
    va_list arglist;
    char    loglvl[7];                /* six chars for level plus newline   */
    char    msg_buffer[MAX_LOGMSG_LEN];
    char    time_buffer[18];          /* buffer for storing msg timestamp   */

    struct timeval now;               /* current time                       */
    struct tm      now_tm;            /* current time broken down           */

    /* message has too low importance, silently drop it */
    if (level < cur_level)
        return;

    /* cast level information into a string */
    switch (level) {
        case SEVERE: strcpy(loglvl, "SEVERE"); break;
        case ERROR:  strcpy(loglvl, "ERROR "); break;
        case WARN:   strcpy(loglvl, "WARN  "); break;
        case INFO:   strcpy(loglvl, "INFO  "); break;
        case DEBUG:  strcpy(loglvl, "DEBUG "); break;
        default:     strcpy(loglvl, "UNKNWN"); break;
    }

    /* create a string timestamp */
    gettimeofday(&now, NULL);
    localtime_r(&now.tv_sec, &now_tm);      /* reentrant version for safety */
    /* timestamp is in German format <day>.<month>.<year> <hr>:<min>:<sec>  */
    strftime(time_buffer, 18, "%d.%m.%y %H:%M:%S", &now_tm);

    va_start(arglist, format);
    (void) vsprintf(msg_buffer, format, arglist);
    va_end(arglist);

    /* take mutex for writing to the logfile to avoid producing garbage     */
    pthread_mutex_lock(&log_lck);

    /* write message to logfile                                             */
    if (logfile != NULL) {
        fprintf(logfile, "[%s]: %s - %s\n", time_buffer, loglvl, msg_buffer);
        fflush(logfile);
    }

    pthread_mutex_unlock(&log_lck);
}

/* Closes the file passed via init_logger.                                  */
void close_logfile(void) {
    (void) fclose(logfile);
}

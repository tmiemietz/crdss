#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sqlite3.h>
#include <limits.h>
#include <time.h>
#include <math.h>

#define NR_RECORDS 50000

static int execute(sqlite3 *db, const char *sql) {
    char *zErrMsg = 0;
    int rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }

    return(rc);
}

static int compare_ularray(const void *p1, const void *p2) {
    unsigned long ul1 = *((unsigned long *) p1);
    unsigned long ul2 = *((unsigned long *) p2);

    if (ul1 < ul2)
        return(-1);
    else if (ul1 > ul2)
        return(1);
    else
        return(0);
}

__attribute__ ((unused))
static unsigned long array_max(unsigned long *array, size_t nr_elems) {
    unsigned long max = 0;
    unsigned int i;

    for (i = 0; i < nr_elems; i++) {
        if (array[i] > max) {
            max = array[i];
        }
    }

    return(max);
}

__attribute__ ((unused))
static unsigned long array_min(unsigned long *array, size_t nr_elems) {
    unsigned long min = ULONG_MAX;
    unsigned int i;

    for (i = 0; i < nr_elems; i++) {
        if (array[i] < min) {
            min = array[i];
        }
    }

    return(min);
}

static unsigned long array_avg(unsigned long *array, size_t nr_elems) {
    unsigned long avg = 0;
    unsigned int i;

    for (i = 0; i < nr_elems; i++) {
        avg += array[i];
    }

    avg = (unsigned long) round((double) avg / nr_elems);
    return(avg);
}

int main(int argc, char **argv) {
    int i;
    unsigned long nano_diffs[NR_RECORDS];
    unsigned long nano_sum = 0;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return(1);
    }

    /* init RNGesus */
    srand(time(NULL));

    sqlite3 *db;
    /* char *zErrMsg = 0; */
    int rc;

    rc = sqlite3_open(argv[1], &db);
    if (rc) {
        fprintf(stderr, "Can't open database file %s: %s\n", 
                argv[1], sqlite3_errmsg(db));
        exit(1);
    }

    for (i = 0; i < NR_RECORDS; i++) {
        struct timespec start;
        struct timespec end;
        char tmpsql[256];
        int query_res;
        
        unsigned int next_idx = rand() % 20000;

        memset(&tmpsql, 0, 256);
        snprintf(tmpsql, sizeof(tmpsql),
            "SELECT * from TEST WHERE ID = %u", next_idx);

        clock_gettime(CLOCK_MONOTONIC, &start);
        query_res = execute(db, tmpsql);
        clock_gettime(CLOCK_MONOTONIC, &end);

        nano_diffs[i] = (end.tv_sec * 1000000000 + end.tv_nsec) -
                        (start.tv_sec * 1000000000 + start.tv_nsec);
   
        nano_sum += nano_diffs[i];

        if (query_res != SQLITE_OK) {
            fprintf(stderr, "Error during database query. "
                    "Terminating benchmark.\n");
            exit(1);
        }
    }

    sqlite3_close(db);
    
    /* do some statistics */
    qsort(nano_diffs, NR_RECORDS, sizeof(unsigned long), &compare_ularray);

    fprintf(stderr, "\n\nStatistics for sqlite benchmark on file %s:\n\n",
            argv[1]);
    fprintf(stderr, "Read %u records in %lu ns.\n", NR_RECORDS, nano_sum);
    fprintf(stderr, "Min lat: %lu ns, Max lat: %lu ns, Avg lat: %lu ns\n",
            nano_diffs[0], nano_diffs[NR_RECORDS - 1], 
            array_avg(nano_diffs, NR_RECORDS));
    fprintf(stderr, "50th: %lu ns, 75th: %lu ns, 95th: %lu ns, 99th %lu ns\n",
            nano_diffs[NR_RECORDS * 50 / 100],
            nano_diffs[NR_RECORDS * 75 / 100],
            nano_diffs[NR_RECORDS * 96 / 100],
            nano_diffs[NR_RECORDS * 99 / 100]);

    return(0);
}

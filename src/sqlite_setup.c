#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>

#define INSERT_COUNT 20000000

static void execute(sqlite3 *db, const char *sql) {
    char *zErrMsg = 0;
    int rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }
}

int main(int argc, char **argv) {
    char random_data[8192];
    random_data[8191] = '\0';

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return(1);
    }

    sqlite3 *db;
    /* char *zErrMsg = 0; */
    int rc;

    rc = sqlite3_open(argv[1], &db);
    if (rc) {
        fprintf(stderr, "Can't open database file %s: %s\n", 
                argv[1], sqlite3_errmsg(db));
        exit(1);
    }

    execute(db, "CREATE TABLE TEST ("  \
        "ID INT PRIMARY KEY NOT NULL," \
        "T_TEXT         TEXT," \
        "T_INT          INT," \
        "T_CHAR         CHAR(50)," \
        "T_REAL         REAL," \
        "T_LCHAR        CHAR(8192)" \
    ");");

    execute(db, "BEGIN TRANSACTION");
    for (int i = 0; i < INSERT_COUNT; ++i) {
        char tmpsql[9000];
        snprintf(tmpsql, sizeof(tmpsql),
            "INSERT INTO TEST (ID, T_TEXT, T_INT, T_CHAR, T_REAL, T_LCHAR) " \
            "VALUES (%d, 'My text', %d, 'My char', %f, '%s');",
            i + 1, i * 12, i * 3.4f, random_data);
        execute(db, tmpsql);
    }
    execute(db, "END TRANSACTION");

    sqlite3_close(db);
    return 0;
}

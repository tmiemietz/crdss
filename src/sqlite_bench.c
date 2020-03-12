#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>

#define INSERT_COUNT    8

static void execute(sqlite3 *db, const char *sql) {
    char *zErrMsg = 0;
    int rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }
}

int main(int argc, char **argv) {
    if(argc < 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }

    sqlite3 *db;
    /* char *zErrMsg = 0; */
    int rc;

    rc = sqlite3_open(argv[1], &db);
    if( rc ) {
        fprintf(stderr, "Can't open database file %s: %s\n", argv[1], sqlite3_errmsg(db));
        exit(0);
    }

    execute(db, "CREATE TABLE TEST ("  \
        "ID INT PRIMARY KEY NOT NULL," \
        "T_TEXT         TEXT," \
        "T_INT          INT," \
        "T_CHAR         CHAR(50)," \
        "T_REAL         REAL" \
    ");");

    for(int i = 0; i < INSERT_COUNT; ++i) {
        char tmpsql[256];
        snprintf(tmpsql, sizeof(tmpsql),
            "INSERT INTO TEST (ID, T_TEXT, T_INT, T_CHAR, T_REAL)" \
            "VALUES (%d, 'My text', %d, 'My char', %f);",
            i + 1, i * 12, i * 3.4f);
        execute(db, tmpsql);
    }

    execute(db, "SELECT * from TEST");

    sqlite3_close(db);
    return 0;
}

/*
* prepared.c - demonstrate how to use prepared statements.
*/

#include <my_global.h>
#include <my_sys.h>
#include <m_string.h> /* for strdup() */
#include <mysql.h>
#include <my_getopt.h>

static void print_stmt_error(MYSQL_STMT *stmt, char *message);
static void print_error(MYSQL *conn, char *message);
void str_unfill(char* str, char toDelete);


#include <sslopt-vars.h>

static int ask_password = 0; /* whether to solicit password */

//static MYSQL *conn; /* pointer to connection handler */


#include "process_prepared_statement.c"

int start_db_connection(MYSQL **conn, char* user, char* pwd, char* ip, int porta, char* dbname)
{
    /*
     *  returned value:
     *  0: no error
     *  1: connection failed
     *  2: mysql init failed
     */

    /* initialize connection handler */
    *conn = mysql_init(NULL);
    if (*conn == NULL)
    {
        print_error(NULL, "mysql_init() failed (probably out of memory)");
        return 2;
    }

    if (mysql_real_connect(*conn, ip, user, pwd, dbname, porta, "/var/run/mysqld/mysqld.sock", "(null)") == NULL)
    {
        printf("mysql_real_connect() failed");
        mysql_close(*conn);
        return 1;
    }

}
//    process_prepared_statements(conn, energia);

int close_db_connection(MYSQL **conn)
{
    /*
     *  returned value:
     *  0: no errors
     *  1: mysql_close failed
     */

    /* disconnect from server*/
    if( *conn != NULL )
    {
        mysql_close(*conn);
        return 0;
    }
    return 1;
}

void str_unfill(char* str, char toDelete)
{

    int i = 0;
    int j = 0;
    char *newString = (char*) malloc(strlen(str) + 1);
    for (i = 0, j = 0; i < strlen(str); i++) {
        if (str[i] != toDelete) {
            newString[j] = str[i];
            j++;
        }
    }
    newString[j] = 0;
    strcpy(str, newString);
    free(newString);
}

static void
print_error(MYSQL *conn, char *message) {
    fprintf(stderr, "%s\n", message);
    if (conn != NULL) {
        fprintf(stderr, "Error %u (%s): %s\n",
                mysql_errno(conn), mysql_sqlstate(conn), mysql_error(conn));
    }
}

/* #@ _PRINT_STMT_ERROR_ */
static void
print_stmt_error(MYSQL_STMT *stmt, char *message) {
    fprintf(stderr, "%s\n", message);
    if (stmt != NULL) {
        fprintf(stderr, "Error %u (%s): %s\n",
                mysql_stmt_errno(stmt),
                mysql_stmt_sqlstate(stmt),
                mysql_stmt_error(stmt));
    }
}


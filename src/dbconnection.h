/* 
 * File:   dbconnection.h
 * Author: nagash
 *
 * Created on 6 maggio 2010, 14.57
 */

#include <my_global.h>
#include <my_sys.h>
#include <m_string.h> /* for strdup() */
#include <mysql.h>
#include <my_getopt.h>


#include <sslopt-vars.h>

#include "statement.h"

#ifndef _DBCONNECTION_H
#define	_DBCONNECTION_H

#ifdef	__cplusplus
extern "C" {
#endif

    
void print_stmt_error(MYSQL_STMT *stmt, char *message);
void print_error(MYSQL *conn, char *message);
void str_unfill(char* str, char toDelete);


int start_db_connection(MYSQL **conn, char* user, char* pwd, char* ip, int porta, char* dbname);
int close_db_connection(MYSQL **conn);


#ifdef	__cplusplus
}
#endif

#endif	/* _DBCONNECTION_H */


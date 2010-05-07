/* 
 * File:   statement.h
 * Author: nagash
 *
 * Created on 6 maggio 2010, 14.56
 */

#ifndef _STATEMENT_H
#define	_STATEMENT_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <mysql/mysql.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>//per funzione free
    
void print_stmt_error (MYSQL_STMT *stmt, char *message);
void print_error(MYSQL *conn, char *msg);
int process_prepared_statements(MYSQL *conn, MYSQL_STMT **stmt);

typedef struct
{
    my_bool valid;
    long EIS;
    my_bool writable;
} Filtro;




typedef struct
{
    MYSQL_TIME data;
    char timestamp[16];
    char mittente[10];
    char destinatario[10];
    float valore;
} Energia;


void initFiltro(Filtro *toInit);

int insert_filtro( MYSQL *conn, char* destinatario);
int insert_dati( MYSQL *conn, Energia toWrite );
int select_filtro ( MYSQL *conn, char* destinatario, Filtro* filtro);
void free_filtro( Filtro* filtro);
int process_prepared_statements(MYSQL *conn, MYSQL_STMT **stmt);

#ifdef	__cplusplus
}
#endif

#endif	/* _STATEMENT_H */


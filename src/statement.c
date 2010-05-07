/* #@ _INSERT_RECORDS_ */

#include "statement.h"


void initFiltro(Filtro *toInit)
{
    toInit->EIS = 0;
    toInit->writable = 0;
}


int insert_filtro( MYSQL *conn, char* destinatario)
{


    MYSQL_STMT *stmt;
    process_prepared_statements(conn, &stmt);
    char *stmt_str = "INSERT INTO filtro (Destinatario) VALUES(?)";

  // my_bool is_null[5];
   MYSQL_BIND param[1];


  if (mysql_stmt_prepare (stmt, stmt_str, strlen (stmt_str)) != 0)
  {
    print_stmt_error (stmt, "Could not prepare INSERT statement");

    return 1;
  }


  memset ((void *) param, 0, sizeof (param)); //setto a 0 tutti i bit



  //definisco il tipo del campo, un puntatore al valore da scrivere nel campo e altro.
  param[0].buffer_type = MYSQL_TYPE_STRING;
  param[0].buffer = (void *) destinatario;
  param[0].buffer_length = strlen(destinatario);
  param[0].is_null = 0;





  if (mysql_stmt_bind_param (stmt, param) != 0)// inserisco i parametri nello statment al posto dei '?'
  {
    print_stmt_error (stmt, "Could not bind parameters for INSERT");
    return 2;
  }


   if (mysql_stmt_execute (stmt) != 0)
   {
      print_stmt_error (stmt, "Could not execute statement");
      return 3;
   }
   else printf ("Statment execution success: record inserting in table SUCCESS!\n");


   mysql_stmt_close(stmt); /* deallocate statement handler */
   return 0;
}

int insert_dati( MYSQL *conn, Energia toWrite )
{
    MYSQL_STMT *stmt;
    process_prepared_statements(conn, &stmt);
    char *stmt_str = "INSERT INTO dati (Data,Timestamp,Mittente,Destinatario,Valore) VALUES(?,?,?,?,?)";

  // my_bool is_null[5];
   MYSQL_BIND param[5];

  printf ("Inserting records... ");


  if (mysql_stmt_prepare (stmt, stmt_str, strlen (stmt_str)) != 0)
  {
    print_stmt_error (stmt, "Could not prepare INSERT statement");
    return 1;
  }


  memset ((void *) param, 0, sizeof (param)); //setto a 0 tutti i bit


  //definisco il tipo del campo, un puntatore al valore da scrivere nel campo e altro.
  param[0].buffer_type = MYSQL_TYPE_DATE;
  param[0].buffer = (void *) &toWrite.data;
  param[0].is_unsigned = 0;
  param[0].is_null = 0;

  param[1].buffer_type = MYSQL_TYPE_STRING;
  param[1].buffer = (void *) toWrite.timestamp;
  param[1].buffer_length = strlen(toWrite.timestamp);
  param[1].is_null = 0;

  param[2].buffer_type = MYSQL_TYPE_STRING;
  param[2].buffer = (void *) toWrite.mittente;
  param[2].buffer_length = strlen(toWrite.mittente);
  param[2].is_null = 0;


  param[3].buffer_type = MYSQL_TYPE_STRING;
  param[3].buffer = (void *) &toWrite.destinatario;
  param[3].buffer_length = strlen(toWrite.destinatario);
  param[3].is_null = 0;


  param[4].buffer_type = MYSQL_TYPE_FLOAT;
  param[4].buffer = (void*)&toWrite.valore;
  param[4].buffer_length = sizeof(toWrite.valore);
  param[4].is_unsigned =  0;
  param[4].is_null = 0;




  if (mysql_stmt_bind_param (stmt, param) != 0)// inserisco i parametri nello statment al posto dei '?'
  {
    print_stmt_error (stmt, "Could not bind parameters for INSERT");
    return 2;
  }


   if (mysql_stmt_execute (stmt) != 0)
   {
      print_stmt_error (stmt, "Could not execute statement");
      return 3;
   }


   else printf ("Statment execution success: record inserting in table SUCCESS!\n");
   mysql_stmt_close(stmt); /* deallocate statement handler */

}


void free_filtro( Filtro* filtro)
{
    if( filtro != NULL )free(filtro);
}
int select_filtro ( MYSQL *conn, char* destinatario, Filtro* filtro)
{
    MYSQL_STMT *stmt;

    process_prepared_statements(conn, &stmt);
    char stmt_str[2048] = "SELECT Writable,EIS FROM filtro WHERE Destinatario = \"";


    strcat(stmt_str, destinatario);
    strcat(stmt_str, "\"");


    MYSQL_BIND param[2];
    my_bool is_null[2];



    printf("query = %s\n",stmt_str);



  if (mysql_stmt_prepare (stmt, stmt_str, strlen (stmt_str)) != 0)
  {
    print_stmt_error (stmt, "Could not prepare SELECT statement");
    return 1;
  }



  memset ((void *) param, 0, sizeof (param)); /* zero the structures */


  param[0].buffer_type = MYSQL_TYPE_BIT;
  param[0].buffer_length = 1;
  param[0].buffer = (void *) &(filtro->writable);
  param[0].is_null = &is_null[0];

  param[1].buffer_type = MYSQL_TYPE_LONG;
  param[1].buffer_length = 4;
  param[1].buffer = (void *) &(filtro->EIS);
  param[1].is_null = &is_null[1];



  if (mysql_stmt_bind_result (stmt, param) != 0)
  {
    print_stmt_error (stmt, "Could not bind parameters for SELECT");
    return 3;
  }


  if (mysql_stmt_execute (stmt) != 0)
  {
    print_stmt_error (stmt, "Could not execute SELECT");
    return 4;
  }


  if (mysql_stmt_store_result (stmt) != 0)
  {
    print_stmt_error (stmt, "Could not buffer result set");
    return 5;
  }
  else
  {
    unsigned long num_rows = (unsigned long) mysql_stmt_num_rows (stmt);

    if(num_rows == 0 )
    {
        filtro->valid = 0;
        filtro->writable = 0;
        filtro->EIS = 0;
    }
  }


  while (mysql_stmt_fetch (stmt) == 0) // fetch each row
  {
    //display row values
     printf("writable = %d\n", filtro->writable);
  }




  mysql_stmt_free_result (stmt); /* deallocate result set */

    mysql_stmt_close (stmt); /* deallocate statement handler */

    return 0;

}



/*
 * char *drop_stmt = "DROP TABLE IF EXISTS t";
    char *create_stmt = "CREATE TABLE t (i INT, f FLOAT, c CHAR(24), dt DATETIME)";
 *
 *   if (mysql_query (conn, use_stmt) != 0
    || mysql_query (conn, drop_stmt) != 0
    || mysql_query (conn, create_stmt) != 0)
  {
    print_error (conn, "Could not set up test table");
    return;
  }


 * */

int process_prepared_statements(MYSQL *conn, MYSQL_STMT **stmt)
{

    char *use_stmt = "USE konnex";
    /* select database and create test table */
    if (mysql_query (conn, use_stmt) != 0 )
    {
        print_error (conn, "Could not set up konnex table");
        return 1;
    }

    *stmt = mysql_stmt_init (conn); /* allocate statement handler */

    if (*stmt == NULL)
    {
        print_error (conn, "Could not initialize statement handler");
        return 2;
    }

    return 0;
}

/*

  Filtro filtro =  select_filtro (stmt,energia.destinatario);
  //se EIS è 0 c'è stato un errore nella funzione select_filtro(..)
  if( filtro.writable == 1 && filtro.EIS != 0 )
  {
      insert_dati (stmt, energia);
  }

 */



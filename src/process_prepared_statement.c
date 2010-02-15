/* #@ _INSERT_RECORDS_ */

#include <mysql/mysql.h>
#include <string.h>
static void print_stmt_error (MYSQL_STMT *stmt, char *message);
static void print_error(MYSQL *conn, char *msg);
//inseriti io.. dovremo usare dei .h ^^
 

typedef struct
{
    MYSQL_TIME data;
    char timestamp[16];
    char mittente[10];
    char destinatario[10];
    char valore[16];
} Energia;





static void insert_dati(MYSQL_STMT *stmt, Energia toWrite )
{
char          *stmt_str = "INSERT INTO dati (Data,Timestamp,Mittente,Destinatario,Valore) VALUES(?,?,?,?,?)";
//                                        DATA  CHAR 15   CHAR 9    CHAR 9      char 15

   MYSQL_BIND    param[5];

  printf ("Inserting records...  ");


  if (mysql_stmt_prepare (stmt, stmt_str, strlen (stmt_str)) != 0)
  {
    print_stmt_error (stmt, "Could not prepare INSERT statement");
    return;
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

  param[4].buffer_type = MYSQL_TYPE_STRING;
  param[4].buffer = (void *) &toWrite.valore;
  param[4].buffer_length = strlen(toWrite.valore);
  param[4].is_null = 0;



  
  if (mysql_stmt_bind_param (stmt, param) != 0)// inserisco i parametri nello statment al posto dei '?'
  {
    print_stmt_error (stmt, "Could not bind parameters for INSERT");
    return;
  }
  



    if (mysql_stmt_execute (stmt) != 0)
    {
      print_stmt_error (stmt, "Could not execute statement");
      return;
    }

   else printf ("Statment execution success: record inserting in table SUCCESS!\n");


}





static bool select_filtro (MYSQL_STMT *stmt, char* destinatario)
{

    char          stmt_str[2048] = "SELECT Writable FROM filtro WHERE Destinatario = \"";


    strcat(stmt_str, destinatario);
    strcat(stmt_str, "\"");


    MYSQL_BIND    param[1];
    my_bool       writable;
    my_bool       is_null[1];

    printf("query =");printf(stmt_str);printf("\n");

  if (mysql_stmt_prepare (stmt, stmt_str, strlen (stmt_str)) != 0)
  {
    print_stmt_error (stmt, "Could not prepare SELECT statement");
    return 0;
  }

  if (mysql_stmt_field_count (stmt) != 1)
  {
    print_stmt_error (stmt, "Unexpected column count from SELECT");
    return 0;
  }


  memset ((void *) param, 0, sizeof (param)); /* zero the structures */



  param[0].buffer_type = MYSQL_TYPE_BIT;
  param[0].buffer_length = 1;
  param[0].buffer = (void *) &writable;
  param[0].is_null = &is_null[0];



  
  if (mysql_stmt_bind_result (stmt, param) != 0)
  {
    print_stmt_error (stmt, "Could not bind parameters for SELECT");
    return 0;
  }


  if (mysql_stmt_execute (stmt) != 0)
  {
    print_stmt_error (stmt, "Could not execute SELECT");
    return 0;
  }



  if (mysql_stmt_store_result (stmt) != 0)
  {
    print_stmt_error (stmt, "Could not buffer result set");
    return 0;
  }
  else
  {
    /* mysql_stmt_store_result() makes row count available */
    unsigned long num_rows = (unsigned long) mysql_stmt_num_rows (stmt);

    if(num_rows == 0 ) return 0;
    else printf ("Number of rows retrieved: %lu\n",num_rows);
    
  }


  while (mysql_stmt_fetch (stmt) == 0)  // fetch each row
  {
    //display row values 
    printf("writable = %d\n", writable);
  }
  


  mysql_stmt_free_result (stmt);      /* deallocate result set */
  
  
  return writable;

}





void process_prepared_statements (MYSQL *conn, Energia energia)
{
MYSQL_STMT *stmt;
char       *use_stmt = "USE konnex";
char       *drop_stmt = "DROP TABLE IF EXISTS t";
char       *create_stmt =
  "CREATE TABLE t (i INT, f FLOAT, c CHAR(24), dt DATETIME)";

  /* select database and create test table */

  if (mysql_query (conn, use_stmt) != 0
    || mysql_query (conn, drop_stmt) != 0
    || mysql_query (conn, create_stmt) != 0)
  {
    print_error (conn, "Could not set up test table");
    return;
  }

  stmt = mysql_stmt_init (conn);  /* allocate statement handler */
  if (stmt == NULL)
  {
    print_error (conn, "Could not initialize statement handler");
    return;
  }

  /* insert and retrieve some records */
     
  if( select_filtro(stmt, energia.destinatario) )
  {
      insert_dati (stmt, energia);
  }
  mysql_stmt_close (stmt);       /* deallocate statement handler */
}


/* #@ _INSERT_RECORDS_ */

#include <mysql/mysql.h>

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

static void insert_energia(MYSQL_STMT *stmt, Energia toWrite )
{
char          *stmt_str = "INSERT INTO energia (Data,Timestamp,Mittente,Destinatario,Valore) VALUES(?,?,?,?,?)";
//                                        DATA  CHAR 15   CHAR 9    CHAR 9      char 15

   MYSQL_BIND    param[5];

  printf ("Inserting records...\n");

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


  printf ("Inserting record in statment 'stmt' success\n");


    if (mysql_stmt_execute (stmt) != 0)
    {
      print_stmt_error (stmt, "Could not execute statement");
      return;
    }

  printf ("Statment execution success: record inserting in table success!\n");


}
/* #@ _INSERT_RECORDS_ */


/* #@ _SELECT_RECORDS_ */
static void select_rows (MYSQL_STMT *stmt)
{
char          *stmt_str = "SELECT i, f, c, dt FROM t";
MYSQL_BIND    param[4];
int           my_int;
float         my_float;
char          my_str[24];
unsigned long my_str_length;
MYSQL_TIME    my_datetime;
my_bool       is_null[4];

  printf ("Retrieving records...\n");

  if (mysql_stmt_prepare (stmt, stmt_str, strlen (stmt_str)) != 0)
  {
    print_stmt_error (stmt, "Could not prepare SELECT statement");
    return;
  }

  if (mysql_stmt_field_count (stmt) != 4)
  {
    print_stmt_error (stmt, "Unexpected column count from SELECT");
    return;
  }

  /*
   * initialize the result column structures
   */

  memset ((void *) param, 0, sizeof (param)); /* zero the structures */

  /* set up INT parameter */

  param[0].buffer_type = MYSQL_TYPE_LONG;
  param[0].buffer = (void *) &my_int;
  param[0].is_unsigned = 0;
  param[0].is_null = &is_null[0];
  /* buffer_length, length need not be set */

  /* set up FLOAT parameter */

  param[1].buffer_type = MYSQL_TYPE_FLOAT;
  param[1].buffer = (void *) &my_float;
  param[1].is_null = &is_null[1];
  /* is_unsigned, buffer_length, length need not be set */

  /* set up CHAR parameter */

  param[2].buffer_type = MYSQL_TYPE_STRING;
  param[2].buffer = (void *) my_str;
  param[2].buffer_length = sizeof (my_str);
  param[2].length = &my_str_length;
  param[2].is_null = &is_null[2];
  /* is_unsigned need not be set */

  /* set up DATETIME parameter */

  param[3].buffer_type = MYSQL_TYPE_DATETIME;
  param[3].buffer = (void *) &my_datetime;
  param[3].is_null = &is_null[3];
  /* is_unsigned, buffer_length, length need not be set */

  if (mysql_stmt_bind_result (stmt, param) != 0)
  {
    print_stmt_error (stmt, "Could not bind parameters for SELECT");
    return;
  }

  if (mysql_stmt_execute (stmt) != 0)
  {
    print_stmt_error (stmt, "Could not execute SELECT");
    return;
  }

  /*
   * fetch result set into client memory; this is optional, but it
   * allows mysql_stmt_num_rows() to be called to determine the
   * number of rows in the result set.
   */

  if (mysql_stmt_store_result (stmt) != 0)
  {
    print_stmt_error (stmt, "Could not buffer result set");
    return;
  }
  else
  {
    /* mysql_stmt_store_result() makes row count available */
    printf ("Number of rows retrieved: %lu\n",
            (unsigned long) mysql_stmt_num_rows (stmt));
  }

  while (mysql_stmt_fetch (stmt) == 0)  /* fetch each row */
  {
    /* display row values */
    printf ("%d  ", my_int);
    printf ("%.2f  ", my_float);
    printf ("%*.*s  ", my_str_length, my_str_length, my_str);
    printf ("%04d-%02d-%02d %02d:%02d:%02d\n",
            my_datetime.year,
            my_datetime.month,
            my_datetime.day,
            my_datetime.hour,
            my_datetime.minute,
            my_datetime.second);
  }

  mysql_stmt_free_result (stmt);      /* deallocate result set */
}
/* #@ _SELECT_RECORDS_ */

/* #@ _PROCESS_PREPARED_STATEMENTS_ */
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

/*
  Energia ene;
  strcpy(ene.destinatario,"dest1");
  strcpy(ene.mittente, "mit");
  strcpy(ene.timestamp, "01:01 tstamp");
  strcpy(ene.valore, "value");
*/
  insert_energia (stmt, energia);
  //select_rows (stmt);

  mysql_stmt_close (stmt);       /* deallocate statement handler */
}
/* #@ _PROCESS_PREPARED_STATEMENTS_ */

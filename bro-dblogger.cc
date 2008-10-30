
#include <string>
#include <list>
#include <map>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>

extern "C" {
	#include "broccoli.h"
	#include "libpq-fe.h"
}

using namespace std;

using std::string;
using std::list;
using std::cout;
using std::cin;
using std::cerr;

string default_postgresql_host = "127.0.0.1";
string default_postgresql_port = "5432";
int default_seconds_between_copyend = 30;

string postgresql_host, postgresql_port;
string postgresql_user, postgresql_password, postgresql_db;
int seconds_between_copyend;

int debugging = 0;
// By default, show output
int verbose_output = 1;
BroConn *bc;

// Only use this if connections to multiple Bro instances is implemented.
//class BroConnection {
//	public:
//		BroConn *bc;
//};
//std::list<BroConnection> bro_conns;

class PGConnection {
	public:
		PGconn *conn;
		
		// The "Copy" query that this connection is associated with.
		std::string query;

		// The record keeping count of records in the current Copy query.
		int records;

		// Unix timestamp of last CopyEnd.
		time_t last_insert;
		
		// This is if the COPY query should be attempted again.
		bool try_it;
};
std::map<std::string, PGConnection> pg_conns;

class BadConversion : public std::runtime_error {
public:
  BadConversion(const std::string& s)
    : std::runtime_error(s)
    { }
};

template<typename T>
inline std::string stringify(const T& x)
{
  std::ostringstream o;
  if (!(o << fixed << x))
    throw BadConversion(std::string("stringify(")
                        + typeid(x).name() + ")");
  return o.str();
}

void usage(void)
	{
	cout << "bro_dblogger - Listens for the db_log event and pushes data into a database." << endl <<
		"USAGE: bro_dblogger -hqD [-s seconds] [-H postgres_host=localhost] [-p postgres_port=5432] -d database_name -u postgres_user [-P postgres_password] bro_host bro_port" << endl << 
		endl << 
		"  -h       Display this help message." << endl <<
		"  -q       Run in quiet mode, only outputting errors." << endl <<
		"  -s secs  Number of seconds between database flushes (default 30)." << endl <<
		"  -D       Enable debugging output from Broccoli (if Broccoli was compiled in debugging mode)." << endl << endl;
	exit(0);
	}

BroConn* connect_to_bro(std::string host, std::string port)
	{
	BroConn *conn;
	
	// now connect to the bro host - on failure, try again three times
	// the flags here are telling us to block on connect, reconnect in the
	// event of a connection failure, and queue up events in the event of a
	// failure to the bro host
	if (! (conn = bro_conn_new_str( (host + ":" + port).c_str(), BRO_CFLAG_NONE)))
		{
		cerr << endl << "Could not connect to Bro (" << host << ") at " <<
		        host << ":" << port << endl;
		exit(-1);
		}

	if (!bro_conn_connect(conn)) {
		cerr << endl << "Could not connect to Bro at " << host << ":" << port << endl;
		exit(-1);
	} else {
		if(verbose_output)
			cerr << "Connected to Bro (" << host << ") at " <<
			        host << ":" << port << endl;
	}
	
	return conn;
	}
	
int connect_to_postgres(std::string table)
	{
	if(pg_conns.count(table)>0)
		return 0;
	
	std::string connect_string =
		"host="+postgresql_host+" port="+postgresql_port+" user="+postgresql_user+" password="+postgresql_password+" dbname="+postgresql_db+" ";
	if( !(pg_conns[table].conn = PQconnectStart(connect_string.c_str())) )
		{
		cerr << "Total screw up with the postgres connection" << endl;
		exit(-1);
		}

	if(verbose_output)
		cout << endl << "Connecting to PostgreSQL";
	while( PQconnectPoll(pg_conns[table].conn) != PGRES_POLLING_OK )
		{
		if( PQstatus(pg_conns[table].conn) == CONNECTION_BAD )
			{
			cout << PQerrorMessage(pg_conns[table].conn) <<endl;
			exit(-1);
			}
			
		if(verbose_output)
			{
			cout << "."; 
			cout.flush();
			}
		sleep(1);
		}
	if(verbose_output)
		cout << "done" << endl;

	PQsetnonblocking(pg_conns[table].conn, 1);
	if(PQisnonblocking(pg_conns[table].conn))
		{
		if(verbose_output)
			cout << "PostgreSQL is in non-blocking mode" << endl;
		}
	return 0;
	}
	
void db_log_flush_all_event_handler(BroConn *bc, void *user_data, BroEvMeta *meta)
	{
	char *error_message = NULL;
	
	if(verbose_output)
		cout << endl << "Flushing all active COPY queries to the database" << endl;
	
	if( meta->ev_numargs > 0 )
		cerr << "db_log_flush_all takes no arguments, but " << meta->ev_numargs << " were given" << endl;
	
	map<string,PGConnection>::iterator iter;   
	for( iter = pg_conns.begin(); iter != pg_conns.end(); iter++ )
		{
		if(PQputCopyEnd(iter->second.conn, error_message) != 1)
			cerr << "ERROR: " << PQerrorMessage(iter->second.conn) << error_message << endl;
		else
			{
			if(verbose_output)
				cout << endl << "Inserting " << iter->second.records << " records into " << iter->first << "." << endl;
			}
		
		}
		
	user_data=NULL;
	meta=NULL;	
	}
	
void db_log_flush_event_handler(BroConn *bc, void *user_data, BroEvMeta *meta)
	{
	char *error_message = NULL;
	std::string table;

	if( meta->ev_numargs != 1 )
		{
		cerr << "db_log_flush takes one arguments, but " << meta->ev_numargs << " were given" << endl;
		return;
		}
		
	table = (const char*) bro_string_get_data( (BroString*) meta->ev_args[0].arg_data );

	if(verbose_output)
		cout << "Flushing active COPY query for table '" << table << "' to the database" << endl;

	if(pg_conns.count(table) > 0)
		{
		if(PQputCopyEnd(pg_conns[table].conn, error_message) != 1)
			cerr << "ERROR: " << PQerrorMessage(pg_conns[table].conn) << error_message << endl;
		else
			{
			if(verbose_output)
				cout << endl << "Inserting " << pg_conns[table].records << " records into " << table << "." << endl;
			}
		}
	else
		{
		cerr << "Attempted to flush table '" << table << "', but no active query for that table exists." << endl;
		}

	user_data=NULL;
	meta=NULL;	
	}

	
//global db_log: event(db_table: string, data: any);
void db_log_event_handler(BroConn *bc, void *user_data, BroEvMeta *meta)
	{
	int type=0;
	int diff_seconds;
	char *error_message = NULL;
	
	struct in_addr ip={0};
	std::string table("");
	std::string field_names("");
	std::string output_value("");
	
	PGresult *result;
	int result_status;
	
	if( meta->ev_numargs != 2 ||
	    meta->ev_args[0].arg_type != BRO_TYPE_STRING ||
	    meta->ev_args[1].arg_type != BRO_TYPE_RECORD)
		{
		cerr << "Arguments to the db_log callback are incorrect! (number and/or type)" << endl;
		return;
		}
		
	table.append((const char*) bro_string_get_data( (BroString*) meta->ev_args[0].arg_data));	

	// If try_it is false, skip all of this.  This query has had a fatal error.
	if( pg_conns.count(table)>0 && !pg_conns[table].try_it )
		{
		cerr << "ERROR: Some earlier fatal error with " << table << endl;
		return;
		}
	
	BroRecord* r = (BroRecord*) meta->ev_args[1].arg_data;
	void* data;
	const char* field_name;
	
	int rec_len = bro_record_get_length(r);
	for(int i=0 ; i < rec_len ; i++)
		{
		if(i>0)
			{
			output_value.append("\t");
			field_names.append(", ");
			}
		// type needs to be zero so that it can be assigned with
		// whatever type the record value actually is.
		type=0;
		data = bro_record_get_nth_val(r, i, &type);
		
		field_name = bro_record_get_nth_name(r, i);
		field_names.append(field_name);
		
		std::string str;
		int x;
		int str_begin=0;
		
		if(data==NULL)
			{
			cerr << "data couldn't be grabbed from record!" << endl;
			return;
			}
		switch (type)
			{
			case BRO_TYPE_INT:
				output_value.append(stringify(*((int *) data)));
				break;
			case BRO_TYPE_PORT:
				output_value.append(stringify( (*((bro_port *) data)).port_num ));
				break;
			case BRO_TYPE_STRING:
				str = stringify(bro_string_get_data((BroString*) data));
				// Double up backslashes so as not to attempt to put 
				// raw data into the database.
				for( x=str.length(); x>str_begin; x--)
					{
					if(str.compare(x,1,"\\")==0)
						str.insert(x+1, "\\");
					if(str.compare(x,1,"\t")==0)
						{
						str.erase(x,1);
						str_begin++;
						}
					}
				output_value.append(str);
				break;
			case BRO_TYPE_COUNT:
				output_value.append(stringify(*((uint32 *) data)));
				break;
			case BRO_TYPE_TIME:
			case BRO_TYPE_DOUBLE:
			case BRO_TYPE_INTERVAL:
				output_value.append(stringify(*((double *) data)));
				break;
			case BRO_TYPE_BOOL:
				output_value.append(*((int *) data) ? "true" : "false");
				break;
			case BRO_TYPE_IPADDR:
				ip.s_addr = *((uint32 *) data);
				output_value.append(inet_ntoa(ip));
				break;
			default:
				cerr << "unhandled data type" << endl;
				output_value.append("\\N");
				break;
			}
		}
		
	// Connect to the database for the current table if not already done.
	if( pg_conns.count(table)<1 )
		{
		connect_to_postgres(table);
		pg_conns[table].records = 0;
		pg_conns[table].last_insert = time((time_t *)NULL);
		pg_conns[table].try_it = true;
		pg_conns[table].query = "COPY " + table + " (" + field_names + ") FROM STDIN";
		}
	
	result = PQgetResult(pg_conns[table].conn);
	result_status = PQresultStatus(result);
	PQclear(result);
	if(result_status != PGRES_COPY_IN)
		{
		if(verbose_output)
			cout << endl << "Executing: " << pg_conns[table].query << endl;
		
		result = PQexec(pg_conns[table].conn, pg_conns[table].query.c_str());
		result_status = PQresultStatus(result);
		PQclear(result);
		if(result_status == PGRES_FATAL_ERROR)
			{
			cerr << "On table (" << table << ") -- " << PQerrorMessage(pg_conns[table].conn) << endl;
			cerr << "    Removing the '" << table << "' table due to failure." << endl;
			pg_conns[table].try_it=false;
			return;
			}
		}

	if(verbose_output)
		{
		cout << ".";
		cout.flush();
		}
		
	output_value.append("\n");
	if(PQputCopyData(pg_conns[table].conn, output_value.c_str(), output_value.length()) != 1)
		cerr << "Put copy data failed! -- " << PQerrorMessage(pg_conns[table].conn) << endl;
	else
		pg_conns[table].records++;
		
	diff_seconds = difftime(time((time_t *)NULL), pg_conns[table].last_insert);
	if(diff_seconds > seconds_between_copyend)
		{
		if(PQputCopyEnd(pg_conns[table].conn, error_message) != 1)
			{
			cerr << "ERROR: " << PQerrorMessage(pg_conns[table].conn) << error_message << endl;
			}
		else
			{
			if(verbose_output)
				cout << endl << "Inserting " << pg_conns[table].records << " records into " << table << "." << endl;
			}
			
		while(PQconsumeInput(pg_conns[table].conn) && PQisBusy(pg_conns[table].conn))
			{
			//cout << "pg is busy" << endl;
			sleep(1);
			}
		pg_conns[table].records=0;
		pg_conns[table].last_insert = time((time_t *)NULL);
		}
	
	user_data=NULL;
	meta=NULL;	
	}

int main(int argc, char **argv)
	{
	bro_debug_messages  = 0;
	bro_debug_calltrace = 0;

	int fd;
	fd_set readfds;
	
	int opt = 0;
	extern char *optarg;
	extern int optind;

	postgresql_host = default_postgresql_host;
	postgresql_port = default_postgresql_port;
	seconds_between_copyend = default_seconds_between_copyend;

	while ( (opt = getopt(argc, argv, "d:hH:p:u:P:qDs:?")) != -1)
		{
		switch (opt)
			{
			case 'd':
				postgresql_db = optarg;
				break;
			
			case 'q':
				verbose_output = 0;
				break;
				
			case 'D':
				debugging++;
				
				if (debugging > 0)
					bro_debug_messages = 1;
				
				if (debugging > 1)
					bro_debug_calltrace = 1;
				break;
			
			case 'H':
				postgresql_host = optarg;
				break;
			
			case 'p':
				postgresql_port = optarg;
				break;
			
			case 'u':
				postgresql_user = optarg;
				break;
			
			case 'P':
				postgresql_password = optarg;
				break;
			
			case 's':
				seconds_between_copyend = atoi(optarg);
				break;
			 
			case '?':
			default:
				usage();
				break;
			}
		}
		 
	argc -= optind;
	argv += optind;
	
	if( postgresql_db.compare("") == 0 || argc < 2 )
		usage();

	BroConn *bc;	
	for(int i=0; i<argc; i+=2)
		{
		string host(argv[i]);
		string port(argv[i+1]);
			
		bc = connect_to_bro(host, port);
		bro_event_registry_add_compact(bc, "db_log", db_log_event_handler, NULL);
		bro_event_registry_add_compact(bc, "db_log_flush_all", db_log_flush_all_event_handler, NULL);
		bro_event_registry_add_compact(bc, "db_log_flush", db_log_flush_event_handler, NULL);
		bro_event_registry_request(bc);

		fd = bro_conn_get_fd(bc);
		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);
		while(select(fd+1, &readfds, NULL, NULL, NULL))
			{
			bro_conn_process_input(bc);
			}
		}
	}



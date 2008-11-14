
#include <string>
#include <list>
#include <map>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <errno.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>

#include "utf_validate.h"

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
// By default, don't show output
int verbose_output = 0;
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
		"  -v       Increase verbosity.  By default only show errors." << endl <<
		"  -s secs  Number of seconds between database flushes (default 30)." << endl <<
		"  -D       Enable debugging output from Broccoli (if Broccoli was compiled in debugging mode)." << endl << endl;
	exit(0);
	}

BroConn* connect_to_bro(std::string host, std::string port)
	{
	BroConn *conn;
	
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
	if( pg_conns.count(table)>0 )
		return 0;
	
	std::string connect_string =
		"host="+postgresql_host+" port="+postgresql_port+
		" user="+postgresql_user+" password="+postgresql_password+
		" dbname="+postgresql_db;
	if( !(pg_conns[table].conn = PQconnectStart(connect_string.c_str())) )
		{
		cerr << "Total screw up with the postgres connection" << endl;
		exit(-1);
		}

	if(verbose_output)
		cout << "Connecting to PostgreSQL";
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

	//PQsetnonblocking(pg_conns[table].conn, 1);
	//if( PQisnonblocking(pg_conns[table].conn) )
	//	{
	//	if(verbose_output)
	//		cout << "PostgreSQL is in non-blocking mode" << endl;
	//	}
	return 0;
	}
	
int flush_table(std::string table, bool use_timeout)
	{
	PGresult *result=NULL;
	ExecStatusType result_status;
	char *error_message = NULL;
	time_t now_time = time((time_t *)NULL);
	int flushed_records = 0;
	
	result = PQgetResult(pg_conns[table].conn);
	result_status = PQresultStatus(result);
	PQclear(result);
	if( result_status != PGRES_COPY_IN )
		return 0;

	if( use_timeout && 
	    difftime(now_time, pg_conns[table].last_insert) < 
	      seconds_between_copyend )
		return 0;

	if( pg_conns.count(table) > 0 )
		{
		if(PQputCopyEnd(pg_conns[table].conn, error_message) == 1)
			{
			if(verbose_output)
				cout << "Inserting " << pg_conns[table].records << " records into " << table << "." << endl;
			}
		else
			{
			cerr << "ERROR: " << PQerrorMessage(pg_conns[table].conn) << error_message << endl;
			return -1;
			}
		
		result = PQgetResult(pg_conns[table].conn);
		result_status = PQresultStatus(result);
		PQclear(result);
		if(result_status != PGRES_COMMAND_OK)
			{
			cerr << "Error when ending copy on \"" << table << "\" table :: " 
				 << PQerrorMessage(pg_conns[table].conn);
			}
			
		while(PQconsumeInput(pg_conns[table].conn) && PQisBusy(pg_conns[table].conn))
			{
			//cout << "pg is busy" << endl;
			sleep(1);
			}
		flushed_records = pg_conns[table].records;
		pg_conns[table].records=0;
		pg_conns[table].last_insert = now_time;
		}
	else
		{
		cerr << "Attempted to flush table '" << table << "', but no active query for that table exists." << endl;
		return 0;
		}
	
	return flushed_records;
	}
	
int flush_tables(bool use_timeout)
	{
	int flushed=0;

	// Iterator for finishing all existing queries by their timeout.
	map<string,PGConnection>::iterator iter;
	for( iter = pg_conns.begin(); iter != pg_conns.end(); iter++ )
		{
		if(flush_table(iter->first, use_timeout))
			flushed++;
		}
	return flushed;
	}

void db_log_flush_all_event_handler(BroConn *bc, void *user_data, BroEvMeta *meta)
	{
	int total_flushed = 0;
	
	if(verbose_output)
		cout << "Flushing all active COPY queries to the database" << endl;
	
	if( meta->ev_numargs > 0 )
		cerr << "db_log_flush_all takes no arguments, but " << meta->ev_numargs << " were given" << endl;
	
	total_flushed = flush_tables(false);
	
	user_data=NULL;
	meta=NULL;	
	}
	
void db_log_flush_event_handler(BroConn *bc, void *user_data, BroEvMeta *meta)
	{
	std::string table;

	if( meta->ev_numargs != 1 )
		{
		cerr << "db_log_flush takes one arguments, but " << meta->ev_numargs << " were given" << endl;
		return;
		}
		
	table = (const char*) bro_string_get_data( (BroString*) meta->ev_args[0].arg_data );

	flush_table(table, false);

	user_data=NULL;
	meta=NULL;	
	}

//global db_log: event(db_table: string, data: any);
void db_log_event_handler(BroConn *bc, void *user_data, BroEvMeta *meta)
	{
	int type=0;
	time_t now_time = time((time_t *)NULL);
	
	struct in_addr ip={0};
	std::string table("");
	std::string field_names("");
	std::string output_value("");
	
	PGresult *result;
	ExecStatusType result_status;
	int query_exists = 0;
	
	if( meta->ev_numargs != 2 )
		{
		cerr << "The db_log event takes 2 arguments, but "
		     << meta->ev_numargs << " were given." << endl;
		return;
		}
		
	if( meta->ev_args[0].arg_type != BRO_TYPE_STRING ||
	    meta->ev_args[1].arg_type != BRO_TYPE_RECORD)
		{
		cerr << "The db_log event takes the argument types: (string, record)." << endl;
		return;
		}
	
	table = (const char*) bro_string_get_data( (BroString*) meta->ev_args[0].arg_data);
	query_exists = pg_conns.count(table);

	// If try_it is false, skip all of this.  This query has had a fatal error.
	if( query_exists && !pg_conns[table].try_it )
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
			if( !query_exists )
				field_names.append(", ");
			}
		// type needs to be zero so that it can be assigned with
		// whatever type the record value actually is.
		type=0;
		data = bro_record_get_nth_val(r, i, &type);
		
		if( !query_exists )
			{
			field_name = bro_record_get_nth_name(r, i);
			field_names.append(field_name);
			}
		
		char *str=NULL;
		char *s=NULL;
		char *sp=NULL; 
		int tmp_char=0;
		std::string single_value("");
		
		if(data==NULL)
			{
			cerr << "data couldn't be extracted from record!" << endl;
			return;
			}
		switch (type)
			{
			case BRO_TYPE_INT:
				single_value = stringify(*((int *) data));
				break;
			case BRO_TYPE_PORT:
				// TODO: handle the port's protocol somehow.
				single_value = stringify( (*((bro_port *) data)).port_num );
				break;
			case BRO_TYPE_STRING:
				// TODO: UTF8 input is handled appropriately
				//       UTF16/32 will come through looking very weird.
				BroString *bs = (BroString*) data;
				str = (char *) bro_string_get_data(bs);
				uint string_length = bro_string_get_length(bs);
				
				// Maxmimum character expansion is as \\xHH, so a factor of 5.
				s = new char[string_length*5 + 1];	// +1 is for final '\0'
				sp = s;
				
				char *hex_fmt = new char[2];
				
				for ( uint i=0; i < string_length; ++i )
					{
					tmp_char = str[i]&0xFF;
					//printf("char (%d): %02x\n", i, tmp_char);
					if ( tmp_char == '\0' )
						{
						*sp++ = '\\'; *sp++ = '\\'; *sp++ = '0';
						}
						
					// TODO: maybe deal with UTF16?
					//else if ( tmp_char > 244 )
					//	{
					//	if (string_length-1 > i)
					//		{
					//		   I doubt if many of the string we'd be encountering
					//		   would actually include the BOM though so
					//		   this technique probably wouldn't help much.
					//		if ( tmp_char == 254 && str[i+1]&0xFF == 255 )
					//			cout << "UTF16-BOM Big Endian" << endl;
					//		else if ( tmp_char == 255 && str[i+1]&0xFF == 254 )
					//			cout << "UTF16-BOM Little Endian" << endl;
					//		}
					//	}
						
					else if ( 193 < tmp_char && tmp_char < 245 )
						{
						int byte_count=0;
						if(193 < tmp_char && tmp_char < 224)
							byte_count=2;
						else if(223 < tmp_char && tmp_char < 240)
							byte_count=3;
						else if(239 < tmp_char && tmp_char < 245)
							byte_count=4;
						
						//cout << byte_count << " byte sequence " << i << endl;
						
						// Don't overrun the buffer in case of invalid UTF8.
						if((int) (string_length-1-i) > byte_count)
							byte_count = string_length-i-3;
						
						if(utf_is_valid(str+i, byte_count))
							{
							// if utf8 is valid, include it verbatim
							*sp++ = tmp_char;
							for(int y=0; y<byte_count-1; ++y)
								*sp++ = str[++i];
							}
						}
                
					else if ( tmp_char == '\x7f' )
						{
						*sp++ = '^'; *sp++ = '?';
						}
                    
					else if ( tmp_char <= 26 )
						{
						*sp++ = '^'; *sp++ = tmp_char + 'A' - 1;
						}
					
					else if ( tmp_char == '\\' )
						{
						*sp++ = '\\'; *sp++ = '\\';
						}
					
					else if ( tmp_char > 126 )
						{
						// extended ascii and anything else not yet handled
						// should be displayed as hex.
						*sp++ = '\\'; *sp++ = '\\'; *sp++ = 'x';
						sprintf(hex_fmt, "%02x", tmp_char);
						*sp++ = hex_fmt[0]; *sp++ = hex_fmt[1];
						}
					else
						{
						*sp++ = tmp_char;
						}
					}
				*sp++ = '\0';	// NUL-terminate.
                
				if ( verbose_output > 1 )
					cout << "After munging: " << s << endl;
					
				single_value = s;
				break;
			case BRO_TYPE_COUNT:
				single_value = stringify(*((uint32 *) data));
				break;
			case BRO_TYPE_TIME:
			case BRO_TYPE_DOUBLE:
			case BRO_TYPE_INTERVAL:
				single_value = stringify(*((double *) data));
				break;
			case BRO_TYPE_BOOL:
				single_value = *((int *) data) ? "true" : "false";
				break;
			case BRO_TYPE_IPADDR:
				ip.s_addr = *((uint32 *) data);
				single_value = inet_ntoa(ip);
				break;
			default:
				cerr << "unhandled data type" << endl;
				break;
			}
			
			if( single_value == "" )
					single_value = "\\N";
			output_value.append(single_value);
		}
		
	// Connect to the database for the current table if not already done.
	if( !query_exists )
		{
		connect_to_postgres(table);
		pg_conns[table].records = 0;
		pg_conns[table].last_insert = now_time;
		pg_conns[table].try_it = true;
		pg_conns[table].query = "COPY " + table + " (" + field_names + ") FROM STDIN";
		}
	
	result = PQgetResult(pg_conns[table].conn);
	result_status = PQresultStatus(result);
	PQclear(result);
	if(result_status != PGRES_COPY_IN)
		{
		if(verbose_output)
			cout << "Executing: " << pg_conns[table].query << endl;
		
		pg_conns[table].last_insert = now_time;
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

	if(verbose_output>2)
		{
		// Instead of just a dot, output the first character of the table for 
		// visual accounting.
		cout << table[0];
		cout.flush();
		}
		
	output_value.append("\n");
	if(PQputCopyData(pg_conns[table].conn, output_value.c_str(), output_value.length()) != 1)
		cerr << "Put copy data failed! -- " << PQerrorMessage(pg_conns[table].conn) << endl;
	else
		pg_conns[table].records++;
		
	flush_table(table, true);
	
	user_data=NULL;
	meta=NULL;	
	}
	
/* Signal handler for SIGINT. */
void SIGINT_handler (int signum)
	{
	// Shut down the connection to Bro
	if( !bro_conn_delete(bc) )
		cerr << "There was a problem shutting down the Bro connection." << endl;
	
	// Flush all existing queries to the database.
	flush_tables(false);
	
	// Shut down and delete all PostgreSQL connections
	map<string,PGConnection>::iterator iter;
	for( iter = pg_conns.begin(); iter != pg_conns.end(); iter++ )
		{
			PQfinish(pg_conns[iter->first].conn);
		}
		
	cout << "Finished flushing current queries and freeing memory.  Now quitting." << endl;
	exit(0);
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
	
	int readsocks;
	struct timeval timeout;  /* Timeout for select */

	postgresql_host = default_postgresql_host;
	postgresql_port = default_postgresql_port;
	seconds_between_copyend = default_seconds_between_copyend;

	signal (SIGINT, SIGINT_handler);

	while ( (opt = getopt(argc, argv, "d:hH:p:u:P:vDs:?")) != -1)
		{
		switch (opt)
			{
			case 'd':
				postgresql_db = optarg;
				break;
				
			case 'v': 
				verbose_output++;
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
		for(;;)
			{
			timeout.tv_sec = 5;
			timeout.tv_usec = 0;
			
			//BUG?: If I don't do this for each loop, the select doesn't trigger
			//      with incoming data and the timeout fires eventually.
			FD_ZERO(&readfds);
			FD_SET(fd, &readfds);
			
			readsocks = select(fd+1, &readfds, NULL, NULL, &timeout);

			// Always attempt to process input.
			bro_conn_process_input(bc);
			
			// Handle timer expirations AND socket disconnects.
			if(readsocks <= 0)
				{
				// TODO: maybe some reconnect attempt limit?
				while( !bro_conn_alive(bc) )
					{
					cerr << "Bro connection is lost; reconnecting...";
					if( bro_conn_reconnect(bc) )
						cerr << "done." << endl;
					else
						cerr << "failed!" << endl;
					bro_conn_process_input(bc);
					sleep(3);
					}
					
				// This is run when the select timeout is reached.
				if(readsocks == 0)
					{
					int flush_count = flush_tables(true);
					if(verbose_output>1)
						cout << "Flushed " << flush_count 
						     << " table(s) based on last-flush time." 
						     << endl;
					}
				}
			}
		}
	}



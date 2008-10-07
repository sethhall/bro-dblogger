// 10/02/2008

#include <string>
#include <vector>
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
using std::vector;
using std::cout;
using std::cin;
using std::cerr;

string default_host = "127.0.0.1";
string default_port = "47757";
int default_seconds_between_copyend = 30;

string host;
string port;
int seconds_between_copyend;

int count = -1;
int seq;
BroConn *bc;

class PGConnection {
	public:
		PGconn *conn;
		
		// The "Copy" query that this connection is associated with.
		std::string query;

		// The record keeping count of records in the current Copy query.
		int records;

		// Unix timestamp of last CopyEnd.
		uint32 last_insert;
		
		// This is an initial guess at how many records should be done per insert.
		int records_per_insert;
		
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
	cout << "bro_dblogger - Listens for the db_log event and pushes data into a database table.";
	//cout << "broclient - sends events with string arguments from stdin to a\n"
	//	"	running Bro\n"
	//	"USAGE: broclient [-p port=47760] [host=127.0.0.1]\n"
	//	"Input format (each line): event_name type=arg1 type=arg2...\n";
	exit(0);
	}

void showtypes(void)
	{
	cout << "Legitimate event types are:\n"
		"	string, int, count, double, bool, time, \n"
		"	interval, port, addr, net, subnet\n\n"
		"	examples: string=foo, port=23/tcp, addr=10.10.10.10, \n"
		"	net=10.10.10.0 and subnet=10.0.0.0/8\n";
	exit(0);
	}

int connect_to_bro()
	{
	// now connect to the bro host - on failure, try again three times
	// the flags here are telling us to block on connect, reconnect in the
	// event of a connection failure, and queue up events in the event of a
	// failure to the bro host
	int c=0;
	if (! (bc = bro_conn_new_str( (host + ":" + port).c_str(), BRO_CFLAG_RECONNECT|BRO_CFLAG_ALWAYS_QUEUE)))
		{
		cerr << endl << "Could not connect to Bro (" << host << ") at " <<
		        host.c_str() << ":" << port.c_str() << endl;
		exit(-1);
		}

	if (! bro_conn_connect(bc)) {
		cerr << endl << "WTF?  Why didn't it connect?" << endl;
	} else {
		cerr << endl << "Connected to Bro (" << host << ") at " <<
		        host.c_str() << ":" << port.c_str() << endl;
	}
	
	return 0;
	}
	
int connect_to_postgres(std::string table)
	{
	if(pg_conns.count(table)>0)
		return 0;
		
	if( !(pg_conns[table].conn = PQconnectStart("host=127.0.0.1 port=5555 user=bro password=qwerty dbname=netsec")) )
		cerr << "Total screw up with the postgres connection" << endl;
	if( PQstatus(pg_conns[table].conn) == CONNECTION_BAD )
		cerr << "hmm.. postgres connection status is bad" << endl;

	cout << "Connecting to PostgreSQL";
	while( PQconnectPoll(pg_conns[table].conn) != PGRES_POLLING_OK )
		{
		cout << "."; 
		cout.flush();
		sleep(1);
		}
	cout << "done" << endl;

	PQsetnonblocking(pg_conns[table].conn, 1);
	if(PQisnonblocking(pg_conns[table].conn))
		cout << "PostgreSQL is in non-blocking mode" << endl;

	return 0;
	}
	
//global db_log: event(db_table: string, data: any);
void db_log_event_handler(BroConn *bc, void *user_data, BroEvMeta *meta)
	{
	int i=0;
	int type=0;
	int total_size,size=0;
	char *error_message = NULL;
	
	struct in_addr ip={0};
	std::string table;
	std::string field_names("");
	std::string output_value("");
	
	if( meta->ev_numargs != 2 ||
	    meta->ev_args[0].arg_type != BRO_TYPE_STRING ||
	    meta->ev_args[1].arg_type != BRO_TYPE_RECORD)
		{
		cerr << "Arguments to the db_log callback are incorrect! (arity and/or type)" << endl;
		return;
		}
		
	table.append((const char*) bro_string_get_data( (BroString*) meta->ev_args[0].arg_data));

	// If try_it is false, skip all of this.  This query has had a fatal error.
	if( pg_conns.count(table)>0 && pg_conns[table].try_it==false )
		return;
		
	BroRecord* r = (BroRecord*) meta->ev_args[1].arg_data;
	void* data;
	const char* field_name;
	
	int rec_len = bro_record_get_length(r);
	for(i=0 ; i < rec_len ; i++)
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
		
		//if(pg_conns.count(table)>0 && pg_conns[table].query.length() == 0)
		//	{
			field_name = bro_record_get_nth_name(r, i);
			field_names.append(field_name);
		//	}
			
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
			case BRO_TYPE_STRING:
				output_value.append((const char*) bro_string_get_data( (BroString*) data));
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
	bro_record_free(r);
		
	if( pg_conns.count(table)<1 )
		{
		connect_to_postgres(table);
		pg_conns[table].records = 0;
		pg_conns[table].last_insert = time((time_t *)NULL);
		pg_conns[table].try_it = true;
		pg_conns[table].query = "COPY " + table + " (" + field_names + ") FROM STDIN";
		}
	else
		{
		PGresult *result = PQgetResult(pg_conns[table].conn);
		switch(PQresultStatus(result))
			{
			case PGRES_TUPLES_OK:
			case PGRES_COMMAND_OK:
			case PGRES_EMPTY_QUERY:
			case PGRES_NONFATAL_ERROR:
				//cout << "Not in a Copy query (for " << table << ").  Running one..." << endl;
				PGresult *result = PQexec(pg_conns[table].conn, pg_conns[table].query.c_str());
				PQclear(result);
				break;
			case PGRES_FATAL_ERROR:
				cout << PQerrorMessage(pg_conns[table].conn) << endl;
				pg_conns[table].try_it=false;
				return;
				break;
			}
		PQclear(result);
		}
	
	PGresult *result = PQgetResult(pg_conns[table].conn);
	int result_status = PQresultStatus(result);
	PQclear(result);
	if(result_status != PGRES_COPY_IN)
		{
		cout << "Executing: " << pg_conns[table].query << endl;
		PGresult *result = PQexec(pg_conns[table].conn, pg_conns[table].query.c_str());
		if(PQresultStatus(result) == PGRES_FATAL_ERROR)
			{
			cerr << PQerrorMessage(pg_conns[table].conn);
			pg_conns[table].try_it=false;
			cerr << "Removing the '" << table << "' table due to failure." << endl;
			return;
			}
		PQclear(result);
		}

	cout << ".";
	cout.flush();
	
	output_value.append("\n");
	if(PQputCopyData(pg_conns[table].conn, output_value.c_str(), output_value.length()) != 1)
		cerr << "Put copy data failed! " << PQerrorMessage(pg_conns[table].conn) << endl;
	else
		pg_conns[table].records++;
		
	int diff_seconds = time((time_t *)NULL) - pg_conns[table].last_insert;
	if(diff_seconds > seconds_between_copyend && pg_conns[table].try_it)
		{
		if(PQputCopyEnd(pg_conns[table].conn, error_message) != 1)
			cerr << "ERROR: " << PQerrorMessage(pg_conns[table].conn) << error_message << endl;
		else
			cout << "Inserting " << pg_conns[table].records << " records into " << table << "." << endl;
		
		// Ruin the fact that I'm trying to do things asynchronously.
		while(PQconsumeInput(pg_conns[table].conn) && PQisBusy(pg_conns[table].conn))
			{
			//cout << "pg is busy" << endl;
			sleep(1);
			}
		pg_conns[table].records=0;
		pg_conns[table].last_insert = time((time_t *)NULL);
		}
		
	}

int main(int argc, char **argv)
	{
	bro_debug_messages  = 0;
	bro_debug_calltrace = 0;

	int fp,rc,n;
	int j;
	fd_set readfds;
	char buf[1024];
	struct timeval tv;
	
	int opt, debugging = 0;
	extern char *optarg;
	extern int optind;

	host = default_host;
	port = default_port;
	seconds_between_copyend = default_seconds_between_copyend;

	while ( (opt = getopt(argc, argv, "p:dh?s:")) != -1)
	{
		switch (opt)
			{
			case 'd':
				debugging++;
 
				if (debugging == 1)
					bro_debug_messages = 1;
 
				if (debugging > 1)
					bro_debug_calltrace = 1;
				break;
 
			case 'h':
			case '?':
				usage();
				break;
 
			case 'p':
				port = optarg;
				break;
				
			case 's':
				seconds_between_copyend = atoi(optarg);
				break;
 
			default:
				usage();
				break;
			}
	}
 
	argc -= optind;
	argv += optind;

	if (argc > 0)
		host = argv[0];

	connect_to_bro();
	cout << "connected!" << endl;
	bro_event_registry_add_compact(bc, "db_log", db_log_event_handler, NULL);
	cout << "event registered" << endl;
	bro_event_registry_request(bc);
	cout << "event registry request" << endl;

	int fd = bro_conn_get_fd(bc);
	fd_set readset;
	FD_ZERO(&readset);
	FD_SET(fd, &readset);
	
	while(select(fd+1, &readset, NULL, NULL, NULL))
		{
		//cout << endl << "********processing input*********" << endl;
		// Grab data from Bro and run all callbacks
		bro_conn_process_input(bc);
		}
	}



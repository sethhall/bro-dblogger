/*
 * Copyright (c) 2008, Seth Hall <hall.692@osu.edu>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * (1) Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 * 
 * (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 
 * (3) Neither the name of the University of California, Lawrence Berkeley
 *     National Laboratory, U.S. Dept. of Energy, International Computer
 *     Science Institute, nor the names of contributors may be used to endorse
 *     or promote products derived from this software without specific prior
 *     written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 **/

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

//string default_bro_host = "127.0.0.1";
//string default_bro_port = "47757";
string default_postgresql_host = "127.0.0.1";
string default_postgresql_port = "5432";
int default_seconds_between_copyend = 30;

string postgresql_host, postgresql_port;
string postgresql_user, postgresql_password, postgresql_db;
int seconds_between_copyend;

int debugging = 0;
int count = -1;
int seq;
BroConn *bc;

class BroConnection {
	public:
		BroConn *bc;
};
std::list<BroConnection> bro_conns;

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
	cout << "bro_dblogger - Listens for the db_log event and pushes data into a database table." << endl <<
 	"USAGE: bro_dblogger [-h postgres_host=localhost] [-p postgres_port=5432] -u postgres_user [-P postgres_password] database_name [[bro_host] [bro_port]]\n";
	exit(0);
	}

BroConn* connect_to_bro(std::string host, std::string port)
	{
	BroConn *conn;
	
	// now connect to the bro host - on failure, try again three times
	// the flags here are telling us to block on connect, reconnect in the
	// event of a connection failure, and queue up events in the event of a
	// failure to the bro host
	if (! (conn = bro_conn_new_str( (host + ":" + port).c_str(), 
			BRO_CFLAG_RECONNECT|BRO_CFLAG_ALWAYS_QUEUE|BRO_CFLAG_DONTCACHE)))
		{
		cerr << endl << "Could not connect to Bro (" << host.c_str() << ") at " <<
		        host.c_str() << ":" << port.c_str() << endl;
		exit(-1);
		}

	if (!bro_conn_connect(conn)) {
		cerr << endl << "WTF?  Why didn't it connect?" << endl;
	} else {
		if(debugging)
			cerr << "Connected to Bro (" << host.c_str() << ") at " <<
			        host.c_str() << ":" << port.c_str() << endl;
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

	if(debugging)
		cout << "Connecting to PostgreSQL";
	while( PQconnectPoll(pg_conns[table].conn) != PGRES_POLLING_OK )
		{
		if( PQstatus(pg_conns[table].conn) == CONNECTION_BAD )
			{
			cout << PQerrorMessage(pg_conns[table].conn) <<endl;
			exit(-1);
			}
			
		if(debugging)
			{
			cout << "."; 
			cout.flush();
			}
		sleep(1);
		}
	if(debugging)
		cout << "done" << endl;

	PQsetnonblocking(pg_conns[table].conn, 1);
	if(PQisnonblocking(pg_conns[table].conn))
		{
		if(debugging)
			cout << "PostgreSQL is in non-blocking mode" << endl;
		}
	return 0;
	}
	
void db_log_flush_all_event_handler(BroConn *bc, void *user_data, BroEvMeta *meta)
	{
	char *error_message = NULL;
	
	if(debugging)
		cout << "Flushing all active COPY queries to the database" << endl;
	
	if( meta->ev_numargs > 0 )
		cerr << "db_log_flush_all takes no arguments, but " << meta->ev_numargs << " were given" << endl;
	
	map<string,PGConnection>::iterator iter;   
	for( iter = pg_conns.begin(); iter != pg_conns.end(); iter++ )
		{
		if(PQputCopyEnd(iter->second.conn, error_message) != 1)
			cerr << "ERROR: " << PQerrorMessage(iter->second.conn) << error_message << endl;
		else
			{
			if(debugging)
				cout << "Inserting " << iter->second.records << " records into " << iter->first << "." << endl;
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

	if(debugging)
		cout << "Flushing active COPY query for table '" << table << "' to the database" << endl;

	if(pg_conns.count(table) > 0)
		{
		if(PQputCopyEnd(pg_conns[table].conn, error_message) != 1)
			cerr << "ERROR: " << PQerrorMessage(pg_conns[table].conn) << error_message << endl;
		else
			{
			if(debugging)
				cout << "Inserting " << pg_conns[table].records << " records into " << table << "." << endl;
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
	int i=0;
	int type=0;
	int diff_seconds;
	char *error_message = NULL;
	
	struct in_addr ip={0};
	std::string table;
	std::string field_names("");
	std::string output_value("");
	
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
		// Check for errors from earlier queries...
		PGresult *result = PQgetResult(pg_conns[table].conn);
		if(PQresultStatus(result) == PGRES_FATAL_ERROR)
			{
			cerr << "On table (" << table << ") -- " << PQerrorMessage(pg_conns[table].conn) << endl;
			pg_conns[table].try_it=false;
			PQclear(result);
			return;
			}
		PQclear(result);
		}
	
	PGresult *result = PQgetResult(pg_conns[table].conn);
	int result_status = PQresultStatus(result);
	PQclear(result);
	if(result_status != PGRES_COPY_IN)
		{
		if(debugging)
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

	if(debugging)
		{
		cout << ".";
		cout.flush();
		}
		
	output_value.append("\n");
	if(PQputCopyData(pg_conns[table].conn, output_value.c_str(), output_value.length()) != 1)
		cerr << "Put copy data failed! -- " << PQerrorMessage(pg_conns[table].conn) << endl;
	else
		pg_conns[table].records++;
		
	diff_seconds = time((time_t *)NULL) - pg_conns[table].last_insert;
	if(diff_seconds > seconds_between_copyend)
		{
		if(PQputCopyEnd(pg_conns[table].conn, error_message) != 1)
			cerr << "ERROR: " << PQerrorMessage(pg_conns[table].conn) << error_message << endl;
		else
			{
			if(debugging)
				cout << "Inserting " << pg_conns[table].records << " records into " << table << "." << endl;
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

	//bro_host = default_bro_host;
	//input_bro_port = default_bro_port;
	postgresql_host = default_postgresql_host;
	postgresql_port = default_postgresql_port;
	seconds_between_copyend = default_seconds_between_copyend;

	while ( (opt = getopt(argc, argv, "h:p:u:P:ds:?")) != -1)
	{
		switch (opt)
			{
			case 'd':
				debugging++;
				
				if (debugging > 1)
					bro_debug_messages = 1;
				
				if (debugging > 2)
					bro_debug_calltrace = 1;
				break;
			
			case 'h':
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

	if (argc > 0)
		postgresql_db = argv[0];

	BroConn *bc;
	BroConnection conn;
	int status;
	
	for(int i=1; i<argc; i+=2)
		{
		string host(argv[i]);
		string port(argv[i+1]);
			
		int pid = fork();
		
		if(pid < 0)
			{
			cerr << "Couldn't fork children, aborting." << endl;
			exit(-1);
			}
	    
		if(pid==0)
			{
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
		else if(pid>0)
			{
			if(debugging)
				cerr << "Spawned child process.  Pid:" << pid << endl;
			wait(&status);
			cout << "PARENT: Child's exit code is:" << WEXITSTATUS(status) << endl;
			exit(0);
			}
		}
	}



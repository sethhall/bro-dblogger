# Declare the db_log events
global db_log: event(db_table: string, data: any);
global db_log_flush: event(db_table: string);
global db_log_flush_all: event();

event bro_init()
	{
	# Listen locally for bro-dblogger (only sending events to bro-dblogger)
	Remote::destinations["bro-dblogger"]
	  = [$host = 127.0.0.1, $connect=F, $sync=F];
	}
	
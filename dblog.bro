# Declare the db_log events
global db_log: event(table: string, data: any);
global db_log_flush_all: event();
global db_log_flush: event(table: string);

event bro_init()
	{
	# Listen locally for events from bro-dblogger
	Remote::destinations["db_logger"]
	    =  [$host = 127.0.0.1, $connect=F, $sync=F, $events=/db_log.*/];
	}
	
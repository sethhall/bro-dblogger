# This file only needs to be loaded if you are using a cluster deployment
# and it should *only* be loaded by the manager.
#
# Change the cluster_events (in cluster-manager.remote.bro) variable to the following: 
#     const cluster_events = /.*(print_hook|db_log|notice_action|TimeMachine::command).*/;
#
@load dblog

event db_log(table: string, data: any)
	{
	if ( is_remote_event() )
		event db_log(db_table, data);
	}

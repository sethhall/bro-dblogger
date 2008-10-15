@load dblog

event connection_established(c: connection)
	{
	local id = c$id;
	event db_log("connections", [$epoch=network_time(),
	                             $orig_ip=id$orig_h, 
	                             $orig_port=id$orig_p, 
	                             $resp_ip=id$resp_h, 
	                             $resp_port=id$resp_p]);
	}
	
bro_dblogger: bro_dblogger.cc
	g++ -g -Wall -I/cluster/include -L/cluster/lib -I/usr/local/include -L/usr/local/lib -I/opt/local/include/postgresql83 -I/usr/local/bro/include -L/opt/local/lib/postgresql83 -L/usr/local/bro/lib/ -lbroccoli -lpq -o bro_dblogger bro_dblogger.cc
clean:
	rm bro_dblogger


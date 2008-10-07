bro_dblogger: bro_dblogger.cc
	g++ -g -I/opt/local/include/postgresql83 -I/usr/local/bro/include -L/opt/local/lib/postgresql83 -L/usr/local/bro/lib/ -lbroccoli -lpq -o bro_dblogger bro_dblogger.cc
clean:
	rm bro_dblogger


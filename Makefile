CC=g++
CPPFLAGS=-g -Wall -L/cluster/lib -I/cluster/include -I/usr/local/include -L/usr/local/lib -L/opt/local/lib/postgresql83 -I/opt/local/include/postgresql83 -L/usr/local/bro/lib/ -I/usr/local/bro/include
LDFLAGS=-lbroccoli -lpq

bro-dblogger: bro-dblogger.cc

clean:
	rm -f bro-dblogger 
	rm -rf bro-dblogger.dSYM

CC=g++
CPPFLAGS=-g -Wall -L/cluster/lib -I/cluster/include -I/usr/local/include -L/usr/local/lib -L/opt/local/lib/postgresql83 -I/opt/local/include/postgresql83 -L/usr/l
ocal/bro/lib/ -I/usr/local/bro/include
SOURCES=bro-dblogger.cc utf_validate.c
OBJECTS=$(SOURCES:.cpp=.o)
CFLAGS=${CPPFLAGS}
LDFLAGS=-lbroccoli -lpq
EXECUTABLE=bro-dblogger

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(CPPFLAGS) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) $< -o $@

clean:
	rm -f bro-dblogger
	rm -f *.o
	rm -rf bro-dblogger.dSYM

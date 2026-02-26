CC = gcc
CFLAGS = -Wall -g

OBJS = antivirus.o database.o workqueue.o

antivirus.exe: $(OBJS)
	$(CC) $(OBJS) -o antivirus.exe

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	del *.o antivirus.exe
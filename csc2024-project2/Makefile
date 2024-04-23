CFLAGS = -Wall
LIBS = -lpthread -lnetfilter_queue
TARGETS = mitm_attack pharm_attack

.PHONY: all clean

all: $(TARGETS)

mitm_attack: mitm_attack.cpp
    g++ $(CFLAGS) -o $@ $< $(LIBS)

pharm_attack: pharm_attack.cpp
    g++ $(CFLAGS) -o $@ $< $(LIBS)

clean:
    rm -f $(TARGETS)
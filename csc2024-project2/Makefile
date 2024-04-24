all: mitm_attack pharm_attack

mitm_attack: mitm_attack.cpp
	g++ -o mitm_attack mitm_attack.cpp -lpthread -lnetfilter_queue

pharm_attack: pharm_attack.cpp
	g++ -o pharm_attack pharm_attack.cpp -lpthread -lnetfilter_queue

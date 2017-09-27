CC = g++ 
CFLAGS = -O3 -Wall -fno-operator-names -std=c++0x
LIBS = -lcrypto -lssl -lpthread -lsnappy 
INCLUDES =-I./leveldb/include/
MAIN_OBJS = locality_attack_e.o tran2vm_without_zero tran2vm_with_zero db_rank lr_checker

#all: Locality_attack

locality_Attack_e: ./segment.cpp
	$(shell ! test -d "dbs" && mkdir dbs)
	$(shell ! test -d "tmp" && mkdir tmp)
	$(shell ! test -d "ground-truth" && mkdir ground-truth)
	$(CC) $(CFLAGS) -o slicing segment.cpp $(INCLUDES) ./leveldb/out-static/libleveldb.a $(LIBS)
 
clean:
	@rm -f attack
	@rm -f count
	@rm -f minhash
	@rm -r ./ground-truth
	@rm -rf ./tmp
	@rm -f $(MAIN_OBJS)
	@rm -rf ./dbs

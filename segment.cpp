#include <assert.h>
#include <stdio.h>
#include <queue>
#include <string.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <time.h>
#include <inttypes.h>
#include <vector>
#include "leveldb/db.h"
#include <iostream>
// #define ANALYSIS_DB "./db/"
#define FP_SIZE 6
#define K_MINHASH 1
#define SEG_SIZE ((2<<20)) //1MB default
#define SEG_MIN ((2<<19)) //512KB
#define SEG_MAX ((2<<21)) //2MB

using namespace std;

struct node
{
	char key[FP_SIZE];
	uint64_t size;
};

struct cmp
{
	bool operator()(node a, node b)
	{
		return memcmp(b.key, a.key, FP_SIZE); // b > a return 1
	}
};
//leveldb::DB *relate; //refer to ground-truth db, using for simulate attack
leveldb::DB *segmentDb;
leveldb::DB *sliceDb;
priority_queue<node, vector<node>, cmp > pq;
queue<node> sq;
void init_segment(const char *rel)
{
      leveldb::Options options;
      options.create_if_missing = true;
      leveldb::Status status = leveldb::DB::Open(options, rel, &segmentDb);
      assert(status.ok());
        assert(segmentDb != NULL);
}
void init_slice(const char *rel)
{
      leveldb::Options options;
      options.create_if_missing = true;
      leveldb::Status status = leveldb::DB::Open(options, rel, &sliceDb);
      assert(status.ok());
        assert(sliceDb != NULL);
}
uint64_t sq_size = 0;

void process_seg()
{
	char ft[FP_SIZE*2];
	unsigned char md5full[16];

	int k = rand()%K_MINHASH;
	for (int i = 0; i < k; i++)
	{
		pq.pop();
	}
	node core = pq.top();//use min hash to Encrypted chunk hash
	memcpy(ft+FP_SIZE, core.key, FP_SIZE);
    string segmentValue = "";
	while(!sq.empty())
	{
		node now = sq.front();
		//memcpy(ft, now.key, FP_SIZE);		
		//MD5((unsigned char*)ft, FP_SIZE*2, md5ful);
		//memcpy(ret, md5full, FP_SIZE);
        string chunkHash(now.key, FP_SIZE);
        segmentValue += chunkHash;
		//leveldb::Status cst;
		//leveldb::Slice key(ret, FP_SIZE);
		//leveldb::Slice pkey(now.key, FP_SIZE);
		//cst = relate->Put(leveldb::WriteOptions(), key, pkey);//record plaintext and ciphertext pair
		/*int j;
		printf("%.2hhx", ret[0]);//printf ciphertext using the structure the same as hf-stat
		for(j = 1; j < FP_SIZE; j++)
			printf(":%.2hhx", ret[j]);
		printf("\t\t%" PRIu64 " ", now.size);
		printf("\t\t\t10\n");*/
        sq.pop();
    }
    //--------------Write segment db-----------------
    leveldb::Status cst;
    MD5((unsigned char *)segmentValue.c_str(), segmentValue.length(), md5full);
    leveldb::Slice segkey((char *)md5full, FP_SIZE);
    leveldb::Slice segvalue(segmentValue);
    cst = segmentDb->Put(leveldb::WriteOptions(), segkey, segvalue);
    if(!cst.ok())cout<<"IO_er\n";
    //--------------slicing-------------------------
    string liy((char *)md5full, FP_SIZE);
    leveldb::Slice sliceKey(core.key, FP_SIZE);
    string sliceValue = "";
    cst = sliceDb->Get(leveldb::ReadOptions(), sliceKey, &sliceValue);
    if(cst.ok()){
        sliceValue += liy;
	cst = sliceDb->Delete(leveldb::WriteOptions(), sliceKey);
    }else{
        sliceValue = liy;
    }
    cst = sliceDb->Put(leveldb::WriteOptions(), sliceKey, sliceValue);
    if(!cst.ok())cout<<"IO_er\n";
}

void read_hashes(FILE *fp) 
{
	char read_buffer[256];
	char *item;
	char last[FP_SIZE];
	memset(last, 0, FP_SIZE);

	while (fgets(read_buffer, 256, fp)) 
	{
		// skip title line
		if (strpbrk(read_buffer, "Chunk")) {continue;}
		// a new chunk
		char hash[FP_SIZE];
		memset(hash, 0, FP_SIZE);
		// store chunk hash and size
		item = strtok(read_buffer, ":\t\n ");
		int idx = 0;
		while (item != NULL && idx < FP_SIZE)
		{
			hash[idx++] = strtol(item, NULL, 16);
			item = strtok(NULL, ":\t\n");
		}

		uint64_t size = atoi((const char*)item);


		if (sq_size + size > SEG_MAX /*|| (sq_size >= SEG_MIN && (hash[5] << 2) >> 2 == 0x3f)*/)
		{
			process_seg();
			while(!pq.empty()) pq.pop();
			while(!sq.empty()) sq.pop();
			sq_size = 0;
		}

		node entry;
		memcpy(entry.key, hash, FP_SIZE);
		entry.size = size;

		sq_size += size;
		sq.push(entry);
		if (pq.size() < K_MINHASH)
		{
			pq.push(entry);
		}else
		{
			node max = pq.top();
			if(memcmp(max.key, entry.key, FP_SIZE) > 0)
			{
				pq.pop();
				pq.push(entry);
			}
		}
	}
}

int main (int argc, char *argv[])
{
	srand((unsigned)time(NULL));
	assert(argc >= 2);
	// argv[1] points to hash file; argv[2] points to segment db; argv[3] points to slice db;  

	FILE *fp = NULL;
	fp = fopen(argv[1], "r");
	assert(fp != NULL);
    	init_segment(argv[2]);
    	init_slice(argv[3]);
	read_hashes(fp);
	process_seg();
	fclose(fp);
	return 0;
}

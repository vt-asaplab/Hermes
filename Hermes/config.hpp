#pragma once
const int NUM_BITS              = 224;
const int MAX_KEYWORDS          = 100;
const int MAX_THREADS_INIT      = 8;
const int MAX_THREADS_SEARCH    = 8;
const int MAX_THREADS_UPDATE    = 4;
const int MAX_THREADS_REBUILD   = 4;
const int SERVER_PORT           = 8888;

// The maximum number of partitions is based on the largest database including 57,639 keywords
const int MAX_PARTITIONS        = 240; 
const int MAX_TOKEN_SIZE        = 148;
const int MAX_MATCH_OUTPUT      = 4096;

const int RECURSIVE_LEVEL       = 3;
const int PARTITION_SIZE        = 10;
const int NUM_PARTITIONS        = 1000;

#define ENABLE_SEPARATE_SEARCH  1
#define WRITER_EFFICIENCY       1
#define SEARCH_EFFICIENCY       1

/*
The fundamental rule of WAL is:
Log the changes BEFORE writing the actual data to the disk.

https://en.wikipedia.org/wiki/Non-volatile_memory
Non-volatile memory (NVM) or non-volatile storage is a type of computer memory that can retain stored information even after power is removed. 
In contrast, volatile memory needs constant power in order to retain data.
*/

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>

/*
magic, version, pagesize, 
*/
static const int WAL_MAGIC_NUMBER = 0x4B43594B;
static const int WAL_VERSION = 1;
static const int WAL_PAGE_SIZE = 4096;
static const int WAL_MAX_RECORD_SIZE = WAL_PAGE_SIZE * 4; // warning, standard ? 
static const int WAL_DEFAULT_FILE_SIZE = 16 * 1024 * 1024; // 16MB
/*
What is a Checkpoint?

A checkpoint is a point in time where:

All modified data in memory is flushed to disk
The WAL records up to that point are no longer needed for recovery
Old WAL records can be discarded or overwritten
*/
static const int WAL_CHECKPOINT_INTERVAL = 1000; 

enum wal_record_type {
    WAL_RECORD_ALLOC = 1,        // Allocation operation
    WAL_RECORD_FREE,             // Free operation
    WAL_RECORD_SPLIT,            // Block split
    WAL_RECORD_COALESCE,         // Block merge
    WAL_RECORD_REGION_CREATE,    // New region creation
    WAL_RECORD_REGION_DESTROY,   // Region destruction
    WAL_RECORD_CHECKPOINT,       // Checkpoint marker
    WAL_RECORD_COMMIT,           // Transaction commit
    WAL_RECORD_ABORT,            // Transaction abort
    WAL_RECORD_METADATA_UPDATE   // Metadata modification
};

// warning 
struct wal_header {
    uint32_t magic;  
    uint32_t version;
    // 8 bytes

    uint32_t timeline_id; 
    uint32_t page_size;          // (usually 4096)
    // 8 bytes

    uint64_t last_lsn;           // Last Log Sequence Number
    uint64_t last_checkpoint_lsn;// LSN of last checkpoint
    uint64_t last_checkpoint_time;// Timestamp of last checkpoint
    // 32 bytes 

    uint32_t record_count; 
    uint32_t checksum; 
    uint32_t flags;              // WAL flags (e.g., dirty, clean)
    uint8_t  reserved[28];       // Reserved for future use
    // 16 bytes
} __attribute__((packed));
_Static_assert(sizeof(struct wal_header) == 80, "wal_header size changed!");

struct wal_record_header {
    uint64_t lsn;                // Log Sequence Number (unique, increasing)
    uint64_t prev_lsn; 
    uint64_t transaction_id; 
    uint32_t record_type;        // Type of record (from enum)
    uint32_t record_size;        // Size of this record (including header)
    uint32_t data_size;   
    uint32_t crc32;   
    uint32_t flags;              // Record flags (e.g., compressed, encrypted)
    uint64_t timestamp;   
    uint8_t  padding[16]; 
} __attribute__((packed));

// WAL PAYLOAD TYPES
struct wal_alloc_payload {
    // warning name
    void *user_ptr;              // User-facing pointer (what user gets) 
    void *block_ptr;             // Block header pointer (internal)
    /*
    region -> block1, block2...

Heap Region (large chunk from OS, typically 2MB+)
├── Block 1 (small allocation unit, e.g., 32 bytes)
├── Block 2
├── Block 3
├── ...
└── Block N

Region 2 (another large chunk)
├── Block 1
├── Block 2
└── ...

Region 3
└── ...

--- REGION (2MB from OS) ---
┌─────────────────────────────────────────────────┐
│ Region metadata (struct heap_region)            │
│  - base: 0x100000                               │
│  - size: 2MB                                    │
│  - canary: 0xDEADBEEF                           │
├─────────────────────────────────────────────────┤
│ BLOCK 1 (32 bytes)                              │
│  - block_header (metadata)                      │
│  - user data                                    │
├─────────────────────────────────────────────────┤
│ BLOCK 2 (64 bytes)                              │
│  - block_header                                 │
│  - user data                                    │
├─────────────────────────────────────────────────┤
│ BLOCK 3 (32 bytes)                              │
│  - block_header                                 │
│  - user data                                    │
├─────────────────────────────────────────────────┤
│ ... more blocks ...                             │
└─────────────────────────────────────────────────┘
    */
    uint64_t region_id;          // Region identifier
    /*
    (!) Why Store block_size in WAL When We Have block_ptr? (!)

    1. The block header might be corrupted or unavailable during recovery
// During normal operation, you can do this:
struct block_header *block = (struct block_header *)block_ptr;
uint32_t size = block->size;  // Get size from header

// BUT during crash recovery:
// - The block header might be corrupted
// - The memory might not be accessible
// - The block might have been partially written
// - The canary might be invalid

- In WAL recovery, you need the size without relying on the potentially corrupted block header. <--- IT's important !

2. WAL records should be self-contained

A good WAL record should contain all information needed for recovery !

3. The size might change between logging and recovery

// Time of allocation:
block->size = 128;  // Original size
wal_write_alloc(wal, user_ptr, block_ptr, 128);

// Later... block gets split:
block->size = 64;   // Changed!
new_block->size = 64;

// During recovery, if we read block->size, we get 64, not 128
// But the WAL record has the original size: 128!

4. Performance optimization (preventing cache misses and etc);

5. Validation and consistency checking
// You can verify that the stored size matches the actual header
bool validate_record(wal_record_t *record) {
    struct block_header *block = (struct block_header *)record->block_ptr;
    
    if (block->size != record->block_size) {
        // Corruption detected!
        // The block was modified after logging
        return false;
    }
    
    return true;
}
    */
    uint32_t block_size;         // Size of allocated block
    uint32_t class_index;        // Size class index
    uint32_t thread_id;          // Thread that performed allocation
    uint32_t alignment;          // Alignment used
};

struct wal_free_payload {
    void *user_ptr;
    void *block_ptr;
    uint64_t region_id;
    uint32_t block_size;
    uint32_t thread_id;
    uint32_t free_reason;
};

// large file -> small files (roughly speaking)
struct wal_split_payload {
    void *original_block;
    void *new_block;
    uint32_t original_size;
    uint32_t new_size;
    uint32_t remaining_size;
};

// small files -> large files (roughly speaking)
struct wal_coalesce_payload {
    void *block1;
    void *block2;
    uint32_t block1_size;
    uint32_t block2_size;
    uint32_t coalesced_size;
};

struct wal_region_payload {
    void *region_base;
    uint32_t region_id;
    uint32_t region_size;
    uint32_t region_flags;
    uint32_t canary;
};

struct wal_checkpoint_payload {
    uint64_t checkpoint_lsn;
    uint32_t total_regions; 
    uint32_t total_allocations; 
    uint32_t total_frees;  
    uint64_t total_memory;       
    uint64_t free_memory;     
};

/*
 * ideal scenario: records_read = records_applied + records_scipped;
 * */ 
struct wal_recovery_stats {
    uint64_t records_read;
    uint64_t records_applied;
    uint64_t records_scipped;
    uint64_t last_valid_lsn;
    uint64_t bytes_read;
    uint64_t current_offset;
    _Bool    stopped_early;
};

// Отдельная структура для каждого типа записи
struct wal_record_alloc {
    struct wal_record_header header;
    struct wal_alloc_payload payload;
};

struct wal_record_free {
    struct wal_record_header header;
    struct wal_free_payload payload;
};

struct wal_record_split {
    struct wal_record_header header;
    struct wal_split_payload payload;
};

struct wal_record_coalesce {
    struct wal_record_header header;
    struct wal_coalesce_payload payload;
};

struct wal_record_region {
    struct wal_record_header header;
    struct wal_region_payload payload;
};

struct wal_record_checkpoint {
    struct wal_record_header header;
    struct wal_checkpoint_payload payload;
};

// WAL FILE STRUCTURE
struct wal_file {
    struct wal_header header;
    struct wal_record_alloc records[];  // Just for example, actual file contains mixed records
};

// WAL BUFFER
struct wal_buffer {
    uint8_t *buffer;
    size_t buffer_size;
    size_t current_offset;
    size_t flush_offset;
    uint64_t current_lsn;
    pthread_mutex_t buffer_lock;
};

_Bool (*wal_replay_fn)(void *user_ctx, const struct wal_record_header *hdr, const void *payload, uint32_t payload_size);

struct wal_context {
    char *wal_file_path;  
    int wal_file_fd;
    _Bool is_open;

    struct wal_buffer buffer;

    // State tracking
    uint64_t last_lsn; 
    uint64_t last_flushed_lsn;  
    uint64_t last_checkpoint_lsn; 
    uint64_t transaction_id; 

    // Statistics
    uint64_t total_records_written;
    uint64_t total_records_flushed;
    uint64_t total_sync_flushed;
    uint64_t total_bytes_written;
    uint64_t total_bytes_flushed;
    uint64_t total_flushes;
    uint64_t total_checkpoints;

    // Synchronization
    pthread_mutex_t wal_lock;    // Main WAL lock
    pthread_cond_t flush_cond;   // Condition for flush notification
    // bool warning 
    _Bool flush_requested;        // Flush requested flag
    _Bool checkpoint_requested;   // Checkpoint requested flag

    // Callbacks
    void (*on_flush)(void *ctx);           // Called after flush
    void (*on_checkpoint)(void *ctx);      // Called after checkpoint
    void *callback_ctx;                     // Context for callbacks
    
    wal_replay_fn wal_replay;
    void *replay_ctx;

    // Recovery state
    _Bool in_recovery;            // Is recovery in progress
    uint32_t recovery_errors;    // Number of errors during recovery
};

struct wal_operation {
    struct wal_context *context; 
    uint64_t lsn;     
    uint64_t transaction_id;    
    _Bool is_active;    
    _Bool needs_commit; 
};

static const uint32_t crc32_table[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
    0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
    0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
    0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
    0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
    0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
    0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
    0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
    0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
    0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
    0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
    0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
    0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
    0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
    0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
    0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
    0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
    0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
    0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
    0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
    0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
    0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
    0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
    0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
    0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
    0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
    0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,
    0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
    0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
    0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,
    0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,
    0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
    0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

/*
The binary number 1101 becomes x³ + x² + 0x + 1
Each bit position represents a power of x
Arithmetic is done in GF(2) - the finite field with just 0 and 1

Addition is XOR (no carry)
Subtraction equals addition (since 1+1=0 in GF(2))

like:
we have message: 11010011101100
Generator polynomial: x³ + x + 1 (binary: 1011)
1011 -> 1 (1) + 1 (x^1) + 0x (dont use this) + x^3 (because we have 101 (size 3) | why 3, not 4? cuz we add first 1 in start)
crc width: 3 bits

step 1:
append 3 zeros to the message:
11010011101100 000

step 2:
polynomial long division :

11010011101100 000
1011              ← divisor
------------------
01100011101100 000
 1011             ← divisor shifted
------------------
00111011101100 000
  1011
------------------
00010111101100 000
   1011
------------------
00000001101100 000
       1011
------------------
00000000110100 000
        1011
------------------
00000000011000 000
         1011
------------------
00000000001110 000
          1011
------------------
00000000000101 000
           101 1
------------------
00000000000000 100  ← This is the CRC (remainder)

step 3:
send data with CRC:

the sender transmits: 11010011101100 + 100 (the CRC)

step 4:
verification:
the receiver performs the same division on the received data + CRC. If the remainder is zero, the data is likely error-free.

(!) CRC is NOT for security: (!)

No authentication: An attacker can modify data and recalculate CRC
Reversible: Unlike cryptographic hashes, CRC can be reversed
Linear property: CRC(x⊕y) = CRC(x) ⊕ CRC(y) ⊕ c
This was famously exploited in the WEP protocol vulnerability
*/
static uint32_t crc32_calculate(const void *data, size_t size) {
    if (data == NULL && size > 0) return 0;

    const uint8_t *bytes = (const uint8_t*)data;
    uint32_t crc = 0xFFFFFFFF;

    /*
    // Current crc = 0xFFFFFFFF (before processing)
crc >> 8 = 0x00FFFFFF
// 11111111 11111111 11111111 11111111 shifted right 8:
// 00000000 11111111 11111111 11111111

// Look up table[0xBE] = 0x352441C2 (hypothetical value)
// XOR: 0x352441C2 ^ 0x00FFFFFF = 0x35DBBE3D
    */
    for (size_t i = 0; i < size; i++) {
        crc = crc32_table[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    }

    return crc ^ 0xFFFFFFFF;
}

// --- util function ---
static uint64_t get_timestamp(void) {
    /*
    struct timespec {
           time_t     tv_sec;   /* Seconds  
           /* ...   tv_nsec;  /* Nanoseconds [0, 999'999'999]  
       };
    */
    struct timespec ts;
    memset(&ts, 0, sizeof(ts));

    /*
    int clock_gettime(clockid_t clockid, struct timespec *tp);
    */
    clock_gettime(CLOCK_REALTIME, &ts);

    /* 
    in one sec -> 1 000 000 000 + nanosec
    */
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// ====================== FORWARD DECLARATIONS ======================
static _Bool wal__flush_sync_locked(struct wal_context *ctx);
static uint64_t wal__append_record_locked(struct wal_context *ctx,
                                          uint32_t record_type,
                                          const void *payload,
                                          uint32_t payload_size);
static uint64_t wal_append_record(struct wal_context *ctx,
                                  uint32_t record_type,
                                  const void *payload,
                                  uint32_t payload_size);

struct wal_context *wal_init(const char *wal_file_path) {
    if (!wal_file_path) return NULL;

    struct wal_context *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        fprintf(stderr, "WAL: Failed to allocate context\n");
        return NULL;
    }

    ctx->wal_file_path = strdup(wal_file_path);
    if (!ctx->wal_file_path) {
        fprintf(stderr, "WAL: Failed to allocate file path\n");
        free(ctx);
        return NULL;
    }

    ctx->buffer.buffer_size = WAL_DEFAULT_FILE_SIZE;
    ctx->buffer.buffer = calloc(1, ctx->buffer.buffer_size);
    if (!ctx->buffer.buffer) {
        fprintf(stderr, "WAL: Failed to allocate buffer\n");
        free(ctx->wal_file_path);
        free(ctx);
        return NULL;
    }

    pthread_mutex_init(&ctx->wal_lock, NULL);
    pthread_mutex_init(&ctx->buffer.buffer_lock, NULL);
    pthread_cond_init(&ctx->flush_cond, NULL);

    ctx->wal_file_fd = -1;
    ctx->is_open = false;
    ctx->last_lsn = 0;
    ctx->last_flushed_lsn = 0;
    ctx->last_checkpoint_lsn = 0;
    ctx->transaction_id = 1;
    ctx->in_recovery = false;
    ctx->recovery_errors = 0;

    return ctx;
}

_Bool wal_open(struct wal_context *ctx) {
    if (!ctx || !ctx->wal_file_path) return false;

    pthread_mutex_lock(&ctx->wal_lock);

    if (ctx->is_open) {
        pthread_mutex_unlock(&ctx->wal_lock);
        return true;
    }

    /*
    specifies that the file owner has read and write permissions, while the group and others have read-only permissions
    */
    ctx->wal_file_fd = open(ctx->wal_file_path, O_RDWR | O_CREAT, 0644);
    if (ctx->wal_file_fd < 0) {
        fprintf(stderr, "WAL: Failed to open file: %s (errno=%d)\n", 
                ctx->wal_file_path, errno);
        pthread_mutex_unlock(&ctx->wal_lock);
        return false;
    }

    struct stat st;
    memset(&st, 0, sizeof(st));

    /*
    stat and fstat are system functions used to retrieve metadata about a file, such as its size, permissions, and creation time. They do not read the content of the file, only its details.

    stat uses a path: You pass the file's name or path as a string. The file does not need to be open.fstat uses a file descriptor: You pass an integer file descriptor (fd) of a file that you have already opened using open().
    */
    if (fstat(ctx->wal_file_fd, &st) == 0 && st.st_size > 0) {
        struct wal_header header;
        memset(&header, 0, sizeof(header));

        /*
        pread, pwrite - read from or write to a file descriptor at a given
        offset

        ssize_t pread(size_t count;
                     int fd, void buf[count], size_t count,
                     off_t offset);

        (Note: Traditional systems write this identically as ssize_t pread(int fd, void *buf, size_t count, off_t offset);) warning (!)
        */
        ssize_t bytes_read = pread(ctx->wal_file_fd, &header, sizeof(header), 0);

        if (bytes_read != sizeof(header)) {
            fprintf(stderr, "WAL: Failed to read header\n");
            close(ctx->wal_file_fd);
            ctx->wal_file_fd = -1;
            pthread_mutex_unlock(&ctx->wal_lock);
            return false;
        }

        if (header.magic != WAL_MAGIC_NUMBER || header.version != WAL_VERSION) {
            fprintf(stderr, "WAL: Invalid header magic or version\n");
            close(ctx->wal_file_fd);
            ctx->wal_file_fd = -1;
            pthread_mutex_unlock(&ctx->wal_lock);
            return false;
        }

        ctx->last_lsn = header.last_lsn;
        ctx->last_checkpoint_lsn = header.last_checkpoint_lsn;
        ctx->buffer.current_offset = sizeof(struct wal_header);

        // ВАЖНО: без этих двух строк первый flush запишет данные поверх старых
        if (st.st_size >= (off_t)sizeof(struct wal_header)) {
            ctx->total_bytes_flushed = (uint64_t)st.st_size - sizeof(struct wal_header);
        } else {
            ctx->total_bytes_flushed = 0;
        }
        ctx->last_flushed_lsn = header.last_lsn;
    } else {
        struct wal_header header;
        memset(&header, 0, sizeof(header));

        header.magic = WAL_MAGIC_NUMBER;
        header.version = WAL_VERSION;
        header.last_lsn = 0;
        header.last_checkpoint_lsn = 0;
        header.last_checkpoint_time = get_timestamp();
        header.page_size = WAL_PAGE_SIZE;
        header.record_count = 0;
        header.checksum = 0;
        header.flags = 0;

        ssize_t bytes_written = pwrite(ctx->wal_file_fd, &header, sizeof(header), 0);
        if (bytes_written != sizeof(header)) {
            fprintf(stderr, "WAL: Failed to write header\n");
            close(ctx->wal_file_fd);
            ctx->wal_file_fd = -1;
            pthread_mutex_unlock(&ctx->wal_lock);
            return false;
        }

        fsync(ctx->wal_file_fd);
        ctx->buffer.current_offset = sizeof(struct wal_header);
        ctx->total_bytes_flushed = 0;
        ctx->last_flushed_lsn = 0;
    }

    ctx->is_open = true;
    pthread_mutex_unlock(&ctx->wal_lock);

    return true;
}

static uint64_t wal__append_record_locked(struct wal_context *ctx, uint32_t record_type, const void *payload, uint32_t payload_size) {
    if (!ctx || !ctx->is_open) {
        return 0;
    }

    uint32_t record_size = sizeof(struct wal_record_header) + payload_size;

    if (payload_size > (uint32_t)(WAL_MAX_RECORD_SIZE - sizeof(struct wal_record_header))) {
        fprintf(stderr, "WAL: payload too large\n");
        return 0;
    }

    /*
    if buffer is full -> flush 
    */
    if (ctx->buffer.current_offset + record_size > ctx->buffer.buffer_size) {
        if (!wal__flush_sync_locked(ctx)) {
            fprintf(stderr, "WAL: Failed to flush before appending new record\n");
            return 0;
        }
    }

    /*
    Проверка: одна запись должна помещаться в пустой буфер
    Иначе memcpy переполнит буфер
    */
    if (record_size > ctx->buffer.buffer_size - sizeof(struct wal_header)) {
        fprintf(stderr, "WAL: Record too large (%u bytes, buffer %zu bytes)\n",
                record_size, ctx->buffer.buffer_size - sizeof(struct wal_header));
        return 0;
    }

    struct wal_record_header record_header;
    memset(&record_header, 0, sizeof(record_header));

    ctx->last_lsn++;
    record_header.lsn = ctx->last_lsn;
    /*
    if LSN started with 0, then the prev_lsn of the first entry would be -1, which for uint64_t would give a huge number 0xFFFFFFFFFFFFFFFF. 
    LSN usually starts with 1 (just so that 0 means "there is no previous one"). It is worth checking the initialization of ctx->last_lsn in the context creation code.
    */
    record_header.prev_lsn = ctx->last_lsn - 1;
    record_header.transaction_id = ctx->transaction_id;
    record_header.record_size = record_size;
    record_header.record_type = record_type;
    record_header.data_size = payload_size;
    record_header.flags = 0;
    record_header.timestamp = get_timestamp();
    // record_header.crc32 = 0;

    size_t record_start = ctx->buffer.current_offset;
    /*
    void *memcpy(size_t n;
                    void dest[restrict n], const void src[restrict n],
                    size_t n);

    memcpy(buf + off, src, n);
    off += n;
    */
    memcpy(ctx->buffer.buffer + ctx->buffer.current_offset, &record_header, sizeof(record_header));
    ctx->buffer.current_offset += sizeof(record_header);

    if (payload_size > 0) {
        if (payload) {
            memcpy(ctx->buffer.buffer + ctx->buffer.current_offset,
                   payload, payload_size);
        } else {
            /* payload == NULL, but size > 0: zeroing,
               чтобы CRC был детерминированным */
            memset(ctx->buffer.buffer + ctx->buffer.current_offset,
                   0, payload_size);
        }
        ctx->buffer.current_offset += payload_size;
    }

    /*
    static uint32_t crc32_calculate(const void *data, size_t size)
    */
    uint32_t crc = crc32_calculate(ctx->buffer.buffer + record_start, record_size);

    struct wal_record_header *hdr_in_buf =
        (struct wal_record_header *)(ctx->buffer.buffer + record_start);
    hdr_in_buf->crc32 = crc;

    ctx->total_records_written++;
    ctx->total_bytes_written += record_size;

    return record_header.lsn;
}

// ====================== PUBLIC WRAPPER FOR APPEND ======================
static uint64_t wal_append_record(struct wal_context *ctx,
                                  uint32_t record_type,
                                  const void *payload,
                                  uint32_t payload_size) {
    if (!ctx || !ctx->is_open) {
        return 0;
    }

    pthread_mutex_lock(&ctx->wal_lock);
    uint64_t lsn = wal__append_record_locked(ctx, record_type, payload, payload_size);
    pthread_mutex_unlock(&ctx->wal_lock);

    return lsn;
}

uint64_t wal_write_alloc(struct wal_context *ctx, void *user_ptr, void *block_ptr, uint64_t region_id, uint32_t block_size, uint32_t class_index) {
    struct wal_alloc_payload payload;
    memset(&payload, 0, sizeof(payload));

    payload.user_ptr = user_ptr;
    payload.block_ptr = block_ptr;
    payload.region_id = region_id;
    payload.block_size = block_size;
    payload.class_index = class_index;
    payload.thread_id = (uint32_t)(uintptr_t)pthread_self();
    payload.alignment = 16;

    return wal_append_record(ctx, WAL_RECORD_ALLOC, &payload, sizeof(payload));
}

uint64_t wal_write_free(struct wal_context *ctx, void *user_ptr,
                        void *block_ptr, uint64_t region_id,
                        uint32_t block_size) {
    struct wal_free_payload payload;
    memset(&payload, 0, sizeof(payload));
    
    payload.user_ptr = user_ptr;
    payload.block_ptr = block_ptr;
    payload.region_id = region_id;
    payload.block_size = block_size;
    payload.thread_id = (uint32_t)(uintptr_t)pthread_self();
    payload.free_reason = 0;
    
    return wal_append_record(ctx, WAL_RECORD_FREE, &payload, sizeof(payload));
}

uint64_t wal_write_split(struct wal_context *ctx, void *original_block,
                         void *new_block, uint32_t original_size,
                         uint32_t new_size, uint32_t remaining_size) {
    struct wal_split_payload payload;
    memset(&payload, 0, sizeof(payload));
    
    payload.original_block = original_block;
    payload.new_block = new_block;
    payload.original_size = original_size;
    payload.new_size = new_size;
    payload.remaining_size = remaining_size;
    
    return wal_append_record(ctx, WAL_RECORD_SPLIT, &payload, sizeof(payload));
}

uint64_t wal_write_coalesce(struct wal_context *ctx, void *block1,
                            void *block2, uint32_t block1_size,
                            uint32_t block2_size, uint32_t coalesced_size) {
    struct wal_coalesce_payload payload;
    memset(&payload, 0, sizeof(payload));
    
    payload.block1 = block1;
    payload.block2 = block2;
    payload.block1_size = block1_size;
    payload.block2_size = block2_size;
    payload.coalesced_size = coalesced_size;
    
    return wal_append_record(ctx, WAL_RECORD_COALESCE, &payload, sizeof(payload));
}

uint64_t wal_write_region(struct wal_context *ctx, void *region_base,
                          uint32_t region_id, uint32_t region_size,
                          uint32_t canary) {
    struct wal_region_payload payload;
    memset(&payload, 0, sizeof(payload));
    
    payload.region_base = region_base;
    payload.region_id = region_id;
    payload.region_size = region_size;
    payload.region_flags = 0;
    payload.canary = canary;
    
    return wal_append_record(ctx, WAL_RECORD_REGION_CREATE, &payload, sizeof(payload));
}

uint64_t wal_write_checkpoint(struct wal_context *ctx) {
    struct wal_checkpoint_payload payload;
    memset(&payload, 0, sizeof(payload));
    
    payload.checkpoint_lsn = ctx->last_lsn;
    payload.total_regions = 0;
    payload.total_allocations = 0;
    payload.total_frees = 0;
    payload.total_memory = 0;
    payload.free_memory = 0;
    
    return wal_append_record(ctx, WAL_RECORD_CHECKPOINT, &payload, sizeof(payload));
}

// _Bool wal_flush_async(struct wal_context *ctx) {
//     if (!ctx || !ctx->is_open) return false;

//     pthread_mutex_lock(&ctx->wal_lock);

//     if (ctx->buffer.current_offset <= sizeof(struct wal_header)) {
//         pthread_mutex_unlock(&ctx->wal_lock);
//         return true; // empty
//     }

//     size_t bytes_to_write = ctx->buffer.current_offset - sizeof(struct wal_header);
//     ssize_t bytes_written = pwrite(ctx->wal_file_fd, 
//                                    ctx->buffer.buffer + sizeof(struct wal_header), 
//                                    bytes_to_write, 
//                                    sizeof(struct wal_header) + ctx->total_bytes_flushed);

//     if (bytes_written != (ssize_t)bytes_to_write) {
//         fprintf(stderr, "WAL: Async flush failed\n");
//         pthread_mutex_unlock(&ctx->wal_lock);
//         return false;
//     }

//     ctx->total_flushes++;
//     ctx->total_bytes_flushed += bytes_written;
//     // last write
//     ctx->last_flushed_lsn = ctx->last_lsn;
//     // clean buffer for new records
//     ctx->buffer.current_offset = sizeof(struct wal_header);

//     if (ctx->on_flush) {
//         ctx->on_flush(ctx->callback_ctx);
//     }

//     pthread_mutex_unlock(&ctx->wal_lock);
//     return true;
// }

static _Bool wal__flush_sync_locked(struct wal_context *ctx) {
    if (!ctx || !ctx->is_open || ctx->wal_file_fd < 0) {
        return false;
    }

    if (ctx->buffer.current_offset <= sizeof(struct wal_header)) {
        return true; // empty
    }

    size_t bytes_to_write = ctx->buffer.current_offset - sizeof(struct wal_header);
    off_t offset = (off_t)(sizeof(struct wal_header) + ctx->total_bytes_flushed);
    ssize_t bytes_written = pwrite(ctx->wal_file_fd,
                               ctx->buffer.buffer + sizeof(struct wal_header),
                               bytes_to_write,
                               offset);

    if (bytes_written < 0) {
        fprintf(stderr, "WAL: pwrite failed: %s\n", strerror(errno));
        return false;
    }
    
    if ((size_t)bytes_written < bytes_to_write) {
        size_t remaining = bytes_to_write - bytes_written;
        /* 
        void *memmove(size_t n;
                      void dest[n], const void src[n], size_t n);
        */
        memmove(ctx->buffer.buffer + sizeof(struct wal_header), ctx->buffer.buffer + sizeof(struct wal_header) + bytes_written, remaining);
        ctx->buffer.current_offset = sizeof(struct wal_header) + remaining;
        ctx->total_bytes_flushed += bytes_written;
        fprintf(stderr, "WAL: Partial write, %zu bytes remaining\n", remaining);

        return false;
    }

    /*
    fsync() is a POSIX system call that forces the operating system to flush all modified data and metadata associated with a specific file descriptor directly to persistent storage
    
    It blocks execution and does not return to the application until the underlying storage hardware acknowledges that the data has been safely written.
    */
    if (fsync(ctx->wal_file_fd) != 0) {
        fprintf(stderr, "WAL: fsync failed: %s\n", strerror(errno));
        return false;
    }

    ctx->total_flushes++;
    ctx->total_sync_flushed++;
    ctx->total_bytes_flushed += bytes_written;
    ctx->last_flushed_lsn = ctx->last_lsn;
    ctx->buffer.current_offset = sizeof(struct wal_header);

    return true;
}

_Bool wal_flush_sync(struct wal_context *ctx) {
    if (!ctx || !ctx->is_open) {
        return false;
    }

    pthread_mutex_lock(&ctx->wal_lock);
    _Bool ok = wal__flush_sync_locked(ctx);
    pthread_mutex_unlock(&ctx->wal_lock);

    if (ok && ctx->on_flush) {
        ctx->on_flush(ctx->callback_ctx);
    }

    return ok;
}

_Bool wal_checkpoint(struct wal_context *ctx, _Bool flush_first) {
    if (!ctx || !ctx->is_open) return false;

    pthread_mutex_lock(&ctx->wal_lock);

    if (flush_first) {
        if (!wal__flush_sync_locked(ctx)) {
            pthread_mutex_unlock(&ctx->wal_lock);
            return false;
        }
    }

    // Write checkpoint record
    struct wal_checkpoint_payload payload;
    memset(&payload, 0, sizeof(payload));
    payload.checkpoint_lsn = ctx->last_lsn;

    uint64_t lsn = wal__append_record_locked(ctx, WAL_RECORD_CHECKPOINT,
                                             &payload, sizeof(payload));
    if (lsn == 0) {
        pthread_mutex_unlock(&ctx->wal_lock);
        return false;
    }

    // Сбрасываем checkpoint-запись на диск
    if (!wal__flush_sync_locked(ctx)) {
        pthread_mutex_unlock(&ctx->wal_lock);
        return false;
    }

    // Update header
    struct wal_header header;
    memset(&header, 0, sizeof(header));
    
    header.magic = WAL_MAGIC_NUMBER;
    header.version = WAL_VERSION;
    header.last_lsn = ctx->last_lsn;
    header.last_checkpoint_lsn = ctx->last_lsn;
    header.last_checkpoint_time = get_timestamp();
    header.page_size = WAL_PAGE_SIZE;
    header.record_count = ctx->total_records_written;
    header.flags = 0;
    
    if (pwrite(ctx->wal_file_fd, &header, sizeof(header), 0) != sizeof(header)) {
        fprintf(stderr, "WAL: Failed to update header in checkpoint\n");
        pthread_mutex_unlock(&ctx->wal_lock);
        return false;
    }
    fsync(ctx->wal_file_fd);
    
    ctx->last_checkpoint_lsn = ctx->last_lsn;
    ctx->total_checkpoints++;

    // Сохраняем callback и ctx для вызова вне блокировки
    void *cb_ctx = ctx->callback_ctx;
    void (*cb)(void *) = ctx->on_checkpoint;

    pthread_mutex_unlock(&ctx->wal_lock);

    if (cb) {
        cb(cb_ctx);
    }
    
    return true;
}

/*
 *  > 0 - RECORD SIZE 
 *  0 - END OF FILE 
 *  -1 - READ ERROR 
 *  -2 - CORRUPTED RECORDING 
 *  -3 - THE RECORDING IS TRUNCATED
 * */
static int wal__read_record(int fd, off_t offset,
                            struct wal_record_header *out_header,
                            void *out_payload,
                            uint32_t out_payload_capacity) {
    if (!out_header) return -1;

    struct wal_record_header record_header;
    memset(&record_header, 0, sizeof(record_header));

    ssize_t n = pread(fd, &record_header, sizeof(record_header), offset);

    if (n == 0) {
        return 0;
    }
    if (n < 0) {
        return -1;
    }
    if ((size_t)n < sizeof(record_header)) {
        return -3;
    }

    if (record_header.record_size < sizeof(struct wal_record_header)) {
        return -2;
    }
    if (record_header.record_size > (uint32_t)WAL_MAX_RECORD_SIZE) {
        return -2;
    }
    if (record_header.record_size != sizeof(struct wal_record_header) + record_header.data_size) {
        return -2;
    }
    if (record_header.record_type < WAL_RECORD_ALLOC ||
        record_header.record_type > WAL_RECORD_METADATA_UPDATE) {
        return -2;
    }

    if (out_payload && record_header.data_size > 0) {
        if (record_header.data_size > out_payload_capacity) {
            return -2;
        }
        ssize_t pn = pread(fd, out_payload, record_header.data_size,
                           offset + sizeof(struct wal_record_header));
        if (pn < 0) {
            return -1;
        }
        if ((size_t)pn < record_header.data_size) {
            return -3;
        }
    }

    uint8_t *record_buf = calloc(1, record_header.record_size);
    if (!record_buf) {
        return -1;
    }

    ssize_t rn = pread(fd, record_buf, record_header.record_size, offset);
    if (rn < 0 || (size_t)rn < record_header.record_size) {
        free(record_buf);
        return (rn < 0) ? -1 : -3;
    }

    struct wal_record_header *hdr_in_buf = (struct wal_record_header *)record_buf;
    uint32_t saved_crc = hdr_in_buf->crc32;
    hdr_in_buf->crc32 = 0;

    uint32_t computed_crc = crc32_calculate(record_buf, record_header.record_size);
    hdr_in_buf->crc32 = saved_crc;
    free(record_buf);

    if (computed_crc != saved_crc) {
        return -2;
    }

    *out_header = record_header;
    return (int)record_header.record_size;
}

static _Bool wal__check_sequence(uint64_t prev_lsn, const struct wal_record_header *record_header) {
	if (prev_lsn == 0) {
		return record_header->prev_lsn == 0;
	}

	return record_header->lsn == prev_lsn + 1;
} 

/*  
  * Recovery stops at the first bit‑rot record — beyond that, it’s garbage.  (!) Save the garbage in seperate file (this may contain important information)
  * * */
_Bool wal_recovery(struct wal_context *ctx) {
    if (!ctx) return false;
    
    pthread_mutex_lock(&ctx->wal_lock);
    
	if (!ctx->is_open || ctx->wal_file_fd < 0) {
		pthread_mutex_unlock(&ctx->wal_lock);
		return false;
	}

	if (ctx->in_recovery) {
		pthread_mutex_unlock(&ctx->wal_lock);
		return false;
	}
	ctx->in_recovery = true;

	int fd = ctx->wal_file_fd;
	uint64_t checkpoint_lsn = ctx->last_checkpoint_lsn;
	wal_replay_fn replay_fn = ctx->wal_replay;
	void *replay_ctx = ctx->replay_ctx;

	pthread_mutex_unlock(&ctx->wal_lock);

    printf("WAL: Starting recovery (checkpoint_lsn=%llu)...\n",
          (unsigned long long)checkpoint_lsn);
	
	struct wal_recovery_stats stats;
	memset(&stats, 0, sizeof(stats));

	uint8_t *payload_buf = malloc(WAL_MAX_RECORD_SIZE);
	if (!payload_buf) {
		pthread_mutex_lock(&ctx->wal_lock);
		ctx->in_recovery = false;
		ctx->recovery_errors++;
		pthread_mutex_unlock(&ctx->wal_lock);
		return false;
	}

	off_t offset = sizeof(struct wal_header);
	uint64_t prev_lsn = 0;
	_Bool ok = true;

	while (1) {
		struct wal_record_header record_header;
		memset(&record_header, 0, sizeof(record_header));

		int result = wal__read_record(fd, offset, &record_header, payload_buf, WAL_MAX_RECORD_SIZE);

		if (result == 0) {
            printf("WAL: Recovery reached end of file at offset %lld\n",
                   (long long)offset);
            break;
        }

		if (result == -1) {
            fprintf(stderr, "WAL: Recovery I/O error at offset %lld\n",
                    (long long)offset);
            stats.current_offset = (uint64_t)offset;
            stats.stopped_early = true;
            ok = false;
            break;
        }

		if (result == -2) {
            fprintf(stderr, "WAL: Corrupt record at offset %lld "
                            "(validation failed)\n",
                    (long long)offset);
            stats.current_offset = (uint64_t)offset;
            stats.stopped_early = true;
            break;
        }

		if (result == -3) {
            fprintf(stderr, "WAL: Truncated record at offset %lld\n",
                    (long long)offset);
            stats.current_offset = (uint64_t)offset;
            stats.stopped_early = true;
            break;
        }

		uint32_t record_size = (uint32_t)result;

        if (!wal__check_sequence(prev_lsn, &record_header)) {
            fprintf(stderr, "WAL: LSN sequence broken at offset %lld "
                            "(expected prev_lsn=%llu, got lsn=%llu, prev=%llu)\n",
                    (long long)offset,
                    (unsigned long long)prev_lsn,
                    (unsigned long long)record_header.lsn,
                    (unsigned long long)record_header.prev_lsn);
            stats.current_offset = (uint64_t)offset;
            stats.stopped_early = true;
            break;
        }

		stats.records_read++;
        stats.bytes_read += record_size;
        stats.last_valid_lsn = record_header.lsn;
        prev_lsn = record_header.lsn;

		if (record_header.lsn <= checkpoint_lsn) {
            stats.records_skipped++;
            offset += record_size;
            continue;
        }

		if (replay_fn) {
			_Bool applied = replay_fn(replay_ctx, &record_header, payload_buf, record_header.data_size);
			if (!applied) {
				fprintf(stderr, "WAL: replay_fn rejected record LSN=%llu "
								"at offset %lld\n",
						(unsigned long long)record_header.lsn,
						(long long)offset);
				stats.current_offset = (uint64_t)offset;
				stats.stopped_early = true;
				ok = false;
				break;
			}
			stats.records_applied++;
		}

		offset += record_size;
	}

	free(payload_buf);

	pthread_mutex_lock(&ctx->wal_lock);

	if (stats.last_valid_lsn > 0) {
		ctx->last_lsn = stats.last_valid_lsn;
		/* Буфер пуст, но данные на диске есть.
		 * Ставим buffer_size, чтобы следующий append вызвал flush
		 * и записал в конец файла. */
		ctx->buffer.current_offset = ctx->buffer.buffer_size;
	}

	ctx->in_recovery = false;
	if (!ok) {
		ctx->recovery_errors++;
	}

	pthread_mutex_unlock(&ctx->wal_lock);

	printf("WAL: Recovery done. read=%llu applied=%llu skipped=%llu "
           "last_lsn=%llu stopped_early=%s\n",
           (unsigned long long)stats.records_read,
           (unsigned long long)stats.records_applied,
           (unsigned long long)stats.records_skipped,
           (unsigned long long)stats.last_valid_lsn,
           stats.stopped_early ? "yes" : "no");

	return ok;
}

void wal_close(struct wal_context *ctx) {
    if (!ctx) return;

    pthread_mutex_lock(&ctx->wal_lock);

    if (ctx->in_recovery) {
        pthread_mutex_unlock(&ctx->wal_lock);
        return;
    }

    if (ctx->is_open) {
        // БЕЗ deadlock — используем locked-версию
        wal__flush_sync_locked(ctx);
        
        // Update header
        struct wal_header header;
        memset(&header, 0, sizeof(header));
        
        header.magic = WAL_MAGIC_NUMBER;
        header.version = WAL_VERSION;
        header.last_lsn = ctx->last_lsn;
        header.last_checkpoint_lsn = ctx->last_checkpoint_lsn;
        header.last_checkpoint_time = get_timestamp();
        header.page_size = WAL_PAGE_SIZE;
        header.record_count = ctx->total_records_written;
        header.flags = 0;
        
        pwrite(ctx->wal_file_fd, &header, sizeof(header), 0);
        fsync(ctx->wal_file_fd);
        
        close(ctx->wal_file_fd);
        ctx->wal_file_fd = -1;
        ctx->is_open = false;
    }
    
    pthread_mutex_unlock(&ctx->wal_lock);
}

void wal_destroy(struct wal_context *ctx) {
    if (!ctx) return;
    
    wal_close(ctx);
    
    pthread_mutex_destroy(&ctx->wal_lock);
    pthread_mutex_destroy(&ctx->buffer.buffer_lock);
    pthread_cond_destroy(&ctx->flush_cond);
    
    free(ctx->buffer.buffer);
    free(ctx->wal_file_path);
    free(ctx);
}

void wal_print_stats(struct wal_context *ctx) {
    if (!ctx) return;
    
    pthread_mutex_lock(&ctx->wal_lock);
    
    printf("\n=== WAL Statistics ===\n");
    printf("File: %s\n", ctx->wal_file_path);
    printf("Open: %s\n", ctx->is_open ? "Yes" : "No");
    printf("Last LSN: %llu\n", (unsigned long long)ctx->last_lsn);
    printf("Last Flushed LSN: %llu\n", (unsigned long long)ctx->last_flushed_lsn);
    printf("Last Checkpoint LSN: %llu\n", (unsigned long long)ctx->last_checkpoint_lsn);
    printf("Buffer Used: %zu / %zu bytes\n", 
           ctx->buffer.current_offset, ctx->buffer.buffer_size);
    printf("Total Records Written: %llu\n", 
           (unsigned long long)ctx->total_records_written);
    printf("Total Bytes Written: %llu\n", 
           (unsigned long long)ctx->total_bytes_written);
    printf("Total Flushes: %llu\n", 
           (unsigned long long)ctx->total_flushes);
    printf("Total Sync Flushes: %llu\n", 
           (unsigned long long)ctx->total_sync_flushed);
    printf("Total Checkpoints: %llu\n", 
           (unsigned long long)ctx->total_checkpoints);
    printf("Recovery Errors: %u\n", ctx->recovery_errors);
    
    pthread_mutex_unlock(&ctx->wal_lock);
}

// ====================== TEST MAIN ======================
#ifdef WAL_TEST

static _Bool test_replay(void *user_ctx,
                         const struct wal_record_header *hdr,
                         const void *payload,
                         uint32_t payload_size) {
    (void)user_ctx;
    (void)payload;
    printf("  [replay] LSN=%llu type=%u size=%u data_size=%u\n",
           (unsigned long long)hdr->lsn,
           hdr->record_type,
           hdr->record_size,
           payload_size);
    return true;
}

int main(void) {
    const char *path = "/tmp/test_wal.log";

    // Удаляем старый файл, чтобы тест был чистым
    unlink(path);

    printf("=== WAL TEST START ===\n\n");

    // 1. Инициализация
    struct wal_context *wal = wal_init(path);
    if (!wal) {
        fprintf(stderr, "wal_init failed\n");
        return 1;
    }

    // 2. Открытие
    if (!wal_open(wal)) {
        fprintf(stderr, "wal_open failed\n");
        wal_destroy(wal);
        return 1;
    }

    printf("[OK] WAL opened: %s\n\n", path);

    // 3. Запись alloc
    void *fake_ptr1 = (void *)0x1000;
    void *fake_ptr2 = (void *)0x2000;

    uint64_t lsn1 = wal_write_alloc(wal, fake_ptr1, fake_ptr1, 1, 32, 0);
    printf("[OK] wal_write_alloc #1 -> LSN %llu\n", (unsigned long long)lsn1);

    uint64_t lsn2 = wal_write_alloc(wal, fake_ptr2, fake_ptr2, 1, 64, 1);
    printf("[OK] wal_write_alloc #2 -> LSN %llu\n", (unsigned long long)lsn2);

    // 4. Запись free
    uint64_t lsn3 = wal_write_free(wal, fake_ptr1, fake_ptr1, 1, 32);
    printf("[OK] wal_write_free  #1 -> LSN %llu\n", (unsigned long long)lsn3);

    // 5. Запись region
    uint64_t lsn4 = wal_write_region(wal, (void *)0x100000, 1, 2*1024*1024, 0xDEADBEEF);
    printf("[OK] wal_write_region -> LSN %llu\n", (unsigned long long)lsn4);

    // 6. Flush (синхронный)
    if (!wal_flush_sync(wal)) {
        fprintf(stderr, "wal_flush_sync failed\n");
        wal_destroy(wal);
        return 1;
    }
    printf("[OK] wal_flush_sync done\n\n");

    // 7. Checkpoint
    if (!wal_checkpoint(wal, true)) {
        fprintf(stderr, "wal_checkpoint failed\n");
        wal_destroy(wal);
        return 1;
    }
    printf("[OK] wal_checkpoint done\n\n");

    // 8. Статистика
    wal_print_stats(wal);

    // 9. Закрытие
    wal_close(wal);
    printf("\n[OK] WAL closed\n");

    // 10. Открываем заново — проверяем, что заголовок читается
    printf("\n=== REOPEN TEST ===\n");
    if (!wal_open(wal)) {
        fprintf(stderr, "reopen failed\n");
        wal_destroy(wal);
        return 1;
    }

    printf("[OK] WAL reopened\n");
    printf("     last_lsn         = %llu\n", (unsigned long long)wal->last_lsn);
    printf("     last_flushed_lsn = %llu\n", (unsigned long long)wal->last_flushed_lsn);
    printf("     total_bytes_flushed = %llu\n", (unsigned long long)wal->total_bytes_flushed);

    // 11. Recovery
    wal->wal_replay = test_replay;
    wal->replay_ctx = NULL;

    if (!wal_recovery(wal)) {
        fprintf(stderr, "wal_recovery failed\n");
        wal_destroy(wal);
        return 1;
    }
    printf("[OK] wal_recovery done\n");

    wal_print_stats(wal);

    wal_destroy(wal);

    printf("\n=== WAL TEST END ===\n");
    return 0;
}
#endif

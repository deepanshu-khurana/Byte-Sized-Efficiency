#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#ifndef MAP_ANONYMOUS
# ifdef MAP_ANON
#  define MAP_ANONYMOUS MAP_ANON
# endif
#endif

#define POOL_SIZE       (1024 * 1024) // 1 MiB
#define MIN_BLOCK_SIZE  32             // Smallest block size
#define MAX_LEVEL       15             // log2(POOL_SIZE / MIN_BLOCK_SIZE)

void* buddy_malloc(size_t size);
void  buddy_free(void* ptr);

// Buddy block metadata structure
typedef struct BuddyBlock {
    struct BuddyBlock* next;
    int is_free;
    int level;  // block size level (0 = MIN_BLOCK_SIZE, 1=MIN_BLOCK_SIZE*2, ...)
} BuddyBlock;

static BuddyBlock* free_lists[MAX_LEVEL] = {NULL};
static void* pool_start = NULL;

typedef struct {
    void *ptr;
    size_t requested_size;
} UserBlock;

#define BLOCK_COUNT 128

// Initialize buddy allocator
void buddy_allocator_init() {
    pool_start = mmap(NULL, POOL_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pool_start == MAP_FAILED) {
        perror("mmap failed");
        exit(EXIT_FAILURE);
    }

    // Initialize metadata for every minimal block to avoid uninitialized garbage
    uintptr_t pool_base = (uintptr_t)pool_start;
    uintptr_t pool_end = pool_base + POOL_SIZE;
    for (uintptr_t addr = pool_base; addr < pool_end; addr += MIN_BLOCK_SIZE) {
        BuddyBlock* b = (BuddyBlock*)addr;
        b->next = NULL;
        b->level = -1;   // sentinel: not yet split/used
        b->is_free = 0;  // not free until explicitly added to free list
    }

    // Create the single large free block covering entire pool
    BuddyBlock* block = (BuddyBlock*)pool_start;
    block->next = NULL;
    block->level = MAX_LEVEL - 1;
    block->is_free = 1;
    free_lists[MAX_LEVEL - 1] = block;
}

// Round up to next power of two >= MIN_BLOCK_SIZE
size_t next_power_of_two(size_t size) {
    size_t v = MIN_BLOCK_SIZE;
    while (v < size && v < POOL_SIZE) v <<= 1;
    return v;
}

// Find buddy list level index for requested size
int find_level(size_t size) {
    int level = 0;
    size_t block_size = MIN_BLOCK_SIZE;
    while (block_size < size && level < MAX_LEVEL - 1) {
        block_size <<= 1;
        level++;
    }
    return level;
}

void allocate_block(UserBlock user_blocks[], size_t block_count) {
    int index;
    size_t size;

    printf("Enter index (0-%d): ", (int)block_count - 1);
    if (scanf("%d", &index) != 1) {
        while (getchar() != '\n'); // flush
        printf("Invalid input.\n");
        return;
    }

    if (index < 0 || index >= (int)block_count) {
        printf("Invalid index!\n");
        return;
    }
    if (user_blocks[index].ptr) {
        printf("Index already occupied. Free it first.\n");
        return;
    }
    printf("Enter size (max %zu): ", (size_t)POOL_SIZE);
    if (scanf("%zu", &size) != 1) {
        while (getchar() != '\n');
        printf("Invalid input.\n");
        return;
    }

    if (size == 0 || size > POOL_SIZE - sizeof(BuddyBlock)) {
        printf("Requested size invalid or too large.\n");
        return;
    }

    void* blk = buddy_malloc(size);
    if (blk) {
        user_blocks[index].ptr = blk;
        user_blocks[index].requested_size = size;
        printf("Block allocated at %p of size %zu bytes.\n", blk, (size_t) size);
    } else {
        printf("Allocation failed.\n");
    }
}

// Allocate memory using buddy system
void* buddy_malloc(size_t size) {
    // include metadata overhead
    size += sizeof(BuddyBlock);
    size_t alloc_size = next_power_of_two(size);
    if (alloc_size > POOL_SIZE) return NULL;

    int level = find_level(alloc_size);

    // Find suitable free block
    int l = level;
    while (l < MAX_LEVEL && !free_lists[l]) l++;
    if (l == MAX_LEVEL) return NULL;

    // Split larger blocks down to target level
    while (l > level) {
        BuddyBlock* block = free_lists[l];
        if (!block) return NULL; // should not happen
        free_lists[l] = block->next;

        size_t half_size = MIN_BLOCK_SIZE << (l - 1);
        BuddyBlock* buddy1 = block;
        BuddyBlock* buddy2 = (BuddyBlock*)((char*)block + half_size);

        // Initialize split buddies' metadata
        buddy1->level = l - 1;
        buddy1->is_free = 1;
        buddy1->next = buddy2;

        buddy2->level = l - 1;
        buddy2->is_free = 1;
        buddy2->next = free_lists[l - 1];
        free_lists[l - 1] = buddy1;

        l--;
    }

    // Allocate block at required level
    BuddyBlock* block = free_lists[level];
    if (!block) return NULL;
    free_lists[level] = block->next;
    block->is_free = 0;
    block->next = NULL;
    return (void*)(block + 1);
}

void free_block(UserBlock user_blocks[], size_t block_count) {
    int index;

    printf("Enter index to free (0-%d): ", (int)block_count - 1);
    if (scanf("%d", &index) != 1) {
        while (getchar() != '\n');
        printf("Invalid input.\n");
        return;
    }

    if (index < 0 || index >= (int)block_count || user_blocks[index].ptr == NULL) {
        printf("Invalid index or block not allocated.\n");
        return;
    }
    buddy_free(user_blocks[index].ptr);
    printf("Freed block at %p of size %zu bytes.\n", user_blocks[index].ptr, (size_t) user_blocks[index].requested_size);
    user_blocks[index].ptr = NULL;
    user_blocks[index].requested_size = 0;
}

// Free memory and coalesce buddies if possible
void buddy_free(void* ptr) {
    if (!ptr) return;

    BuddyBlock* block = (BuddyBlock*)ptr - 1;
    block->is_free = 1;
    int level = block->level;
    if (level < 0) {
        // Unknown level: can't free
        fprintf(stderr, "Error: trying to free a block with unknown level\n");
        return;
    }
    size_t block_size = MIN_BLOCK_SIZE << level;

    uintptr_t block_offset = (uintptr_t)block - (uintptr_t)pool_start;
    uintptr_t buddy_offset = block_offset ^ block_size;
    BuddyBlock* buddy = (BuddyBlock*)((char*)pool_start + buddy_offset);

    // Try to coalesce buddies at this level recursively
    while (level < MAX_LEVEL - 1 && buddy->is_free && buddy->level == level) {
        // Remove buddy from free list
        BuddyBlock** current = &free_lists[level];
        while (*current && *current != buddy) {
            current = &(*current)->next;
        }
        if (*current == buddy) {
            *current = buddy->next;
        } else {
            break;
        }

        // Determine the lower address block
        if ((uintptr_t)block > (uintptr_t)buddy)
            block = buddy;

        block->level++;
        level = block->level;

        // compute next buddy for this (now coalesced) block
        size_t new_block_size = MIN_BLOCK_SIZE << level;
        buddy = (BuddyBlock*)((char*)pool_start + (((uintptr_t)block - (uintptr_t)pool_start) ^ new_block_size));
    }

    block->next = free_lists[level];
    block->is_free = 1;
    free_lists[level] = block;
}

// Print allocator status & fragmentation
void allocator_print_stats(UserBlock user_blocks[], size_t block_count) {
    printf("\nAllocator Visualization:\n");
    printf("+------+------------------+--------+--------+\n");
    printf("|Level | Block Size (byte)|  Free  |  Used  |\n");
    printf("+------+------------------+--------+--------+\n");
    for (int i = 0; i < MAX_LEVEL; i++) {
        size_t block_size = MIN_BLOCK_SIZE << i;
        size_t free_blocks = 0;
        size_t used_blocks = 0;

        // Only count blocks on the free list for this level
        for (BuddyBlock *b = free_lists[i]; b; b = b->next)
            free_blocks++;

        // Count used blocks: iterate over the pool in block_size steps
        uintptr_t pool_base = (uintptr_t)pool_start;
        uintptr_t pool_end = pool_base + POOL_SIZE;
        for (uintptr_t addr = pool_base; addr + block_size <= pool_end; addr += block_size) {
            BuddyBlock* block = (BuddyBlock*)addr;
            // Only count if the block has been split/assigned to this level and allocated
            if (block->level == i && block->is_free == 0) {
                used_blocks++;
            }
        }

        printf("|%5d |%16zu |%7zu |%7zu |\n", i, block_size, free_blocks, used_blocks);
    }
    printf("+------+------------------+--------+--------+\n");
}

void list_allocated_blocks(UserBlock user_blocks[], size_t block_count) {
    printf("\nAllocated blocks:\n");
    printf("+-------+-------------------+-------+\n");
    printf("| Index | Pointer           | Size  |\n");
    printf("+-------+-------------------+-------+\n");
    for (size_t i = 0; i < block_count; ++i) {
        if (user_blocks[i].ptr)
            printf("| %5zu | %17p | %5zu |\n", i, user_blocks[i].ptr, user_blocks[i].requested_size);
    }
    printf("+-------+-------------------+-------+\n");
}

// Interactive menu for user visualization
void allocator_interactive_menu() {
    printf("\n=== Buddy System Memory Allocator Interactive Demo ===\n");
    printf("Memory pool: %zu bytes, Min block size: %d bytes\n", (size_t) POOL_SIZE, MIN_BLOCK_SIZE);

    UserBlock user_blocks[BLOCK_COUNT] = {0};
    const size_t block_count = 128;
    int running = 1;

    while (running) {
        printf("\nMenu:\n");
        printf("1. Allocate block\n");
        printf("2. Free block\n");
        printf("3. Show stats\n");
        printf("4. List allocated blocks\n");
        printf("5. Exit\n");
        printf("Choice: ");

        int choice = 0;
        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            printf("Invalid input.\n");
            continue;
        }

        switch (choice) {
            case 1:
                allocate_block(user_blocks, BLOCK_COUNT);
                break;
            case 2:
                free_block(user_blocks, BLOCK_COUNT);
                break;
            case 3:
                allocator_print_stats(user_blocks, BLOCK_COUNT);
                break;
            case 4:
                list_allocated_blocks(user_blocks, BLOCK_COUNT);
                break;
            case 5:
                running = 0;
                break;
            default:
                printf("Invalid choice.\n");
        }
    }
}

// Cleanup buddy allocator
void buddy_allocator_destroy() {
    if (pool_start) {
        munmap(pool_start, POOL_SIZE);
        pool_start = NULL;
        for (int i = 0; i < MAX_LEVEL; i++) {
            free_lists[i] = NULL;
        }
        printf("Buddy allocator destroyed.\n");
    }
}

int main() {
    buddy_allocator_init();
    allocator_interactive_menu();
    buddy_allocator_destroy();
    return 0;
}

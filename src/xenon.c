#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char ptr[32];
    size_t size;
    int allocated;
    int freed;
    int free_line;
    int alloc_line;
} Block;

typedef struct {
    Block *items;
    size_t len;
    size_t cap;
} BlockList;

typedef struct {
    int double_free;
    int invalid_free;
    int use_after_free;
    int out_of_bounds;
    int invalid_access;
} Findings;

static void block_list_push(BlockList *list, Block block) {
    if (list->len == list->cap) {
        size_t next_cap = list->cap == 0 ? 16 : list->cap * 2;
        Block *next = realloc(list->items, next_cap * sizeof(Block));
        if (next == NULL) {
            fprintf(stderr, "Out of memory while growing block list.\n");
            exit(1);
        }
        list->items = next;
        list->cap = next_cap;
    }
    list->items[list->len++] = block;
}

static Block *find_latest_block(BlockList *list, const char *ptr) {
    for (size_t i = list->len; i > 0; i--) {
        if (strcmp(list->items[i - 1].ptr, ptr) == 0) {
            return &list->items[i - 1];
        }
    }
    return NULL;
}

static int tokenize(char *line, char **tokens, int max_tokens) {
    int count = 0;
    char *tok = strtok(line, " \t\r\n");
    while (tok != NULL && count < max_tokens) {
        tokens[count++] = tok;
        tok = strtok(NULL, " \t\r\n");
    }
    return count;
}

static int parse_size(const char *s, size_t *out) {
    char *end = NULL;
    unsigned long long value = strtoull(s, &end, 10);
    if (end == s || *end != '\0') {
        return 0;
    }
    *out = (size_t)value;
    return 1;
}

static int parse_trace(const char *path, BlockList *blocks, Findings *findings) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        perror(path);
        return 0;
    }

    char buf[256];
    int line_no = 0;

    while (fgets(buf, sizeof(buf), f) != NULL) {
        line_no++;

        char *p = buf;
        while (isspace((unsigned char)*p)) {
            p++;
        }
        if (*p == '\0' || *p == '#') {
            continue;
        }

        char *tokens[6] = {0};
        int n = tokenize(p, tokens, 6);
        if (n < 2) {
            fprintf(stderr, "Ignoring malformed line %d\n", line_no);
            continue;
        }

        const char *op = tokens[0];
        const char *ptr = tokens[1];

        if (strcmp(op, "alloc") == 0) {
            if (n < 3) {
                fprintf(stderr, "alloc requires size at line %d\n", line_no);
                continue;
            }
            size_t size = 0;
            if (!parse_size(tokens[2], &size)) {
                fprintf(stderr, "invalid alloc size at line %d\n", line_no);
                continue;
            }
            Block b;
            memset(&b, 0, sizeof(b));
            strncpy(b.ptr, ptr, sizeof(b.ptr) - 1);
            b.size = size;
            b.allocated = 1;
            b.freed = 0;
            b.alloc_line = line_no;
            block_list_push(blocks, b);
            continue;
        }

        Block *block = find_latest_block(blocks, ptr);

        if (strcmp(op, "free") == 0) {
            if (block == NULL) {
                findings->invalid_free++;
                printf("[line %d] invalid free of unknown pointer %s\n", line_no, ptr);
                continue;
            }
            if (block->freed) {
                findings->double_free++;
                printf("[line %d] double free on %s (already freed at line %d)\n", line_no, ptr, block->free_line);
                continue;
            }
            block->freed = 1;
            block->free_line = line_no;
            continue;
        }

        if (strcmp(op, "write") == 0 || strcmp(op, "read") == 0) {
            if (n < 4) {
                fprintf(stderr, "%s requires offset and length at line %d\n", op, line_no);
                continue;
            }
            size_t offset = 0;
            size_t len = 0;
            if (!parse_size(tokens[2], &offset) || !parse_size(tokens[3], &len)) {
                fprintf(stderr, "invalid access dimensions at line %d\n", line_no);
                continue;
            }

            if (block == NULL) {
                findings->invalid_access++;
                printf("[line %d] %s to unknown pointer %s\n", line_no, op, ptr);
                continue;
            }
            if (block->freed) {
                findings->use_after_free++;
                printf("[line %d] %s after free on %s (freed at line %d)\n", line_no, op, ptr, block->free_line);
                continue;
            }
            if (offset + len > block->size) {
                findings->out_of_bounds++;
                printf("[line %d] out-of-bounds %s on %s: offset=%zu len=%zu size=%zu\n",
                       line_no, op, ptr, offset, len, block->size);
                continue;
            }
            continue;
        }

        fprintf(stderr, "Unknown operation '%s' at line %d\n", op, line_no);
    }

    fclose(f);
    return 1;
}

static int count_leaks(const BlockList *blocks) {
    int leaks = 0;
    for (size_t i = 0; i < blocks->len; i++) {
        if (blocks->items[i].allocated && !blocks->items[i].freed) {
            leaks++;
        }
    }
    return leaks;
}

static void print_leaks(const BlockList *blocks) {
    for (size_t i = 0; i < blocks->len; i++) {
        const Block *b = &blocks->items[i];
        if (b->allocated && !b->freed) {
            printf("LEAK ptr=%s size=%zu allocated_at=%d\n", b->ptr, b->size, b->alloc_line);
        }
    }
}

static void usage(const char *argv0) {
    printf("xenon - Memory Poison/Leak Visualizer (trace analyzer)\n\n");
    printf("Usage:\n");
    printf("  %s analyze <trace_file>\n\n", argv0);
    printf("Trace format:\n");
    printf("  alloc <ptr> <size>\n");
    printf("  free <ptr>\n");
    printf("  write <ptr> <offset> <len>\n");
    printf("  read  <ptr> <offset> <len>\n");
}

int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "analyze") != 0) {
        usage(argv[0]);
        return 1;
    }

    BlockList blocks = {0};
    Findings findings = {0};

    if (!parse_trace(argv[2], &blocks, &findings)) {
        free(blocks.items);
        return 1;
    }

    int leaks = count_leaks(&blocks);

    printf("\n=== Xenon Analysis Summary ===\n");
    printf("double_free: %d\n", findings.double_free);
    printf("invalid_free: %d\n", findings.invalid_free);
    printf("use_after_free: %d\n", findings.use_after_free);
    printf("out_of_bounds: %d\n", findings.out_of_bounds);
    printf("invalid_access: %d\n", findings.invalid_access);
    printf("leaks: %d\n", leaks);

    if (leaks > 0) {
        printf("\n--- Leaked Blocks ---\n");
        print_leaks(&blocks);
    }

    free(blocks.items);

    int issue_count = findings.double_free + findings.invalid_free + findings.use_after_free + findings.out_of_bounds + findings.invalid_access + leaks;
    return issue_count == 0 ? 0 : 2;
}

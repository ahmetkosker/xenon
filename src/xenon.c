#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    PTR_CAP = 64,
    TOK_CAP = 8,
};

typedef struct {
    char ptr[PTR_CAP];
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
    int overwritten_alloc;
} Findings;

typedef struct {
    int json;
} Options;

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
    if (end == s || *end != '\0' || value > SIZE_MAX) {
        return 0;
    }
    *out = (size_t)value;
    return 1;
}

static void print_event(const Options *opt, int line_no, const char *message) {
    if (opt->json) {
        return;
    }
    printf("[line %d] %s\n", line_no, message);
}

static int parse_trace(const char *path, const Options *opt, BlockList *blocks, Findings *findings) {
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

        char *tokens[TOK_CAP] = {0};
        int n = tokenize(p, tokens, TOK_CAP);
        if (n < 2) {
            fprintf(stderr, "Ignoring malformed line %d\n", line_no);
            continue;
        }

        const char *op = tokens[0];
        const char *ptr = tokens[1];
        if (strlen(ptr) >= PTR_CAP) {
            fprintf(stderr, "pointer token too long at line %d\n", line_no);
            continue;
        }

        Block *block = find_latest_block(blocks, ptr);

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
            if (block != NULL && !block->freed) {
                findings->overwritten_alloc++;
                char msg[160];
                snprintf(msg, sizeof(msg),
                         "overwritten allocation on %s (previous alloc at line %d not freed)",
                         ptr, block->alloc_line);
                print_event(opt, line_no, msg);
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

        if (strcmp(op, "free") == 0) {
            if (block == NULL) {
                findings->invalid_free++;
                char msg[128];
                snprintf(msg, sizeof(msg), "invalid free of unknown pointer %s", ptr);
                print_event(opt, line_no, msg);
                continue;
            }
            if (block->freed) {
                findings->double_free++;
                char msg[128];
                snprintf(msg, sizeof(msg), "double free on %s (already freed at line %d)", ptr, block->free_line);
                print_event(opt, line_no, msg);
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
                char msg[128];
                snprintf(msg, sizeof(msg), "%s to unknown pointer %s", op, ptr);
                print_event(opt, line_no, msg);
                continue;
            }
            if (block->freed) {
                findings->use_after_free++;
                char msg[160];
                snprintf(msg, sizeof(msg), "%s after free on %s (freed at line %d)", op, ptr, block->free_line);
                print_event(opt, line_no, msg);
                continue;
            }
            if (offset > block->size || len > block->size - offset) {
                findings->out_of_bounds++;
                char msg[180];
                snprintf(msg, sizeof(msg), "out-of-bounds %s on %s: offset=%zu len=%zu size=%zu",
                         op, ptr, offset, len, block->size);
                print_event(opt, line_no, msg);
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

static void print_leaks(const Options *opt, const BlockList *blocks) {
    size_t leak_count = 0;
    size_t emitted = 0;

    for (size_t i = 0; i < blocks->len; i++) {
        const Block *b = &blocks->items[i];
        if (b->allocated && !b->freed) {
            leak_count++;
        }
    }

    for (size_t i = 0; i < blocks->len; i++) {
        const Block *b = &blocks->items[i];
        if (b->allocated && !b->freed) {
            emitted++;
            if (opt->json) {
                printf("      {\"ptr\":\"%s\",\"size\":%zu,\"allocated_at\":%d}%s\n",
                       b->ptr, b->size, b->alloc_line,
                       emitted == leak_count ? "" : ",");
            } else {
                printf("LEAK ptr=%s size=%zu allocated_at=%d\n", b->ptr, b->size, b->alloc_line);
            }
        }
    }
}

static int print_summary(const Options *opt, const BlockList *blocks, const Findings *findings) {
    int leaks = count_leaks(blocks);
    int issue_count = findings->double_free + findings->invalid_free + findings->use_after_free +
                      findings->out_of_bounds + findings->invalid_access + findings->overwritten_alloc + leaks;

    if (opt->json) {
        printf("{\n");
        printf("  \"double_free\": %d,\n", findings->double_free);
        printf("  \"invalid_free\": %d,\n", findings->invalid_free);
        printf("  \"use_after_free\": %d,\n", findings->use_after_free);
        printf("  \"out_of_bounds\": %d,\n", findings->out_of_bounds);
        printf("  \"invalid_access\": %d,\n", findings->invalid_access);
        printf("  \"overwritten_alloc\": %d,\n", findings->overwritten_alloc);
        printf("  \"leaks\": %d,\n", leaks);
        printf("  \"leaked_blocks\": [\n");
        print_leaks(opt, blocks);
        printf("  ]\n");
        printf("}\n");
    } else {
        printf("\n=== Xenon Analysis Summary ===\n");
        printf("double_free: %d\n", findings->double_free);
        printf("invalid_free: %d\n", findings->invalid_free);
        printf("use_after_free: %d\n", findings->use_after_free);
        printf("out_of_bounds: %d\n", findings->out_of_bounds);
        printf("invalid_access: %d\n", findings->invalid_access);
        printf("overwritten_alloc: %d\n", findings->overwritten_alloc);
        printf("leaks: %d\n", leaks);

        if (leaks > 0) {
            printf("\n--- Leaked Blocks ---\n");
            print_leaks(opt, blocks);
        }
    }

    return issue_count;
}

static void usage(const char *argv0) {
    printf("xenon - Memory Poison/Leak Visualizer (trace analyzer)\n\n");
    printf("Usage:\n");
    printf("  %s analyze <trace_file> [--json]\n\n", argv0);
    printf("Trace format:\n");
    printf("  alloc <ptr> <size>\n");
    printf("  free <ptr>\n");
    printf("  write <ptr> <offset> <len>\n");
    printf("  read  <ptr> <offset> <len>\n");
}

static int parse_options(int argc, char **argv, Options *opt) {
    if (argc != 3 && argc != 4) {
        return 0;
    }
    if (strcmp(argv[1], "analyze") != 0) {
        return 0;
    }
    if (argc == 4) {
        if (strcmp(argv[3], "--json") == 0) {
            opt->json = 1;
        } else {
            return 0;
        }
    }
    return 1;
}

int main(int argc, char **argv) {
    Options opt = {0};
    if (!parse_options(argc, argv, &opt)) {
        usage(argv[0]);
        return 1;
    }

    BlockList blocks = {0};
    Findings findings = {0};

    if (!parse_trace(argv[2], &opt, &blocks, &findings)) {
        free(blocks.items);
        return 1;
    }

    int issue_count = print_summary(&opt, &blocks, &findings);

    free(blocks.items);
    return issue_count == 0 ? 0 : 2;
}

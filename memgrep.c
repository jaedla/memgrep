#define _LARGEFILE64_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct map;
typedef struct map map_t;
struct map {
  size_t start;
  size_t end;
  char flags;
  char *file;
  map_t *next;
};

#define FLAG_R 1
#define FLAG_W 2
#define FLAG_X 4
#define FLAG_P 8

int pid;
unsigned char *hex;
size_t hexlen;
map_t *maps;

void usage() {
  printf("usage: memgrep pid hex\nhex example: 68656c6c6f0a\n");
  exit(1);
}

size_t parse_hex_digit(char d) {
  if (d >= '0' && d <= '9') {
    return d - '0';
  } else if (d >= 'a' && d <= 'f') {
    return d - 'a' + 10;
  }
  printf("Invalid hex digit: %c\n", d);
  exit(1);
}

int parse_hex(char *str, unsigned char **hex, size_t *length) {
  size_t len = strlen(str);
  if (len % 2) {
    printf("Hex length not divisible by 2\n");
    exit(1);
  }
  len >>= 1;
  unsigned char *buf = malloc(len);
  for (size_t i = 0; i < len; i++) {
    size_t d1 = parse_hex_digit(*str++);
    size_t d2 = parse_hex_digit(*str++);
    buf[i] = (d1 << 4) + d2;
  }
  *hex = buf;
  *length = len;
}

void parse_args(int argc, char **argv) {
  if (argc != 3) {
    usage();
  }
  if (sscanf(argv[1], "%d", &pid) != 1) {
    usage();
  }
  parse_hex(argv[2], &hex, &hexlen);
}

int open_proc_file(char *file) {
  char filename[128];
  snprintf(filename, sizeof(filename), "/proc/%d/%s", pid, file);
  int fd = open(filename, O_RDONLY);
  if (fd == -1) {
    printf("Failed to open %s\n", filename);
    exit(0);
  }
  return fd;
}

size_t read_fd(char *file, int fd, unsigned char *buf, size_t size) {
  size_t total = 0;
  while (1) {
    ssize_t ret = read(fd, buf, size);
    if (ret < 0) {
      printf("Error reading %s\n", file);
      exit(1);
    }
    if (!ret) {
      break;
    }
    total += ret;
    buf += ret;
    size -= ret;
    if (!size) {
      break;
    }
  }
  return total;
}

void read_maps() {
  map_t **next = &maps;
  int fd = open_proc_file("maps");
  size_t bufsize = 4096;
  unsigned char *buf = malloc(bufsize);
  size_t filled = 0;
  while (1) {
    size_t read = read_fd("maps", fd, buf + filled, bufsize - filled);
    if (!read) {
      if (filled) {
        printf("Unexpected end of maps\n");
        exit(1);
      }
      break;
    }
    filled += read;
    while (1) {
      size_t nl;
      for (nl = 0; nl < filled; nl++) {
        if (buf[nl] == '\n') {
          buf[nl] = '\0';
          break;
        }
      }
      if (nl == filled) {
        if (filled == bufsize) {
          bufsize <<= 1;
          buf = realloc(buf, bufsize);
        }
        break;
      }
      size_t start, end;
      char r, w, x, p;
      size_t unused1, unused2, unused3, unused4;
      int consumed;
      char *line = (char *)buf;
      if (sscanf(buf, "%lx-%lx %c%c%c%c %lx %lx:%lx %ld%n",
          &start, &end, &r, &w, &x, &p, &unused1, &unused2, &unused3, &unused4, &consumed) != 10) {
        printf("Failed to parse maps line: %s\n", line);
        exit(1);
      }
      char *file = line + consumed;
      while (*file == ' ') {
        file++;
      }
      char flags = 0;
      if (r == 'r') {
        flags |= FLAG_R;
      }
      if (w == 'w') {
        flags |= FLAG_W;
      }
      if (x == 'x') {
        flags |= FLAG_X;
      }
      if (p == 'p') {
        flags |= FLAG_P;
      }
      map_t *map = malloc(sizeof(map_t));
      map->start = start;
      map->end = end;
      map->flags = flags;
      map->file = strdup(file);
      map->next = NULL;
      *next = map;
      next = &map->next;
      memmove(buf, buf + nl + 1, filled - (nl + 1));
      filled -= nl + 1;
    }
  }
  free(buf);
}

void grep() {
  map_t *map = maps;
  int fd = open_proc_file("mem");
  while (map) {
    if ((map->flags & FLAG_R) && strcmp(map->file, "[vvar]")) {
      size_t size = map->end - map->start;
      unsigned char *chunk = malloc(size);
      off64_t ret = lseek64(fd, map->start, SEEK_SET);
      if (ret == (off64_t)-1) {
        printf("Failed to seek mem file\n");
        exit(1);
      }
      size_t read = read_fd("mem", fd, chunk, size);
      if (read != size) {
        printf("Failed to read mapped memory chunk\n");
        exit(1);
      }
      for (size_t i = 0; (i + hexlen) <= size; i++) {
        size_t j;
        for (j = 0; j < hexlen; j++) {
          if (chunk[i + j] != hex[j]) {
            break;
          }
        }
        if (j == hexlen) {
          printf("0x%016lx\n", map->start + i);
        }
      }
      free(chunk);
    }
    map = map->next;
  }
}

int main(int argc, char **argv) {
  parse_args(argc, argv);
  read_maps();
  grep();
}

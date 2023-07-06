#ifndef MAP_H
#define MAP_H

#include <stdio.h>
#include <string.h>

#define MAX_SIZE 100

typedef struct Map Map;
typedef struct MapEntry MapEntry;

struct MapEntry{
    char key[MAX_SIZE];
    char value[MAX_SIZE];
};

struct Map{
    MapEntry entries[MAX_SIZE];
    int size;
};

void add_to_map(Map *map, const char *key, const char* value);
char* get_from_map(Map *map, const char *key);
char * get_value_by_index(Map *map, int index, int count);
int get_count(Map *map);
#endif

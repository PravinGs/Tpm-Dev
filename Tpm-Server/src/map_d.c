#include "map_d.h"
#include <stdlib.h>

/*static void init_map(Map *map) {
    map->size = 0;
}
*/
void add_to_map(Map *map, const char *key, const char* value) {
    if (map->size >= MAX_SIZE) {
        printf("Error: map is full\n");
        return;
    }
    MapEntry entry;
    strcpy(entry.key, key);
    //entry.value = value;
    strcpy(entry.value, value);
    map->entries[map->size] = entry;
    map->size++;
}

char * get_value_by_index(Map *map, int index, int count)
{
    if ((map->size == 0) || (index > count))
    {
         return NULL;
    }
    return map->entries[(index+3)].value;
}

char* get_from_map(Map *map, const char *key) {
    for (int i = 0; i < map->size; i++) {
        if (strcmp(map->entries[i].key, key) == 0) {
            return map->entries[i].value;
        }
    }
    printf("Error: key not found\n");
    return NULL;
}

int get_count(Map *map)
{
    if (map == NULL) {return 0;}
    return atoi(map->entries[2].value);
}

/*int main() {
    Map my_map;
    init_map(&my_map);
    add_to_map(&my_map, "foo", 1);
    add_to_map(&my_map, "bar", 2);
    int result = get_from_map(&my_map, "foo");
    printf("%d\n", result);
    result = get_from_map(&my_map, "baz");
    printf("%d\n", result);
    return 0;
}*/

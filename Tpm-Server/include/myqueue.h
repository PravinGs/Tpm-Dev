#ifndef MYQUEUE_H
#define MYQUEUE_H
#include <openssl/ssl.h>

typedef struct node node_t;

struct node {
    struct node* next;
    SSL *ssl;
};

SSL* dequeue();
void enqueue(SSL *ssl);



#endif

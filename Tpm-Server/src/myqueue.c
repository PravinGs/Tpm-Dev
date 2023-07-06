#include "myqueue.h"
#include <stdlib.h>


node_t * head = NULL;
node_t * tail = NULL;

void enqueue(SSL *ssl)
{
    node_t *newnode = malloc(sizeof(node_t));
    newnode->ssl = ssl;
    newnode->next = NULL;

    if (tail == NULL)
    {
        head = newnode;
    }
    else
    {
        tail->next = newnode;
    }
    tail = newnode;
}

SSL* dequeue()
{
    if (head == NULL)
    {
        return NULL;
    }
    else
    {
        SSL *result = head->ssl;
        node_t *temp = head;
        head = head->next;
        if (head == NULL) {tail = NULL;}
        free(temp);
        return result;
    }
}

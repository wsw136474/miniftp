#include "hash.h"
#include "common.h"
#include <memory.h>
///链地址法
typedef struct hash_node
{
    void *key;///关键码
    void *value;///数据项
    struct hash_node *prev;
    struct hash_node *next;
}hash_node_t;

struct hash
{
  unsigned  int buckets;///表长度
  hashfunc_t hash_func;///hashfunc_t 函数指针
  hash_node_t**  nodes;///表首地址
};

///创建hash表,返回hash表指针,传入哈希函数
hash_t* hash_alloc(unsigned int buckets,hashfunc_t hash_func)
{
    hash_t *hash=(hash_t*)malloc(sizeof(hash_t));
    //assert(hash!=NULL);
    hash->buckets=buckets;
    hash->hash_func=hash_func;
    ///保存buckets个指针，每个指针的大小
    int size=buckets*sizeof(hash_node_t *);
    ///分配内存
    hash->nodes=(hash_node_t **)malloc(size);
    ///所有内存清零
    memset(hash->nodes,0,size);
    return hash;
}
///往哈希表中添加一项Key
void hash_add_entry(hash_t* hash,void* key,unsigned int key_size,void* value,unsigned int value_size)
{
    if(hash_lookup_entry(hash,key,key_size))
    {
        fprintf(stderr,"duplicate hash key\n");
        return;
    }
    ///申请一个新结点
    hash_node_t *node=malloc(sizeof(hash_node_t));
    node->prev=NULL;
    node->next=NULL;
    node->key=malloc(key_size);
    memcpy(node->key,key,key_size);

    node->value=malloc(value_size);
    memcpy(node->value,value,value_size);
    ///头插法
    hash_node_t **bucket=hash_get_bucket(hash,key);
    if(*bucket==NULL)
    {
        *bucket=node;
    }
    else
    {
        ///将结点插到链表的头部
        node->next=*bucket;
        (*bucket)->prev=node;
        *bucket=node;
    }
}
///获取桶地址，桶内容指向hash_node_t链表，桶地址就是指针的指针
hash_node_t** hash_get_bucket(hash_t *hash,void *key)
{
    ///首先得到桶号
    unsigned int bucket=hash->hash_func(hash->buckets,key);
    ///不会超过hash->buckets
    if(bucket>=hash->buckets){
        fprintf(stderr,"bad bucket lookup\n");
        exit(EXIT_FAILURE);
    }
    return &(hash->nodes[bucket]);
}
///根据key获取哈希表中的一个结点
hash_node_t* hash_get_node_by_key(hash_t *hash,void* key,unsigned int key_size)
{
    hash_node_t** bucket=hash_get_bucket(hash,key);
    hash_node_t *node=*bucket;
    if(node==NULL)
        return NULL;
    while(node!=NULL && memcmp(node->key,key,key_size)!=0)
        node=node->next;
    return node;
}
///在哈希表中查找.给定关键码，找到所对应的数据项
void* hash_lookup_entry(hash_t *hash,void* key,unsigned int key_size)
{
///查找结点
    hash_node_t *node=hash_get_node_by_key(hash,key,key_size);
    if(node==NULL)
        return NULL;
///返回结点的数据项
    return node->value;
}

///从哈希表中删除一项，释放一个结点
void hash_free_entry(hash_t *hash,void *key,unsigned int key_size)
{
    hash_node_t *node=hash_get_node_by_key(hash,key,key_size);
    if(node==NULL)
    {
        return ;
    }
    free(node->prev);
    free(node->value);
    if(node->prev)
    {
        node->prev->next=node->next;
    }
    else
    {
        hash_node_t **bucket=hash_get_bucket(hash,key);
        *bucket=node->next;
    }
    if(node->next)
    {
        node->next->prev=node->prev;
    }
    free(node);
}









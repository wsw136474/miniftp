#ifndef  _HASH_H_
#define  _HASH_H_
typedef struct hash  hash_t;
typedef struct hash_node  hash_node_t;
///函数指针，传递进来哈希函数
typedef unsigned int (*hashfunc_t)(unsigned int ,void*);
///创建hash表,返回hash表指针,第一个参数是表的长度，第二个参数是哈希函数
hash_t* hash_alloc(unsigned int buckets,hashfunc_t hash_func);
///在哈希表中查找，第二个参数是关键码，第三个参数是关键码的长度
void* hash_lookup_entry(hash_t *hash,void* key,unsigned int key_size);
///删除一项
void hash_free_entry(hash_t *hash,void *key,unsigned int key_size);
///往哈希表中添加一项，第四个参数是要插入的数据项
void hash_add_entry(hash_t* hash,void* key,unsigned int key_size,void *value,unsigned int value_size);
///获取桶地址
hash_node_t** hash_get_bucket(hash_t *hash,void *key);
///根据key获取哈希表中的一个结点
hash_node_t* hash_get_node_by_key(hash_t *hash,void* key,unsigned int key_size);
#endif // _HASH_H_

//开发环境 linux kernel 3.13.0-43
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>//for ip header

#define HASH_MAP_SIZE 760000

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("muto");

typedef struct HashNode {
    unsigned int key;
    unsigned int val;
} HashNode;

typedef struct HashMap {
    unsigned int size;
    HashNode** storage;
} HashMap;

HashMap* hash_create(int size);
void hash_destroy(HashMap* hashMap);
void hash_set(HashMap* hashMap, int key, int value);
HashNode* hash_get(HashMap* hashMap, int key);

HashMap* hash_create(int size){
    HashMap* hashMap = malloc(sizeof(HashMap));
    hashMap->size = size;
    hashMap->storage = calloc(size, sizeof(HashNode*));
    return hashMap;
}

void hash_destroy(HashMap* hashMap) {
    for(int i=0; i < hashMap->size; i++) {
        HashNode *node;
        if((node = hashMap->storage[i])) {
            free(node);
        }
    }
    free(hashMap->storage);
    free(hashMap);
}

void hash_set(HashMap *hashMap, int key, int value) {
    int hash = abs(key) % hashMap->size;
    HashNode* node;
    while ((node = hashMap->storage[hash])) {
        if (hash < hashMap->size - 1) {
            hash++;
        } else {
            hash = 0;
        }
    }
    node = malloc(sizeof(HashNode));
    node->key = key;
    node->val = value;
    hashMap->storage[hash] = node;
}

HashNode* hash_get(HashMap *hashMap, int key) {
    int hash = abs(key) % hashMap->size;
    HashNode* node;
    while ((node = hashMap->storage[hash])) {
        if (node->key == key) {
            return node;
        }
        if (hash < hashMap->size - 1) {
            hash++;
        } else {
            hash = 0;
        }
    }
    return NULL;
}

static struct nf_hook_ops nfho;
// static unsigned char *drop_if = "\x6f\xcc\xdb\xc6";//ip address big endian
static HashMap* hashMap;

//钩子函数，注意参数格式与开发环境源码树保持一致
unsigned int hook_func(const struct nf_hook_ops *ops, 
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
        HashNode* node;
        static unsigned int num = 0;
        hashMap = hash_create(HASH_MAP_SIZE);
        printk("Create hashMap, size %d\n",HASH_MAP_SIZE);

	struct iphdr *ip = ip_hdr(skb);//获取数据包的ip首部
	
	node = hash_get(hashMap,ip->saddr);
	if(!node)
	{
		printk("first meet: %d\n",(node->val));
		hash_set(hashMap, ip->saddr, ip->saddr);
		return NF_DROP;
	}
	else
	{
		return NF_ACCEPT;
	}
}

static int __init hook_init(void)
{
	nfho.hook = hook_func;//关联对应处理函数
	nfho.hooknum = NF_INET_PRE_ROUTING;//ipv4的第一个hook
	nfho.pf = PF_INET;//ipv4，所以用这个
	nfho.priority = NF_IP_PRI_FIRST;//优先级，第一顺位

	nf_register_hook(&nfho);//注册

	return 0;
}
static void __exit hook_exit(void)
{
	hash_destroy(hashMap);
	printk("Destroy hashMap\n");
	nf_unregister_hook(&nfho);//注销
}

module_init(hook_init);
module_exit(hook_exit);

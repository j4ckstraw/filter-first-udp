#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>//for ip header

#define INT_BITS sizeof(int)
#define SHIFT 5 // 2^5=32
#define MASK 0x1f // 2^5=32
#define MAX 4*1024*1024 //max number
#define SIZE (MAX/INT_BITS) 
static int bitmap[SIZE];
void set(unsigned int i){
    bitmap[(i >> SHIFT)%SIZE] |= 1 << (i & MASK);
}
bool test(unsigned int i){
    return bitmap[(i >> SHIFT)%SIZE] & (1 << (i & MASK));
}

void clear(unsigned int i){
    bitmap[(i >> SHIFT)%SIZE] & ~(1 << (i & MASK));
}

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("muto");

static struct nf_hook_ops nfho;

// static unsigned char *drop_if = "\x0a\xa3\x52\x58";//10.163.82.88

//钩子函数，注意参数格式与开发环境源码树保持一致
unsigned int hook_func(const struct nf_hook_ops *ops, 
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
    struct iphdr *ip = ip_hdr(skb);//获取数据包的ip首部
    if(ip->protocol == 17 && !test(ip->saddr)) //ip首部中的源端ip地址比对  udp protocol
    {
        printk("first meet ip saddr: %lu\n",ip->saddr)	;
        set(ip->saddr);
        return NF_DROP;
    }
    else if(ip->protocol == 17 && test(ip->saddr))
    {
        printk("meet ip saddr: %lu again\n",ip->saddr);
        return NF_ACCEPT;
    }
    else {
        return NF_ACCEPT;
    }
}


static int __init hook_init(void)
{
    nfho.hook = hook_func;//关联对应处理函数
    nfho.hooknum = NF_INET_PRE_ROUTING;//ipv4的第一个hook
    nfho.pf = PF_INET;//ipv4，所以用这个
    nfho.priority = NF_IP_PRI_FIRST;//优先级，第一顺位
    printk("Filter module installed.\n");
    nf_register_hook(&nfho);//注册

    return 0;
}
static void __exit hook_exit(void)
{
    nf_unregister_hook(&nfho);//注销
    printk("Filter module uninstalled.\n");
}

module_init(hook_init);
module_exit(hook_exit);

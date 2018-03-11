//开发环境 linux kernel 3.13.0-43
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>//for ip header

MODULE_LICENSE("Dual BSD/GPL");

static struct nf_hook_ops nfho;

// static unsigned char *drop_if = "\x77\x4b\xd9\x6d";//baidu的ip地址
static unsigned char *drop_if = "\x0a\xa3\x52\x58";//10.163.82.88

//钩子函数，注意参数格式与开发环境源码树保持一致
unsigned int hook_func(const struct nf_hook_ops *ops, 
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
    struct iphdr *ip = ip_hdr(skb);//获取数据包的ip首部
    if(ip->protocol == 17 && ip->saddr == *(unsigned int *)drop_if)//ip首部中的源端ip地址比对  udp protocol
    {
        //打印网址
        printk("Dropped packet from %d.%d.%d.%d\n",*drop_if,
                *(drop_if+1), *(drop_if+2),*(drop_if+3));
        return NF_DROP;
    }
    else
    {
        //打印网址，这里把长整型转换成点十格式
        unsigned char *p = (unsigned char *)&(ip->saddr);
        // printk("Allowed packet from %d.%d.%d.%d\n",p[0]&0xff,
        //        p[1]&0xff, p[2]&0xff, p[3]&0xff);
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
    nf_unregister_hook(&nfho);//注销
}

module_init(hook_init);
module_exit(hook_exit);

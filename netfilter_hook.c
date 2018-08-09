/* хедеры */
#include  <linux/kernel.h>
#include  <linux/module.h>
#include <linux/init.h>

//#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include  <linux/netfilter_ipv4.h>
#include  <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops nfho;

static unsigned int hook_func(void* priv, struct sk_buff *skb, const struct nf_hook_state* state)
{
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
    struct tcphdr *tcp_header;
    unsigned int dest, source;
    if (ip_header->protocol == 6) //TCP protocol
    {
        tcp_header= (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
        dest = ntohs(tcp_header->dest);
        source = ntohs(tcp_header->source);
        if(source == 80)
        {
            printk("TCP Source Port: %u, Dest Port: %u bloked\n", source, dest);
	    return NF_DROP;
        }
    }
    return NF_ACCEPT; //accept the packet
}
#define USER_BUF_PAGE 4096
static ssize_t f_proc_write(struct file *file, const char __user *ubuf,
				  size_t len, loff_t *offp)
{
	char *tmpbuf;

	if (len == 0)
		return 0;
	tmpbuf = memdup_user_nul(ubuf, len);
	printk("read %d bytes from userspace %s\n", (int)len,tmpbuf);

//	ret = ddebug_exec_queries(tmpbuf, NULL);
	kfree(tmpbuf);

	*offp += len;
	return len;
}
static const struct file_operations file_fops = {
    // .open = tasks_proc_open,
    // .read = seq_read,
    // .llseek = seq_lseek,
    // .release = single_release,
    // .write = seq_write
     .write = f_proc_write
    };
/* стандартная функция инициализации */
static int __init init_hook(void)
{
	int retval;
    nfho.hook = hook_func;
    nfho.hooknum  = NF_INET_PRE_ROUTING;
    //nfho.hooknum = NF_INET_LOCAL_IN;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    retval = nf_register_net_hook(&init_net, &nfho);
    printk("nf_register_net_hook returned %d\n", retval);

    if(proc_create("Tcp_block_port",0,NULL,&file_fops))
    	printk("Tcp_block_port created \n");
    return retval;
}
 
/* стандартная функция удаления модуля */
static void __exit cleanup_hook(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    printk("Unregistered the net hook.\n");
}

  MODULE_LICENSE("GPL"); 
  module_init(init_hook);
  module_exit(cleanup_hook); 

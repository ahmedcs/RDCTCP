#ifndef	RDCTCP_H
#define	RDCTCP_H

//---------------------------------------------
//include linux, net header files
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/inet.h>
#include <linux/netfilter_ipv4.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/fs.h>
#include <linux/random.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/vmalloc.h>
#include <linux/etherdevice.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/xfrm.h>
#include <asm/uaccess.h> /* copy_from/to_user */
#include <asm/byteorder.h>
#include <asm/unaligned.h>

//---------------------------------------------
//Structures
//Define structure of a TCP flow
//Flow is defined by 4-tuple <local_ip,remote_ip,local_port,remote_port> and its related information
struct Flow
{
	//4-tuple
    unsigned int local_ip;           //Local IP address
    unsigned int remote_ip;		 //Remote IP address
    unsigned short int local_port;  //Local TCP port
    unsigned short int remote_port;	//Remote TCP port
    //Extra Info
    unsigned char   local_eth[ETH_ALEN];       // local eth addr 
    unsigned char   remote_eth[ETH_ALEN];     // remote ether addr
     bool active;    
    const struct net_device *in, *out;    // In and Out net_device
    
    //RDCTCP related variables
     __u8 scaleval;  						//Receive window scaling factor, sent at connection setup
    __u8 rcvwnd;  						//Receive window scaling factor, sent at connection setup
    bool ecn_enabled;
	int dupacks;
    bool ce_state;
    unsigned long last_data_sent, last_data_recv, last_ack_sent, last_ack_recv, last_ecn_update, last_ecnecho_update, conn_time;
    ktime_t last_ecn_ktupdate, last_ecnecho_ktupdate;
    unsigned int total_data_sent,  total_data_recv, total_ack_sent, total_ack_recv;
    u64 in_pkt_count, ecn_pkt_count, in_byte_count, ecn_byte_count;
	u64 in_ack_count, ecnecho_ack_count, in_ackedbyte_count, ecnecho_byte_count;    
    u32 ecn_alpha, ecnecho_alpha;
    u32 init_ack, last_ack;
};


//---------------------------------------------
//Define global macros
#define MAX(a,b) ({ __typeof__ (a) _a = (a);  __typeof__ (b) _b = (b);  _a > _b ? _a : _b; })
#define MIN(a,b) ({ __typeof__ (a) _a = (a);  __typeof__ (b) _b = (b);  _a < _b ? _a : _b; })

/** Print format for a mac address. */
#define MACFMT "%02x:%02x:%02x:%02x:%02x:%02x"

#define MAC6TUPLE(_mac) (_mac)[0], (_mac)[1], (_mac)[2], (_mac)[3], (_mac)[4], (_mac)[5]
//---------------------------------------------
//Define global constants 
#define RDCTCP_MAX_ALPHA 1024U
#define MSS 1500
#define AVG_RTT 700
#define MIN_RWND (1 * MSS)
#define INIT_CWND (10 * MSS)
#define DUPACK_THRESH 3
#define SIZE (1<<13) //(HASH_RANGE * QUEUE_SIZE)
#define CHECK_INTERVAL_MS 1 // every 1 ms
#define FLOW_TIMEOUT_INTERVAL_MS 100 //(1<<3) //8ms
#define ECN_g 4 //shift by 4 = 1/6
#define ECNECHO_g 4 //shift by 4 = 1/6

#define RETRANS_SIZE 100
#define MAX_ACK_SIZE 120 //60 bytes for IP and 60 bytes for TCP

#define MIN_RTO 199000 // RTO in microseconds -((1<<8) - (1<<6))
#define RTT8 11

#define OPEN_TOS 240
#define CLOSE_TOS 248

#define MIN_RTT 300
#define DELAY_IN_US 500 //200000
#define MAX_INT ((1<<32)-1)

#define TCP_HDSIZE 20
#define TCP_OPT_SIZE 24

#define OUR_TTL 127

//microsecond to nanosecond
#define US_TO_NS(x)	(x * 1E3L)
//millisecond to nanosecond
#define MS_TO_NS(x)	(x * 1E6L)

//---------------------------------------------
//static variables

static struct Flow flist[SIZE];
//static struct Racklist head;
static unsigned int count = 0;

//Lock for global information (e.g. tokens)
static spinlock_t globalLock;

//other static variables
static u32 hash_seed;

//Outgoing packets POSTROUTING
static struct nf_hook_ops nfho_outgoing;
//incoming packets PRETROUTING
static struct nf_hook_ops nfho_incoming;

//---------------------------------------------
//Function declarations
static unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));
static unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));
void my_timer_callback(unsigned  long  data);

//-----------------------------------------------
//inline helper functions 
static inline void reset_rdctcpvar(struct Flow* f)
{
	f->scaleval=0;
	f->rcvwnd=0;
	f->ecn_enabled=false;
	f->active=false;
	f->ce_state=false;
	f->dupacks=0;
    f->last_data_sent= f->last_data_recv= f->last_ack_sent= f->last_ack_recv = f->last_ecn_update = f->last_ecnecho_update = f->conn_time = 0;
    f->total_data_sent= f->total_data_recv= f->total_ack_sent= f->total_ack_recv = 0;
    f->in_pkt_count=f->ecn_pkt_count=f->in_byte_count=f->ecn_byte_count=0;
    f->in_ack_count=f->ecnecho_ack_count=f->in_ackedbyte_count=f->ecnecho_byte_count=0;
    f->ecn_alpha=f->ecnecho_alpha=0;//RDCTCP_MAX_ALPHA;

}

static inline void reset_flow(struct Flow* f)
{
    f->active =false;
    f->local_port = f->remote_port = 0;
    f->local_ip = f->remote_ip = 0;
    strcpy(f->local_eth, "");
    strcpy(f->remote_eth, "");
    f->in=f->out=NULL;
    
	//reset RDCTCP related variables
    reset_rdctcpvar(f);
    
    //reset RACK related variables
    //reset_rackvar(f);
   
}



//---------------------------------------------
//Function definitions

//Function to calculate microsecond-granularity TCP timestamp value
static inline unsigned int get_now(void)
{
    //return (unsigned int)(ktime_to_ns(ktime_get())>>10);
    return (unsigned int)(ktime_to_us(ktime_get()));
}

//TCP flow ID information hash function
static inline unsigned int hash(struct Flow* f)
{
     static u32 flow[4];
     flow[0] = f->local_ip;
     flow[1] = f->local_port;
     flow[2] = f->remote_ip;
     flow[3] = f->remote_port;
     u32 temp_hash, temp_hash1, temp_hash2;

    temp_hash = jhash2(flow, 4, 0); //hash_seed);
    u32 hashval =  jhash_1word(temp_hash, hash_seed); //jhash_2words(temp_hash1, temp_hash2, hash_seed);
    int index = hashval & (SIZE-1);

    if(index>=SIZE || index<0)
    {
        //printk("INFO: %pI4 %d %pI4 %d, Log entry hash %u %u index %d\n", &f->local_ip, ntohs(f->local_port), &f->remote_ip, ntohs(f->remote_port), temp_hash, hashval, index);
    	return -1;
    }
    else
         return index;
}

//Extract incoming flow from ip_header, tcp_header
static inline struct Flow* extract_inflow(struct iphdr *ip_header, struct tcphdr *tcp_header)
{
		struct Flow tf;
		int k=-1;
		reset_flow(&tf);
	    //Note that: source and destination should be changed !!!
        tf.local_ip=ip_header->daddr;
        tf.remote_ip=ip_header->saddr;
        tf.local_port= tcp_header->dest;
        tf.remote_port= tcp_header->source;
        
        k=hash(&tf);
        if(k<0 || k>=SIZE)
        	return NULL;
        //copy flow information to the new flow
        if(!flist[k].active)
        	flist[k] = tf;
        return &flist[k];
}

//Extract outgoing flow from ip_header, tcp_header
static inline struct Flow* extract_outflow(struct iphdr *ip_header, struct tcphdr *tcp_header)
{
		struct Flow tf;
		int k=-1;
		
		reset_flow(&tf);
	    //Note that: source and destination should be changed !!!
        tf.local_ip=ip_header->saddr;
        tf.remote_ip=ip_header->daddr;
        tf.local_port= tcp_header->source;
        tf.remote_port= tcp_header->dest;
        
        k=hash(&tf);
        if(k<0 || k>=SIZE)
        	return NULL;
        //copy flow information to the new flow
        if(!flist[k].active)
        	flist[k] = tf;
        return &flist[k];
}

static inline bool flow_timeout(struct Flow* f, int flowTO)
{
		return !(f->last_ack_recv < flowTO &&  f->last_ack_sent < flowTO && f->last_data_recv < flowTO && f->last_data_sent < flowTO);
}

//not really used but can be used to hash the ETHERNET address if needed
static inline unsigned int hashstr(unsigned char *str)
{
    unsigned int hash = 5381;
    int c;

    while (c = *(str++))
    {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    return hash;
}

//enable Evil bit in the header
static inline void enable_evil(struct iphdr *iph)
{
    iph->frag_off|=htons(IP_CE);
    //Recalculate IP checksum
    iph->check=0;
    iph->check=ip_fast_csum(iph,iph->ihl);
}
//clear Evil bit in the header
static inline void clear_evil(struct iphdr *iph)
{
    iph->frag_off &= ~htons(IP_CE);
    //Recalculate IP checksum
    iph->check=0;
    iph->check=ip_fast_csum(iph,iph->ihl);
}
//enable ECT bit in the header
static inline void enable_ecn(struct iphdr *iph)
{
    ipv4_change_dsfield(iph, 0xff, iph->tos | INET_ECN_ECT_0);
}
//clear ECN bit in the header
static inline void clear_ecn(struct iphdr *iph)
{
    ipv4_change_dsfield(iph, 0xff, iph->tos & ~0x3);
}

//Function: set ECE (ECN Echo) of TCP header
static inline void set_ecnecho(struct tcphdr *tcp_header)
{
	__u8 oldece = tcp_header->ece;
	tcp_header->ece=1; 
	__sum16 oldcheck = tcp_header->check;
	csum_replace2(&tcp_header->check, oldece, tcp_header->ece);
}

//Function: clear ECE (ECN Echo) of TCP header
static inline void clear_ecnecho(struct tcphdr *tcp_header)
{
	__u8 oldece = tcp_header->ece;
	tcp_header->ece=0; 
	__sum16 oldcheck = tcp_header->check;
	csum_replace2(&tcp_header->check, oldece, tcp_header->ece);
}
/****************************************ECN*************************************************/

void store_scale(struct Flow * f, struct sk_buff *skb)
{
	struct tcp_options_received opt;
	tcp_clear_options(&opt);
	opt.wscale_ok = opt.snd_wscale = 0;
	tcp_parse_options(skb, &opt, 0, NULL);
	if(opt.wscale_ok)
	{
		 f->scaleval=opt.snd_wscale;
		 //printk(KERN_INFO "[WND_SCALE->%pI4:%pI4] New Scaling arrived : %d snd:%d rcv:%d \n", &f->local_ip, &f->remote_ip, opt.wscale_ok, opt.snd_wscale, opt.rcv_wscale);
	 }
	else
		 f->scaleval=0;
}

//Function: Add scale factor to Reserved bits of TCP header
/*static void add_scale(struct tcphdr *tcp_header, struct iphdr *ip_header )
{
	//__u8 oldres1 = tcp_header->res1;
	//tcp_header->res1 = 0; //htons(0);
	//__sum16 oldcheck = tcp_header->check;
	//csum_replace2(&tcp_header->check, oldres1, tcp_header->res1);
	printk(KERN_INFO "[WND_SCALE_RESET->%pI4:%pI4] RESET : old:%d:%d new:%d:%d \n", &ip_header->saddr, &ip_header->daddr, oldres1, oldcheck, tcp_header->res1, tcp_header->check);

}*/

//Function: modify the outgoing TCP header
static unsigned int tcp_modify_outgoing(struct Flow* flow, struct sk_buff *skb)
{
	struct iphdr *ip_header=NULL;         //IP  header structure
	struct tcphdr *tcp_header=NULL;       //TCP header structure
	int tcplen=0;                    //Length of TCP

	if (skb_linearize(skb)!= 0)
	{
		return 0;
	}

	ip_header=(struct iphdr *)skb_network_header(skb);
	tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);

	 /*if(scaleval > 0)
	 {
		tcp_header->res1 = scaleval;
		printk(KERN_INFO "[WND_SCALE_MOD->%pI4:%pI4]  Scaling : %d res:%d win:%d checksum:%d \n", &ip_header->saddr, &ip_header->daddr, scaleval, tcp_header->res1, tcp_header->window, tcp_header->check);
	 }*/

	/*//Modify TCP window
	tcp_header->window=htons(win*MSS);
	//TCP length=Total length - IP header length
	tcplen=skb->len-(ip_header->ihl<<2);
	tcp_header->check=0;
	tcp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr,
						tcplen, ip_header->protocol,
						csum_partial((char *)tcp_header, tcplen, 0));
	skb->ip_summed = CHECKSUM_UNNECESSARY;*/

	return 1;
}

//Function: Modify the incoming TCP header, modify RWND in received ACKs of TCP header
static unsigned int tcp_modify_incoming(struct Flow* flow, struct sk_buff *skb)
{
	struct iphdr *ip_header=NULL;         //IP  header structure
	struct tcphdr *tcp_header=NULL;       //TCP header structure
	int tcplen=0;                    //Length of TCP
	__be16 old_win, new_win, win_dec, old_check;

	if (skb_linearize(skb)!= 0)
	{
		return 0;
	}

	ip_header=(struct iphdr *)skb_network_header(skb);
	tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
	
	 if(flow->ecnecho_alpha > 15)
	 {
			//------------------- We need to handle cases when there is 3 DUPACK
			if(flow->dupacks >= DUPACK_THRESH)
				win_dec = (INIT_CWND * flow->ecnecho_alpha) >> 11U;
			else
				win_dec =(INIT_CWND * flow->ecnecho_alpha) >> 10U;
			new_win =  MAX(MIN_RWND, INIT_CWND - win_dec);	
			if(flow->scaleval > 0)
			{
				new_win = htons(new_win>>flow->scaleval);	
			}
			old_win = tcp_header->window;
			new_win =  MIN(old_win, new_win);	
			tcp_header->window = new_win;
			old_check = tcp_header->check;
			csum_replace2(&tcp_header->check, old_win, new_win);
			printk(KERN_INFO "[WND_MOD %pI4:%d->%pI4:%d]  Scaling : %d win:%d->%d checksum:%d->%d alpha:%d\n", &flow->remote_ip, htons(flow->remote_port), &flow->local_ip, htons(flow->local_port), flow->scaleval, 
								old_win, tcp_header->window, old_check, tcp_header->check, flow->ecnecho_alpha);
					
	}
	
	return 1;
}


static bool is_ecn(struct Flow* flow, const struct sk_buff *skb, struct iphdr *ip_header,  unsigned int payload_len)
{
    bool is_ecn_pkt = INET_ECN_is_ce(ip_header->tos);
    if(flow)
    {
        //spin_lock(&flow->lock);
        flow->in_pkt_count++;
        flow->in_byte_count += payload_len; //skb->len;
        if(is_ecn_pkt)
        {
            flow->ecn_pkt_count++;
            flow->ecn_byte_count += payload_len; //skb->len;
            //printk(KERN_INFO "[ISECN: ECN %pI4:%d->%pI4:%d] Ncount::%u->%u ECNcount:%u->%u\n", &flow->remote_ip, htons(flow->remote_port), &flow->local_ip, htons(flow->local_port),  flow->in_pkt_count,  flow->in_byte_count, flow->ecn_pkt_count, flow->ecn_byte_count);
        }
        //correct values for division or values that can be more than 1
        if(flow->in_pkt_count==0)
            flow->in_pkt_count=1;
        if(flow->in_pkt_count <  flow->ecn_pkt_count)
            flow->ecn_pkt_count = flow->in_pkt_count;
		
	//wait for 1 MSS before updating
    	//calculate ECN_alpha to indicate the level of congestion
	//if(jiffies - flow->last_ecn_update >= 1)
	ktime_t now_ktime=ktime_get();
	int delta_us = ktime_us_delta(now_ktime, flow->last_ecn_ktupdate);
	if(delta_us > AVG_RTT)
	{
		u32 old_alpha = flow->ecn_alpha;
		flow->ecn_alpha = min_not_zero(flow->ecn_alpha, flow->ecn_alpha - (flow->ecn_alpha >> ECN_g));
		if(flow->ecn_byte_count)
		{
					 u64 bytes_ecn = flow->ecn_byte_count;
					 bytes_ecn = flow->ecn_byte_count << (10-ECN_g);
					do_div(bytes_ecn, max(1U, flow->ecn_byte_count));
					flow->ecn_alpha  = MIN(flow->ecn_alpha + (u32)bytes_ecn, RDCTCP_MAX_ALPHA);
		}
		//flow->last_ecn_update = jiffies;
		flow->last_ecn_ktupdate = now_ktime;
	        flow->ecn_pkt_count = flow->ecn_byte_count =0;
	        flow->in_pkt_count = flow->in_byte_count = 0;	
	        //printk(KERN_INFO "[ISECN: ECN_ALPHA_UPDATE %pI4:%d->%pI4:%d] alpha:%d->%d\n", &flow->remote_ip, htons(flow->remote_port), &flow->local_ip, htons(flow->local_port), old_alpha, flow->ecn_alpha);
	}
        //spin_unlock(&flow->lock);

    }
    //printk("RFCTCP: Returning from is_ecn: %d \n", is_track_pkt);
    return is_ecn_pkt;
}


static bool is_ecnecho(struct Flow* flow, const struct sk_buff *skb, struct tcphdr *tcp_header)
{
    bool is_ecnecho_pkt = tcp_header->ece;
    u64 acked_bytes=0;
    if(flow->last_ack)
		acked_bytes = tcp_header->ack_seq - flow->last_ack;
	else
		return is_ecnecho_pkt;
    if(flow)
    {
        //spin_lock(&flow->lock);        
        flow->in_ack_count++;
		if(acked_bytes)
			flow->in_ackedbyte_count += acked_bytes ;
		else
			flow->in_ackedbyte_count += MSS ;
        if(is_ecnecho_pkt)
        {
            flow->ecnecho_ack_count++;
			if(acked_bytes)
				 flow->ecnecho_byte_count += acked_bytes;
			else
				flow->ecnecho_byte_count += MSS ;
			//printk(KERN_INFO "[ISECNCHO: ECNECHO %pI4:%d->%pI4:%d] Ncount::%u->%u ECEcount:%u->%u\n", &flow->remote_ip, flow->remote_port, &flow->local_ip, flow->local_port, flow->in_ack_count, flow->in_ackedbyte_count, flow->ecnecho_ack_count, flow->ecnecho_byte_count);
        }
        if(flow->in_ack_count==0)
            flow->in_ack_count=1;
        if(flow->in_ack_count <  flow->ecnecho_ack_count)
            flow->ecnecho_ack_count = flow->in_ack_count;
		
		//Wait for 1 RTT - to simpilfy we will wait for 1 ms
    		//calculate ECN_alpha to indicate the level of congestion
		//if(jiffies - flow->last_ecnecho_update >= 1)
	ktime_t now_ktime=ktime_get();
	int delta_us = ktime_us_delta(now_ktime, flow->last_ecnecho_ktupdate);
	if(delta_us > AVG_RTT)
	{
			u32 old_alpha = flow->ecnecho_alpha;
			flow->ecnecho_alpha = min_not_zero(flow->ecn_alpha, flow->ecnecho_alpha - (flow->ecnecho_alpha >> ECNECHO_g));
			if(flow->ecnecho_byte_count > 0)
			{
				u64 bytes_ecnecho = flow->ecnecho_byte_count;
				bytes_ecnecho = flow->ecnecho_byte_count << (10-ECNECHO_g);
				do_div(bytes_ecnecho, max(1U, flow->in_ackedbyte_count));
				flow->ecnecho_alpha  = MIN(flow->ecnecho_alpha + (u32)bytes_ecnecho, RDCTCP_MAX_ALPHA);
			}
			//flow->last_ecnecho_update = jiffies;
			flow->last_ecnecho_ktupdate = now_ktime;
			flow->ecnecho_ack_count = flow->ecnecho_byte_count =0;
			flow->in_ack_count = flow->in_ackedbyte_count = 0;
			//printk(KERN_INFO "[ISECNCHO: ECNECHO_ALPHA_UPDATE %pI4:%d->%pI4:%d]  alpha:%d->%d\n", &flow->remote_ip, flow->remote_port, &flow->local_ip, flow->local_port, old_alpha, flow->ecnecho_alpha);
		}
		
        //spin_unlock(&flow->lock);
    }
    //printk("RDCTCP: Returning from is_ecnecho: %d \n", is_track_pkt);
    return is_ecnecho_pkt;
}

#endif

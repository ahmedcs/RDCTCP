/*
 * RDCTCP - A Kernel Loadable module designed for implementing Receive Window based DCTCP.
 *
 *  Author: Ahmed Mohamed Abdelmoniem Sayed, <ahmedcs982@gmail.com, github:ahmedcs>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of CRAPL LICENCE avaliable at
 *    http://matt.might.net/articles/crapl/.
 *    http://matt.might.net/articles/crapl/CRAPL-LICENSE.txt
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *  See the CRAPL LICENSE for more details.
 *
 * Please READ carefully the attached README and LICENCE file with this software
 */

//include header file
#include "rdctcp.h"

 
//setup module description and license information
//MODULE_LICENSE("CRAPL");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ahmed Sayed ahmedcs982@gmail.com");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("Kernel module to perform DCTCP congestion control on RECEIVE WINDOW FIELD");

//Module parameters
static int port1=80;
static int port2=5001;
static int debug=0;
static int enable1=0;
static int flowTO=100;
//RACK
static int enable2=0;
static int rtoinms=1;
static int maxackthresh=0;

//---------------------------------------------
//Module variables settings (desc and access rights)
MODULE_PARM_DESC(debug, "DEBUG Enable, default  is disabled");
module_param(debug, int, 0644);

MODULE_PARM_DESC(enable1, "RDCTCP Enable1, default  is disabled");
module_param(enable1, int, 0644);

MODULE_PARM_DESC(port1, "TCP Port Number 1 (MICE) to perform RDCTCP, default is 80");
module_param(port1, int, 0644);

MODULE_PARM_DESC(port2, "TCP Port Number 2 (ELEPHANT) to perform RDCTCP, default is 5001");
module_param(port2, int, 0644);

MODULE_PARM_DESC(flowTO, "RDCTCP flow inactivity timeout, default is 100ms");
module_param(flowTO, int, 0644);

MODULE_PARM_DESC(enable2, "RDCTCP RACK Enable2, default is disabled");
module_param(enable2, int, 0644);

MODULE_PARM_DESC(rtoinms, "RDCTCP ACK RTO suited for data centers, default is 1 ms, max is 100ms");
module_param(rtoinms, int, 0644);

MODULE_PARM_DESC(maxackthresh, "MAX ACK sequence number to track within the module, default is 0 (infinite)");
module_param(maxackthresh, int, 0644);

//POSTROUTING for outgoing packets
static unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header=NULL;         //IP  header structure
	struct tcphdr *tcp_header=NULL;       //TCP header structure
	struct ethhdr *eth_header;  //Ethernet Header
	unsigned short int dst_port,src_port;     	  //TCP destination port
	unsigned long flags;
    unsigned int payload_len, opt_len;        //TCP payload length
    unsigned char * tcp_opt;
    struct Flow* f;
    int i,k;
    bool ecn_pkt, ecnecho_pkt;
	
	if (!skb && !in && !out && !enable1)
    		return NF_ACCEPT;
    		
	ip_header=(struct iphdr *)skb_network_header(skb);

	//The packet is not ip packet (e.g. ARP or others)
	if (!ip_header )
		return NF_ACCEPT;

	if(ip_header->protocol==IPPROTO_TCP) //TCP
	{
		tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
		
		if(!tcp_header)
			return NF_ACCEPT;

		//Get source and destination TCP port
		src_port=htons((unsigned short int) tcp_header->source);
		dst_port=htons((unsigned short int) tcp_header->dest);
		
		//Other TCP header information of interest
		payload_len= (unsigned int)ntohs(ip_header->tot_len)-(ip_header->ihl<<2)-(tcp_header->doff<<2);
        opt_len= (unsigned int)(tcp_header->doff<<2) - 20; // length of TCP options
        tcp_opt=(unsigned char*)tcp_header + 20;  //pointer to TCP options
        
		//We only use ICTCP to control incast traffic (tcp port 5001)
		if(src_port==port1 || dst_port==port1 || src_port==port2 || dst_port==port2)
		{
			f=extract_outflow(ip_header,tcp_header);
			
			if(!f)
				return NF_ACCEPT;
				
			//printk(KERN_INFO "[OUT: FLOW INFO %pI4:%d->%pI4:%d] Scaling : %d  ECT:%d \n", &f->remote_ip, htons(f->remote_port), &f->local_ip, htons(f->local_port), f->scaleval, f->ecn_enabled);
			//RESET flow if it timesout
			/*if(flow_timeout(f, flowTO))
					reset_flow(f);*/
			//f->ecn_enabled=INET_ECN_is_capable(ip_header->tos);// & INET_ECN_ECT_0) || (ip_header->tos & INET_ECN_ECT_1))
			if(tcp_header->syn) //&& !tcp_header->ack)
			{
				store_scale(f, skb);
				if(tcp_header->ack)
				{
					if(tcp_header->ece && tcp_header->cwr)
						f->ecn_enabled=true;
					f->active=true;
					f->conn_time=f->last_ecn_update=f->last_ecnecho_update=jiffies;
					f->last_ecn_ktupdate=f->last_ecnecho_ktupdate=ktime_get();
					f->last_ack = f->init_ack = tcp_header->ack_seq;
					printk(KERN_INFO "[OUT: SYNACK CONN_OPEN %pI4:%d->%pI4:%d]  Scaling : %d  \n", &ip_header->saddr, src_port, &ip_header->daddr, dst_port, f->scaleval);
					//memcpy(f->local_eth, eth_header->h_source, ETH_ALEN);
					//memcpy(f->remote_eth, eth_header->h_dest, ETH_ALEN);
				}
			}
			else if(f->active)
			{
				if(payload_len > 0)
				{
					f->last_data_sent = jiffies;
					f->total_data_sent++;
					//enable ECN on all outgoing packets if the flow is not enabling ECT
					if(!f->ecn_enabled)
                 		enable_ecn(ip_header);
                 	//printk(KERN_INFO "[OUT: ECTSET %pI4:%d->%pI4:%d]  ECN: %d\n", &ip_header->saddr, src_port, &ip_header->daddr, dst_port, ip_header->tos);

                 }
				if(tcp_header->ack)
				{
					/*__u8 scaleval;
					bool isok = find_scale(ip_header, &scaleval); //, tcp_header);
					if(isok)
					{
						tcp_modify_outgoing(skb, scaleval);
						//printk(KERN_INFO "[WND_SCALE_MOD->%pI4:%pI4]  Scaling : %d res:%d win:%d \n", &ip_header->saddr, &ip_header->daddr, scaleval, tcp_header->res1, tcp_header->window);
					}*/
					//int delta_us = ktime_us_delta(now_ktime, f->last_sent);
					f->last_ack_sent = jiffies;
					f->total_ack_sent++;
					if(f->ecn_pkt_count > 0)
					{
						set_ecnecho(tcp_header);
						f->ecn_pkt_count = MAX(0, f->ecn_pkt_count--);
						//printk(KERN_INFO "[OUT: ECNECHOSET %pI4:%d->%pI4:%d]  TCPECE: %d\n", &ip_header->saddr, src_port, &ip_header->daddr, dst_port, tcp_header->ece);
					}
				}
			}
			
		}

	}
	return NF_ACCEPT;
}

//PRETROUTING for incoming packets
static unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header=NULL;         //IP  header structure
	struct tcphdr *tcp_header=NULL;       //TCP header structure
	struct ethhdr *eth_header;  //Ethernet Header
	unsigned short int dst_port,src_port;     	  //TCP destination port
	unsigned long flags;
    unsigned int payload_len, opt_len;        //TCP payload length
    unsigned char * tcp_opt;
    struct Flow* f;
    int i,k;
	bool ecn_pkt=false, ecnecho_pkt=false;
	
	if (!skb && !in && !out && !enable1)
    		return NF_ACCEPT;
    		
	ip_header=(struct iphdr *)skb_network_header(skb);

	//The packet is not ip packet (e.g. ARP or others)
	if (!ip_header)
		return NF_ACCEPT;

	if(ip_header->protocol==IPPROTO_TCP) //TCP
	{
		tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
		
		if(!tcp_header)
			return NF_ACCEPT;

		//Get source and destination TCP port
		src_port=htons((unsigned short int) tcp_header->source);
		dst_port=htons((unsigned short int) tcp_header->dest);
		
		//Other TCP header information of interest
		payload_len= (unsigned int)ntohs(ip_header->tot_len)-(ip_header->ihl<<2)-(tcp_header->doff<<2);
        opt_len= (unsigned int)(tcp_header->doff<<2) - 20; // length of TCP options
        tcp_opt=(unsigned char*)tcp_header + 20;  //pointer to TCP options
        
		//We only use ICTCP to control incast traffic (tcp port 5001)
		if(src_port==port1 || dst_port==port1 || src_port==port2 || dst_port==port2)
		{
			f=extract_inflow(ip_header,tcp_header);
			if(!f)
				return NF_ACCEPT;
			//printk(KERN_INFO "[IN: FLOW INFO %pI4:%d->%pI4:%d] Scaling : %d  ECT:%d \n", &f->remote_ip, htons(f->remote_port), &f->local_ip, htons(f->local_port), f->scaleval, f->ecn_enabled);
			/*if(flow_timeout(f, flowTO))
					reset_flow(f);*/
			//f->ecn_enabled=INET_ECN_is_capable(ip_header->tos);// & INET_ECN_ECT_0) || (ip_header->tos & INET_ECN_ECT_1))
			if(tcp_header->syn && tcp_header->ack)
			{
					if(tcp_header->ece && tcp_header->cwr)
						f->ecn_enabled=true;
					f->active=true;
					f->conn_time=f->last_ecn_update=f->last_ecnecho_update=jiffies;
					f->last_ecn_ktupdate=f->last_ecnecho_ktupdate=ktime_get();
					f->last_ack = f->init_ack = tcp_header->ack_seq;
					printk(KERN_INFO "[IN: SYNACK CONN_OPEN %pI4:%d->%pI4:%d]  Scaling : %d  \n", &ip_header->saddr, src_port, &ip_header->daddr, dst_port, f->scaleval);
					//memcpy(f->local_eth, eth_header->h_source, ETH_ALEN);
					//memcpy(f->remote_eth, eth_header->h_dest, ETH_ALEN);
			}
			else if(f->active)
			{
				if(payload_len > 0)
				{
					f->last_data_recv = jiffies;
					f->total_data_recv++;
					ecn_pkt =is_ecn(f, skb, ip_header, payload_len); //Check if pkts is ECN marked and account for that
					//printk(KERN_INFO "[IN: CHECK ECNRECV %pI4:%d->%pI4:%d]  ECN: %d\n", &ip_header->saddr, src_port, &ip_header->daddr, dst_port, ip_header->tos);
					if(!f->ecn_enabled) //&& ecn_pkt
					{
						//printk(KERN_INFO "[IN: CLEAR ECNRECV %pI4:%d->%pI4:%d]  ECN:%d count: %d\n", &ip_header->saddr, src_port, &ip_header->daddr, dst_port, ecn_pkt, f->ecn_pkt_count);
						clear_ecn(ip_header);
					}
				}
				else if(tcp_header->ack)
				{
					f->last_ack_recv = jiffies;
					f->total_ack_recv++;
					ecnecho_pkt =is_ecnecho(f, skb, tcp_header); //Check if pkts is ECN echo and account for that
					//printk(KERN_INFO "[IN: CHECK ECNECHORECV %pI4:%d->%pI4:%d]  ECN echo: %d\n", &ip_header->saddr, src_port, &ip_header->daddr, dst_port, tcp_header->ece);
					if(ecnecho_pkt && !f->ecn_enabled)
					{
						//printk(KERN_INFO "[IN: CLEAR ECNECHORECV %pI4:%d->%pI4:%d]  ECE:%d count: %d\n", &ip_header->saddr, src_port, &ip_header->daddr, dst_port, ecnecho_pkt, f->ecnecho_ack_count);
						clear_ecnecho(tcp_header);
					}
					
					//Modify incoming ACK receive window based on ECNECNO_ALPAHA
					if(f->ecnecho_alpha > 0)
						tcp_modify_incoming(f, skb);
						
					//Process incoming ACK
					if(f->last_ack <= tcp_header->ack_seq)
						f->dupacks++;
					else
						f->dupacks=0;
					f->last_ack = tcp_header->ack_seq;
				}
            }			
		}
		
	}
	return NF_ACCEPT;
}

//Called when module loaded using 'insmod'
int init_module()
{

	int i;

    for(i=0; i<SIZE; i++)
    {
        reset_flow(&flist[i]);
	}

    //Initialize lock for global information
    spin_lock_init(&globalLock);

    get_random_bytes(&hash_seed, sizeof(u32));
    
	//POSTROUTING - for outgoing
	nfho_outgoing.hook = hook_func_out;                 //function to call when conditions below met
	nfho_outgoing.hooknum = NF_INET_POST_ROUTING;       //called in post_routing
	nfho_outgoing.pf = PF_INET;                         //IPV4 packets
	nfho_outgoing.priority = NF_IP_PRI_FIRST;           //set to highest priority over all other hook functions
	nf_register_hook(&nfho_outgoing);                   //register hook*/

	//PRETROUTING - for incoming
	nfho_incoming.hook = hook_func_in;                 //function to call when conditions below met
	nfho_incoming.hooknum = NF_INET_PRE_ROUTING;       //called in post_routing
	nfho_incoming.pf = PF_INET;                         //IPV4 packets
	nfho_incoming.priority = NF_IP_PRI_FIRST;           //set to highest priority over all other hook functions
	nf_register_hook(&nfho_incoming);                   //register hook*/

	printk(KERN_INFO "Start RDCTCP kernel module\n");

	return 0;
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
	//Unregister the hook
	nf_unregister_hook(&nfho_outgoing);
	nf_unregister_hook(&nfho_incoming);
	printk(KERN_INFO "Stop RDCTCP kernel module\n");
}


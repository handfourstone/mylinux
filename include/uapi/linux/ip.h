/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the IP protocol.
 *
 * Version:	@(#)ip.h	1.0.2	04/28/93
 *
 * Authors:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _UAPI_LINUX_IP_H
#define _UAPI_LINUX_IP_H
#include <linux/types.h>
#include <asm/byteorder.h>

#define IPTOS_TOS_MASK		0x1E
#define IPTOS_TOS(tos)		((tos)&IPTOS_TOS_MASK)
#define	IPTOS_LOWDELAY		0x10
#define	IPTOS_THROUGHPUT	0x08
#define	IPTOS_RELIABILITY	0x04
#define	IPTOS_MINCOST		0x02

#define IPTOS_PREC_MASK		0xE0
#define IPTOS_PREC(tos)		((tos)&IPTOS_PREC_MASK)
#define IPTOS_PREC_NETCONTROL           0xe0
#define IPTOS_PREC_INTERNETCONTROL      0xc0
#define IPTOS_PREC_CRITIC_ECP           0xa0
#define IPTOS_PREC_FLASHOVERRIDE        0x80
#define IPTOS_PREC_FLASH                0x60
#define IPTOS_PREC_IMMEDIATE            0x40
#define IPTOS_PREC_PRIORITY             0x20
#define IPTOS_PREC_ROUTINE              0x00


/* IP options */
#define IPOPT_COPY		0x80
#define IPOPT_CLASS_MASK	0x60
#define IPOPT_NUMBER_MASK	0x1f

#define	IPOPT_COPIED(o)		((o)&IPOPT_COPY)
#define	IPOPT_CLASS(o)		((o)&IPOPT_CLASS_MASK)
#define	IPOPT_NUMBER(o)		((o)&IPOPT_NUMBER_MASK)

#define	IPOPT_CONTROL		0x00
#define	IPOPT_RESERVED1		0x20
#define	IPOPT_MEASUREMENT	0x40
#define	IPOPT_RESERVED2		0x60

#define IPOPT_END	(0 |IPOPT_CONTROL)
#define IPOPT_NOOP	(1 |IPOPT_CONTROL)
#define IPOPT_SEC	(2 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_LSRR	(3 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_TIMESTAMP	(4 |IPOPT_MEASUREMENT)
#define IPOPT_CIPSO	(6 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_RR	(7 |IPOPT_CONTROL)
#define IPOPT_SID	(8 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_SSRR	(9 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_RA	(20|IPOPT_CONTROL|IPOPT_COPY)

#define IPVERSION	4
#define MAXTTL		255
#define IPDEFTTL	64

#define IPOPT_OPTVAL 0
#define IPOPT_OLEN   1
#define IPOPT_OFFSET 2
#define IPOPT_MINOFF 4
#define MAX_IPOPTLEN 40
#define IPOPT_NOP IPOPT_NOOP
#define IPOPT_EOL IPOPT_END
#define IPOPT_TS  IPOPT_TIMESTAMP

#define	IPOPT_TS_TSONLY		0		/* timestamps only */
#define	IPOPT_TS_TSANDADDR	1		/* timestamps and addresses */
#define	IPOPT_TS_PRESPEC	3		/* specified modules only */

#define IPV4_BEET_PHMAXLEN 8
/******************************************************************************
 * @ihl      ip 头部长度，包括选项，4位最大15,头部最长支持60
 * @version  版本，IPv4 对应的为 4
 * @tos      服务类型，包括3bit优先权子字段(现在已被忽略)，4bit的TOS子字段和
 *           1bit未用位但必须置为0。4bit的TOS子字段分别表示：最小时延，最大吞吐
 *           量，最高可靠性和最小费用。4bit中只能设置1bit，如果所有4bit均为0,那
 *           么就意味着一般服务。
 * @tot_len  IP 数据报的总长度，包括头部和数据部分，最长65536
 * @id       标识字段唯一的表示主机发送的每一份数据报。通常每发送一份报文它的值
 *           就会加1。
 * @frag_off 低13位表示分段偏移，指明了该分段在当前的数据报什么位置上。除了一个
 *           数据报的最后一个分段以外，其它所有的分段(分片)必须是8字节的倍数。8
 *           字节是基本分段单位。
 *           高3为：
 *           bit0 保留位，必须为0
 *           bit1 更多分片(MF More Fragment)标志。除了最后一片外，其它每个组成
 *                数据报的片段都要把该比特置为1。
 *           bit2 不分片(DF Don't Fragment)标志。如果将这一比特置为1，IP将不对
 *                数据报进行分片。这时，如果有需要进行分片的数据报到来，就会丢
 *                弃该数据报并发送一个ICMP差错报文给起始端。
 * @ttl      生存时间字段，一个数据报一旦经过一个路由器，该字段就会减1。当该字
 *           段值为0的时候，数据报就会被丢弃，并发送ICMP报文同志源主机。
 * @protocol 标识哪个协议向 IP 传递数据。
 * @check    只对 IP 首部进行校验。发送端先将该字段置0,然后将IP首部每16bit进行
 *           2进制循坏求和，结果存在该字段中。接收方校验将头部每16bit求和，如
 *           果传输途中没有发生差错，校验结果应该为全1。如果不是全1,那么IP层就
 *           丢掉该数据报。但是不生成差错报文，由上层去发现丢失的数据报并进行
 *           重传。
 * @saddr    源 IP 地址。
 * @daddr    目的 IP 地址。
 * ***************************************************************************/
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__be32	saddr;
	__be32	daddr;
	/*The options start here. */
};


struct ip_auth_hdr {
	__u8  nexthdr;
	__u8  hdrlen;		/* This one is measured in 32 bit units! */
	__be16 reserved;
	__be32 spi;
	__be32 seq_no;		/* Sequence number */
	__u8  auth_data[0];	/* Variable len but >=4. Mind the 64 bit alignment! */
};

struct ip_esp_hdr {
	__be32 spi;
	__be32 seq_no;		/* Sequence number */
	__u8  enc_data[0];	/* Variable len but >=8. Mind the 64 bit alignment! */
};

struct ip_comp_hdr {
	__u8 nexthdr;
	__u8 flags;
	__be16 cpi;
};

struct ip_beet_phdr {
	__u8 nexthdr;
	__u8 hdrlen;
	__u8 padlen;
	__u8 reserved;
};

/* index values for the variables in ipv4_devconf */
enum
{
	IPV4_DEVCONF_FORWARDING=1,
	IPV4_DEVCONF_MC_FORWARDING,
	IPV4_DEVCONF_PROXY_ARP,
	IPV4_DEVCONF_ACCEPT_REDIRECTS,
	IPV4_DEVCONF_SECURE_REDIRECTS,
	IPV4_DEVCONF_SEND_REDIRECTS,
	IPV4_DEVCONF_SHARED_MEDIA,
	IPV4_DEVCONF_RP_FILTER,
	IPV4_DEVCONF_ACCEPT_SOURCE_ROUTE,
	IPV4_DEVCONF_BOOTP_RELAY,
	IPV4_DEVCONF_LOG_MARTIANS,
	IPV4_DEVCONF_TAG,
	IPV4_DEVCONF_ARPFILTER,
	IPV4_DEVCONF_MEDIUM_ID,
	IPV4_DEVCONF_NOXFRM,
	IPV4_DEVCONF_NOPOLICY,
	IPV4_DEVCONF_FORCE_IGMP_VERSION,
	IPV4_DEVCONF_ARP_ANNOUNCE,
	IPV4_DEVCONF_ARP_IGNORE,
	IPV4_DEVCONF_PROMOTE_SECONDARIES,
	IPV4_DEVCONF_ARP_ACCEPT,
	IPV4_DEVCONF_ARP_NOTIFY,
	IPV4_DEVCONF_ACCEPT_LOCAL,
	IPV4_DEVCONF_SRC_VMARK,
	IPV4_DEVCONF_PROXY_ARP_PVLAN,
	IPV4_DEVCONF_ROUTE_LOCALNET,
	IPV4_DEVCONF_IGMPV2_UNSOLICITED_REPORT_INTERVAL,
	IPV4_DEVCONF_IGMPV3_UNSOLICITED_REPORT_INTERVAL,
	IPV4_DEVCONF_IGNORE_ROUTES_WITH_LINKDOWN,
	IPV4_DEVCONF_DROP_UNICAST_IN_L2_MULTICAST,
	IPV4_DEVCONF_DROP_GRATUITOUS_ARP,
	__IPV4_DEVCONF_MAX
};

#define IPV4_DEVCONF_MAX (__IPV4_DEVCONF_MAX - 1)

#endif /* _UAPI_LINUX_IP_H */

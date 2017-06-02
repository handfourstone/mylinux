#ifndef _NET_NEIGHBOUR_H
#define _NET_NEIGHBOUR_H

#include <linux/neighbour.h>

/*
 *	Generic neighbour manipulation
 *
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *	Alexey Kuznetsov	<kuznet@ms2.inr.ac.ru>
 *
 * 	Changes:
 *
 *	Harald Welte:		<laforge@gnumonks.org>
 *		- Add neighbour cache statistics like rtstat
 */

#include <linux/atomic.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/bitmap.h>

#include <linux/err.h>
#include <linux/sysctl.h>
#include <linux/workqueue.h>
#include <net/rtnetlink.h>

/*
 * NUD stands for "neighbor unreachability detection"
 * 当邻居项处于该状态时，则会启动定时器。下面我们一一分析这
 * 几个邻居状态，通过分析完这几个状态，我们就基本上会理解邻
 * 居项状态机中定时器处理函数 neigh_timer_handler
 * 1.对于NUD_INCOMPLETE，当本机发送完 arp 请求包后，还未收到
 *   应答时，即会进入该状态。进入该状态，即会启动定时器，如果
 *   在定时器到期后，还没有收到应答时：如果没有到达最大发包上
 *   限时，即会重新进行发送请求报文；如果超过最大发包上限还没
 *   有收到应答，则会将状态设置为 failed。
 * 2.对于收到可达性确认后，即会进入 NUD_REACHABLE，当进入
 *   NUD_REACHABLE状态后，即会启动一个定时器，当定时器到时前，
 *   该邻居协议没有被使用过，就会将邻居项的状态转换为 NUD_STALE。
 * 3.对于NUD_STALE状态的邻居项，即会启动一个定时器。如果在定时器
 *   到时前，有数据需要发送，则直接将数据包发送出去，并将状态设
 *   置为NUD_DELAY；如果在定时器到时前，没有数据需要发送，且该
 *   邻居项的引用计数为1，则会通过垃圾回收机制，释放该邻居项对
 *   应的缓存。
 * 4.处于NUD_DELAY状态的邻居项，如果在定时器到时后，没有收到可达
 *   性确认，则会进入NUD_PROBE状态；如果在定时器到达之前，收到可
 *   达性确认，则会进入NUD_REACHABLE（在该状态下的邻居项不会发送
 *   solicit请求，而只是等待可到达性应答。主要包括对以前的 silicit
 *   请求的应答或者收到一个对于本设备以前发送的一个数据包的应答）。
 * 5.处于NUD_PROBE状态的邻居项，会发送 arp solicit 请求，并启动一个
 *   定时器。如果在定时器到时前，收到可达性确认，则进入NUD_REACHABLE;
 *   如果在定时器到时后，没有收到可达性确认：
 *     a)没有超过最大发包次数时，则继续发送solicit请求，并启动定时器
 *     b)如果超过最大发包次数，则将邻居项状态设置为failed
 *
 * 上面的5个状态中，在NUD_REACHABLE、NUD_PROBE、NUD_STALE、NUD_DELAY
 * 状态时，数据包是可以正常发送的，只是发送的函数不同。这样就不难理解
 * NUD_VALID 包含NUD_PERMANENT、NUD_NOARP、NUD_REACHABLE、NUD_PROBE、
 * NUD_DELAY了。NUD_CONNECTED 主要表示另据是可达的状态，对于
 * NUD_PERMANENT、NUD_NOARP状态的邻居项，其邻居状态是不会改变的，一直
 * 是有效的，除非删除该邻居项。对于NUD_REACHABLE我们在上面已经介绍过了。*/

#define NUD_IN_TIMER	(NUD_INCOMPLETE|NUD_REACHABLE|NUD_DELAY|NUD_PROBE)
#define NUD_VALID	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE|NUD_PROBE|NUD_STALE|NUD_DELAY)
#define NUD_CONNECTED	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE)

struct neighbour;

enum {
	NEIGH_VAR_MCAST_PROBES,
	NEIGH_VAR_UCAST_PROBES,
	NEIGH_VAR_APP_PROBES,
	NEIGH_VAR_MCAST_REPROBES,
	NEIGH_VAR_RETRANS_TIME,
	NEIGH_VAR_BASE_REACHABLE_TIME,
	NEIGH_VAR_DELAY_PROBE_TIME,
	NEIGH_VAR_GC_STALETIME,
	NEIGH_VAR_QUEUE_LEN_BYTES,
	NEIGH_VAR_PROXY_QLEN,
	NEIGH_VAR_ANYCAST_DELAY,
	NEIGH_VAR_PROXY_DELAY,
	NEIGH_VAR_LOCKTIME,
#define NEIGH_VAR_DATA_MAX (NEIGH_VAR_LOCKTIME + 1)
	/* Following are used as a second way to access one of the above */
	NEIGH_VAR_QUEUE_LEN, /* same data as NEIGH_VAR_QUEUE_LEN_BYTES */
	NEIGH_VAR_RETRANS_TIME_MS, /* same data as NEIGH_VAR_RETRANS_TIME */
	NEIGH_VAR_BASE_REACHABLE_TIME_MS, /* same data as NEIGH_VAR_BASE_REACHABLE_TIME */
	/* Following are used by "default" only */
	NEIGH_VAR_GC_INTERVAL,
	NEIGH_VAR_GC_THRESH1,
	NEIGH_VAR_GC_THRESH2,
	NEIGH_VAR_GC_THRESH3,
	NEIGH_VAR_MAX
};
/* 该结构存储着邻居协议的配置参数。对于每个使用邻居协议配置
 * 好的 L3 协议，有多个 neigh_parms 实例：每个 L3 地址配置
 * 使用了邻居子系统的设备对应一个，再加上一个默认参数值。*/
struct neigh_parms {
	possible_net_t net;
	struct net_device *dev;
	struct list_head list;
/* 对于仍然使用旧邻居基础结构的设备，主要使用这个函数来
 * 初始化。通常该函数只用于将 neighbour->ops 初始化为
 * arp_broken_ops 实例。参见 drivers/net/shaper.c中的
 * shaper_neigh_setup 函数。
 * 不要将这个虚函数与 net_device->netgh_setup 函数混淆。
 * 当第一次给一个设备配置 L3 地址，和初始化
 * neigh_parms->neigh_setup 时，要调用后者。每个设备只
 * 调用 net_device->neigh_setup 一次。每个与设备关联的
 * neighbour 也只调用 neigh_parms->neigh_setup 一次。*/
	int	(*neigh_setup)(struct neighbour *);
	void	(*neigh_cleanup)(struct neighbour *);
/* 回溯指针，指向持有该结构的 neigh_table 结构。*/
	struct neigh_table *tbl;
/* 这个表在 net/ipv4/neighbour.c 文件的结尾的程序中完成
 * 初始化。它与允许用户修改 neigh_parms 结构中某些参数的
 * 值有关，这些参数可以导出到 /proc 中。*/
	void	*sysctl_table;
/* 这是一个布尔标志，设置后表示该邻居实例可以“被删除”。
 * 参见 neigh_parma_release。*/
	int dead;
/* 引用计数。*/
	atomic_t refcnt;
/* 负责管理互斥。*/
	struct rcu_head rcu_head;
/* 表示自从最近一次收到可到达性证明后经过的时间。*/
	int	reachable_time;
	int	data[NEIGH_VAR_DATA_MAX];
	DECLARE_BITMAP(data_state, NEIGH_VAR_DATA_MAX);
};

static inline void neigh_var_set(struct neigh_parms *p, int index, int val)
{
	set_bit(index, p->data_state);
	p->data[index] = val;
}

#define NEIGH_VAR(p, attr) ((p)->data[NEIGH_VAR_ ## attr])

/* In ndo_neigh_setup, NEIGH_VAR_INIT should be used.
 * In other cases, NEIGH_VAR_SET should be used.
 */
#define NEIGH_VAR_INIT(p, attr, val) (NEIGH_VAR(p, attr) = val)
#define NEIGH_VAR_SET(p, attr, val) neigh_var_set(p, NEIGH_VAR_ ## attr, val)

static inline void neigh_parms_data_state_setall(struct neigh_parms *p)
{
	bitmap_fill(p->data_state, NEIGH_VAR_DATA_MAX);
}

static inline void neigh_parms_data_state_cleanall(struct neigh_parms *p)
{
	bitmap_zero(p->data_state, NEIGH_VAR_DATA_MAX);
}
/* 这个结构中存储着对邻居协议的统计信息，用户可以
 * 仔细查看这些信息。每个邻居协议都有它自己的该结
 * 构实例，该结构定义在 include/net/neighbour.h 文
 * 件中。 */
struct neigh_statistics {
/* 邻居协议分配的 neighbour 结构呀的综合。包括那些
 * 已经被删除的 neighbour 结构。*/
	unsigned long allocs;
/* 删除的 neighbour 项的数目。由 neigh_destroy 函
 * 数负责更新。*/
	unsigned long destroys;
/* hash 表容量增加的次数，由 neigh_hash_grow 函数
 * 负责更新。*/
	unsigned long hash_grows;
/* 解析一个邻居地址失败后尝试的次数。每次送出一个新
 * 的 silicitation 封包，不会增加该值；只有当所有的
 * 尝试都失败后，才会由 neigh_timer_handler 函数将
 * 该值递增。*/
	unsigned long res_failed;
/* 调用 neigh_lookup 函数的次数。*/
	unsigned long lookups;
/* neigh_lookup 函数查询成功的次数。*/
	unsigned long hits;
/* 下面两个字段只有 IPv6 使用，表示受到 solicitation
 * 请求的数量。两个字段分别表示多播地址请求和单播地址
 * 请求。*/
	unsigned long rcv_probes_mcast;
	unsigned long rcv_probes_ucast;
/* neigh_periodic_gc_runs 函数被调用的次数。*/
	unsigned long periodic_gc_runs;
/* neigh_forced_gc 函数被调用的次数。*/
	unsigned long forced_gc_runs；

	unsigned long unres_discards;
	unsigned long table_fulls;
};

#define NEIGH_CACHE_STAT_INC(tbl, field) this_cpu_inc((tbl)->stats->field)
/* 存储邻居有关的信息，例如，L2和L3地址、NUD状态、
   访问该邻居经过的设备等。注意，一个 neighbor 项
   不是与一台主机相关，而是与一个L3地址相关。一台
   主机可能有多个L3地址。*/
struct neighbour {
/* 每个 neighbour 项都被插入到一个 hash 表中。next 指向
   另外一个 neighbour 结构，这个结构与当前结构冲突且共享
   同一个bucket。新元素总是被插入到bucket列表的表头。*/
	struct neighbour __rcu	*next;
/* 指向 neigh_table 结构体的指针，这个结构体定义了与当前
   邻居项有关的协议，例如：如果邻居使用一个 IPv4 地址，
   tbl 就指向 arp_tbl 结构。*/
	struct neigh_table	*tbl;
/* 用于调整邻居协议行为的参数。当建立一个 neighbour 结构。
   时，用嵌入到和协议相关的 neigh_table 结构中的 neigh_paras
   结构中的默认值初始化 parms。当neigh_create 函数调用协议的
   constructor 方法时（对ARP来说是 arp_constructor）,用相关
   设备的配置信息取代初始化时的默认值。而大多数设备使用的都
   是系统的默认值，可以使用不同的参数启动设备，或者管理员以
   后可以用不同的参数配置设备。*/
	struct neigh_parms	*parms;
/* 时间戳(用 jiffies 表示)表示该邻居可到达性最后验证过的
   时间。L4协议用 neight_confirm 函数更新这个值。邻居基础
   结构用 neigh_upgrade 函数更新它。*/
	unsigned long		confirmed;
/* 时间戳，表示 neigh_upgrade 函数最近一次更新该邻居的时间
   (首次初始化是由 neigh_alloc 函数设置)。不要将 updated 
   和confirmed混淆，这两个字段表示不同的事件。当邻居的状态
   改变时，要设置 updated 字段；而 confirmed 字段只记录邻居
   特殊的一次状态改变：当邻居最近一次证明是有效时，发生的
   状态转变。*/
	unsigned long		updated;
/* 用于在出现竞争时对 neighbour 结构进行保护。*/
	rwlock_t		lock;
/* 引用计数。*/
	atomic_t		refcnt;
/* 目的 L3 地址还没有被解析的封包被临时放到这个队列中。不要
 * 管这个队列的名称，它能被所有的邻居协议使用，不止是ARP。*/
	struct sk_buff_head	arp_queue;
	unsigned int		arp_queue_len_bytes;
/* 用于处理几个任务的定时器。*/
	struct timer_list	timer;
/* 邻居项最近一次被使用的时间。这个值不会随着数据传输而同步
   更新。当该邻居项还没有到 NUD_CONNECTED 态时，这个字段由
   neigh_resolve_output 函数调用 neigh_event_send 来更新。
   相应的，当邻居项进入 NUD_CONNECTED 态时，它的值由
   neigh_periodic_timer 更新为该邻居项的可到达性最近被证实
   的时间。*/
	unsigned long		used;
/* 失败的 solicitation 尝试的次数。它的值由 neigh_timer_handler
 * 定时器检测。当尝试次数到达允许的最大值时，这个定时器就将
 * 该 neighbour 项转移到 NUD_FAILED 态。*/
	atomic_t		probes;
/* 这个字段的可选值在 include/linux/rtnetlink.h 和
   include/net/neighbour.h 文件中。分别为
   NTF_PROXY 和 NTF_ROUTER。*/
	__u8			flags;
/* 指示邻居项的状态。可能的取值以 NUD_xxx 形式命名，它定义
   在 include/net/neighbour.h 和
   include/linux/rtnetlink.h中。*/
	__u8			nud_state;
/*******************************************************************************
 * 当 neigh_create 函数调用协议的 constructor 方法(对于 ARP是 arp_constructor)创
 * 建邻居项时，就会设置这个字段。它的值可以用于各种场合，例如，决定哪些值可以赋
 * 给 nud_state。type 可用的值在 inlcude/linux/rtnetlink.h 中。在邻接子系统中，
 * 我们感兴趣的值只有：RTN_UNICAST、RTN_LOCAL、RTN_BROADCAST、RTN_ANYCAST 和
 * RTN_MULTICAST。加入有个 IPv4 地址(例如，与一个neighbour 项相关的L3地址)，
 * inet_addr_type 函数就会找到相应的 RTN_xxx 值，对于 IPv6来说，有个类似的函数：
 * ipv6_addr_type。
 * ****************************************************************************/
	__u8			type;
/* 若 dead 被置为 1，表示该结构体将被删除，不能再使用了。*/
	__u8			dead;
	seqlock_t		ha_lock;
/* 与 primary_key(见下面)表示的L3地址关联的L2地址。*/
	unsigned char		ha[ALIGN(MAX_ADDR_LEN, sizeof(unsigned long))];
/* 缓存的 L2 帧头列表。*/
	struct hh_cache		hh;
/* 用于向邻居发送帧的函数。根据一些因素，该函数指针指向的函数在该
 * 结构的生存期内可以改变多次。它的初始化是用 neigh_table 结构的
 * constructor 方法。当邻居项的状态为 NUD_REACHABLE 态或者 NUD_STALE
 * 态时，可以分别通过调用 neigh_connect 和 neigh_supect 函数更新
 * 该字段的值。*/
	int			(*output)(struct neighbour *, struct sk_buff *);
/* VFT 中包含的各种方法，它们用于维护 neighbour 项。例如，这些方法
 * 中，有几个是用于传送封包的，每个方法都为不同状态优化或相关的设备
 * 类型进行了优化。每个协议会提供三个或四个不同的 VFT；根据L3地址的
 * 类型、相关设备的类型、以及链路的类型(例如，点对点链路)，选择合适
 * 的 VTF 用于特殊的 neighbour 项。*/
	const struct neigh_ops	*ops;
	struct rcu_head		rcu;
/* 通过这个设备可以访问该邻居。每个邻居只能通过一个设备来访问。该
 * 值不能为 NULL ，因为在其他内核子系统中，NULL 值是个通配符，表示
 * 所有设备。*/
	struct net_device	*dev;
/* 该邻居的L3地址。它作为缓存查找函数的查找关键字。对ARP项来说，它是
 * 一个IPv4的地址；对邻居发现项来说，它是一个IPv6地址。*/
	u8			primary_key[0];
};
/* 一组函数，用来表示 L3 协议（如IP）和 dev_queue_xmit
 * 之间的接口。这些虚拟函数可以根据它们使用的上下文环境
 * 来改变（也就是说，根据邻居的状态）。*/
struct neigh_ops {
/* 邻居协议所表示的邻居项的地址簇。它的可能趣旨位于
 * include/linux/socket.h 文件中，名称都是 AP_XXX的
 * 形式，对于IPv4和IPv6，对应的值分别是 AF_INET 和
 * AF_INET6。*/
	int			family;
/* 发送 solicitation 请求的函数。*/
	void			(*solicit)(struct neighbour *, struct sk_buff *);
/* 当一个邻居被认为不可达时，要调用这个函数。*/
	void			(*error_report)(struct neighbour *, struct sk_buff *);
/* 这个是最普通的函数，用于所有的情况下。它会检查地址是否已经被
 * 解析过：在没有被解析的情况下，它会启动解析程序。如果地址还未
 * 准备好，它会把封包保存在一个临时队列中，并启动解析程序。由于
 * 该函数是为了保证接收方是可到达的，他会做每一件必要的事情，因
 * 此它相对来说需要的操作比较多。不要将
 * neigh_ops->output 和 neighbour->output 想混淆。*/
	int			(*output)(struct neighbour *, struct sk_buff *);
/* 当已经知道邻居是可到达时(邻居状态是 NUD_CONNECTED)，使用该
 * 函数。因为所有需要的信息都是满足的，该函数只要简单填充一下
 * L2 帧头，因此它比 output 快。*/
	int			(*connected_output)(struct neighbour *, struct sk_buff *);
};
/* 用于基于目的地址的代理。 */
struct pneigh_entry {
	struct pneigh_entry	*next;
	possible_net_t		net;
	struct net_device	*dev;
	u8			flags;
	u8			key[0];
};

/*
 *	neighbour table manipulation
 */

#define NEIGH_NUM_HASH_RND	4

struct neigh_hash_table {
	struct neighbour __rcu	**hash_buckets;
	unsigned int		hash_shift;
	__u32			hash_rnd[NEIGH_NUM_HASH_RND];
	struct rcu_head		rcu;
};

/* 描述一种邻居协议所用的参数和所用函数。每个邻居协议
 * 都有该结构体的一个实例
 * 		arp_tbl,IPv4 使用的ARP协议。参见 net/ipv4/arp.c
 * 		nd_tbl,IPv6 使用的邻居发现协议。参见 net/ipv6/ndisc.c
 * 		dn_neigh_table,DECnet 使用的邻居发现协议。参见 net/decent/dn_neigh.c
 * 		clip_tbl ATM over IP 协议。参见 net/atm/clip.c
 * 所有实例都插入到一个由静态变量 neight_tables 指向
 * 的一个全局表中，并由 neigh_tbl_lock 来加锁保护。该
 * 锁只保护全局表的完整性，并不对表中每个条目的内容进
 * 行保护。*/
struct neigh_table {
/* 邻居协议所表示的邻居项的地址簇。它的可能趣旨位于
 * include/linux/socket.h 文件中，名称都是 AP_XXX的
 * 形式，对于IPv4和IPv6，对应的值分别是 AF_INET 和
 * AF_INET6。*/
	int			family;
/* 插入到缓存长度中的数据结构的长度。由于一个 neighbour
 * 结构包含一个字段，它的长度与具体的协议有关(primary_key)。
 * entry_size 字段的值就是一个 neighbour 结构的字节数和
 * 协议提供的 primary_key 字段的字节数之和。例如，在
 * IPv4/ARP下，该字段被初始化为 sizeof(struct neighbour) +4,
 * 这里 4 就表示 IPv4 地址占4个字节。例如，当 neigh_alloc
 * 函数要清理从缓存中取回的邻居项的内容时，就要用到该字段。*/
	int			entry_size;
/* 查找函数使用的查找关键字的长度。由于查找关键字是一个L3
 * 地址，对 IPv4 来说，该字段值就是4；对IPv6来说，就是8。*/
	int			key_len;
	__be16			protocol;
/* Hash 函数，在查找一个邻居项时，该函数用搜索关键字从 hash
 * 表中选择正确的 bucket。*/
	__u32			(*hash)(const void *pkey,
					const struct net_device *dev,
					__u32 *hash_rnd);
	bool			(*key_eq)(const struct neighbour *, const void *pkey);
/* 当建立一个新的邻居项时，neigh_create 函数调用的 constructor 方法。
 * 该方法会初始化新 neighbour 项中协议指定的一些字段。*/
	int			(*constructor)(struct neighbour *);
/* pconstructor 方法时 constructor 方法的对应体。现在，只有IPv6使用
 * pconstructor;当首次配置关联的设备时，这个方法会注册一个特殊的多播
 * 地址。当释放一个代理的邻居时，要调用 pdestructor 方法。它只能由
 * IPv6中使用，撤销pconstuctor方法所作的工作。*/
	int			(*pconstructor)(struct pneigh_entry *);
	void			(*pdestructor)(struct pneigh_entry *);
/* 当solicit请求(例如,ARP下的ARPOP_REQUEST)从代理队列 neigh_table ->
 * proxy_queue 中取出后，处理该请求的函数。*/
	void			(*proxy_redo)(struct sk_buff *skb);
/* 这只是一个用于标识协议的字符串。在分配内存池时(参见neigh_table_init)，
 * 这个内存池用于分配 neighbour 结构，该字段主要作为一个 ID。*/
	char			*id;
/* 这个结构包含了一些用于调整邻居协议行为的参数，例如，在没有收到应答
 * 后，重新发送一个 solicitation 请求前要等待多长时间；等待一应答时，
 * 队列中保存多少个要发送的封包。*/
	struct neigh_parms	parms;
/* 没有使用 */
	struct list_head	parms_list;
/* 这个变量用来控制 gc_interval 定时器多久会超时，并启动垃圾回收。定时器每次
 * 只会触发 hash 表中一个 bucket 中的垃圾回收。*/
	int			gc_interval;
/* 这三个阈值定义了三个不同级别的内存状态，邻居协议可将这些状态赋给
 * 当前缓存中的 neighbour 项。*/
	int			gc_thresh1;
	int			gc_thresh2;
	int			gc_thresh3;
/* 这个变量表示 neight_forced_gc 函数最近一次执行的时间，用 jiffies 测量。
 * 换句话说，它表示由于内存不足，最近一次垃圾回收程序执行的时间。*/
	unsigned long		last_flush;
	struct delayed_work	gc_work;
/* 当 proxy_queue 队列中至少由一个元素时，就会启动这个定时器。若定时器
 * 超时，执行的处理函数是neigh_proxy_process。由 neigh_table_init 函数
 * 在协议初始化时对这个定时器初始化。它与 neigh_table -> gc_interval 定时器
 * 不同，不会周期性启动，只会在需要的时候启动(例如，在往 proxy_queue中
 * 首次增加一个元素时，协议就会启动它)。*/
	struct timer_list 	proxy_timer;
/* 当启动代理并且配置了非空的 proxy_delay 延迟时，收到的 solicit
 * 请求(例如，ARP下收到ARPOP_REQUEST封包)就放到这个队列中。新元素
 * 被加到队尾。*/
	struct sk_buff_head	proxy_queue;
/* 在协议缓冲中当前neighbour结构实例的书目。每当用neigh_alloc分配
 * 一个新的邻居项，它的值就会加1；用neig_destroy 释放一个邻居项，
 * 它的值就减1.*/
	atomic_t		entries;
/* 表示在出现竞争时保护这个表的锁。对于只需要读权限的函数，例如，
 * neigh_lookup，该锁用于只读模式；对于其它函数，例如：
 * neigh_periodic_timer，它可以处于读/写模式。
 * 注意，整张表由单独一个锁保护，和常见的情况正好相反，例如，缓存
 * 表中的每个 bucket 都有一个不同的锁。*/
	rwlock_t		lock;
/* 与一个表(每个设备由这样一个表)关联的neigh_parms结构中，变量
 * reachable_time最近被更新的时间(用jiffies表示)。*/
	unsigned long		last_rand;
/* 缓存中的 neighbour 实例的各种统计信息。*/
	struct neigh_statistics	__percpu *stats;
	struct neigh_hash_table __rcu *nht;
/* 存储要被代理的 L3 地址的表。*/
	struct pneigh_entry	**phash_buckets;
};

enum {
	NEIGH_ARP_TABLE = 0,
	NEIGH_ND_TABLE = 1,
	NEIGH_DN_TABLE = 2,
	NEIGH_NR_TABLES,
	NEIGH_LINK_TABLE = NEIGH_NR_TABLES /* Pseudo table for neigh_xmit */
};

static inline int neigh_parms_family(struct neigh_parms *p)
{
	return p->tbl->family;
}

#define NEIGH_PRIV_ALIGN	sizeof(long long)
#define NEIGH_ENTRY_SIZE(size)	ALIGN((size), NEIGH_PRIV_ALIGN)

static inline void *neighbour_priv(const struct neighbour *n)
{
	return (char *)n + n->tbl->entry_size;
}

/* flags for neigh_update() */
#define NEIGH_UPDATE_F_OVERRIDE			0x00000001
#define NEIGH_UPDATE_F_WEAK_OVERRIDE		0x00000002
#define NEIGH_UPDATE_F_OVERRIDE_ISROUTER	0x00000004
#define NEIGH_UPDATE_F_ISROUTER			0x40000000
#define NEIGH_UPDATE_F_ADMIN			0x80000000


static inline bool neigh_key_eq16(const struct neighbour *n, const void *pkey)
{
	return *(const u16 *)n->primary_key == *(const u16 *)pkey;
}

static inline bool neigh_key_eq32(const struct neighbour *n, const void *pkey)
{
	return *(const u32 *)n->primary_key == *(const u32 *)pkey;
}

static inline bool neigh_key_eq128(const struct neighbour *n, const void *pkey)
{
	const u32 *n32 = (const u32 *)n->primary_key;
	const u32 *p32 = pkey;

	return ((n32[0] ^ p32[0]) | (n32[1] ^ p32[1]) |
		(n32[2] ^ p32[2]) | (n32[3] ^ p32[3])) == 0;
}

static inline struct neighbour *___neigh_lookup_noref(
	struct neigh_table *tbl,
	bool (*key_eq)(const struct neighbour *n, const void *pkey),
	__u32 (*hash)(const void *pkey,
		      const struct net_device *dev,
		      __u32 *hash_rnd),
	const void *pkey,
	struct net_device *dev)
{
	struct neigh_hash_table *nht = rcu_dereference_bh(tbl->nht);
	struct neighbour *n;
	u32 hash_val;

	hash_val = hash(pkey, dev, nht->hash_rnd) >> (32 - nht->hash_shift);
	for (n = rcu_dereference_bh(nht->hash_buckets[hash_val]);
	     n != NULL;
	     n = rcu_dereference_bh(n->next)) {
		if (n->dev == dev && key_eq(n, pkey))
			return n;
	}

	return NULL;
}

static inline struct neighbour *__neigh_lookup_noref(struct neigh_table *tbl,
						     const void *pkey,
						     struct net_device *dev)
{
	return ___neigh_lookup_noref(tbl, tbl->key_eq, tbl->hash, pkey, dev);
}

void neigh_table_init(int index, struct neigh_table *tbl);
int neigh_table_clear(int index, struct neigh_table *tbl);
struct neighbour *neigh_lookup(struct neigh_table *tbl, const void *pkey,
			       struct net_device *dev);
struct neighbour *neigh_lookup_nodev(struct neigh_table *tbl, struct net *net,
				     const void *pkey);
struct neighbour *__neigh_create(struct neigh_table *tbl, const void *pkey,
				 struct net_device *dev, bool want_ref);

/* 创建数据结构本身要用的函数，它的返回值是指向创建 neighbour
 * 结构的指针。
 * =>@ tbl: 表示使用的邻居协议。设置这个参数的方式很简单：如果
 * 		调用者来自 IPv4 程序(也就是说，来自 arp_rcv)，就设置
 * 		为 arp_tbl 等等。
 * =>@ pkey: 标识 L3 地址。之所以被称为 pkey，是因为它在缓存
 * 		查找中被用作查找关键字。
 * =>@ dev: 与要创建的邻居项相关的设备。因为每个 neighbour 项
 * 		都与一个 L3 地址相关联，并且后者总是与一个设备相关联，
 * 		所以 neighbour 实例就与一个设备相关联。*/
static inline struct neighbour *neigh_create(struct neigh_table *tbl,
					     const void *pkey,
					     struct net_device *dev)
{
	return __neigh_create(tbl, pkey, dev, true);
}
void neigh_destroy(struct neighbour *neigh);
int __neigh_event_send(struct neighbour *neigh, struct sk_buff *skb);
int neigh_update(struct neighbour *neigh, const u8 *lladdr, u8 new, u32 flags);
void __neigh_set_probe_once(struct neighbour *neigh);
void neigh_changeaddr(struct neigh_table *tbl, struct net_device *dev);
int neigh_ifdown(struct neigh_table *tbl, struct net_device *dev);
int neigh_resolve_output(struct neighbour *neigh, struct sk_buff *skb);
int neigh_connected_output(struct neighbour *neigh, struct sk_buff *skb);
int neigh_direct_output(struct neighbour *neigh, struct sk_buff *skb);
struct neighbour *neigh_event_ns(struct neigh_table *tbl,
						u8 *lladdr, void *saddr,
						struct net_device *dev);

struct neigh_parms *neigh_parms_alloc(struct net_device *dev,
				      struct neigh_table *tbl);
void neigh_parms_release(struct neigh_table *tbl, struct neigh_parms *parms);

static inline
struct net *neigh_parms_net(const struct neigh_parms *parms)
{
	return read_pnet(&parms->net);
}

unsigned long neigh_rand_reach_time(unsigned long base);

void pneigh_enqueue(struct neigh_table *tbl, struct neigh_parms *p,
		    struct sk_buff *skb);
struct pneigh_entry *pneigh_lookup(struct neigh_table *tbl, struct net *net,
				   const void *key, struct net_device *dev,
				   int creat);
struct pneigh_entry *__pneigh_lookup(struct neigh_table *tbl, struct net *net,
				     const void *key, struct net_device *dev);
int pneigh_delete(struct neigh_table *tbl, struct net *net, const void *key,
		  struct net_device *dev);

static inline struct net *pneigh_net(const struct pneigh_entry *pneigh)
{
	return read_pnet(&pneigh->net);
}

void neigh_app_ns(struct neighbour *n);
void neigh_for_each(struct neigh_table *tbl,
		    void (*cb)(struct neighbour *, void *), void *cookie);
void __neigh_for_each_release(struct neigh_table *tbl,
			      int (*cb)(struct neighbour *));
int neigh_xmit(int fam, struct net_device *, const void *, struct sk_buff *);
void pneigh_for_each(struct neigh_table *tbl,
		     void (*cb)(struct pneigh_entry *));

struct neigh_seq_state {
	struct seq_net_private p;
	struct neigh_table *tbl;
	struct neigh_hash_table *nht;
	void *(*neigh_sub_iter)(struct neigh_seq_state *state,
				struct neighbour *n, loff_t *pos);
	unsigned int bucket;
	unsigned int flags;
#define NEIGH_SEQ_NEIGH_ONLY	0x00000001
#define NEIGH_SEQ_IS_PNEIGH	0x00000002
#define NEIGH_SEQ_SKIP_NOARP	0x00000004
};
void *neigh_seq_start(struct seq_file *, loff_t *, struct neigh_table *,
		      unsigned int);
void *neigh_seq_next(struct seq_file *, void *, loff_t *);
void neigh_seq_stop(struct seq_file *, void *);

int neigh_proc_dointvec(struct ctl_table *ctl, int write,
			void __user *buffer, size_t *lenp, loff_t *ppos);
int neigh_proc_dointvec_jiffies(struct ctl_table *ctl, int write,
				void __user *buffer,
				size_t *lenp, loff_t *ppos);
int neigh_proc_dointvec_ms_jiffies(struct ctl_table *ctl, int write,
				   void __user *buffer,
				   size_t *lenp, loff_t *ppos);

int neigh_sysctl_register(struct net_device *dev, struct neigh_parms *p,
			  proc_handler *proc_handler);
void neigh_sysctl_unregister(struct neigh_parms *p);

static inline void __neigh_parms_put(struct neigh_parms *parms)
{
	atomic_dec(&parms->refcnt);
}

static inline struct neigh_parms *neigh_parms_clone(struct neigh_parms *parms)
{
	atomic_inc(&parms->refcnt);
	return parms;
}

/*
 *	Neighbour references
 */

/* 每次执行，会对 neighbour 的引用计数减 1，当减到 0 之后，
 * 就会删除该 neighbour 项。*/
static inline void neigh_release(struct neighbour *neigh)
{
	if (atomic_dec_and_test(&neigh->refcnt))
		neigh_destroy(neigh);
}

static inline struct neighbour * neigh_clone(struct neighbour *neigh)
{
	if (neigh)
		atomic_inc(&neigh->refcnt);
	return neigh;
}

#define neigh_hold(n)	atomic_inc(&(n)->refcnt)

static inline int neigh_event_send(struct neighbour *neigh, struct sk_buff *skb)
{
	unsigned long now = jiffies;
	
	if (neigh->used != now)
		neigh->used = now;
	if (!(neigh->nud_state&(NUD_CONNECTED|NUD_DELAY|NUD_PROBE)))
		return __neigh_event_send(neigh, skb);
	return 0;
}

#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
static inline int neigh_hh_bridge(struct hh_cache *hh, struct sk_buff *skb)
{
	unsigned int seq, hh_alen;

	do {
		seq = read_seqbegin(&hh->hh_lock);
		hh_alen = HH_DATA_ALIGN(ETH_HLEN);
		memcpy(skb->data - hh_alen, hh->hh_data, ETH_ALEN + hh_alen - ETH_HLEN);
	} while (read_seqretry(&hh->hh_lock, seq));
	return 0;
}
#endif

static inline int neigh_hh_output(const struct hh_cache *hh, struct sk_buff *skb)
{
	unsigned int seq;
	int hh_len;

	do {
		seq = read_seqbegin(&hh->hh_lock);
		hh_len = hh->hh_len;
		if (likely(hh_len <= HH_DATA_MOD)) {
			/* this is inlined by gcc */
			memcpy(skb->data - HH_DATA_MOD, hh->hh_data, HH_DATA_MOD);
		} else {
			int hh_alen = HH_DATA_ALIGN(hh_len);

			memcpy(skb->data - hh_alen, hh->hh_data, hh_alen);
		}
	} while (read_seqretry(&hh->hh_lock, seq));

	skb_push(skb, hh_len);
	return dev_queue_xmit(skb);
}

static inline int neigh_output(struct neighbour *n, struct sk_buff *skb)
{
	const struct hh_cache *hh = &n->hh;

	if ((n->nud_state & NUD_CONNECTED) && hh->hh_len)
		return neigh_hh_output(hh, skb);
	else
		return n->output(n, skb);
}

static inline struct neighbour *
__neigh_lookup(struct neigh_table *tbl, const void *pkey, struct net_device *dev, int creat)
{
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n || !creat)
		return n;

	n = neigh_create(tbl, pkey, dev);
	return IS_ERR(n) ? NULL : n;
}

static inline struct neighbour *
__neigh_lookup_errno(struct neigh_table *tbl, const void *pkey,
  struct net_device *dev)
{
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n)
		return n;

	return neigh_create(tbl, pkey, dev);
}

/*******************************************************************************
 * 这个控制结构在 ARP 中使用工作队列时会发挥作用，sched_next 代表下次被调度的时
 * 间，flags 是标志。
 * ****************************************************************************/
struct neighbour_cb {
	unsigned long sched_next;
	unsigned int flags;
};

#define LOCALLY_ENQUEUED 0x1

#define NEIGH_CB(skb)	((struct neighbour_cb *)(skb)->cb)

static inline void neigh_ha_snapshot(char *dst, const struct neighbour *n,
				     const struct net_device *dev)
{
	unsigned int seq;

	do {
		seq = read_seqbegin(&n->ha_lock);
		memcpy(dst, n->ha, dev->addr_len);
	} while (read_seqretry(&n->ha_lock, seq));
}


#endif

#ifndef _NBUFF_SKBUFF_ADDITION_
#define _NBUFF_SKBUFF_ADDITION_

/* This is required even if blog is not defined, so it falls
 under the nbuff catagory
*/
struct blog_t;					/* defined(CONFIG_BLOG) */

#ifndef NULL_STMT
#define NULL_STMT		do { /* NULL BODY */ } while (0)
#endif

typedef void (*RecycleFuncP)(void *nbuff_p, unsigned long context, uint32_t flags);
#define SKB_DATA_RECYCLE	(1 << 0)
#define SKB_RECYCLE		(1 << 1)
#define SKB_DATA_NO_RECYCLE	(~SKB_DATA_RECYCLE)	/* to mask out */
#define SKB_NO_RECYCLE		(~SKB_RECYCLE)		/* to mask out */
#define SKB_RECYCLE_NOFREE	(1 << 2)		/* do not use */

struct fkbuff;

extern void skb_frag_xmit4(struct sk_buff *origskb, struct net_device *txdev,
			   uint32_t is_pppoe, uint32_t minMtu, void *ip_p);
extern void skb_frag_xmit6(struct sk_buff *origskb, struct net_device *txdev,
			   uint32_t is_pppoe, uint32_t minMtu, void *ip_p);
extern struct sk_buff * skb_xlate(struct fkbuff *fkb_p);
extern struct sk_buff * skb_xlate_dp(struct fkbuff *fkb_p, uint8_t *dirty_p);
extern int skb_avail_headroom(const struct sk_buff *skb);

#define SKB_VLAN_MAX_TAGS	4

#define CONFIG_SKBSHINFO_HAS_DIRTYP	1

typedef union wlFlowInf
{
	uint32_t u32;
	union {
		union {
			struct {
				/* Start - Shared fields between ucast and mcast */
				uint32_t is_ucast:1;
				/* wl_prio is 4 bits for nic and 3 bits for dhd. Plan is
				to make NIC as 3 bits after more analysis */
				uint32_t wl_prio:4;
				/* End - Shared fields between ucast and mcast */
				uint32_t nic_reserved1:11;
				uint32_t nic_reserved2:8;
				uint32_t wl_chainidx:8;
			};
			struct {
				uint32_t overlayed_field:16;
				uint32_t ssid_dst:16; /* For bridged traffic we don't have chainidx (0xFE) */
			};
		} nic;

		struct {
			/* Start - Shared fields between ucast and mcast */
			uint32_t is_ucast:1;
			uint32_t wl_prio:4;
			/* End - Shared fields between ucast and mcast */
			/* Start - Shared fields between dhd ucast and dhd mcast */
			uint32_t flowring_idx:10;
			/* End - Shared fields between dhd ucast and dhd mcast */
			uint32_t dhd_reserved:13;
			uint32_t ssid:4;
		} dhd;
	} ucast;
	struct {
		/* Start - Shared fields between ucast and mcast */
		/* for multicast, WFD does not need to populate this flowring_idx, it is used internally by dhd driver */ 
		uint32_t is_ucast:1; 
		uint32_t wl_prio:4;
		/* End - Shared fields between ucast and mcast */
		/* Start - Shared fields between dhd ucast and dhd mcast */
		uint32_t flowring_idx:10;
		/* End - Shared fields between dhd ucast and dhd mcast */
		uint32_t mcast_reserved:1;
		uint32_t ssid_vector:16;
	} mcast;
} wlFlowInf_t;

/* Returns size of struct sk_buff */
extern size_t skb_size(void);
extern size_t skb_aligned_size(void);
extern int skb_layout_test(int head_offset, int tail_offset, int end_offset);

/**
 *	skb_headerinit	-	initialize a socket buffer header
 *	@headroom: reserved headroom size
 *	@datalen: data buffer size, data buffer is allocated by caller
 *	@skb: skb allocated by caller
 *	@data: data buffer allocated by caller
 *	@recycle_hook: callback function to free data buffer and skb
 *	@recycle_context: context value passed to recycle_hook, param1
 *  @blog_p: pass a blog to a skb for logging
 *
 *	Initializes the socket buffer and assigns the data buffer to it.
 *	Both the sk_buff and the pointed data buffer are pre-allocated.
 *
 */
void skb_headerinit(unsigned int headroom, unsigned int datalen,
		    struct sk_buff *skb, unsigned char *data,
		    RecycleFuncP recycle_hook, unsigned long recycle_context,
		    struct blog_t * blog_p);

/* Wrapper function to skb_headerinit() with no Blog association */
static inline void skb_hdrinit(unsigned int headroom, unsigned int datalen,
			       struct sk_buff *skb, unsigned char * data,
			       RecycleFuncP recycle_hook,
			       unsigned long recycle_context)
{
	skb_headerinit(headroom, datalen, skb, data, recycle_hook, recycle_context,
			(struct blog_t *)NULL);	/* No associated Blog object */
}
#endif
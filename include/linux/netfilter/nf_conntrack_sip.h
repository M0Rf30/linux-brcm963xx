#ifndef __NF_CONNTRACK_SIP_H__
#define __NF_CONNTRACK_SIP_H__
#ifdef __KERNEL__

#define SIP_PORT	5060
#define SIP_TIMEOUT	3600


/******************************************For Linux Native SIP ALG*********************************************/
/* Zyxel 
 * If an de-register packet with remove all binding contact. It will return NF_ACCEPT without update cseq from here.
 * This will cause the 200 OK response of this packet not be accept in SIP ALG, thus the expect of signaling will not be remove.
 * Now we will Try to parsing Contact with remove all binding when parsing Contact header failed.
 * Steve 2017-11-16
 */
#define ZYXEL_SIP_ALG_SUPPORT_RM_ALL_BINDING 1



/* Zyxel
 * Only SIP traffic which be NATed will into SIP ALG.
 */
#define ZYXEL_SIP_ALG_IGNORE_LOCAL_TRAFFIC 1

#define ZYXEL_SIP_ALG_DEFAULT_DIRECT_SIGNALLING 0 //sip_direct_signalling, original is 1 use this macro to define new
#define ZYXEL_SIP_ALG_DEFAULT_DIRECT_MEDIA 0 //sip_direct_media, original is 1 use this macro to define new
/******************************************For Linux Native SIP ALG (END)****************************************/



#if defined(CONFIG_BCM_KF_NETFILTER) && !defined(CONFIG_ZYXEL_USE_LINUX_SIP_ALG)

/* Classes defined by Broadcom */
#define SIP_EXPECT_CLASS_SIGNALLING	0
#define SIP_EXPECT_CLASS_AUDIO		1
#define SIP_EXPECT_CLASS_VIDEO		2
#define SIP_EXPECT_CLASS_OTHER		3
#define SIP_EXPECT_CLASS_MAX		3

enum sip_header_pos {
	POS_VIA,
	POS_CONTACT,
	POS_CONTENT,
	POS_OWNER_IP4,
	POS_CONNECTION_IP4,
	POS_ANAT,
	POS_MEDIA_AUDIO,
	POS_MEDIA_VIDEO,
	POS_ARTCP_IP4,
};

extern int (*nf_nat_addr_hook)(struct sk_buff *skb, unsigned int protoff,
			       struct nf_conn *ct,
			       enum ip_conntrack_info ctinfo, char **dptr,
			       int *dlen, char **addr_begin, int *addr_len,
			       struct nf_conntrack_man *addr);

extern int (*nf_nat_rtp_hook)(struct sk_buff *skb, unsigned int protoff,
			      struct nf_conn *ct,
			      enum ip_conntrack_info ctinfo, char **dptr,
			      int *dlen, struct nf_conntrack_expect *exp,
			      char **port_begin, int *port_len);

extern int (*nf_nat_snat_hook)(struct nf_conn *ct,
			       enum ip_conntrack_info ctinfo,
			       struct nf_conntrack_expect *exp);

extern int (*nf_nat_sip_hook)(struct sk_buff *skb, unsigned int protoff,
			      struct nf_conn *ct,
			      enum ip_conntrack_info ctinfo, char **dptr,
			      int *dlen, struct nf_conntrack_expect *exp,
			      char **addr_begin, int *addr_len);

struct nf_ct_sip_master {
	unsigned int	register_cseq;
	unsigned int	invite_cseq;
};
#else /* CONFIG_BCM_KF_NETFILTER */

struct nf_ct_sip_master {
	unsigned int	register_cseq;
	unsigned int	invite_cseq;
};

enum sip_expectation_classes {
	SIP_EXPECT_SIGNALLING,
	SIP_EXPECT_AUDIO,
	SIP_EXPECT_VIDEO,
	SIP_EXPECT_IMAGE,
	__SIP_EXPECT_MAX
};
#define SIP_EXPECT_MAX	(__SIP_EXPECT_MAX - 1)

struct sdp_media_type {
	const char			*name;
	unsigned int			len;
	enum sip_expectation_classes	class;
};

#define SDP_MEDIA_TYPE(__name, __class)					\
{									\
	.name	= (__name),						\
	.len	= sizeof(__name) - 1,					\
	.class	= (__class),						\
}

struct sip_handler {
	const char	*method;
	unsigned int	len;
	int		(*request)(struct sk_buff *skb, unsigned int dataoff,
				   const char **dptr, unsigned int *datalen,
				   unsigned int cseq);
	int		(*response)(struct sk_buff *skb, unsigned int dataoff,
				    const char **dptr, unsigned int *datalen,
				    unsigned int cseq, unsigned int code);
};

#define SIP_HANDLER(__method, __request, __response)			\
{									\
	.method		= (__method),					\
	.len		= sizeof(__method) - 1,				\
	.request	= (__request),					\
	.response	= (__response),					\
}

struct sip_header {
	const char	*name;
	const char	*cname;
	const char	*search;
	unsigned int	len;
	unsigned int	clen;
	unsigned int	slen;
	int		(*match_len)(const struct nf_conn *ct,
				     const char *dptr, const char *limit,
				     int *shift);
};

#define __SIP_HDR(__name, __cname, __search, __match)			\
{									\
	.name		= (__name),					\
	.len		= sizeof(__name) - 1,				\
	.cname		= (__cname),					\
	.clen		= (__cname) ? sizeof(__cname) - 1 : 0,		\
	.search		= (__search),					\
	.slen		= (__search) ? sizeof(__search) - 1 : 0,	\
	.match_len	= (__match),					\
}

#define SIP_HDR(__name, __cname, __search, __match) \
	__SIP_HDR(__name, __cname, __search, __match)

#define SDP_HDR(__name, __search, __match) \
	__SIP_HDR(__name, NULL, __search, __match)

enum sip_header_types {
	SIP_HDR_CSEQ,
	SIP_HDR_FROM,
	SIP_HDR_TO,
	SIP_HDR_CONTACT,
#ifdef ZYXEL_SIP_ALG_SUPPORT_RM_ALL_BINDING
	SIP_HDR_CONTACT_RM_ALL_BINDING,
#endif //#ifdef ZYXEL_SIP_ALG_SUPPORT_RM_ALL_BINDING
	SIP_HDR_VIA_UDP,
	SIP_HDR_VIA_TCP,
	SIP_HDR_EXPIRES,
	SIP_HDR_CONTENT_LENGTH,
	SIP_HDR_CALL_ID,
};

enum sdp_header_types {
	SDP_HDR_UNSPEC,
	SDP_HDR_VERSION,
	SDP_HDR_OWNER_IP4,
	SDP_HDR_CONNECTION_IP4,
	SDP_HDR_OWNER_IP6,
	SDP_HDR_CONNECTION_IP6,
	SDP_HDR_MEDIA,
};

extern unsigned int (*nf_nat_sip_hook)(struct sk_buff *skb,
				       unsigned int dataoff,
				       const char **dptr,
				       unsigned int *datalen);
extern void (*nf_nat_sip_seq_adjust_hook)(struct sk_buff *skb, s16 off);
extern unsigned int (*nf_nat_sip_expect_hook)(struct sk_buff *skb,
					      unsigned int dataoff,
					      const char **dptr,
					      unsigned int *datalen,
					      struct nf_conntrack_expect *exp,
					      unsigned int matchoff,
					      unsigned int matchlen);
extern unsigned int (*nf_nat_sdp_addr_hook)(struct sk_buff *skb,
					    unsigned int dataoff,
					    const char **dptr,
					    unsigned int *datalen,
					    unsigned int sdpoff,
					    enum sdp_header_types type,
					    enum sdp_header_types term,
					    const union nf_inet_addr *addr);
extern unsigned int (*nf_nat_sdp_port_hook)(struct sk_buff *skb,
					    unsigned int dataoff,
					    const char **dptr,
					    unsigned int *datalen,
					    unsigned int matchoff,
					    unsigned int matchlen,
					    u_int16_t port);
extern unsigned int (*nf_nat_sdp_session_hook)(struct sk_buff *skb,
					       unsigned int dataoff,
					       const char **dptr,
					       unsigned int *datalen,
					       unsigned int sdpoff,
					       const union nf_inet_addr *addr);
extern unsigned int (*nf_nat_sdp_media_hook)(struct sk_buff *skb,
					     unsigned int dataoff,
					     const char **dptr,
					     unsigned int *datalen,
					     struct nf_conntrack_expect *rtp_exp,
					     struct nf_conntrack_expect *rtcp_exp,
					     unsigned int mediaoff,
					     unsigned int medialen,
					     union nf_inet_addr *rtp_addr);

extern int ct_sip_parse_request(const struct nf_conn *ct,
				const char *dptr, unsigned int datalen,
				unsigned int *matchoff, unsigned int *matchlen,
				union nf_inet_addr *addr, __be16 *port);
extern int ct_sip_get_header(const struct nf_conn *ct, const char *dptr,
			     unsigned int dataoff, unsigned int datalen,
			     enum sip_header_types type,
			     unsigned int *matchoff, unsigned int *matchlen);
extern int ct_sip_parse_header_uri(const struct nf_conn *ct, const char *dptr,
				   unsigned int *dataoff, unsigned int datalen,
				   enum sip_header_types type, int *in_header,
				   unsigned int *matchoff, unsigned int *matchlen,
				   union nf_inet_addr *addr, __be16 *port);
extern int ct_sip_parse_address_param(const struct nf_conn *ct, const char *dptr,
				      unsigned int dataoff, unsigned int datalen,
				      const char *name,
				      unsigned int *matchoff, unsigned int *matchlen,
				      union nf_inet_addr *addr);
extern int ct_sip_parse_numerical_param(const struct nf_conn *ct, const char *dptr,
					unsigned int off, unsigned int datalen,
					const char *name,
					unsigned int *matchoff, unsigned int *matchen,
					unsigned int *val);

extern int ct_sip_get_sdp_header(const struct nf_conn *ct, const char *dptr,
				 unsigned int dataoff, unsigned int datalen,
				 enum sdp_header_types type,
				 enum sdp_header_types term,
				 unsigned int *matchoff, unsigned int *matchlen);
#endif /* CONFIG_BCM_KF_NETFILTER */
#endif /* __KERNEL__ */
#endif /* __NF_CONNTRACK_SIP_H__ */

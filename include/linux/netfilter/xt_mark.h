#ifndef _XT_MARK_H
#define _XT_MARK_H

#include <linux/types.h>

/* Version 1 */
#if 1 /* ZyXEL QoS, John (porting from MSTC) */
enum {
        XT_MARK_SET=0,
        XT_MARK_AND,
        XT_MARK_OR,
	XT_MARK_VTAG_SET
};
#endif

struct xt_mark_tginfo2 {
	__u32 mark, mask;
#if 1 /* ZyXEL QoS, John */
	__u8 mode;
#endif
};

struct xt_mark_mtinfo1 {
	__u32 mark, mask;
	__u8 invert;
};

#endif /*_XT_MARK_H*/

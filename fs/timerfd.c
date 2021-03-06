/*
 *  fs/timerfd.c
 *
 *  Copyright (C) 2007  Davide Libenzi <davidel@xmailserver.org>
 *
 *
 *  Thanks to Thomas Gleixner for code reviews and useful comments.
 *
 */

#if defined(CONFIG_BCM_KF_ANDROID) && defined(CONFIG_BCM_ANDROID)
#include <linux/alarmtimer.h>
#endif
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/time.h>
#include <linux/hrtimer.h>
#include <linux/anon_inodes.h>
#include <linux/timerfd.h>
#include <linux/syscalls.h>
#include <linux/rcupdate.h>

struct timerfd_ctx {
#if !defined(CONFIG_BCM_KF_ANDROID) || !defined(CONFIG_BCM_ANDROID)
	struct hrtimer tmr;
#else
	union {
		struct hrtimer tmr;
		struct alarm alarm;
	} t;
#endif
	ktime_t tintv;
	ktime_t moffs;
	wait_queue_head_t wqh;
	u64 ticks;
	int expired;
	int clockid;
	struct rcu_head rcu;
	struct list_head clist;
	bool might_cancel;
};

static LIST_HEAD(cancel_list);
static DEFINE_SPINLOCK(cancel_lock);

#if defined(CONFIG_BCM_KF_ANDROID) && defined(CONFIG_BCM_ANDROID)
static inline bool isalarm(struct timerfd_ctx *ctx)
{
	return ctx->clockid == CLOCK_REALTIME_ALARM ||
		ctx->clockid == CLOCK_BOOTTIME_ALARM;
}

#endif
/*
 * This gets called when the timer event triggers. We set the "expired"
 * flag, but we do not re-arm the timer (in case it's necessary,
 * tintv.tv64 != 0) until the timer is accessed.
 */
#if !defined(CONFIG_BCM_KF_ANDROID) || !defined(CONFIG_BCM_ANDROID)
static enum hrtimer_restart timerfd_tmrproc(struct hrtimer *htmr)
#else
static void timerfd_triggered(struct timerfd_ctx *ctx)
#endif
{
#if !defined(CONFIG_BCM_KF_ANDROID) || !defined(CONFIG_BCM_ANDROID)
	struct timerfd_ctx *ctx = container_of(htmr, struct timerfd_ctx, tmr);
#endif
	unsigned long flags;

	spin_lock_irqsave(&ctx->wqh.lock, flags);
	ctx->expired = 1;
	ctx->ticks++;
	wake_up_locked(&ctx->wqh);
	spin_unlock_irqrestore(&ctx->wqh.lock, flags);
#if defined(CONFIG_BCM_KF_ANDROID) && defined(CONFIG_BCM_ANDROID)
}
#endif

#if defined(CONFIG_BCM_KF_ANDROID) && defined(CONFIG_BCM_ANDROID)
static enum hrtimer_restart timerfd_tmrproc(struct hrtimer *htmr)
{
	struct timerfd_ctx *ctx = container_of(htmr, struct timerfd_ctx,
					       t.tmr);
	timerfd_triggered(ctx);
#endif
	return HRTIMER_NORESTART;
}

#if defined(CONFIG_BCM_KF_ANDROID) && defined(CONFIG_BCM_ANDROID)
static enum alarmtimer_restart timerfd_alarmproc(struct alarm *alarm,
	ktime_t now)
{
	struct timerfd_ctx *ctx = container_of(alarm, struct timerfd_ctx,
					       t.alarm);
	timerfd_triggered(ctx);
	return ALARMTIMER_NORESTART;
}

#endif
/*
 * Called when the clock was set to cancel the timers in the cancel
 * list. This will wake up processes waiting on these timers. The
 * wake-up requires ctx->ticks to be non zero, therefore we increment
 * it before calling wake_up_locked().
 */
void timerfd_clock_was_set(void)
{
	ktime_t moffs = ktime_get_monotonic_offset();
	struct timerfd_ctx *ctx;
	unsigned long flags;

	rcu_read_lock();
	list_for_each_entry_rcu(ctx, &cancel_list, clist) {
		if (!ctx->might_cancel)
			continue;
		spin_lock_irqsave(&ctx->wqh.lock, flags);
		if (ctx->moffs.tv64 != moffs.tv64) {
			ctx->moffs.tv64 = KTIME_MAX;
			ctx->ticks++;
			wake_up_locked(&ctx->wqh);
		}
		spin_unlock_irqrestore(&ctx->wqh.lock, flags);
	}
	rcu_read_unlock();
}

static void timerfd_remove_cancel(struct timerfd_ctx *ctx)
{
	if (ctx->might_cancel) {
		ctx->might_cancel = false;
		spin_lock(&cancel_lock);
		list_del_rcu(&ctx->clist);
		spin_unlock(&cancel_lock);
	}
}

static bool timerfd_canceled(struct timerfd_ctx *ctx)
{
	if (!ctx->might_cancel || ctx->moffs.tv64 != KTIME_MAX)
		return false;
	ctx->moffs = ktime_get_monotonic_offset();
	return true;
}

static void timerfd_setup_cancel(struct timerfd_ctx *ctx, int flags)
{
#if !defined(CONFIG_BCM_KF_ANDROID) || !defined(CONFIG_BCM_ANDROID)
	if (ctx->clockid == CLOCK_REALTIME && (flags & TFD_TIMER_ABSTIME) &&
	    (flags & TFD_TIMER_CANCEL_ON_SET)) {
#else
	if ((ctx->clockid == CLOCK_REALTIME ||
	     ctx->clockid == CLOCK_REALTIME_ALARM) &&
	    (flags & TFD_TIMER_ABSTIME) && (flags & TFD_TIMER_CANCEL_ON_SET)) {
#endif
		if (!ctx->might_cancel) {
			ctx->might_cancel = true;
			spin_lock(&cancel_lock);
			list_add_rcu(&ctx->clist, &cancel_list);
			spin_unlock(&cancel_lock);
		}
	} else if (ctx->might_cancel) {
		timerfd_remove_cancel(ctx);
	}
}

static ktime_t timerfd_get_remaining(struct timerfd_ctx *ctx)
{
	ktime_t remaining;

#if !defined(CONFIG_BCM_KF_ANDROID) || !defined(CONFIG_BCM_ANDROID)
	remaining = hrtimer_expires_remaining(&ctx->tmr);
#else
	if (isalarm(ctx))
		remaining = alarm_expires_remaining(&ctx->t.alarm);
	else
		remaining = hrtimer_expires_remaining(&ctx->t.tmr);

#endif
	return remaining.tv64 < 0 ? ktime_set(0, 0): remaining;
}

static int timerfd_setup(struct timerfd_ctx *ctx, int flags,
			 const struct itimerspec *ktmr)
{
	enum hrtimer_mode htmode;
	ktime_t texp;
	int clockid = ctx->clockid;

	htmode = (flags & TFD_TIMER_ABSTIME) ?
		HRTIMER_MODE_ABS: HRTIMER_MODE_REL;

	texp = timespec_to_ktime(ktmr->it_value);
	ctx->expired = 0;
	ctx->ticks = 0;
	ctx->tintv = timespec_to_ktime(ktmr->it_interval);
#if !defined(CONFIG_BCM_KF_ANDROID) || !defined(CONFIG_BCM_ANDROID)
	hrtimer_init(&ctx->tmr, clockid, htmode);
	hrtimer_set_expires(&ctx->tmr, texp);
	ctx->tmr.function = timerfd_tmrproc;
#else

	if (isalarm(ctx)) {
		alarm_init(&ctx->t.alarm,
			   ctx->clockid == CLOCK_REALTIME_ALARM ?
			   ALARM_REALTIME : ALARM_BOOTTIME,
			   timerfd_alarmproc);
	} else {
		hrtimer_init(&ctx->t.tmr, clockid, htmode);
		hrtimer_set_expires(&ctx->t.tmr, texp);
		ctx->t.tmr.function = timerfd_tmrproc;
	}

#endif
	if (texp.tv64 != 0) {
#if !defined(CONFIG_BCM_KF_ANDROID) || !defined(CONFIG_BCM_ANDROID)
		hrtimer_start(&ctx->tmr, texp, htmode);
#else
		if (isalarm(ctx)) {
			if (flags & TFD_TIMER_ABSTIME)
				alarm_start(&ctx->t.alarm, texp);
			else
				alarm_start_relative(&ctx->t.alarm, texp);
		} else {
			hrtimer_start(&ctx->t.tmr, texp, htmode);
		}

#endif
		if (timerfd_canceled(ctx))
			return -ECANCELED;
	}
	return 0;
}

static int timerfd_release(struct inode *inode, struct file *file)
{
	struct timerfd_ctx *ctx = file->private_data;

	timerfd_remove_cancel(ctx);
#if !defined(CONFIG_BCM_KF_ANDROID) || !defined(CONFIG_BCM_ANDROID)
	hrtimer_cancel(&ctx->tmr);
#else

	if (isalarm(ctx))
		alarm_cancel(&ctx->t.alarm);
	else
		hrtimer_cancel(&ctx->t.tmr);
#endif
	kfree_rcu(ctx, rcu);
	return 0;
}

static unsigned int timerfd_poll(struct file *file, poll_table *wait)
{
	struct timerfd_ctx *ctx = file->private_data;
	unsigned int events = 0;
	unsigned long flags;

	poll_wait(file, &ctx->wqh, wait);

	spin_lock_irqsave(&ctx->wqh.lock, flags);
	if (ctx->ticks)
		events |= POLLIN;
	spin_unlock_irqrestore(&ctx->wqh.lock, flags);

	return events;
}

static ssize_t timerfd_read(struct file *file, char __user *buf, size_t count,
			    loff_t *ppos)
{
	struct timerfd_ctx *ctx = file->private_data;
	ssize_t res;
	u64 ticks = 0;

	if (count < sizeof(ticks))
		return -EINVAL;
	spin_lock_irq(&ctx->wqh.lock);
	if (file->f_flags & O_NONBLOCK)
		res = -EAGAIN;
	else
		res = wait_event_interruptible_locked_irq(ctx->wqh, ctx->ticks);

	/*
	 * If clock has changed, we do not care about the
	 * ticks and we do not rearm the timer. Userspace must
	 * reevaluate anyway.
	 */
	if (timerfd_canceled(ctx)) {
		ctx->ticks = 0;
		ctx->expired = 0;
		res = -ECANCELED;
	}

	if (ctx->ticks) {
		ticks = ctx->ticks;

		if (ctx->expired && ctx->tintv.tv64) {
			/*
			 * If tintv.tv64 != 0, this is a periodic timer that
			 * needs to be re-armed. We avoid doing it in the timer
			 * callback to avoid DoS attacks specifying a very
			 * short timer period.
			 */
#if !defined(CONFIG_BCM_KF_ANDROID) || !defined(CONFIG_BCM_ANDROID)
			ticks += hrtimer_forward_now(&ctx->tmr,
						     ctx->tintv) - 1;
			hrtimer_restart(&ctx->tmr);
#else
			if (isalarm(ctx)) {
				ticks += alarm_forward_now(
					&ctx->t.alarm, ctx->tintv) - 1;
				alarm_restart(&ctx->t.alarm);
			} else {
				ticks += hrtimer_forward_now(&ctx->t.tmr,
							     ctx->tintv) - 1;
				hrtimer_restart(&ctx->t.tmr);
			}
#endif
		}
		ctx->expired = 0;
		ctx->ticks = 0;
	}
	spin_unlock_irq(&ctx->wqh.lock);
	if (ticks)
		res = put_user(ticks, (u64 __user *) buf) ? -EFAULT: sizeof(ticks);
	return res;
}

static const struct file_operations timerfd_fops = {
	.release	= timerfd_release,
	.poll		= timerfd_poll,
	.read		= timerfd_read,
	.llseek		= noop_llseek,
};

static struct file *timerfd_fget(int fd)
{
	struct file *file;

	file = fget(fd);
	if (!file)
		return ERR_PTR(-EBADF);
	if (file->f_op != &timerfd_fops) {
		fput(file);
		return ERR_PTR(-EINVAL);
	}

	return file;
}

SYSCALL_DEFINE2(timerfd_create, int, clockid, int, flags)
{
	int ufd;
	struct timerfd_ctx *ctx;

	/* Check the TFD_* constants for consistency.  */
	BUILD_BUG_ON(TFD_CLOEXEC != O_CLOEXEC);
	BUILD_BUG_ON(TFD_NONBLOCK != O_NONBLOCK);

	if ((flags & ~TFD_CREATE_FLAGS) ||
	    (clockid != CLOCK_MONOTONIC &&
#if !defined(CONFIG_BCM_KF_ANDROID) || !defined(CONFIG_BCM_ANDROID)
	     clockid != CLOCK_REALTIME))
#else
	     clockid != CLOCK_REALTIME &&
	     clockid != CLOCK_REALTIME_ALARM &&
	     clockid != CLOCK_BOOTTIME_ALARM))
#endif
		return -EINVAL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	init_waitqueue_head(&ctx->wqh);
	ctx->clockid = clockid;
#if !defined(CONFIG_BCM_KF_ANDROID) || !defined(CONFIG_BCM_ANDROID)
	hrtimer_init(&ctx->tmr, clockid, HRTIMER_MODE_ABS);
#else

	if (isalarm(ctx))
		alarm_init(&ctx->t.alarm,
			   ctx->clockid == CLOCK_REALTIME_ALARM ?
			   ALARM_REALTIME : ALARM_BOOTTIME,
			   timerfd_alarmproc);
	else
		hrtimer_init(&ctx->t.tmr, clockid, HRTIMER_MODE_ABS);

#endif
	ctx->moffs = ktime_get_monotonic_offset();

	ufd = anon_inode_getfd("[timerfd]", &timerfd_fops, ctx,
			       O_RDWR | (flags & TFD_SHARED_FCNTL_FLAGS));
	if (ufd < 0)
		kfree(ctx);

	return ufd;
}

SYSCALL_DEFINE4(timerfd_settime, int, ufd, int, flags,
		const struct itimerspec __user *, utmr,
		struct itimerspec __user *, otmr)
{
	struct file *file;
	struct timerfd_ctx *ctx;
	struct itimerspec ktmr, kotmr;
	int ret;

	if (copy_from_user(&ktmr, utmr, sizeof(ktmr)))
		return -EFAULT;

	if ((flags & ~TFD_SETTIME_FLAGS) ||
	    !timespec_valid(&ktmr.it_value) ||
	    !timespec_valid(&ktmr.it_interval))
		return -EINVAL;

	file = timerfd_fget(ufd);
	if (IS_ERR(file))
		return PTR_ERR(file);
	ctx = file->private_data;

	timerfd_setup_cancel(ctx, flags);

	/*
	 * We need to stop the existing timer before reprogramming
	 * it to the new values.
	 */
	for (;;) {
		spin_lock_irq(&ctx->wqh.lock);
#if !defined(CONFIG_BCM_KF_ANDROID) || !defined(CONFIG_BCM_ANDROID)
		if (hrtimer_try_to_cancel(&ctx->tmr) >= 0)
			break;
#else

		if (isalarm(ctx)) {
			if (alarm_try_to_cancel(&ctx->t.alarm) >= 0)
				break;
		} else {
			if (hrtimer_try_to_cancel(&ctx->t.tmr) >= 0)
				break;
		}
#endif
		spin_unlock_irq(&ctx->wqh.lock);
#if !defined(CONFIG_BCM_KF_ANDROID) || !defined(CONFIG_BCM_ANDROID)
		hrtimer_wait_for_timer(&ctx->tmr);
#else
		cpu_relax();
#endif
	}

	/*
	 * If the timer is expired and it's periodic, we need to advance it
	 * because the caller may want to know the previous expiration time.
	 * We do not update "ticks" and "expired" since the timer will be
	 * re-programmed again in the following timerfd_setup() call.
	 */
#if !defined(CONFIG_BCM_KF_ANDROID) || !defined(CONFIG_BCM_ANDROID)
	if (ctx->expired && ctx->tintv.tv64)
		hrtimer_forward_now(&ctx->tmr, ctx->tintv);
#else
	if (ctx->expired && ctx->tintv.tv64) {
		if (isalarm(ctx))
			alarm_forward_now(&ctx->t.alarm, ctx->tintv);
		else
			hrtimer_forward_now(&ctx->t.tmr, ctx->tintv);
	}
#endif

	kotmr.it_value = ktime_to_timespec(timerfd_get_remaining(ctx));
	kotmr.it_interval = ktime_to_timespec(ctx->tintv);

	/*
	 * Re-program the timer to the new value ...
	 */
	ret = timerfd_setup(ctx, flags, &ktmr);

	spin_unlock_irq(&ctx->wqh.lock);
	fput(file);
	if (otmr && copy_to_user(otmr, &kotmr, sizeof(kotmr)))
		return -EFAULT;

	return ret;
}

SYSCALL_DEFINE2(timerfd_gettime, int, ufd, struct itimerspec __user *, otmr)
{
	struct file *file;
	struct timerfd_ctx *ctx;
	struct itimerspec kotmr;

	file = timerfd_fget(ufd);
	if (IS_ERR(file))
		return PTR_ERR(file);
	ctx = file->private_data;

	spin_lock_irq(&ctx->wqh.lock);
	if (ctx->expired && ctx->tintv.tv64) {
		ctx->expired = 0;
#if !defined(CONFIG_BCM_KF_ANDROID) || !defined(CONFIG_BCM_ANDROID)
		ctx->ticks +=
			hrtimer_forward_now(&ctx->tmr, ctx->tintv) - 1;
		hrtimer_restart(&ctx->tmr);
#else

		if (isalarm(ctx)) {
			ctx->ticks +=
				alarm_forward_now(
					&ctx->t.alarm, ctx->tintv) - 1;
			alarm_restart(&ctx->t.alarm);
		} else {
			ctx->ticks +=
				hrtimer_forward_now(&ctx->t.tmr, ctx->tintv)
				- 1;
			hrtimer_restart(&ctx->t.tmr);
		}
#endif
	}
	kotmr.it_value = ktime_to_timespec(timerfd_get_remaining(ctx));
	kotmr.it_interval = ktime_to_timespec(ctx->tintv);
	spin_unlock_irq(&ctx->wqh.lock);
	fput(file);

	return copy_to_user(otmr, &kotmr, sizeof(kotmr)) ? -EFAULT: 0;
}


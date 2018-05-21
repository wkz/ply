#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <ply/ply.h>
#include <ply/internal.h>

static int perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
			   int cpu, int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, hw_event, pid, cpu,
		       group_fd, flags);
}

static int perf_event_id(struct ply_probe *pb, const char *name)
{
	FILE *fp;
	int id;

	fp = fopenf("r", TRACEPATH "events/%s/%s_%s/id",
		    pb->ply->group, pb->provider->name, name);
	if (!fp)
		goto err;

	if (fscanf(fp, "%d", &id) != 1)
		goto err;

	return id;
err:
	return -errno;
}

int perf_event_attach(struct ply_probe *pb, const char *name)
{
	struct perf_event_attr attr = {};
	int fd, id;

	id = perf_event_id(pb, name);
	if (id < 0)
		return id;

	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;
	attr.config = id;

	fd = perf_event_open(&attr, -1, 0, pb->ply->group_fd, 0);
	if (fd < 0)
		return -errno;

	/* if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0)) { */
	/* 	close(fd); */
	/* 	return -errno; */
	/* } */

	if (ioctl(fd, PERF_EVENT_IOC_SET_BPF, pb->bpf_fd)) {
		close(fd);
		return -errno;
	}

	if (pb->ply->group_fd == -1)
		pb->ply->group_fd = fd;

	return fd;
}

int perf_event_enable(int group_fd)
{
	if (ioctl(group_fd, PERF_EVENT_IOC_ENABLE, 0))
		return -errno;

	return 0;
}

int perf_event_disable(int group_fd)
{
	if (ioctl(group_fd, PERF_EVENT_IOC_DISABLE, 0))
		return -errno;

	return 0;
}

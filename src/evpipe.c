#include <poll.h>
#include <stdio.h>
#include <unistd.h>

#include <ply/bpf-syscall.h>
#include <ply/evpipe.h>
#include <ply/ply.h>

#include <sys/mman.h>
#include <sys/queue.h>

struct lost_event {
	struct perf_event_header hdr;
	uint64_t id;
	uint64_t lost;
};

struct evqueue {
	int fd;
	struct perf_event_mmap_page *mem;

	void *buf;
};

TAILQ_HEAD(evhandlers, evhandler);
static struct evhandlers evh_list = TAILQ_HEAD_INITIALIZER(evh_list);
static uint64_t next_type = 0;

static evhandler_t *evhandler_find(uint64_t type)
{
	evhandler_t *evh;

	TAILQ_FOREACH(evh, &evh_list, node) {
		if (evh->type == type)
			return evh;
	}

	return NULL;
}

void evhandler_register(evhandler_t *evh)
{
	evh->type = next_type++;
	TAILQ_INSERT_TAIL(&evh_list, evh, node);
}


static int event_handle(event_t *ev, size_t size)
{
	evhandler_t *evh;

	evh = evhandler_find(ev->type);
	if (!evh) {
		_e("unknown event: type:%#"PRIx64" size:%#zx\n",
		   ev->type, size);
		return -ENOSYS;
	}

	return evh->handle(ev, evh->priv);
}

static inline uint64_t __get_head(struct perf_event_mmap_page *mem)
{
	uint64_t head = *((volatile uint64_t *)&mem->data_head);

	asm volatile("" ::: "memory");
	return head;
}

static inline void __set_tail(struct perf_event_mmap_page *mem, uint64_t tail)
{
	asm volatile("" ::: "memory");

	mem->data_tail = tail;
}

int evqueue_drain(struct evqueue *q, int strict)
{
	struct lost_event *lost;
	uint64_t size, offs, head, tail;
	uint8_t *base, *this, *next;
	event_t *ev;
	int err = 0;

	size = q->mem->data_size;
	offs = q->mem->data_offset;
	base = (uint8_t *)q->mem + offs;

	for (head = __get_head(q->mem); q->mem->data_tail != head;
	     __set_tail(q->mem, q->mem->data_tail + ev->hdr.size)) {
		tail = q->mem->data_tail;

		this = base + (tail % size);
		ev   = (void *)this;
		next = base + ((tail + ev->hdr.size) % size);

		if (next < this) {
			size_t left = (base + size) - this;

			q->buf = realloc(q->buf, ev->hdr.size);
			memcpy(q->buf, this, left);
			memcpy(q->buf + left, base, ev->hdr.size - left);
			ev = q->buf;
		}

		switch (ev->hdr.type) {
		case PERF_RECORD_SAMPLE:
			err = event_handle(ev, ev->hdr.size);
			break;

		case PERF_RECORD_LOST:
			lost = (void *)ev;

			if (strict) {
				_e("lost %"PRId64" events", lost->lost);
				err = -EOVERFLOW;
			} else {
				_w("lost %"PRId64" events", lost->lost);
			}
			break;

		default:
			_e("unknown perf event %#"PRIx32, ev->hdr.type);
			err = -EINVAL;
			break;
		}

		if (err)
			break;
	}

	return err;
}

int evqueue_init(evpipe_t *evp, uint32_t cpu, size_t size)
{
	struct perf_event_attr attr = { 0 };
	struct evqueue *q = &evp->q[cpu];
	int err;

	attr.type          = PERF_TYPE_SOFTWARE;
	attr.config        = PERF_COUNT_SW_BPF_OUTPUT;
	attr.sample_type   = PERF_SAMPLE_RAW;
	attr.wakeup_events = 1;

	q->fd = perf_event_open(&attr, -1, cpu, -1, 0);
	if (q->fd < 0) {
		_eno("could not create queue");
		return q->fd;
	}

	err = bpf_map_update(evp->mapfd, &cpu, &q->fd, BPF_ANY);
	if (err) {
		_eno("could not link map to queue");
		return err;
	}

	size += sysconf(_SC_PAGESIZE);
	q->mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, q->fd, 0);
	if (q->mem == MAP_FAILED) {
		_eno("could not mmap queue");
		return -1;
	}

	evp->poll[cpu].fd     = q->fd;
	evp->poll[cpu].events = POLLIN;
	return 0;
}

int evpipe_loop(evpipe_t *evp, int *sig, int strict)
{
	int cpu, err, ready;

	for (;!(*sig);) {
		ready = poll(evp->poll, evp->ncpus, -1);
		if (ready <= 0)
			return ready ? : 0;

		for (cpu = 0; ready && (cpu < evp->ncpus); cpu++) {
			if (!(evp->poll[cpu].revents & POLLIN))
				continue;

			err = evqueue_drain(&evp->q[cpu], strict);
			if (err)
				return err;

			ready--;
		}
	}

	return 0;
}

int evpipe_init(evpipe_t *evp, size_t qsize)
{
	uint32_t cpu;
	int err;

	if (G.dump) {
		evp->mapfd = 0xeeee;
		return 0;
	}

	evp->ncpus = sysconf(_SC_NPROCESSORS_ONLN);

	evp->mapfd = bpf_map_create(BPF_MAP_TYPE_PERF_EVENT_ARRAY,
				    sizeof(uint32_t), sizeof(int), evp->ncpus);
	if (evp->mapfd < 0) {
		_eno("could not create map");
		return evp->mapfd;
	}

	evp->q = calloc(evp->ncpus, sizeof(*evp->q));
	assert(evp->q);

	evp->poll = calloc(evp->ncpus, sizeof(*evp->poll));
	assert(evp->poll);

	for (cpu = 0; cpu < evp->ncpus; cpu++) {
		err = evqueue_init(evp, cpu, qsize);
		if (err)
			break;
	}

	return err;
}

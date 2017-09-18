/*
 * l2pipe - a layer 2 based multi interface network pipe
 *
 * Copyright (c) 2017 Andreas Steinmetz (ast@domdv.de)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include <pthread.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <poll.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <lz4.h>
#include <stdio.h>

#ifdef __GNUC__
#define LIKELY(a)	__builtin_expect((a),1)
#define UNLIKELY(a)	__builtin_expect((a),0)
#define HOT		__attribute__((hot))
#define COLD		__attribute__((cold))
#define NORETURN	__attribute__((noreturn))
#else
#define __attribute__(x)
#define LIKELY(a)	a
#define UNLIKELY(a)	a
#define HOT
#define COLD
#define NORETURN
#endif

#define H2LEN (sizeof(struct ethhdr)+sizeof(uint32_t)+2*sizeof(uint16_t))

typedef struct buffer
{
	struct buffer *next;
	union
	{
		struct
		{
			unsigned short seq;
			unsigned short hdr;
			unsigned char bfr[32768];
		} __attribute__((packed));
		unsigned char data[32772];
	} __attribute__((packed));
} BUFFER;

struct packet
{
	union
	{
		struct
		{
			struct ethhdr hdr;
			uint16_t sum;
			uint16_t len;
			uint32_t seq;
			unsigned char data[3002-H2LEN];
		} __attribute__((packed));
		uint16_t chk[3002/sizeof(uint16_t)];
	} __attribute__((packed));
} __attribute__((packed));

struct conn
{
	int fd;
	int eio;
	int tfd;
	int fin;
	int eof;
	int cnt;
	int mtu;
	int max;
	BUFFER *head;
	BUFFER *tail;
	BUFFER *pool;
	void *base;
	pthread_t h;
	unsigned char src[ETH_ALEN];
	unsigned char dst[ETH_ALEN];
	struct packet pkt[256];
};

struct compress
{
	int ein;
	int eout;
	int efin;
	pthread_t h;
	BUFFER *bfr;
	union
	{
		BUFFER *inhead;
		BUFFER **pinhead;
	};
	BUFFER *intail;
	BUFFER *outhead;
	BUFFER *outtail;
};

struct rw
{
	int io;
	int efin;
	int tot;
	int comp;
	pthread_t h;
	union
	{
		struct
		{
			int tot;
			int val;
			struct conn c;
		} tx[0];
		struct
		{
			struct compress d;
			struct conn c;
		} rx[0];
	};
};

static struct sock_filter filter[5]=
{
	{BPF_LD |BPF_H  |BPF_ABS,0,0,2*ETH_ALEN   },
	{BPF_JMP|BPF_JEQ|BPF_K,  0,2,ETH_P_802_EX1},
	{BPF_LD |BPF_B  |BPF_ABS,0,0,ETH_HLEN     },
	{BPF_RET|BPF_K,	  0,0,3002	 },
	{BPF_RET|BPF_K,	  0,0,0	    }
};

static pthread_mutex_t ptx=PTHREAD_MUTEX_INITIALIZER;
static BUFFER *pool;
static void *base;
static int ecnt;
static int err;
static int verbose;

static COLD int setprio(int mode)
{
	struct sched_param sched;

	memset(&sched,0,sizeof(sched));
	if(mode)
	{
		sched.sched_priority=1;
		return sched_setscheduler(0,SCHED_RR,&sched);
	}
	else return sched_setscheduler(0,SCHED_OTHER,&sched);
}

static COLD int setrbuf(int s,int size)
{
	socklen_t l;

	l=sizeof(size);
	if(setsockopt(s,SOL_SOCKET,SO_RCVBUF,&size,l))return -1;
	return 0;
}

static COLD int setwbuf(int s,int size)
{
	socklen_t l;

	l=sizeof(size);
	if(setsockopt(s,SOL_SOCKET,SO_SNDBUF,&size,l))return -1;
	return 0;
}

static COLD int getrbuf(int s)
{
	int size;
	socklen_t l;

	l=sizeof(size);
	if(getsockopt(s,SOL_SOCKET,SO_RCVBUF,&size,&l))return -1;
	return size>>1;
}

static COLD int getwbuf(int s)
{
	int size;
	socklen_t l;

	l=sizeof(size);
	if(getsockopt(s,SOL_SOCKET,SO_SNDBUF,&size,&l))return -1;
	return size>>1;
}

static COLD int getmtu(char *ifname)
{
	int s;
	struct ifreq ifreq;

	if((s=socket(AF_INET,SOCK_DGRAM,0))==-1)goto err1;
	memset(&ifreq,0,sizeof(ifreq));
	strncpy(ifreq.ifr_name,ifname, sizeof(ifreq.ifr_name)-1);
	if(ioctl(s,SIOCGIFMTU,&ifreq))goto err2;
	close(s);
	return ifreq.ifr_mtu;

err2:	close(s);
err1:	return -1;
}

static COLD int getmac(char *ifname,void *mac)
{
	int s;
	struct ifreq ifreq;

	if((s=socket(AF_INET,SOCK_DGRAM,0))==-1)goto err1;
	memset(&ifreq,0,sizeof(ifreq));
	strncpy(ifreq.ifr_name,ifname, sizeof(ifreq.ifr_name)-1);
	if(ioctl(s,SIOCGIFHWADDR,&ifreq))goto err2;
	close(s);
	if(ifreq.ifr_hwaddr.sa_family!=ARPHRD_ETHER)goto err1;
	memcpy(mac,ifreq.ifr_hwaddr.sa_data,ETH_ALEN);
	return 0;

err2:	close(s);
err1:	return -1;
}

static COLD int mksock(char *ifname,struct conn *c)
{
	int mtu;
	int rsize;
	int wsize;
	int size;
	struct ifreq ifreq;
	struct sockaddr_ll addr;
	struct sock_fprog prg={5,filter};

	if((c->fd=socket(PF_PACKET,SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC,
		htons(ETH_P_ALL)))==-1)goto err1;
	memset(&ifreq,0,sizeof(ifreq));
	strncpy(ifreq.ifr_name,ifname, sizeof(ifreq.ifr_name)-1);
	if(ioctl(c->fd,SIOCGIFINDEX,&ifreq))goto err2;
	memset(&addr,0,sizeof(addr));
	addr.sll_ifindex=ifreq.ifr_ifindex;
	addr.sll_family=AF_PACKET;
	addr.sll_protocol=htons(ETH_P_ALL);
	if(setsockopt(c->fd,SOL_SOCKET,SO_ATTACH_FILTER,&prg,sizeof(prg)))
		goto err2;
	if(setsockopt(c->fd,SOL_SOCKET,SO_BINDTODEVICE,ifname,strlen(ifname)))
		goto err2;
	if(bind(c->fd,(struct sockaddr *)&addr,sizeof(addr)))goto err2;
	if((mtu=getmtu(ifname))<1500)goto err2;
	if(mtu>3002)mtu=3002;
	setrbuf(c->fd,mtu<<6);
	setwbuf(c->fd,mtu<<6);
	rsize=getrbuf(c->fd);
	wsize=getwbuf(c->fd);
	if((size=rsize<wsize?rsize:wsize)<0)goto err2;
	if((size>>=6)<1500)goto err2;
	if(mtu>size)mtu=size;
	if(getmac(ifname,c->src))goto err2;
	c->mtu=(size<mtu?size:mtu);
	c->max=c->mtu-H2LEN;
	return 0;

err2:	close(c->fd);
err1:	return -1;
}

static COLD int doconnect(struct conn *c)
{
	int mtu;
	struct pollfd p[2];
	struct ethhdr hdr;
	struct msghdr msg;
	struct iovec iov[2];
	unsigned short bfr[25];

	iov[0].iov_base=&hdr;
	iov[0].iov_len=sizeof(hdr);
	iov[1].iov_base=bfr;
	iov[1].iov_len=sizeof(bfr);
	msg.msg_name=NULL;
	msg.msg_namelen=0;
	msg.msg_iov=iov;
	msg.msg_iovlen=2;
	msg.msg_control=NULL;
	msg.msg_controllen=0;
	msg.msg_flags=0;
	memset(hdr.h_dest,0xff,sizeof(c->dst));
	memcpy(hdr.h_source,c->src,sizeof(c->src));
	hdr.h_proto=htons(ETH_P_802_EX1);
	bfr[0]=htons(c->mtu);
	if(sendmsg(c->fd,&msg,0)!=64)goto err1;
	p[0].fd=c->fd;
	p[0].events=POLLIN;
	p[1].fd=c->fin;
	p[1].events=POLLIN;
again:	if(poll(p,2,20)<1)goto err1;
	if(p[1].revents&POLLIN)goto err1;
	if(!(p[0].revents&POLLIN))goto again;
	if(recvmsg(c->fd,&msg,0)<64)goto err1;
	if(memcmp(hdr.h_dest,c->src,sizeof(c->src)))goto again;
	if(hdr.h_proto!=htons(ETH_P_802_EX1))goto again;
	mtu=ntohs(bfr[0]);
	if(mtu<1500||mtu>3002)goto err1;
	memcpy(c->dst,hdr.h_source,sizeof(c->dst));
	if(mtu<c->mtu)
	{
		c->mtu=mtu;
		c->max=mtu-H2LEN;
	}
	return 0;

err1:	return -1;
}

static COLD int doaccept(struct conn *c)
{
	int mtu;
	struct pollfd p[2];
	struct ethhdr hdr;
	struct msghdr msg;
	struct iovec iov[2];
	unsigned short bfr[25];

	memset(c->dst,0xff,sizeof(c->dst));
	iov[0].iov_base=&hdr;
	iov[0].iov_len=sizeof(hdr);
	iov[1].iov_base=bfr;
	iov[1].iov_len=sizeof(bfr);
	msg.msg_name=NULL;
	msg.msg_namelen=0;
	msg.msg_iov=iov;
	msg.msg_iovlen=2;
	msg.msg_control=NULL;
	msg.msg_controllen=0;
	msg.msg_flags=0;
	p[0].fd=c->fd;
	p[0].events=POLLIN;
	p[1].fd=c->fin;
	p[1].events=POLLIN;
again:	if(poll(p,2,-1)<1)goto err1;
	if(p[1].revents&POLLIN)goto err1;
	if(!(p[0].revents&POLLIN))goto again;
	if(recvmsg(c->fd,&msg,0)<64)goto err1;
	if(memcmp(hdr.h_dest,c->dst,sizeof(c->dst)))goto again;
	if(hdr.h_proto!=htons(ETH_P_802_EX1))goto again;
	mtu=ntohs(bfr[0]);
	if(mtu<1500||mtu>3002)goto err1;
	memcpy(c->dst,hdr.h_source,sizeof(c->src));
	memcpy(hdr.h_dest,c->dst,sizeof(c->dst));
	memcpy(hdr.h_source,c->src,sizeof(c->src));
	hdr.h_proto=htons(ETH_P_802_EX1);
	bfr[0]=htons(c->mtu);
	if(sendmsg(c->fd,&msg,0)!=64)goto err1;
	if(mtu<c->mtu)
	{
		c->mtu=mtu;
		c->max=mtu-H2LEN;
	}
	return 0;

err1:	return -1;
}

static COLD int mkpool(BUFFER **chain,void **mem,int *efd,int total)
{       
	int i; 
	BUFFER *ptr;
	
	if((*efd=eventfd(total,EFD_CLOEXEC|EFD_NONBLOCK|EFD_SEMAPHORE))==-1)
		return -1;
	if(!(*mem=ptr=malloc(total*sizeof(BUFFER))))
	{       
		close(*efd);
		return -1;
	}
	for(*chain=NULL,i=0;i<total;i++)
	{       
		ptr[i].next=*chain;
		*chain=&ptr[i];
	}
	return 0;
}

static HOT BUFFER *poolget(BUFFER **chain,int efd)
{       
	uint64_t dummy;
	BUFFER *ptr;
	
	if(read(efd,&dummy,sizeof(dummy))!=sizeof(dummy))return NULL;
	pthread_mutex_lock(&ptx);
	ptr=*chain;
	*chain=ptr->next;
	pthread_mutex_unlock(&ptx);
	return ptr;
}

static HOT void poolput(BUFFER **chain,int efd,BUFFER *ptr)
{
	uint64_t dummy=1;

	if(!ptr)return;
	pthread_mutex_lock(&ptx);
	ptr->next=*chain;
	*chain=ptr;
	pthread_mutex_unlock(&ptx);
	dummy=write(efd,&dummy,sizeof(dummy));
}

static HOT void *sender(void *d)
{
	uint32_t head;
	uint32_t tail;
	uint32_t tx;
	uint32_t idx;
	uint32_t val;
	int i;
	int j;
	int l;
	int l2;
	int wtick;
	int rtick;
	int stall;
	int inflight;
	int fill;
	int eof;
	int again;
	int hold;
	uint64_t dummy;
	struct conn *data=d;
	uint16_t *ptr;
	BUFFER *bfr;
	struct itimerspec it;
	struct pollfd p[5];
	struct packet pkt;
	struct packet idle;
	unsigned char state[256];
	int len[256];

	it.it_interval.tv_sec=0;
	it.it_interval.tv_nsec=10000000;
	it.it_value.tv_sec=0;
	it.it_value.tv_nsec=10000000;

	p[0].fd=data->eio;
	p[1].fd=data->fd;
	p[1].events=POLLIN;
	p[2].fd=data->tfd;
	p[2].events=POLLIN;
	p[3].fd=data->fin;
	p[3].events=POLLIN;
	p[4].fd=data->eof;

	wtick=0;
	rtick=0;
	stall=0;
	inflight=0;
	fill=0;
	head=0;
	tail=0;
	tx=0;
	idx=0;
	eof=0;
	again=0;
	hold=1;

	if(doconnect(data))
	{
		if(verbose)fprintf(stderr,"connect error\n");
		pthread_mutex_lock(&ptx);
		err=1;
		pthread_mutex_unlock(&ptx);
		dummy=1;
		dummy=write(data->fin,&dummy,sizeof(dummy));
		pthread_exit(NULL);
	}

	for(i=0;i<256;i++)
	{
		state[i]=0;
		memcpy(data->pkt[i].hdr.h_dest,data->dst,ETH_ALEN);
		memcpy(data->pkt[i].hdr.h_source,data->src,ETH_ALEN);
		data->pkt[i].hdr.h_proto=htons(ETH_P_802_EX1);
	}

	memcpy(idle.hdr.h_dest,data->dst,ETH_ALEN);
	memcpy(idle.hdr.h_source,data->src,ETH_ALEN);
	idle.hdr.h_proto=htons(ETH_P_802_EX1);
	idle.sum=0;
	idle.len=htons(0x8000);
	idle.seq=0;

	for(i=0,idx=0;i<H2LEN>>1;i++)idx+=ntohs(idle.chk[i]);
	idx=(idx&0xffff)+(idx>>16);
	idx=(idx&0xffff)+(idx>>16);
	idle.sum=htons(~idx);

	timerfd_settime(data->tfd,0,&it,NULL);

	while(LIKELY(rtick<25))
	{
		if(fill<=224)
		{
			p[0].events=POLLIN;
			if(LIKELY(!eof))p[4].events=POLLIN;
			else
			{
				p[4].events=0;
				p[4].revents=0;
			}
		}
		else
		{
			p[0].events=0;
			p[0].revents=0;
			p[4].events=0;
			p[4].revents=0;
		}

		while(UNLIKELY(poll(p,5,UNLIKELY(again)?0:-1)<0));

		if(UNLIKELY(p[3].revents&POLLIN))break;

		if(p[0].revents&POLLIN)
			if(LIKELY(read(data->eio,&dummy,sizeof(dummy))
				==sizeof(dummy)))
		{
			pthread_mutex_lock(&ptx);
			bfr=data->head;
			data->head=bfr->next;
			pthread_mutex_unlock(&ptx);
			if(ntohs(bfr->seq)&0x8000)l=4;
			else l=(ntohs(bfr->hdr)&0x7fff)+5;
			for(j=0,l2=0;l;l-=len[i],j+=len[i])
			{
				i=head++&0xff;
				state[i]=0;
				if(l>data->max)len[i]=data->max;
				else len[i]=l;
				memcpy(data->pkt[i].data,bfr->data+l2,len[i]);
				l2+=len[i];
				fill++;
			}
			poolput(&pool,ecnt,bfr);
		}

		if(UNLIKELY(p[4].revents&POLLIN))if(!(p[0].revents&POLLIN))
			if(!eof)
		{
			eof=1;
			i=head++&0xff;
			state[i]=0;
			len[i]=0;
			fill++;
		}

		if(p[2].revents&POLLIN)
			if(LIKELY(read(data->tfd,&dummy,sizeof(dummy))
				==sizeof(dummy)))
		{
			rtick++;
			wtick++;
		}

		if(p[1].revents&POLLIN)
		  if(LIKELY((l=recv(data->fd,&pkt,data->mtu,0))>=64))
		    if(LIKELY(!memcmp(pkt.hdr.h_dest,data->src,ETH_ALEN)))
		      if(LIKELY(!memcmp(pkt.hdr.h_source,data->dst,ETH_ALEN)))
			if(LIKELY(pkt.hdr.h_proto==htons(ETH_P_802_EX1)))
		{
			if(UNLIKELY((l2=ntohs(pkt.len))&0x8000))l2=H2LEN;
			else l2=(l2+H2LEN+1)&(~1);
			if(LIKELY(l>=l2))
			{
				for(idx=0,j=0,l2>>=1,ptr=pkt.chk;j<l2;j++)
					idx=idx+ntohs(ptr[j]);
				idx=(idx&0xffff)+(idx>>16);
				idx=(idx&0xffff)+(idx>>16);
				if(LIKELY(idx==0xffff))
				{
					rtick=0;
					stall=0;
					if(LIKELY(!pkt.len))
					{
						i=idx=ntohl(pkt.seq);
						i&=0xff;
						idx-=tail;
						val=tx-tail;
						if(LIKELY(idx<val))
							switch(state[i])
						{
						case 1:	inflight--;
						case 2:	state[i]=0;
						}
						for(i=tail&0xff;fill&&!state[i]
							&&tx!=tail;)
						{
							fill--;
							i=++tail&0xff;
						}
						hold=1;
					}
					else hold=7;
				}
			}
		}

		if(UNLIKELY(hold!=1))again=0;

		if(UNLIKELY(again))for(again=0,i=0;i<32;i++)
		{
			idx=tail+(uint32_t)i;
			if(UNLIKELY(idx==tx))break;
			idx&=0xff;
			if(!state[idx])continue;
			l=(len[idx]+H2LEN+1)&(~1);
			if(l<64)l=64;
			if(UNLIKELY(send(data->fd,&data->pkt[idx],l,0)!=l))break;
			if(state[idx]==1)
			{
				state[idx]=2;
				inflight--;
			}
			wtick=0;
		}
		else if(UNLIKELY((inflight||hold==7)&&rtick&&!(rtick&hold)&&
			rtick!=stall))for(stall=rtick,i=0;i<32;i++)
		{
			idx=tail+(uint32_t)i;
			if(UNLIKELY(idx==tx))break;
			idx&=0xff;
			if(!state[idx])continue;
			l=(len[idx]+H2LEN+1)&(~1);
			if(l<64)l=64;
			if(UNLIKELY(send(data->fd,&data->pkt[idx],l,0)!=l))break;
			if(state[idx]==1)
			{
				state[idx]=2;
				inflight--;
			}
			wtick=0;
		}

		for(idx=tx-tail;inflight<32&&tx!=head&&idx<160;)
		{
			i=tx&0xff;
			l=(len[i]+H2LEN+1)&(~1);
			l2=l>>1;
			if(l<64)l=64;
			data->pkt[i].sum=0;
			data->pkt[i].len=htons(len[i]);
			data->pkt[i].seq=htonl(tx);
			for(j=0,idx=0,ptr=data->pkt[i].chk;j<l2;j++)
				idx+=ntohs(ptr[j]);
			idx=(idx&0xffff)+(idx>>16);
			idx=(idx&0xffff)+(idx>>16);
			data->pkt[i].sum=htons(~idx);
			if(UNLIKELY(send(data->fd,&data->pkt[i],l,0)!=l))break;
			wtick=0;
			state[i]=1;
			inflight++;
			idx=++tx-tail;
			if(idx==64||idx==128)again=1;
		}

		if(UNLIKELY(wtick>=10))if(LIKELY(send(data->fd,&idle,64,0)==64))
			wtick=0;

		if(UNLIKELY(eof))if(!fill)break;
	}

	if(rtick>=25)
	{
		if(verbose)fprintf(stderr,"receive timeout\n");
		pthread_mutex_lock(&ptx);
		err=1;
		pthread_mutex_unlock(&ptx);
		dummy=1;
		dummy=write(data->fin,&dummy,sizeof(dummy));
	}

	memset(&it,0,sizeof(it));
	timerfd_settime(data->tfd,0,&it,NULL);
	dummy=read(data->tfd,&dummy,sizeof(dummy));

	pthread_exit(NULL);
}

static HOT void *compressor(void *d)
{
	int ilen;
	int olen;
	uint64_t dummy;
	struct compress *data=d;
	BUFFER *in;
	BUFFER *out;
	BUFFER *res;
	struct pollfd p[2];

	if(setprio(0))
	{
		if(verbose)fprintf(stderr,"compressor prio setup error\n");
		pthread_mutex_lock(&ptx);
		err=1;
		pthread_mutex_unlock(&ptx);
		dummy=1;
		dummy=write(data->efin,&dummy,sizeof(dummy));
		goto abort;
	}

	p[0].fd=data->ein;
	p[0].events=POLLIN;
	p[1].fd=data->efin;
	p[1].events=POLLIN;

	while(1)
	{
		if(UNLIKELY(poll(p,2,-1)<1))continue;
		if(UNLIKELY(p[1].revents&POLLIN))break;
		if(UNLIKELY(!(p[0].revents&POLLIN)))continue;
		if(UNLIKELY(read(data->ein,&dummy,sizeof(dummy))!=sizeof(dummy)))
			continue;

		pthread_mutex_lock(&ptx);
		in=data->inhead;
		data->inhead=in->next;
		pthread_mutex_unlock(&ptx);
		out=data->bfr;
		ilen=ntohs(in->hdr)+1;

		olen=LZ4_compress_default((const char *)(in->bfr),
			(char *)(out->bfr),ilen,32768);
		if(!olen||olen>=ilen)res=in;
		else
		{
			olen-=1;
			olen|=0x8000;
			out->hdr=htons(olen);
			data->bfr=in;
			res=out;
		}

		res->next=NULL;
		pthread_mutex_lock(&ptx);
		if(!data->outhead)data->outhead=res;
		else data->outtail->next=res;
		data->outtail=res;
		pthread_mutex_unlock(&ptx);
		dummy=1;
		dummy=write(data->eout,&dummy,sizeof(dummy));
	}

abort:	pthread_exit(NULL);
}

static HOT void *reader(void *d)
{
	unsigned short seq=0;
	int i;
	int len;
	int eof;
	int n=3;
	int queued=0;
	int insel=0;
	int outsel=0;
	int txidx=0;
	uint64_t dummy;
	struct rw *data=d;
	BUFFER *bfr=NULL;
	BUFFER *ptr;
	BUFFER *fin;
	struct pollfd p[3];
	struct compress c[4];

	eof=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);
	fin=poolget(&pool,ecnt);

	for(i=0;i<data->comp;i++)
	{
		c[i].inhead=NULL;
		c[i].outhead=NULL;
		c[i].efin=data->efin;
		c[i].ein=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC|EFD_SEMAPHORE);
		c[i].eout=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC|EFD_SEMAPHORE);
		c[i].bfr=poolget(&pool,ecnt);
	}

	for(i=0;i<data->tot;i++)
	{
		data->tx[i].c.head=NULL;
		data->tx[i].c.eio=
			eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC|EFD_SEMAPHORE);
		data->tx[i].c.tfd=
			timerfd_create(CLOCK_MONOTONIC,TFD_NONBLOCK|TFD_CLOEXEC);
		data->tx[i].c.eof=eof;
		data->tx[i].c.fin=data->efin;
	}

	if(eof==-1||!fin)goto fail;

	for(i=0;i<data->comp;i++)if(c[i].ein==-1||c[i].eout==-1||!c[i].bfr)
		goto fail;

	for(i=0;i<data->tot;i++)if(data->tx[i].c.eio==-1||data->tx[i].c.tfd==-1)
		goto fail;

	i=1;
	if(ioctl(data->io,FIONBIO,&i))goto fail;

	for(i=0;i<data->comp;i++)
		if(pthread_create(&c[i].h,NULL,compressor,&c[i]))
	{
		while(i-->=0)
		{
			pthread_cancel(c[i].h);
			pthread_join(c[i].h,NULL);
		}
		goto fail;
	}

	for(i=0;i<data->tot;i++)if(pthread_create(&data->tx[i].c.h,NULL,sender,
		&data->tx[i].c))
	{
		while(i-->=0)
		{
			pthread_cancel(data->tx[i].c.h);
			pthread_join(data->tx[i].c.h,NULL);
		}

		for(i=0;i<data->comp;i++)
		{
			pthread_cancel(c[i].h);
			pthread_join(c[i].h,NULL);
		}

		goto fail;
	}

	if(setprio(0))
	{
		if(verbose)fprintf(stderr,"reader prio setup error\n");
		pthread_mutex_lock(&ptx);
		err=1;
		pthread_mutex_unlock(&ptx);
		dummy=1;
		dummy=write(data->efin,&dummy,sizeof(dummy));
		goto term;
	}

	p[0].fd=data->efin;
	p[0].events=(data->comp?POLLIN:0);
	p[0].revents=0;
	p[1].fd=data->efin;
	p[1].events=POLLIN;
	p[2].fd=data->io;
	p[2].events=POLLIN;

	while(LIKELY(n==3||queued))
	{
		if(!bfr)
		{
			bfr=poolget(&pool,ecnt);
			len=0;
		}

		if(data->comp)p[0].fd=c[outsel].eout;

		if(UNLIKELY(!bfr))
		{
			p[2].revents=0;
			if(queued)while(poll(p,2,-1)<1);
			else
			{
				while((i=poll(p,2,1))<0);
				if(!i)continue;
			}
		}
		else while(UNLIKELY(poll(p,n,-1)<1));

		if(p[2].revents&(POLLIN|POLLHUP))
			switch((i=read(data->io,bfr->bfr+len,32768-len)))
		{
		case -1:if(errno==EINTR)break;
			if(verbose)fprintf(stderr,"read error\n");
			pthread_mutex_lock(&ptx);
			err=1;
			pthread_mutex_unlock(&ptx);
			dummy=1;
			dummy=write(data->efin,&dummy,sizeof(dummy));
			goto term;

		case 0:	n=2;
			p[1].revents=0;
			if(!len)break;
			goto cont;

		default:len+=i;
			if(len<32768)break;
cont:			len--;
			bfr->hdr=htons(len);
			bfr->next=NULL;
			queued++;
			if(data->comp)
			{
				pthread_mutex_lock(&ptx);
				if(!c[insel].inhead)c[insel].inhead=bfr;
				else c[insel].intail->next=bfr;
				c[insel].intail=bfr;
				pthread_mutex_unlock(&ptx);
				dummy=1;
				dummy=write(c[insel].ein,&dummy,sizeof(dummy));
				if(++insel==data->comp)insel=0;
				bfr=NULL;
			}
			else
			{
				ptr=bfr;
				bfr=NULL;
				pthread_mutex_lock(&ptx);
				goto direct;
			}
		}

		if(p[0].revents&POLLIN)
			if(LIKELY(read(p[0].fd,&dummy,sizeof(dummy))
				==sizeof(dummy)))
		{
			pthread_mutex_lock(&ptx);
			ptr=c[outsel].outhead;
			c[outsel].outhead=ptr->next;
			ptr->next=NULL;
direct:			ptr->seq=htons(seq++);
			if(!data->tx[txidx].c.head)data->tx[txidx].c.head=ptr;
			else data->tx[txidx].c.tail->next=ptr;
			data->tx[txidx].c.tail=ptr;
			pthread_mutex_unlock(&ptx);
			dummy=1;
			dummy=write(data->tx[txidx].c.eio,&dummy,sizeof(dummy));
			seq&=0x7fff;
			if(!--data->tx[txidx].val)
			{
				data->tx[txidx].val=data->tx[txidx].tot;
				if(++txidx==data->tot)txidx=0;
			}
			if(data->comp)if(++outsel==data->comp)outsel=0;
			queued--;
		}

		if(UNLIKELY(p[1].revents&POLLIN))goto term;
	}

	fin->next=NULL;
	fin->seq=htons(seq|0x8000);
	fin->hdr=0;
	pthread_mutex_lock(&ptx);
	if(!data->tx[txidx].c.head)data->tx[txidx].c.head=fin;
	else data->tx[txidx].c.tail->next=fin;
	data->tx[txidx].c.tail=fin;
	pthread_mutex_unlock(&ptx);
	dummy=1;
	dummy=write(data->tx[txidx].c.eio,&dummy,sizeof(dummy));

	dummy=1;
	dummy=write(eof,&dummy,sizeof(dummy));

term:	for(i=0;i<data->tot;i++)pthread_join(data->tx[i].c.h,NULL);

	dummy=1;
	dummy=write(data->efin,&dummy,sizeof(dummy));

	for(i=0;i<data->comp;i++)pthread_join(c[i].h,NULL);

	if(0)
	{
fail:		if(verbose)fprintf(stderr,"reader setup error\n");
		pthread_mutex_lock(&ptx);
		err=1;
		pthread_mutex_unlock(&ptx);
	}

	if(eof!=-1)close(eof);

	for(i=0;i<data->comp;i++)
	{
		if(c[i].ein!=-1)close(c[i].ein);
		if(c[i].eout!=-1)close(c[i].eout);
	}

	for(i=0;i<data->tot;i++)
	{
		if(data->tx[i].c.eio!=-1)close(data->tx[i].c.eio);
		if(data->tx[i].c.tfd!=-1)close(data->tx[i].c.tfd);
	}

	pthread_exit(NULL);
}

static HOT void *receiver(void *d)
{
	uint32_t tail;
	uint32_t idx;
	unsigned char nxt;
	int i;
	int j;
	int l;
	int l2;
	int eof;
	int wtick;
	int rtick;
	uint64_t dummy;
	BUFFER *bfr;
	BUFFER *tmp;
	struct conn *data=d;
	struct packet *ptr;
	struct itimerspec it;
	struct pollfd p[4];
	int len[256];
	struct packet *pkt[256];
	struct packet ack;
	struct packet idle;

	it.it_interval.tv_sec=0;
	it.it_interval.tv_nsec=10000000;
	it.it_value.tv_sec=0;
	it.it_value.tv_nsec=10000000;

	for(i=0;i<256;i++)pkt[i]=NULL;

	p[0].fd=data->fd;
	p[0].events=POLLIN;
	p[1].fd=data->tfd;
	p[1].events=POLLIN;
	p[2].fd=data->fin;
	p[2].events=POLLIN;

	eof=0;
	wtick=0;
	rtick=0;
	tail=0;
	nxt=0;
	ptr=&data->pkt[nxt++];
	bfr=NULL;

	if(doaccept(data))
	{
		if(verbose)fprintf(stderr,"accept error\n");
		pthread_mutex_lock(&ptx);
		err=1;
		pthread_mutex_unlock(&ptx);
		dummy=1;
		dummy=write(data->fin,&dummy,sizeof(dummy));
		pthread_exit(NULL);
	}

	memcpy(idle.hdr.h_dest,data->dst,ETH_ALEN);
	memcpy(idle.hdr.h_source,data->src,ETH_ALEN);
	idle.hdr.h_proto=htons(ETH_P_802_EX1);
	idle.sum=0;
	idle.len=htons(0x8000);
	idle.seq=0;

	for(i=0,idx=0;i<H2LEN>>1;i++)idx+=ntohs(idle.chk[i]);
	idx=(idx&0xffff)+(idx>>16);
	idx=(idx&0xffff)+(idx>>16);
	idle.sum=htons(~idx);

	memcpy(ack.hdr.h_dest,data->dst,ETH_ALEN);
	memcpy(ack.hdr.h_source,data->src,ETH_ALEN);
	ack.hdr.h_proto=htons(ETH_P_802_EX1);
	ack.len=0;

	timerfd_settime(data->tfd,0,&it,NULL);

	while(LIKELY(rtick<(UNLIKELY(eof)?15:25)))
	{
		while(UNLIKELY(poll(p,3,-1)<1));

		if(UNLIKELY(p[2].revents&POLLIN))break;

		if(p[1].revents&POLLIN)
			if(LIKELY(read(data->tfd,&dummy,sizeof(dummy))
				==sizeof(dummy)))
		{
			rtick++;
			wtick++;
		}

		if(!bfr)bfr=poolget(&data->pool,data->cnt);

		if(p[0].revents&POLLIN)
		  if(LIKELY((l=recv(data->fd,ptr,data->mtu,0))>=64))
		    if(LIKELY(!memcmp(ptr->hdr.h_dest,data->src,ETH_ALEN)))
		      if(LIKELY(!memcmp(ptr->hdr.h_source,data->dst,ETH_ALEN)))
			if(LIKELY(ptr->hdr.h_proto==htons(ETH_P_802_EX1)))
		{
			if((l2=ntohs(ptr->len))&0x8000)l2=H2LEN;
			else l2=(l2+H2LEN+1)&(~1);
			if(LIKELY(l>=l2))
			{
				for(idx=0,j=0,l2>>=1;j<l2;j++)
					idx+=ntohs(ptr->chk[j]);
				idx=(idx&0xffff)+(idx>>16);
				idx=(idx&0xffff)+(idx>>16);
				if(LIKELY(idx==0xffff))
				{
					rtick=0;
					if(LIKELY(
						!((l2=ntohs(ptr->len))&0x8000)))
					{
						ack.seq=ptr->seq;
						ack.sum=0;
						for(idx=0,j=0;j<H2LEN>>1;j++)
							idx+=ntohs(ack.chk[j]);
						idx=(idx&0xffff)+(idx>>16);
						idx=(idx&0xffff)+(idx>>16);
						ack.sum=htons(~idx);
						i=idx=ntohl(ack.seq);
						idx-=tail;
						i&=0xff;
						if(LIKELY(idx<=192&&!pkt[i]))
						{
							len[i]=l2;
							pkt[i]=ptr;
							ptr=&data->pkt[nxt++];
						}
						if(LIKELY(bfr!=NULL))
						    if(LIKELY(send(
							data->fd,&ack,64,0)==64))
							    wtick=0;
					}
				}
			}
		}

		if(UNLIKELY(wtick>=10))
			if(LIKELY(send(data->fd,&idle,64,0)==64))wtick=0;

		for(l2=0,l=0,j=tail,i=tail&0xff;bfr&&pkt[i];i=j&0xff)
		{
			if(!len[i])
			{
				eof=1;
				pkt[i]=NULL;
				j++;
				tail++;
				continue;
			}
			if(!l2)
			{
				tmp=(BUFFER *)(pkt[i]->data-sizeof(void *));
				if(ntohs(tmp->seq)&0x8000)l2=4;
				else l2=(ntohs(tmp->hdr)&0x7fff)+5;
			}
			l+=len[i];
			j++;
			if(l==l2)
			{
				for(l=0;tail!=j;tail++)
				{
					i=tail&0xff;
					memcpy(bfr->data+l,pkt[i]->data,len[i]);
					l+=len[i];
					pkt[i]=NULL;
				}
				bfr->next=NULL;
				pthread_mutex_lock(&ptx);
				if(!data->head)data->head=bfr;
				else data->tail->next=bfr;
				data->tail=bfr;
				pthread_mutex_unlock(&ptx);
				bfr=NULL;
				dummy=1;
				dummy=write(data->eio,&dummy,sizeof(dummy));
				l=0;
				l2=0;
			}
		}
	}

	if(!eof)
	{
		if(verbose)
		{
			if(rtick>=25)fprintf(stderr,"receive timeout\n");
			else fprintf(stderr,"unexpected error\n");
		}
		pthread_mutex_lock(&ptx);
		err=1;
		pthread_mutex_unlock(&ptx);
		dummy=1;
		dummy=write(data->fin,&dummy,sizeof(dummy));
	}

	memset(&it,0,sizeof(it));
	timerfd_settime(data->tfd,0,&it,NULL);
	dummy=read(data->tfd,&dummy,sizeof(dummy));

	pthread_exit(NULL);
}

static HOT void *decompressor(void *d)
{
	int ilen;
	int olen;
	uint64_t dummy;
	struct compress *data=d;
	BUFFER *in;
	BUFFER *out;
	BUFFER *res;
	struct pollfd p[2];

	if(setprio(0))
	{
		if(verbose)fprintf(stderr,"decompressor prio setup error\n");
		pthread_mutex_lock(&ptx);
		err=1;
		pthread_mutex_unlock(&ptx);
		dummy=1;
		dummy=write(data->efin,&dummy,sizeof(dummy));
		goto abort;
	}

	p[0].fd=data->ein;
	p[0].events=POLLIN;
	p[1].fd=data->efin;
	p[1].events=POLLIN;

	while(1)
	{
		if(UNLIKELY(poll(p,2,-1)<1))continue;
		if(UNLIKELY(p[1].revents&POLLIN))break;
		if(UNLIKELY(!(p[0].revents&POLLIN)))continue;
		if(UNLIKELY(read(data->ein,&dummy,sizeof(dummy))!=sizeof(dummy)))
			continue;

		pthread_mutex_lock(&ptx);
		in=*(data->pinhead);
		*(data->pinhead)=in->next;
		pthread_mutex_unlock(&ptx);

		if(ntohs(in->seq)&0x8000)ilen=0;
		else ilen=ntohs(in->hdr);
		if(ilen&0x8000)
		{
			ilen&=0x7fff;
			ilen+=1;
			out=data->bfr;
			if((olen=LZ4_decompress_safe((const char *)in->bfr,
				(char *)out->bfr,ilen,32768))<=0)
			{
				if(verbose)fprintf(stderr,"decompress error\n");
				pthread_mutex_lock(&ptx);
				err=1;
				pthread_mutex_unlock(&ptx);
				dummy=1;
				dummy=write(data->efin,&dummy,sizeof(dummy));
				break;
			}
			out->seq=in->seq;
			out->hdr=htons(olen-1);
			res=out;
			data->bfr=in;
		}
		else res=in;

		res->next=NULL;
		pthread_mutex_lock(&ptx);
		if(!data->outhead)data->outhead=res;
		else data->outtail->next=res;
		data->outtail=res;
		pthread_mutex_unlock(&ptx);
		dummy=1;
		dummy=write(data->eout,&dummy,sizeof(dummy));
	}

abort:	pthread_exit(NULL);
}

static HOT void *writer(void *d)
{
	int i;
	int pos;
	int len;
	int l;
	int ein;
	unsigned short seq=0;
	uint64_t dummy;
	BUFFER *bfr;
	struct rw *data=d;
	struct pollfd p[2];
	struct pollfd q[2];

	ein=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC|EFD_SEMAPHORE);

	for(i=0;i<data->tot;i++)
	{
		data->rx[i].d.pinhead=&data->rx[i].c.head;
		data->rx[i].d.outhead=NULL;
		data->rx[i].d.efin=data->efin;
		data->rx[i].d.ein=
			eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC|EFD_SEMAPHORE);
		data->rx[i].d.eout=ein;
		data->rx[i].d.bfr=poolget(&data->rx[i].c.pool,data->rx[i].c.cnt);
		data->rx[i].c.head=NULL;
		data->rx[i].c.eio=data->rx[i].d.ein;
		data->rx[i].c.tfd=
			timerfd_create(CLOCK_MONOTONIC,TFD_NONBLOCK|TFD_CLOEXEC);
		data->rx[i].c.eof=0;
		data->rx[i].c.fin=data->efin;
	}

	if(ein==-1)goto out;
	for(i=0;i<data->tot;i++)if(data->rx[i].d.ein==-1||data->rx[i].c.tfd==-1
		||!data->rx[i].d.bfr)goto out;

	i=1;
	if(ioctl(data->io,FIONBIO,&i))
	{
out:		if(verbose)fprintf(stderr,"writer setup error\n");
		pthread_mutex_lock(&ptx);
		err=1;
		pthread_mutex_unlock(&ptx);
		goto done;
	}

	for(i=0;i<data->tot;i++)if(pthread_create(&data->rx[i].d.h,NULL,
		decompressor,&data->rx[i].d))
	{
		while(i-->=0)
		{
			pthread_cancel(data->rx[i].d.h);
			pthread_join(data->rx[i].d.h,NULL);
		}
		goto out;
	}

	for(i=0;i<data->tot;i++)if(pthread_create(&data->rx[i].c.h,NULL,receiver,
		&data->rx[i].c))
	{
		while(i-->=0)
		{
			pthread_cancel(data->rx[i].c.h);
			pthread_join(data->rx[i].c.h,NULL);
		}

		for(i=0;i<data->tot;i++)
		{
			pthread_cancel(data->rx[i].d.h);
			pthread_join(data->rx[i].d.h,NULL);
		}

		goto out;
	}

	if(setprio(0))
	{
		if(verbose)fprintf(stderr,"writer prio setup error\n");
		pthread_mutex_lock(&ptx);
		err=1;
		pthread_mutex_unlock(&ptx);
		goto abort;
	}

	p[0].fd=ein;
	p[0].events=POLLIN;
	p[1].fd=data->efin;
	p[1].events=POLLIN;

	q[0].fd=data->io;
	q[0].events=POLLOUT;
	q[1].fd=data->efin;
	q[1].events=POLLIN;

	while(1)
	{
		while(UNLIKELY(poll(p,2,-1)<1));
		if(UNLIKELY(p[1].revents&POLLIN))break;
		if(UNLIKELY(!(p[0].revents&POLLIN)))continue;
		if(UNLIKELY(read(ein,&dummy,sizeof(dummy))!=sizeof(dummy)))
			continue;

repeat:		for(i=0;i<data->tot;i++)
		{
			pthread_mutex_lock(&ptx);
			if(data->rx[i].d.outhead)
			    if((ntohs(data->rx[i].d.outhead->seq)&0x7fff)==seq)
			{
				if(ntohs(data->rx[i].d.outhead->seq)&0x8000)
				{
					pthread_mutex_unlock(&ptx);
					goto eof;
				}
				bfr=data->rx[i].d.outhead;
				pthread_mutex_unlock(&ptx);

				len=ntohs(bfr->hdr)+1;
				pos=0;
				while(pos<len)
				{
					while(UNLIKELY(poll(q,2,-1)<1));
					if(UNLIKELY(q[1].revents&POLLIN))
						goto abort;
					if(UNLIKELY(!(q[0].revents&POLLOUT)))
					{
						if(verbose)fprintf(stderr,
							"write not possible\n");
						pthread_mutex_lock(&ptx);
						err=1;
						pthread_mutex_unlock(&ptx);
						goto abort;
					}
					if(UNLIKELY((l=write(data->io,
						bfr->bfr+pos,len-pos))<=0))
					{
						if(verbose)fprintf(stderr,
							"write error\n");
						pthread_mutex_lock(&ptx);
						err=1;
						pthread_mutex_unlock(&ptx);
						goto abort;
					}
					pos+=l;
				}

				pthread_mutex_lock(&ptx);
				data->rx[i].d.outhead=bfr->next;
				pthread_mutex_unlock(&ptx);
				poolput(&data->rx[i].c.pool,data->rx[i].c.cnt,
					bfr);
				seq=(seq+1)&0x7fff;
				goto repeat;
			}
			pthread_mutex_unlock(&ptx);
		}
	}

eof:	for(i=0;i<data->tot;i++)
		pthread_join(data->rx[i].c.h,NULL);

	dummy=1;
	dummy=write(data->efin,&dummy,sizeof(dummy));

	for(i=0;i<data->tot;i++)
		pthread_join(data->rx[i].c.h,NULL);

	if(0)
	{
abort:		dummy=1;
		dummy=write(data->efin,&dummy,sizeof(dummy));

		for(i=0;i<data->tot;i++)
		{
			pthread_join(data->rx[i].d.h,NULL);
			pthread_join(data->rx[i].c.h,NULL);
		}
	}

done:	if(ein)close(ein);

	for(i=0;i<data->tot;i++)
	{
		if(data->rx[i].d.ein!=-1)close(data->rx[i].d.ein);
		if(data->rx[i].c.tfd!=-1)close(data->rx[i].c.tfd);
	}

	pthread_exit(NULL);
}

static COLD struct rw *reader_start(int n,char **iflist,int *nlist,int small,
	int comp,int in,int efin)
{
	int i;
	struct rw *data;

	if(!(data=malloc(sizeof(struct rw)+n*sizeof(data->tx[0]))))goto err1;
	if(mkpool(&pool,&base,&ecnt,(small?4097:32769)+comp))goto err2;
	for(i=0;i<n;i++)if(mksock(iflist[i],&data->tx[i].c))
	{
		while(--i>=0)close(data->tx[i].c.fd);
		goto err3;
	}
	else data->tx[i].val=data->tx[i].tot=nlist[i];
	data->io=in;
	data->efin=efin;
	data->tot=n;
	data->comp=comp;

	if(pthread_create(&data->h,NULL,reader,data))goto err4;
	return data;

err4:	for(i=0;i<n;i++)close(data->tx[i].c.fd);
err3:	free(base);
err2:	free(data);
err1:	err=1;
	if(verbose)fprintf(stderr,"reader start failed\n");
	return NULL;
}

static COLD void reader_end(struct rw *data)
{
	int i;
	uint64_t dummy=1;

	dummy=write(data->efin,&dummy,sizeof(dummy));
	pthread_join(data->h,NULL);
	for(i=0;i<data->tot;i++)close(data->tx[i].c.fd);
	free(base);
	close(ecnt);
	free(data);
}

static COLD struct rw *writer_start(int n,char **iflist,int small,int out,
	int efin)
{
	int i;
	struct rw *data;

	if(!(data=malloc(sizeof(struct rw)+n*sizeof(data->rx[0]))))goto err1;
	for(i=0;i<n;i++)
	{
		if(mksock(iflist[i],&data->rx[i].c))goto fail;
		if(mkpool(&data->rx[i].c.pool,&data->rx[i].c.base,
			&data->rx[i].c.cnt,small?1025:8193))
		{
			close(data->rx[i].c.fd);
fail:			while(--i>=0)
			{
				close(data->rx[i].c.fd);
				close(data->rx[i].c.cnt);
				free(data->rx[i].c.base);
			}
			goto err2;
		}
	}
	data->io=out;
	data->efin=efin;
	data->tot=n;

	if(pthread_create(&data->h,NULL,writer,data))goto err3;
	return data;

err3:	for(i=0;i<n;i++)
	{
		close(data->rx[i].c.fd);
		close(data->rx[i].c.cnt);
		free(data->rx[i].c.base);
	}
err2:	free(data);
err1:	err=1;
	if(verbose)fprintf(stderr,"writer start failed\n");
	return NULL;
}

static COLD void writer_end(struct rw *data)
{
	int i;
	uint64_t dummy=1;

	dummy=write(data->efin,&dummy,sizeof(dummy));
	pthread_join(data->h,NULL);
	for(i=0;i<data->tot;i++)
	{
		close(data->rx[i].c.fd);
		close(data->rx[i].c.cnt);
		free(data->rx[i].c.base);
	}
	free(data);
}

static COLD NORETURN void usage(void)
{
	fprintf(stderr,"Usage: l2pipe -s [-m] [-3|-2|-1|-0] [-a arg] dev ...\n");
	fprintf(stderr,"       l2pipe -r [-m] dev ...\n");
	fprintf(stderr,"A maximum of 10 devices is supported.\n");
	fprintf(stderr,"-s     sender mode\n");
	fprintf(stderr,"-r     receiver mode\n");
	fprintf(stderr,"-v     verbose errors\n");
	fprintf(stderr,"-m     reduced memory footprint\n");
	fprintf(stderr,"-3     use 3 parallel compressors (default 4)\n");
	fprintf(stderr,"-2     use 2 parallel compressors (default 4)\n");
	fprintf(stderr,"-1     use 1 compressor (default 4)\n");
	fprintf(stderr,"-0     use no compressor (default 4 compressors)\n");
	fprintf(stderr,"-a arg use destribution scheme across devices\n");
	fprintf(stderr,"       according to arg:\n");
	fprintf(stderr,"       arg=n[.n[.n[...]]]\n");
	fprintf(stderr,"       n=a numeric value from 1 to 10\n");
	fprintf(stderr,"       use first n as amount of large packets to\n");
	fprintf(stderr,"       queue for first device, use second n for\n");
	fprintf(stderr,"       for second device and so on...\n");
	fprintf(stderr,"       Default is one large packet per device.\n");
	exit(1);
}

COLD int main(int argc,char *argv[])
{
	int i;
	int c;
	int fin;
	int sig;
	int mode=-1;
	int small=0;
	int comp=4;
	char *apd=NULL;
	char *ptr;
	char *end;
	struct rw *rw;
	struct pollfd p[2];
	int dist[10];
	sigset_t set;
	struct signalfd_siginfo info;

	sigfillset(&set);
	sigprocmask(SIG_SETMASK,&set,NULL);

	verbose=0;

	while((c=getopt(argc,argv,"srmv3210a:"))!=-1)switch(c)
	{
	case 's':
		if(mode!=-1)usage();
		mode=1;
		break;

	case 'r':
		if(mode!=-1)usage();
		mode=0;
		break;

	case 'm':
		if(small)usage();
		small=1;
		break;

	case 'v':
		if(verbose)usage();
		verbose=1;
		break;

	case '3':
	case '2':
	case '1':
	case '0':
		if(comp!=4)usage();
		comp=c-'0';
		break;

	case 'a':
		if(apd)usage();
		apd=optarg;
		break;
	}

	if(mode==-1||(!mode&&comp!=4)||(!mode&&apd)||optind>=argc||
		(c=argc-optind)>10)usage();

	if(!apd)for(i=0;i<c;i++)dist[i]=1;
	else
	{
		for(i=0,ptr=strtok(apd,".");ptr;i++,ptr=strtok(NULL,"."))
		{
			if(i==c||!*ptr||strlen(ptr)>2)usage();
			dist[i]=(int)strtoul(ptr,&end,10);
			if(dist[i]<1||dist[i]>10||*end)usage();
		}
		if(i!=c)usage();
	}

	if(setprio(1))
	{
		perror("sched_setscheduler");
		return 1;
	}

	if((fin=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC))==-1)
	{
		perror("eventfd");
		return 1;
	}

	sigemptyset(&set);
	sigaddset(&set,SIGINT);
	sigaddset(&set,SIGHUP);
	sigaddset(&set,SIGTERM);
	sigaddset(&set,SIGQUIT);

	if((sig=signalfd(-1,&set,SFD_NONBLOCK|SFD_CLOEXEC))==-1)
	{
		perror("signalfd");
		close(fin);
		return 1;
	}

	err=0;

	p[0].fd=sig;
	p[0].events=POLLIN;
	p[1].fd=fin;
	p[1].events=POLLIN;

	if(mode)rw=reader_start(c,argv+optind,dist,small,comp,0,fin);
	else rw=writer_start(c,argv+optind,small,1,fin);

	if(rw)
	{
		if(setprio(0))err=1;
		else while(1)
		{
			while(UNLIKELY(poll(p,2,-1)<1));
			if(p[0].events&POLLIN)
				if(read(sig,&info,sizeof(info))==sizeof(info))
			{
				if(verbose)fprintf(stderr,"signal received\n");
				pthread_mutex_lock(&ptx);
				err=1;
				pthread_mutex_unlock(&ptx);
				break;
			}
			if(p[1].events&POLLIN)break;
		}

		if(mode)reader_end(rw);
		else writer_end(rw);
	}
	else err=1;

	close(sig);
	close(fin);

	if(err)fprintf(stderr,"l2pipe: aborted\n");

	return err;
}

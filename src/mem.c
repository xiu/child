/*
Child, Internet Relay Chat Services
Copyright (C) 2005-2009  David Lebrun (target0@geeknode.org)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/


#include <child.h>
#include <globals.h>

inline void FreeAllMem()
{
    while (!LIST_EMPTY(user_list))
        DeleteAccount(LIST_HEAD(user_list));
    while (!LIST_EMPTY(chan_list))
        DeleteChannel(LIST_HEAD(chan_list));
    while (!LIST_EMPTY(nick_list))
        DeleteWildNick(LIST_HEAD(nick_list));
    /* module_list and hook_list are not checked because unloadallmod() should be called before this function. */
    while (!LIST_EMPTY(trust_list))
        DeleteTrust(LIST_HEAD(trust_list));
    while (!LIST_EMPTY(wchan_list))
        DeleteWchan(LIST_HEAD(wchan_list));
    while (!LIST_EMPTY(cflag_list))
        DeleteCflag(LIST_HEAD(cflag_list));
    while (!LIST_EMPTY(member_list))
        DeleteMember(LIST_HEAD(member_list));
    while (!LIST_EMPTY(link_list))
        DeleteLink(LIST_HEAD(link_list)->slave);
    while (!LIST_EMPTY(limit_list))
        DeleteLimit(LIST_HEAD(limit_list));
    while (!LIST_EMPTY(eclient_list))
        DeleteEclient(LIST_HEAD(eclient_list));
    while (!LIST_EMPTY(guest_list))
        DeleteGuest(LIST_HEAD(guest_list)->nick);
#ifdef USE_FILTER
    while (!LIST_EMPTY(rule_list))
        remove_rule(LIST_HEAD(rule_list));
#endif
    while (!LIST_EMPTY(tb_list))
        DeleteTB(LIST_HEAD(tb_list));
    while (!LIST_EMPTY(fake_list))
        DeleteFake(LIST_HEAD(fake_list));
}

inline void cleanup_reconnect()
{
    while (!LIST_EMPTY(member_list))
        DeleteMember(LIST_HEAD(member_list));
    while (!LIST_EMPTY(wchan_list))
        DeleteWchan(LIST_HEAD(wchan_list));
    while (!LIST_EMPTY(limit_list))
        DeleteLimit(LIST_HEAD(limit_list));
    while (!LIST_EMPTY(guest_list))
        DeleteGuest(LIST_HEAD(guest_list)->nick);
    while (!LIST_EMPTY(nick_list))
        DeleteWildNick(LIST_HEAD(nick_list));
    while (!LIST_EMPTY(fake_list))
        DeleteFake(LIST_HEAD(fake_list));
}

long get_mem(int which)
{
    long vsize,rss;
#ifdef __FreeBSD__
    kvm_t *kd;
    char *err = (char *)malloc(64*sizeof(char));
    bzero(err,64);
    struct kinfo_proc *ki;
    int pagesize,cnt,size;
    size = sizeof(pagesize);
    sysctlbyname("hw.pagesize",&pagesize,&size,NULL,0);

    kd = kvm_open(getbootfile(),"/dev/null",NULL,O_RDONLY,err);
    ki = kvm_getprocs(kd,KERN_PROC_PID,getpid(),&cnt);

    vsize = ki->ki_size/1024;
    rss = (ki->ki_rssize*pagesize)/1024;
    kvm_close(kd);
    free(err);
#else
    FILE *proc_stat = fopen("/proc/self/stat","r");
    if (!proc_stat) return -1;

    fscanf(proc_stat,"%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*d %*d %*d %*u %lu %ld %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*d %*d",&vsize,&rss);
    fclose(proc_stat);
    vsize /= 1024;
    rss *= 4;
#endif
    switch(which) {
        case MEM_VSIZE:
            return vsize;
        case MEM_RSS:
            return rss;
        default:
            return -1;
    }
}

inline void InitMem()
{
    LIST_INIT(user_list);
    LIST_INIT(nick_list);
    LIST_INIT(clones_list);
    LIST_INIT(module_list);
    LIST_INIT(hook_list);
    LIST_INIT(trust_list);
    LIST_INIT(link_list);
    LIST_INIT(eclient_list);
    LIST_INIT(guest_list);
    LIST_INIT(chan_list);
    LIST_INIT(wchan_list);
    LIST_INIT(cflag_list);
    LIST_INIT(member_list);
    LIST_INIT(limit_list);
    LIST_INIT(bot_list);
    LIST_INIT(chanbot_list);
    LIST_INIT(command_list);
#ifdef USE_FILTER
    LIST_INIT(rule_list);
#endif
    LIST_INIT(tb_list);
    LIST_INIT(fake_list);
    memset(&indata, 0, sizeof(indata));
    memset(&outdata, 0, sizeof(outdata));
}

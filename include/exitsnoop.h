#ifndef __EXIT_SNOOP_H__
#define __EXIT_SNOOP_H__

#define COMM_BUF_SIZE 4096
#define COMM_BUF_MAX COMM_BUF_SIZE * 2

#define CGROUP_NAME_BUF_SIZE 256

#define RINGBUF_SIZE 1024
#define LRU_HASH_MAP_SIZE 256

struct exit_event {
  pid_t pid;
  pid_t tgid;
  pid_t ppid;
  uid_t uid;
  gid_t gid;
  u64 cgroup_id;
  int exit_code;
  char cgroup_name[CGROUP_NAME_BUF_SIZE];
  char comm[COMM_BUF_MAX];
} __attribute__((packed));

struct exit_event_internal {
  pid_t pid;
  pid_t tgid;
  pid_t ppid;
  uid_t uid;
  gid_t gid;
  u64 cgroup_id;
  char cgroup_name[CGROUP_NAME_BUF_SIZE];
  char comm[COMM_BUF_MAX];
} __attribute__((packed));

#endif 
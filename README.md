Redis Draft Understanding
---------------------------------

### Requirements

Written the report in such a way that the reader can understand the application, security model and get a good sense of it’s security worthiness in the deployment context. Demonstrated proficiency in using tools and techniques for finding the vulnerabilities, provided a good write up on the approach and results.

### Introduction

[REDIS](http://redis.io/) is an open source, advanced key-value store. It is often referred to as a data structure server since keys can contain strings, hashes, lists, sets and sorted sets. Redis is used in several important products and services such as:  [github](https://github.com/blog/530-how-we-made-github-fast), [stackoverflow](http://meta.stackoverflow.com/questions/69164/does-stackoverflow-use-caching-and-if-so-how/69172), [Disqus](http://redis.io/topics/whos-using-redis) and many more that you can from the [who is using](http://redis.io/topics/whos-using-redis) page. 

### Security Model

Redis is designed to a component of back end infrastructure, this is part of Redis design philosophy. In the [Redis Manifesto](http://antirez.com/post/redis-manifesto.html) which has been written by the author [Salvatore Sanfilippo](http://invece.org/), in which he explains philosophy of his development. I quote particular the following:

> We optimize for joy. We believe writing code is a lot of hard work, and the only way it can be worth is by enjoying it. When there is no longer joy in writing code, the best thing to do is stop. To prevent this, we’ll avoid taking paths that will make Redis less of a joy to develop.
The


##### General Security Model

In the 

> In general, Redis is not optimized for maximum security but for maximum performance and simplicity.

It’s a simple solution to the problem of high-performance fast-changing data storage. However, its simplicity (combined with the incompetency of certain users) can easily become a detriment to security.

##### Source Code Security Model

Redis is written in ANSI C and works in most POSIX systems like Linux, BSD, OS X and Solaris without external dependencies. From my limited point of view it’s code is simple and elegant to read. Codebase is not very big (about 20k LOC for 2.2 release).  

In a classical Redis setup, clients are allowed full access to the command set, but accessing the instance should never result in the ability to control the system where Redis is running.
Internally, Redis uses all the well known practices for writing secure code, to prevent buffer overflows, format bugs and other memory corruption issues. However, the ability to control the server configuration using the CONFIG command makes the client able to change the working dir of the program and the name of the dump file. This allows clients to write RDB Redis files at random paths, that is a security issue that may easily lead to the ability to run untrusted code as the same user as Redis is running.

Redis does not requires root privileges to run. It is recommended to run it as an unprivileged redis user that is only used for this purpose. The Redis authors are currently investigating the possibility of adding a new configuration parameter to prevent CONFIG SET/GET dir and other similar run-time configuration directives. This would prevent clients from forcing the server to write Redis dump files at arbitrary locations.

```c
int rdbSave(char *filename) {
    dictIterator *di = NULL;
    dictEntry *de;**
    char tmpfile[256];
    char magic[10];
    int j;
    long long now = mstime();
    FILE *fp;
    rio rdb;
    uint64_t cksum;

    snprintf(tmpfile,256,"temp-%d.rdb", (int) getpid());
    fp = fopen(tmpfile,"w");
    if (!fp) {
        redisLog(REDIS_WARNING, "Failed opening .rdb for saving: %s",
            strerror(errno));
        return REDIS_ERR;
    }

    rioInitWithFile(&rdb,fp);
    if (server.rdb_checksum)
        rdb.update_cksum = rioGenericUpdateChecksum;
    snprintf(magic,sizeof(magic),"REDIS%04d",REDIS_RDB_VERSION);
    if (rdbWriteRaw(&rdb,magic,9) == -1) goto werr;

    for (j = 0; j < server.dbnum; j++) {
        redisDb *db = server.db+j;
        dict *d = db->dict;
        if (dictSize(d) == 0) continue;
        di = dictGetSafeIterator(d);
        if (!di) {
            fclose(fp);
            return REDIS_ERR;
        }
```

In `rdb.c` line 641, the function `rdbSave` does not use a security temporary file creation
routine such as `mkstemp`.  This is vulnerable to a wide range of attacks which
could result in overwriting (in line 693-695) and unlinking (in line 701) any
file / hard link / symlink placed in temp-PID.rdb by an attacker. The code should be creating the temporary file using some kind of safe function like `mkstemp`, `O_EXCL open`, etc. instead of just using a PID value which does not have enough entropy and protection from race conditions. It should also be sure it has set the CWD of itself to a known-safe location that should have permissions which are only open to the redis daemon / redis user
and not to other users or processes.

Reference [1](https://www.owasp.org/index.php/Improper_temp_file_opening),  [2](https://www.owasp.org/index.php/Insecure_Temporary_File)

##### Network Security Model

Redis is designed to be accessed by trusted clients inside trusted environments. This means that usually it is not a good idea to expose the Redis instance directly to the internet or, in general, to an environment where untrusted clients can directly access the Redis TCP port or UNIX socket.

### References

The Redis protocol is a simple plain-text mechanism, offering no transport layer security. This is a problem in itself, but it gets worse. By default, it listens on all available IP addresses on port 6379, with no authentication required at all. So, as you might imagine, quite a few of these servers end up facing the internet. So, I decided to see if I could find any. I wrote up a quick script to scan random /24 ranges for Redis installations, and was amazed at the result. From a single day’s scanning, I found 48 open servers. What’s worse, two of them are major household-name websites – both of which were using Redis to store their page content. Obviously both of these companies have been contacted.

It gets even worse, though. Redis allows you to send a DEBUG SEGFAULT command, which purposefully crashes the server. This means you can take down any Redis installation remotely. Nasty stuff.

```bash
redis_version:2.4.5
redis_git_sha1:00000000
redis_git_dirty:0
arch_bits:32
multiplexing_api:winsock2
process_id:####
uptime_in_seconds:##########
uptime_in_days:6
lru_clock:##########
used_cpu_sys:421.25
used_cpu_user:466.63
used_cpu_sys_children:6.48
used_cpu_user_children:3.12
connected_clients:16
connected_slaves:0
client_longest_output_list:0
client_biggest_input_buf:0
blocked_clients:0
used_memory:680824356
used_memory_human:664.87M
used_memory_rss:680824356
used_memory_peak:697004492
used_memory_peak_human:680.67M
mem_fragmentation_ratio:1.00
mem_allocator:libc
loading:0
aof_enabled:0
changes_since_last_save:6922
bgsave_in_progress:0
last_save_time:1326######
bgrewriteaof_in_progress:0
total_connections_received:802101
total_commands_processed:3692083
expired_keys:34652
evicted_keys:2
keyspace_hits:2763416
keyspace_misses:591228
pubsub_channels:0
pubsub_patterns:0
latest_fork_usec:0
vm_enabled:0
role:master
```

Update: The creator of Redis, antirez, responded to this post, informing me that you can in fact make Redis bind to a single IP in redis.conf. I’d like to clarify my point on the security of Redis – it is designed to be lightweight and provide only minimal security, so this problem is not a flaw of Redis itself. Instead, it’s a flaw of how people are using (or abusing) Redis. The current ethos is that you should always apply network security to your NoSQL systems – if you don’t, it’ll end in tears.


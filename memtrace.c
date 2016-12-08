/*
 * Peak memory usage finder using mm_page_alloc() and mm_page_free()
 * tracing
 *
 * Copyright (C) panand@redhat.com
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * There are several scenarios where we land into oom-killer in the early boot
 * process, specially in a memory constrained environment. It becomes very
 * difficult to identify the user space task or a kernel module who
 * required more memory compared to their previous released versions. This
 * tool is an attempt to debug such issues, which will help us to identify
 * peak memory usage of each task and a kernel module inserted from user
 * space.
 * mm_page_alloc() and mm_page_free() are lowest level of kernel APIs which
 * allocates and frees memory from buddy. This tool enables tracepoint of
 * these two functions and then keeps track of peak memory usage of each
 * task. Additionally, it also enabled tracepoint of module_load and
 * module_put. These two tracepoints helps to identify kernel module if the
 * user space task was insmod or modprobe etc. If a task was already
 * running before this tool was started then, it initializes peak memory of
 * that task with corresponding vmRSS component from /proc/$tid/statm
 *
 * After launching this tool, an user can send signal SIGUSR1(`killall -s
 * SIGUSR1 memtrace`, where memtrace is the name of compiled binary output
 * of this code) to print statistics on STDOUT. A signal SIGUSR2 can be
 * sent to print stats in a file /tmp/mem_debug_log. Last statistics is
 * also save in that file when this tool is terminated.
 *
 * There could still be some cma and memblock allocations which may not be
 * tracked using this tool.
 * Need to find a better way to define MAX_TASK_TO_MONITOR,
 * MAX_NUMBER_OF_CPUS and DEFAULT_LOG_PATH.
 *
 * usage:
 * # gcc -o memtrace memtrace.c
 * # ./memtrace &
 * (if tracing directory is not mounted at /sys/kernel/debug/tracing/ then
 * pass path of tracing directory as argument like following)
 * # ./memtrace /sys/kernel/tracing/ &
 * (to get current stats on screen)
 * # killall -s SIGUSR1 memtrace
 * (to save current stats in file /tmp/mem_debug_log)
 * # killall -s SIGUSR2 memtrace
 * (to terminate the spplication and to save current stats in file)
 * # killall -s SIGTERM memtrace
 */

#include <fcntl.h>
#include <search.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TASK_TO_MONITOR	200
#define MAX_NUMBER_OF_CPUS	128

#define DEFAULT_LOG_PATH "/tmp/mem_trace_log"

struct trace_entry {
	char	key[64];
	char	comm[17];
	int	peak_memory;
	int	memory;
};

struct debug_trace_info {
	char	trace_path[64];
	char	tracing_on_path[64];
	char	set_event_path[64];
	char	events_enable_path[64];
	char	cur_mod[MAX_NUMBER_OF_CPUS][64];
	char	log_path[64];
};

static int read_next_entry(int fd, char *comm, char *pid, int *cpu,
		char *trace)
{
	int i, j;
	char data[32];
	bool space;

	/* read comm, which will be there in first 16 char*/
	space = true;
	j = 0;
	for (i = 0; i < 16; i++) {
		read(fd, &comm[j], 1);
		/* ignore initial white spaces */
		/* if first char is # skip the line */
		if (space) {
			if (comm[j] == '#')
				goto nextline;
			if (!isspace(comm[j])) {
				j++;
				space = false;
			}
		} else {
			j++;
		}
	}
	comm[j] = '\0';
	/* ignore next char(-) */
	read(fd, data, 1);
	/* read pid (max 5 char) */
	for (i = 0; i < 5; i++) {
		read(fd, &pid[i], 1);
		if (isspace(pid[i]))
			break;
		if (!isdigit(pid[i])) {
			/* there is something wrong, not expected */
			printf("A valid pid was not found\n");
			goto nextline;
		}
	}
	pid[i] = '\0';
	if (i !=5)
		i++;
	/* ignore next 2 char( [) */
	read(fd, data, 7-i);
	/* read cpu 3 char */
	for (i = 0; i < 3; i++) {
		read(fd, &data[i], 1);
		if (!isdigit(data[i])) {
			/* there is something wrong, not expected */
			printf("A valid cpu was not found\n");
			goto nextline;
		}
	}
	data[i] = '\0';
	*cpu = atoi(data);
	/* ignore next 21 char(lat and ts) */
	read(fd, data, 21);
	/* read function (till next line, max 256 char) */
	for (i = 0; i < 256; i++) {
		read(fd, &trace[i], 1);
		if (trace[i] == '\n')
			break;
	}
	if (i == 256) {
		/* there is something wrong, not expected */
		printf("A valid trace was not found\n");
		goto nextline;
	}

	return 0;
nextline:
	do {
		read(fd, data, 1);
		printf("%c", data[0]);
	} while(data[0] != '\n');

	printf("comm:%s\n", comm);
	printf("pid:%s\n", pid);
	printf("cpu:%d\n", cpu);
	printf("trace:%s\n", trace);

	return -1;
}

static int disable_event(struct debug_trace_info *trace_info)
{
	int 	ret, fd;

	/* Disable events */
	fd = open(trace_info->events_enable_path, O_WRONLY);
	if (fd == -1) {
		printf("Could not open file %s\n",
				trace_info->events_enable_path);
		return -1;
	}
	ret = write(fd, "0", 1);
	if (ret != 1) {
		printf("Could not disable events\n");
		return -1;
	}
	close(fd);
	/* Disable Tracing */
	fd = open(trace_info->tracing_on_path, O_WRONLY);
	if (fd == -1) {
		printf("Could not open file %s\n",
				trace_info->tracing_on_path);
		return -1;
	}
	ret = write(fd, "0", 1);
	if (ret != 1) {
		printf("Could not disable trace\n");
		return -1;
	}
	close(fd);
	/* clear events */
	fd = open(trace_info->set_event_path, O_WRONLY | O_TRUNC);
	if (fd == -1) {
		printf("Could not open file %s\n",
				trace_info->set_event_path);
		return -1;
	}
	close(fd);

	return 0;
}

static int initialize_event(struct debug_trace_info *trace_info)
{
	int	ret, fd;

	disable_event(trace_info);
	/* set required events to measure memory consumption */
	fd = open(trace_info->set_event_path, O_WRONLY);
	if (fd == -1) {
		printf("Could not open file %s\n",
				trace_info->set_event_path);
		return -1;
	}
	ret = write(fd, "module:module_load", strlen("module:module_load"));
	if (ret != strlen("module:module_load")) {
		printf("Could not set module:module_load event %d\n", ret);
		return -1;
	}
	ret = write(fd, "module:module_put", strlen("module:module_put"));
	if (ret != strlen("module:module_put")) {
		printf("Could not set module:module_put event %d\n", ret);
		return -1;
	}
	ret = write(fd, "kmem:mm_page_alloc", strlen("kmem:mm_page_alloc"));
	if (ret != strlen("kmem:mm_page_alloc")) {
		printf("Could not set kmem:mm_page_alloc event %d\n", ret);
		return -1;
	}
	ret = write(fd, "kmem:mm_page_free", strlen("kmem:mm_page_free"));
	if (ret != strlen("kmem:mm_page_free")) {
		printf("Could not set kmem:mm_page_free event %d\n", ret);
		return -1;
	}
	close(fd);
	/* Enable Tracing */
	fd = open(trace_info->tracing_on_path, O_WRONLY);
	if (fd == -1) {
		printf("Could not open file %s\n",
				trace_info->tracing_on_path);
		return -1;
	}
	ret = write(fd, "1", 1);
	if (ret != 1) {
		printf("Could not enable trace\n");
		return -1;
	}
	close(fd);
	return 0;
}

static struct trace_entry *trace_entry_array[MAX_TASK_TO_MONITOR];
static int task_cnt;
static struct debug_trace_info trace_info;

static int get_pid_statm(char *pid)
{
	char statm[16];
	char rss[16];
	int fd, i = 0;

	strcpy(statm, "/proc/");
	strcat(statm, pid);
	strcat(statm, "/statm");

	fd = open(statm, O_RDONLY);
	if (fd == -1)
		return 0;
	/* ignore first entry */
	do {
		read(fd, rss, 1);
	} while (!isspace(rss[0]));
	/* read second entry:rss */
	do {
		read(fd, &rss[i], 1);
	} while (!isspace(rss[i++]));
	rss[i] = '\0';

	return atol(rss);

	close(fd);
}

static struct trace_entry* alloc_entry(char *key, char *mod, char *pid)
{
	ENTRY 	e, *ep;
	struct trace_entry* entry;

	if (task_cnt >= MAX_TASK_TO_MONITOR)
		return NULL;

	strcpy(key, mod);
	if (strcmp(mod, "") != 0)
		strcat(key, ":");
	strcat(key, pid);

	/* alloc a new entry only for a new pid */
	e.key = key;
	ep = hsearch(e, FIND);
	if (!ep) {
		entry = calloc(sizeof(struct trace_entry), 1);
		if (!entry) {
			printf("No heap memory\n");
			return NULL;
		}
		e.data = entry;
		ep = hsearch(e, ENTER);
		if (!ep) {
			free(entry);
			printf("No space in hash table to enter a new task\n");
			return NULL;
		}
		strcpy(entry->key, key);
		entry->peak_memory = get_pid_statm(pid);
		trace_entry_array[task_cnt++] = entry;
	}

	return (struct trace_entry*) ep->data;
}

static int process_entries(struct debug_trace_info *trace_info)
{
	int	fd, ret, pidno, cpu, memory;
	char	comm[17];
	char	pid[6];
	char	trace[256];
	char	function[64];
	char	discard[64];
	char	key[64];
	char	order[4];
	struct trace_entry *entry;

	fd = open(trace_info->trace_path, O_RDONLY);
	if (fd == -1) {
		printf("could not open file %s\n", trace_info->trace_path);
		return -1;
	}

	while (1) {
		ret = read_next_entry(fd, comm, pid, &cpu, trace);
		if (ret < 0) {
			printf("Could not read correct entry.\n");
			continue;
		}
		sscanf(trace, "%[^:]", function);
		if (strcmp(function, "module_load") == 0) {
			sscanf(trace, "%[^ ] %[^ \n]",
					discard, trace_info->cur_mod[cpu]);
			continue;
		} else if (strcmp(function, "module_put") == 0) {
			strcpy(trace_info->cur_mod[cpu], "");
			continue;
		}
		entry = alloc_entry(key, trace_info->cur_mod[cpu], pid);
		if (!entry)
			return -1;
		strcpy(entry->comm, comm);
		/*
		 * We should reach here only in case of either a new
		 * mm_page_alloc*() or mm_page_free*() is hit.
		 */
		sscanf(trace, "%[^:]%[^=]=%[^=]=%[^=]=%[^ ]",
				function, discard, discard,
				discard, order);
		sscanf(order, "%d", &memory);
		memory = 1 << memory;
		if (strncmp(function, "mm_page_alloc", strlen("mm_page_alloc"))
				== 0)
			entry->memory += memory;
		else
			entry->memory -= memory;
		if (entry->memory > entry->peak_memory)
			entry->peak_memory = entry->memory;
	}
	close(fd);
	return 0;
}

static void free_entries(void)
{
	int	task;

	for (task = 0; task < task_cnt; task++)
		free(trace_entry_array[task]);
}

static void print_stats(struct debug_trace_info *trace_info, bool file)
{
	FILE 	*fp = stdout;
	int	task;

	if (file) {
		fp = fopen(trace_info->log_path, "w");
		if (fp == NULL) {
			printf("Could not open log file %s\n",
					trace_info->log_path);
			return;
		}
	}
	fprintf(fp, "\nmodule:pid\t\tcomm\t\tpeak memory(in no of pages)\n");
	for (task = 0; task < task_cnt; task++)
		fprintf(fp, "%-20s\t%-20s\t\t%d\n",
				trace_entry_array[task]->key,
				trace_entry_array[task]->comm,
				trace_entry_array[task]->peak_memory);
	if (file)
		fclose(fp);
}

static void exit_handler(int sig_num)
{
	disable_event(&trace_info);
	print_stats(&trace_info, true);
	free_entries();
	hdestroy();
	exit(0);
}

static void print_handler(int sig_num)
{
	if (sig_num == SIGUSR1)
		print_stats(&trace_info, false);
	else
		print_stats(&trace_info, true);
}

int main(int argc, char *argv[])
{
	char	trace_dir[64];
	struct sigaction sterm, sprint;
	pthread_t tid;
	int	i;

	if (argc >= 2 && strlen(argv[1]) < 64)
		strcpy(trace_dir, argv[1]);
	else
		strcpy(trace_dir, "/sys/kernel/debug/tracing/");

	if (argc >= 3 && strlen(argv[2]) < 64)
		strcpy(trace_info.log_path, argv[2]);
	else
		strcpy(trace_info.log_path, DEFAULT_LOG_PATH);
	strcpy(trace_info.trace_path, trace_dir);
	strcat(trace_info.trace_path, "trace_pipe");
	strcpy(trace_info.events_enable_path, trace_dir);
	strcat(trace_info.events_enable_path, "events/enable");
	strcpy(trace_info.tracing_on_path, trace_dir);
	strcat(trace_info.tracing_on_path, "tracing_on");
	strcpy(trace_info.set_event_path, trace_dir);
	strcat(trace_info.set_event_path, "set_event");

	if (initialize_event(&trace_info)) {
		printf("tracefs is not mounted at %s\n", trace_dir);
		printf("Please provide correct path as 1st argument\n");
		return -1;
	}

	for (i = 0; i < MAX_NUMBER_OF_CPUS; i++)
		strcpy(trace_info.cur_mod[i], "");
	memset (&sterm, 0, sizeof (sterm));
	sterm.sa_handler = &exit_handler;
	sigaction (SIGINT, &sterm, NULL);
	sigaction (SIGTERM, &sterm, NULL);
	memset (&sprint, 0, sizeof (sprint));
	sprint.sa_handler = &print_handler;
	sigaction (SIGUSR1, &sprint, NULL);
	sigaction (SIGUSR2, &sprint, NULL);

	/*
	 * hash table to accommodate memory allocation entries corresponding
	 * to each task
	 */
	hcreate(MAX_TASK_TO_MONITOR);

	process_entries(&trace_info);
}

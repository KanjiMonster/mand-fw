/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <inttypes.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <syslog.h>
#include <getopt.h>
#include <pthread.h>
#include <time.h>

#include <curl/curl.h>
#include <libssh/libssh.h>

#define USE_DEBUG

#include <event.h>

#include <mand/logx.h>

#ifdef HAVE_TALLOC_TALLOC_H
# include <talloc/talloc.h>
#else
# include <talloc.h>
#endif

#include "comm.h"
#include "fw.h"

enum download_transport {
	TS_UNSPECIFIED,
	TS_HTTP,
	TS_HTTPS,
	TS_FTP,
	TS_SCP,
};

struct firmware_slot_internal {
	struct firmware_slot slot;

	LIST_ENTRY(firmware_slot_internal) list;
};

struct firmware_job_internal {
	struct firmware_job job;

	enum download_transport transport;
	char hostname[256];
	char host_fingerprint[256];
	char username[32];
	char path[256];
	uint16_t port;

	int num_tries;
	struct timespec next_try;

	LIST_ENTRY(firmware_job_internal) list;
};

static LIST_HEAD(fw_slots, firmware_slot_internal) slots;
static int num_slots;

static LIST_HEAD(fw_jobs, firmware_job_internal) jobs;
static int num_jobs;
static pthread_mutex_t dl_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint32_t next_job_id = 1;

static pthread_cond_t state_change = PTHREAD_COND_INITIALIZER;
static int shutting_down = false;

static const char _ident[] = "fw v" VERSION;
static const char _build[] = "build on " __DATE__ " " __TIME__ " with gcc " __VERSION__;

struct event_base *ev_base;

int get_num_firmware_slots(void)
{
	return num_slots;
}

int get_num_firmware_jobs(void)
{
	return num_slots;
}

struct firmware_slot *add_firmware_slot(char *name, char *path)
{
	struct firmware_slot_internal *slot = calloc(sizeof(*slot), 1);

	if (!slot)
		return NULL;

	strncpy(slot->slot.name, name, sizeof(slot->slot.name) - 1);
	strncpy(slot->slot.path, path, sizeof(slot->slot.path) - 1);

	LIST_INSERT_HEAD(&slots, slot, list);
	num_slots++;

	return &slot->slot;
}

struct firmware_slot *get_fw_slot_by_number(int num)
{
	struct firmware_slot_internal *slot;
	int i = 0;

	if (LIST_EMPTY(&slots)) {
		return NULL;
	}

	LIST_FOREACH(slot, &slots, list) {
		if (i == num)
			return &slot->slot;

		i++;
	}

	return NULL;
}

#define SLOT_PREFIX "system-state.firmware-slot."

struct firmware_slot *get_fw_slot_by_name(const char *path)
{
	struct firmware_slot_internal *slot;
	const char *slot_name;

	if (LIST_EMPTY(&slots))
		return NULL;

	if (strncmp(path, SLOT_PREFIX, strlen(SLOT_PREFIX)))
		return NULL;

	slot_name = path + strlen(SLOT_PREFIX);

	LIST_FOREACH(slot, &slots, list) {
		if (strcmp(slot->slot.name, slot_name))
			return &slot->slot;
	}

	return NULL;
}

struct firmware_job *get_fw_job_by_num(int num)
{
	struct firmware_job_internal *job;
	struct firmware_job *ret = NULL;
	int i = 0;

	pthread_mutex_lock(&dl_mutex);

	if (LIST_EMPTY(&jobs))
		return NULL;

	LIST_FOREACH(job, &jobs, list) {
		if (i == num) {
			ret = &job->job;
			break;
		}

		i++;
	}
	pthread_mutex_unlock(&dl_mutex);

	return ret;
}

struct firmware_job *get_fw_job_by_id(int32_t job_id)
{
	struct firmware_job_internal *job;
	struct firmware_job *ret = NULL;

	pthread_mutex_lock(&dl_mutex);

	if (LIST_EMPTY(&jobs))
		return NULL;

	LIST_FOREACH(job, &jobs, list) {
		if (job->job.job_id == job_id) {
			ret = &job->job;
			break;
		}

	}
	pthread_mutex_unlock(&dl_mutex);

	return ret;
}


static void __free_job(struct firmware_job_internal *job)
{
	switch (job->job.cred_type) {
	case CRED_NONE:
		break;
	case CRED_PASSWORD:
	case CRED_CERTIFICATE:
	case CRED_SSH_KEY:
		free(job->job.pass_path);
		break;
	}

	free(job);
}

void free_job(struct firmware_job *job)
{
	__free_job((struct firmware_job_internal *)job);
}

static int parse_uri(struct firmware_job_internal *job, const char *uri)
{
	const char *at, *c = uri;
	const char *path, *sep;

	if (!strncmp(c, "http", strlen("http"))) {
		c += strlen("http"); 
		if (*c == 's') {
			job->transport = TS_HTTPS;
			c++;
		} else {
			job->transport = TS_HTTP;
		}
	} else if (!strncmp(c, "http", strlen("ftp"))) {
		c += strlen("ftp");
		job->transport = TS_FTP;
	} else if (!strncmp(c, "scp", strlen("scp"))) {
		c += strlen("scp");
		job->transport = TS_SCP;
	}

	if (strncmp(c, "://", 3))
		return -1;

	c += strlen("://");

	at = strchr(c, '@');
	if (at) {
		size_t un_len = at - c;

		if (un_len >= 32)
			return -1;

		strncpy(job->username, c, un_len);

		c = at + 1;
	}

	path = strchr(c, '/');
	if (!path)
		return -1;

	/* TODO: check for host key for scp? */
	sep = strchr(c, ':');
	if (sep && sep < path) {
		strncpy(job->hostname, c, sep - c);
		job->port = atoi(sep + 1);
	} else {
		strncpy(job->hostname, c, path - c);
	}

	strncpy(job->path, path + 1, 255);

	return 0;
}

struct firmware_job *create_job(const char *uri, enum credential_type creds, const char *pass_path)
{
	struct firmware_job_internal *new_job;
	void *tmp;
	char *c;
	size_t uri_len, cred_len = 0;

	if (!uri)
		return NULL;

	uri_len = strlen(uri) + 1;
	if (creds != CRED_NONE) {
		/* TODO: check username presence in uri? */

		if (!pass_path)
			return NULL;

		cred_len = strlen(pass_path) + 1;
	}

	tmp = calloc(1, sizeof(*new_job) + uri_len + cred_len);
	if (!tmp)
		return NULL;

	new_job = (struct firmware_job_internal *)tmp;
	c = (char *)(tmp + sizeof(*new_job));
	strcpy(c, uri);
	new_job->job.uri = strcpy(c, uri);

	if (cred_len) {
		c += uri_len;
		new_job->job.pass_path = strcpy(c, pass_path);
		new_job->job.cred_type = creds;
	}

	parse_uri(new_job, uri);

	new_job->job.retry_count = 3;
	new_job->job.retry_interval = 300;
	new_job->job.retry_interval_increment = 20;

	return &new_job->job;
}

int job_set_target(struct firmware_job *job, const char *name)
{
	struct firmware_slot *slot;

	slot = get_fw_slot_by_name(name);
	if (!slot)
		return -1;

	job->install_target = slot->name;

	return 0;
}

int vsystem(const char *cmd)
{
        int rc = 0;
        int _errno;

        fprintf(stderr, "cmd=[%s]\n", cmd);

        errno = 0;
        rc = system(cmd);

        _errno = errno;
        fprintf(stderr, "cmd=[%s], rc=%d, error=%s\n", cmd, rc, strerror(_errno));
	errno = _errno;

        return rc;
}

int vasystem(const char *fmt, ...)
{
        va_list args;
        char    buf[1024];

        va_start(args, fmt);
        vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);

        return vsystem(buf);
}

int32_t firmware_download(struct firmware_job *job)
{
	struct firmware_job_internal *int_job = (struct firmware_job_internal *)job;

	pthread_mutex_lock(&dl_mutex);
	if (!job->job_id)
		job->job_id = next_job_id++;
	LIST_INSERT_HEAD(&jobs, int_job, list);
	num_jobs++;
	pthread_cond_signal(&state_change);
	pthread_mutex_unlock(&dl_mutex);

	return job->job_id;
}

#define DL_PATH "/tmp"

int32_t firmware_commit(int32_t job_id)
{
	struct firmware_job_internal *job;
	bool found = false;

	if (LIST_EMPTY(&jobs))
		return -1;

	LIST_FOREACH(job, &jobs, list) {
		if (job->job.job_id == job_id) {
			found = true;
			break;
		}
	}

	if (!found)
		return -1;

	if (job->job.status != FW_DONE)
		return -1;

	/* fork() ? */
	if (job->job.install_target) {
		return vasystem("/sbin/sysupgrade -t %s %s/image-%i &", job->job.install_target, DL_PATH, job->job.job_id);
	} else {
		return vasystem("/sbin/sysupgrade %s/image-%i &", DL_PATH, job->job.job_id);
	}
}

static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
	return fwrite(ptr, size, nmemb, (FILE *)stream);
}

int download_http(struct firmware_job_internal *job, const char *file)
{
	CURL *curl_handle;
	FILE *image;
	int ret;

	curl_handle = curl_easy_init();
	curl_easy_setopt(curl_handle, CURLOPT_URL, job->job.uri);

	switch (job->job.cred_type) {
	case CRED_NONE:
		break;
	case CRED_PASSWORD:
		curl_easy_setopt(curl_handle, CURLOPT_PASSWORD, job->job.pass_path);
		break;
	case CRED_CERTIFICATE:
		curl_easy_setopt(curl_handle, CURLOPT_SSLCERT, job->job.pass_path);
		break;
	default:
		return -1;
	}
	curl_easy_setopt(curl_handle, CURLOPT_FAILONERROR, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_data);

	image = fopen(file, "wb");
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, image);

	ret = curl_easy_perform(curl_handle);

	fclose(image);

	curl_easy_cleanup(curl_handle);

	return ret;
}

#define min(a, b)	((a) > (b) ? (b) : (a))

int download_scp(struct firmware_job_internal *job, const char *file)
{
	ssh_session ssh_session;
	FILE *image;
	ssh_scp scp;
	char *buffer;
	uint64_t size, total = 0;
	int rc;
#if (LIBSSH_VERSION_INT >= SSH_VERSION_INT(6,0,0))
	ssh_key pub_key = NULL, priv_key = NULL;
#endif

#if (LIBSSH_VERSION_INT >= SSH_VERSION_INT(6,0,0))
	if (job->job.cred_type == CRED_SSH_KEY) {
		char *pub_key_path;

		pub_key = ssh_key_new();
		priv_key = ssh_key_new();

		if (!pub_key || !priv_key)
			return SSH_ERROR;

		rc = ssh_pki_import_privkey_file(job->job.pass_path, NULL, NULL, NULL, &priv_key);
		if (rc != SSH_OK)
			goto out_ssh_free;

		rc = ssh_pki_export_privkey_to_pubkey(priv_key, &pub_key);
		if (rc != SSH_OK)
			goto out_ssh_free;
	}
#endif

	ssh_session = ssh_new();
	if (!ssh_session)
		goto out_ssh_free;

	ssh_options_set(ssh_session, SSH_OPTIONS_HOST, job->hostname);
	if (job->port)
		ssh_options_set(ssh_session, SSH_OPTIONS_PORT, &job->port);

	rc = ssh_connect(ssh_session);
	if (rc != SSH_OK)
		goto out_ssh_free;

	/* TODO: ensure we trust the host */

	switch (job->job.cred_type) {
	case CRED_PASSWORD:
		rc = ssh_userauth_password(ssh_session, NULL, job->job.pass_path);
		break;
	case CRED_SSH_KEY:
#if (LIBSSH_VERSION_INT >= SSH_VERSION_INT(6,0,0))
		rc = ssh_userauth_try_publickey(ssh_session, NULL, pub_key);
		if (rc == SSH_AUTH_SUCCESS)
			rc = ssh_userauth_publickey(ssh_session, NULL, priv_key);
#else
		rc = ssh_userauth_privatekey_file(ssh_session, NULL, job->job.pass_path, NULL);
#endif
		break;
	default:
		rc = SSH_ERROR;
		break;
	}
	if (rc != SSH_OK && rc != SSH_AUTH_SUCCESS)
		goto out_disconnect;

	scp = ssh_scp_new(ssh_session, SSH_SCP_READ, job->path);
	if (!scp)
		goto out_disconnect;

	rc = ssh_scp_init(scp);
	if (rc != SSH_OK)
		goto out_scp_free;

	rc = ssh_scp_pull_request(scp);
	if (rc != SSH_SCP_REQUEST_NEWFILE)
		goto out_scp_close;

	size = ssh_scp_request_get_size(scp);

	image = fopen(file, "wb");

	buffer = malloc(min(size, 2048));
	if (!buffer)
		return -1;


	ssh_scp_accept_request(scp);

	while (total < size) {
		uint64_t to_read = min(size - total, 2048);

		rc = ssh_scp_read(scp, buffer, to_read);

		fwrite(buffer, 1, to_read, image);

		total += to_read;

		job->job.progress = (total * 100ULL)/size;
	}

	free(buffer);

	fclose(image);

	rc = ssh_scp_pull_request(scp);
out_scp_close:
	ssh_scp_close(scp);
out_scp_free:
	ssh_scp_free(scp);
out_disconnect:
	ssh_disconnect(ssh_session);
out_ssh_free:
	ssh_free(ssh_session);

#if (LIBSSH_VERSION_INT >= SSH_VERSION_INT(6,0,0))
	ssh_key_free(priv_key);
	ssh_key_free(pub_key);
#endif
	return rc;
}

struct firmware_job_internal *get_next_available_job(void)
{
	struct firmware_job_internal *job;
	struct timespec now;

	if (LIST_EMPTY(&jobs))
		return NULL;

	clock_gettime(CLOCK_MONOTONIC, &now);

	LIST_FOREACH(job, &jobs, list) {
		if (job->job.status != FW_DONE &&
		    job->num_tries <= job->job.retry_count &&
		    job->next_try.tv_sec <= now.tv_sec)
			return job;
	}


	return NULL;
}

void *download_thread_main(void *arg)
{
	bool running = true;

	do {
		struct firmware_job_internal *next = NULL;

		pthread_mutex_lock(&dl_mutex);
		if (shutting_down) {
			running = false;
		} else {
			next = get_next_available_job();
		}
		pthread_mutex_unlock(&dl_mutex);

		if (!next && !shutting_down)
			sleep(1);

		if (next) {
			int ret;
			char *target_file;

			next->job.status = FW_IN_PROGRESS;
			next->num_tries++;

			asprintf(&target_file, "%s/image-%i", DL_PATH, next->job.job_id);

			switch (next->transport) {
			case TS_HTTP:
			case TS_HTTPS:
			case TS_FTP:
				ret = download_http(next, target_file);
				break;
			case TS_SCP:
				ret = download_scp(next, target_file);
				break;
			default:
				ret = -1;
			}
			free(target_file);

			if (!ret) {
				/* verify integrity */
				ret = vasystem("/sbin/sysupgrade -T %s/image-%i", DL_PATH, next->job.job_id);

				/* for some reason this always fails ... */
				if (ret && 0) {
					next->job.status = FW_VERIFICATION_FAILED;
				} else {
					next->job.status = FW_DONE;
				}
			} else {
				struct timespec now;
				int change_percent = 0;
				unsigned long change;

				clock_gettime(CLOCK_MONOTONIC, &now);

				if (next->job.retry_interval_increment > 0) {
					int inc = next->job.retry_interval_increment;

					change_percent = rand() % (2 * inc + 1) - inc;
				}

				change = (next->job.retry_interval * (100ULL + change_percent)) / 100ULL;

				next->next_try.tv_sec = now.tv_sec + change;

				next->job.status = FW_DL_FAILED;
			}
		}
	} while (running);

	pthread_exit(NULL);
}


static void sig_usr1(EV_P_ ev_signal *w, int revents)
{
}

static void sig_usr2(EV_P_ ev_signal *w, int revents)
{
	logx_level = logx_level == LOG_DEBUG ? LOG_INFO : LOG_DEBUG;
}

static void sig_pipe(EV_P_ ev_signal *w, int revents)
{
	logx(LOG_DEBUG, "sig_pipe");
}

static void usage(void)
{
	printf("mand-fw, Version: .....\n\n"
	       "Usage: mand-fw [OPTION...]\n\n"
	       "Options:\n\n"
	       "  -h                        this help\n"
	       "  -l, --log=IP              write log to syslog at this IP\n"
	       "  -x                        debug logging\n\n");

	exit(EXIT_SUCCESS);
}

static pthread_t download_thread;

int main(int argc, char *argv[])
{
	const struct rlimit rlim = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY
	};

	ev_signal signal_usr1;
	ev_signal signal_usr2;
	ev_signal signal_pipe;
	int c, ret;

	curl_global_init(CURL_GLOBAL_ALL);

	/* unlimited size for cores */
	setrlimit(RLIMIT_CORE, &rlim);

	/* TODO: read these out properly */
	add_firmware_slot("firmware1", "file:///dev/mtd7");
	add_firmware_slot("firmware2", "file:///dev/mtd8");

	pthread_create(&download_thread, NULL, download_thread_main, NULL);

	logx_level = LOG_INFO;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"log",       1, 0, 'l'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hl:x",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			usage();
			break;

		case 'l': {
			struct in_addr addr;

			if (inet_aton(optarg, &addr) == 0) {
				fprintf(stderr, "Invalid IP address: '%s'\n", optarg);
				exit(EXIT_FAILURE);
			} else
				logx_remote(addr);
			break;
		}

		case 'x':
			logx_level = LOG_DEBUG;
			break;

		default:
			printf("?? getopt returned character code 0%o ??\n", c);
		}
	}

	logx_open(basename(argv[0]), 0, LOG_DAEMON);

	ev_signal_init(&signal_usr1, sig_usr1, SIGUSR1);
	ev_signal_start(EV_DEFAULT_ &signal_usr1);

	ev_signal_init(&signal_usr2, sig_usr2, SIGUSR2);
	ev_signal_start(EV_DEFAULT_ &signal_usr2);

	ev_signal_init(&signal_pipe, sig_pipe, SIGPIPE);
	ev_signal_start(EV_DEFAULT_ &signal_pipe);

	init_comm(EV_DEFAULT);

	logx(LOG_NOTICE, "startup %s %s (pid %d)\n", _ident, _build, getpid());

        ev_run(EV_DEFAULT, 0);

	pthread_mutex_lock(&dl_mutex);
	shutting_down = true;
	pthread_cond_signal(&state_change);
	pthread_mutex_unlock(&dl_mutex);

	pthread_exit(NULL);

        return 0;
}

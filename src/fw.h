/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __FW_H
#define __FW_H

#include <sys/queue.h>
#include <sys/tree.h>
#include <stdbool.h>

enum firmware_status {
	FW_PLANNED,
	FW_IN_PROGRESS,
	FW_DL_FAILED,
	FW_VERIFICATION_FAILED,
	FW_DONE,
};

#define VER_MAX	32

struct firmware_slot {
	char name[PATH_MAX];
	char version[VER_MAX];
	bool active;
	char path[PATH_MAX];
};

enum credential_type {
	CRED_NONE,
	CRED_PASSWORD,
	CRED_CERTIFICATE,
	CRED_SSH_KEY,
};

struct firmware_job {
	const char *uri;
	enum credential_type cred_type;
	char *pass_path;

	char *install_target;

	int32_t timeframe;
	uint8_t retry_count;
	uint32_t retry_interval;
	uint8_t retry_interval_increment;

	int32_t job_id;

	enum firmware_status status;
	const char *status_message;
	uint8_t progress;
};

int get_num_firmware_slots(void);

struct firmware_slot *get_fw_slot_by_number(int num);
struct firmware_slot *get_fw_slot_by_name(const char *path);

int get_num_firmware_jobs(void);
struct firmware_job *get_fw_job_by_num(int num);
struct firmware_job *get_fw_job_by_id(int32_t job_id);

struct firmware_job *create_job(const char *uri, enum credential_type creds, const char *pass_path);
void free_job(struct firmware_job *job);

int job_set_target(struct firmware_job *job, const char *path);

int32_t firmware_download(struct firmware_job *job);

int firmware_commit(int32_t job_id);

#endif

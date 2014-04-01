/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/tree.h>
#include <sys/queue.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>

#include <ev.h>

#include "config.h"
#include <mand/logx.h>

#ifdef HAVE_TALLOC_TALLOC_H
# include <talloc/talloc.h>
#else
# include <talloc.h>
#endif

#include <libdmconfig/codes.h>
#include <libdmconfig/dmmsg.h>
#include <libdmconfig/dmconfig.h>
#include <libdmconfig/dm_dmconfig_rpc_stub.h>
#include <libdmconfig/dm_dmclient_rpc_impl.h>

#include "fw.h"
#include "comm.h"

#define CB_ERR(...) \
	do {					\
		fprintf(stderr, __VA_ARGS__);	\
		fprintf(stderr, "\n");		\
		logx(LOG_ERR, __VA_ARGS__);	\
		return;				\
	} while (0)
#define CB_ERR_RET(ret, ...)			\
	do {					\
		fprintf(stderr, __VA_ARGS__);	\
		fprintf(stderr, "\n");		\
		logx(LOG_ERR, __VA_ARGS__);	\
		return ret;			\
	} while (0)

typedef void (*DECODE_CB)(const char *name, uint32_t code, uint32_t vendor_id, void *data, size_t size, void *cb_data);

#if 0

static void *new_string_list(void *ctx, struct string_list *list)
{
	memset(list, 0, sizeof(struct string_list));
	list->s = talloc_array(ctx, char *, 16);

	return list->s;
}
static void add_string_list(struct string_list *list, const void *data, size_t size)
{
	if ((list->count % 16) == 0) {
		if (!(list->s = talloc_realloc(NULL, list->s, char *, list->count + 16)))
			return;
	}
	list->s[list->count] = talloc_strndup(list->s, data, size);
	list->count++;
}
#endif

uint32_t
decode_node_list(const char *prefix, DM2_AVPGRP *grp, DECODE_CB cb, void *cb_data)
{
	uint32_t r;
	DM2_AVPGRP container;
	char *name, *path;
	uint32_t code;
	uint32_t vendor_id;
	void *data;
	size_t size;
	uint16_t id;
	uint32_t type;

	if ((r = dm_expect_avp(grp, &code, &vendor_id, &data, &size)) != RC_OK)
		return r;

	if (vendor_id != VP_TRAVELPING)
		return RC_ERR_MISC;

	dm_init_avpgrp(grp->ctx, data, size, &container);

	switch (code) {
	case AVP_TABLE:
                if ((r = dm_expect_string_type(&container, AVP_NAME, VP_TRAVELPING, &name)) != RC_OK)
                        return r;

                if (!(path = talloc_asprintf(container.ctx, "%s.%s", prefix, name)))
                        return RC_ERR_ALLOC;

                while (decode_node_list(path, &container, cb, cb_data) == RC_OK) {
                }

                break;

        case AVP_INSTANCE:
                if ((r = dm_expect_uint16_type(&container, AVP_NAME, VP_TRAVELPING, &id)) != RC_OK)
                        return r;

                if (!(path = talloc_asprintf(container.ctx, "%s.%d", prefix, id)))
                        return RC_ERR_ALLOC;

                while (decode_node_list(path, &container, cb, cb_data) == RC_OK) {
                }

                break;

        case AVP_OBJECT:
                if ((r = dm_expect_string_type(&container, AVP_NAME, VP_TRAVELPING, &name)) != RC_OK)
                        return r;

                if (!(path = talloc_asprintf(container.ctx, "%s.%s", prefix, name)))
                        return RC_ERR_ALLOC;

                while (decode_node_list(path, &container, cb, cb_data) == RC_OK) {
                }

                break;

        case AVP_ELEMENT:
                if ((r = dm_expect_string_type(&container, AVP_NAME, VP_TRAVELPING, &name)) != RC_OK
                    || (r = dm_expect_uint32_type(&container, AVP_TYPE, VP_TRAVELPING, &type)) != RC_OK)
                        return r;

                if (!(path = talloc_asprintf(container.ctx, "%s.%s", prefix, name)))
                        return RC_ERR_ALLOC;

                if ((r = dm_expect_avp(&container, &code, &vendor_id, &data, &size)) != RC_OK)
                        return r;

                cb(path, code, vendor_id, data, size, cb_data);
                break;

        case AVP_ARRAY:
                if ((r = dm_expect_string_type(&container, AVP_NAME, VP_TRAVELPING, &name)) != RC_OK
                    || (r = dm_expect_uint32_type(&container, AVP_TYPE, VP_TRAVELPING, &type)) != RC_OK)
                        return r;

                if (!(path = talloc_asprintf(container.ctx, "%s.%s", prefix, name)))
                        return RC_ERR_ALLOC;

                while (dm_expect_group_end(&container) != RC_OK) {
                        if ((r = dm_expect_avp(&container, &code, &vendor_id, &data, &size)) != RC_OK)
                                return r;
                        cb(path, code, vendor_id, data, size, cb_data);
                }
                break;

        default:
                return RC_ERR_MISC;
        }

	return RC_OK;
}


static void
firmware_slots_received(DMCONTEXT *dmCtx, DMCONFIG_EVENT event, DM2_AVPGRP *grp, void *user_data __attribute__((unused)))
{
        if (event != DMCONFIG_ANSWER_READY)
                CB_ERR("Couldn't list object.\n");
#if 0
	while (decode_node_list("system-state.firmware-slots", grp, fw_slot_cb, NULL) == RC_OK);
#endif

}

static void
list_system_state_firmware_slots(DMCONTEXT *dmCtx)
{
        if (rpc_db_list_async(dmCtx, 0, "system-state.firmware-slots", firmware_slots_received, NULL))
                CB_ERR("Couldn't register LIST request.\n");
}

static uint32_t
init_firmware_slots(DMCONTEXT *context)
{
	uint32_t rc = RC_OK;
	int i, slots;
	struct dm2_avp search = {
		.code = AVP_UNKNOWN,
		.vendor_id = VP_TRAVELPING,
		.data = "",
		.size = 0,
	};
	DM2_AVPGRP *answer;

	answer = calloc(sizeof(DM2_AVPGRP), 1);
	if (!answer)
		return RC_ERR_ALLOC;

	slots = get_num_firmware_slots();

	for (i = 0; i < slots; i++) {
		struct firmware_slot *slot = get_fw_slot_by_number(i);
		char *path;
		struct rpc_db_set_path_value set_value = {
			.value = {
				.code = AVP_UNKNOWN,
				.vendor_id = VP_TRAVELPING,
			},
		};
		uint16_t id;


		if (!slot)
			continue;

		search.data = slot->name;
		search.size = strlen(slot->name);

		rc = rpc_db_findinstance(context, "system-state.firmware-slot", "name", &search, answer);
		if (rc == RC_OK) {
			rc = dm_expect_uint16_type(answer, AVP_UINT16, VP_TRAVELPING, &id);
		}

		if (rc != RC_OK) {
			rc = rpc_db_addinstance(context, "system-state.firmware-slot", 0xc000, answer);
			if (rc != RC_OK)
				break;

			rc = dm_expect_uint16_type(answer, AVP_UINT16, VP_TRAVELPING, &id);
		}

		if (rc != RC_OK)
			break;


		asprintf(&path, "system-state.firmware-slot.%i.name", id);
		set_value.path = path;
		set_value.value.data = slot->name;
		set_value.value.size = strlen(slot->name);

		rc = rpc_db_set(context, 1, &set_value, answer);
		free(path);

		if (rc != RC_OK)
			break;

		asprintf(&path, "system-state.firmware-slot.%i.path", id);
		set_value.path = path;
		set_value.value.data = slot->path;
		set_value.value.size = strlen(slot->path);

		rc = rpc_db_set(context, 1, &set_value, answer);
		free(path);
	}

out:
	free(answer);
	return rc;
}

uint32_t rpc_agent_firmware_download(void *ctx, char *address, uint8_t credentialstype, char *credential,
				     char *install_target, uint32_t timeframe, uint8_t retry_count,
				     uint32_t retry_interval, uint32_t retry_interval_increment,
				     DM2_REQUEST *answer)
{
	struct firmware_job *job;
	int32_t job_id;
	uint32_t rc = RC_OK;

	job = create_job(address, credentialstype, credential);
	if (!job)
		return 1;

	job_set_target(job, install_target);
	job->timeframe = timeframe;
	job->retry_count = retry_count;
	job->retry_interval = retry_interval;
	job->retry_interval_increment = retry_interval_increment;

	job_id = firmware_download(job);
	rc = dm_add_int32(answer, AVP_INT32, VP_TRAVELPING, job_id);
out:
	if (rc > 0) {
		free_job(job);
	}

	return rc;
}

uint32_t rpc_agent_firmware_commit(void *ctx, int32_t job_id)
{
	struct firmware_job *job = get_fw_job_by_id(job_id);

	if (!job) {
		printf("no job with id %i\n", job_id);
		return 1;
	}
	if (job->status != FW_DONE) {
		printf("job with wrong state %i\n", job->status);
		return 1;
	}

	return firmware_commit(job_id);
}

uint32_t rpc_agent_set_boot_order(void *ctx, int pcnt, const char **boot_order)
{
	return 0;
}

uint32_t rpc_client_event_broadcast(void *ctx, const char *path, uint32_t type)
{
	if (strncmp(path, "system-state.download-job", 10) == 0) {
	} else if (strncmp(path, "system-state.firmware-slot", 10) == 0) {
	}

	return RC_OK;
}


static uint32_t
socket_connected(DMCONFIG_EVENT event, DMCONTEXT *context, void *userdata __attribute__ ((unused)))
{
	struct timeval timeout = { .tv_sec = 120, .tv_usec = 0 };
	uint32_t rc;

        if (event != DMCONFIG_CONNECTED) {
		ev_break(context->ev, EVBREAK_ALL);
                CB_ERR_RET(RC_ERR_MISC, "Connecting socket unsuccessful.");
	}

        logx(LOG_DEBUG, "Socket connected.");

	if ((rc = rpc_startsession(context, CMD_FLAG_READWRITE, 0, NULL)) != RC_OK) {
		ev_break(context->ev, EVBREAK_ALL);
		CB_ERR_RET(rc, "Couldn't register start session request, rc=%d.", rc);
	}

	logx(LOG_DEBUG, "Start session request registered.");

	if ((rc = rpc_register_role(context, "-firmware")) != RC_OK) {
		ev_break(context->ev, EVBREAK_ALL);
		CB_ERR_RET(rc, "Couldn't register role, rc=%d.", rc);
	}
	logx(LOG_DEBUG, "Role registered.");

	if ((rc = rpc_subscribe_notify(context, NULL)) != RC_OK) {
		ev_break(context->ev, EVBREAK_ALL);
		CB_ERR_RET(rc, "Couldn't register SUBSCRIBE NOTIFY request, rc=%d.", rc);
	}

	logx(LOG_DEBUG, "Notification subscription request registered.");

	if ((rc = init_firmware_slots(context)) != RC_OK)
		return rc;

	return RC_OK;

}

static void
request_cb(DMCONTEXT *socket, DM_PACKET *pkt, DM2_AVPGRP *grp, void *userdata)
{
	DM2_REQUEST *answer = NULL;
	DMC_REQUEST req = {
		.hop2hop = dm_hop2hop_id(pkt),
		.end2end = dm_end2end_id(pkt),
		.code = dm_packet_code(pkt),
	};

	if ((rpc_dmclient_switch(socket, &req, grp, &answer)) == RC_ERR_ALLOC) {
		dm_context_shutdown(socket, DMCONFIG_OK);
		dm_context_release(socket);
		ev_break(socket->ev, EVBREAK_ALL);
		return;
	}

	if (answer)
		dm_enqueue(socket, answer, REPLY, NULL, NULL);
}

void init_comm(struct ev_loop *loop)
{
	uint32_t rc;
	DMCONTEXT *context;

	if (!(context = dm_context_new())) {
		logx(LOG_DEBUG, "Couldn't create socket context.");
		return;
	}
	dm_context_init(context, loop, AF_INET, NULL, socket_connected, request_cb);

	if ((rc = dm_connect_async(context)) != RC_OK) {
		logx(LOG_DEBUG, "Couldn't register connect callback or connecting unsuccessful, rc=%d.", rc);
		dm_context_shutdown(context, DMCONFIG_ERROR_CONNECTING);
		dm_context_release(context);
		return;
	}

        logx(LOG_DEBUG, "Connect callback registered.");
}

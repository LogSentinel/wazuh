/* Copyright (C) 2015-2021, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "active_responses.h"

#define KILL_LINUX "kill"

int main (int argc, char **argv) {
    (void)argc;
    int action = OS_INVALID;
    cJSON *input_json = NULL;
	char *pid;

    action = setup_and_check_message(argv, &input_json);
    if ((action != ADD_COMMAND) && (action != DELETE_COMMAND)) {
        return OS_INVALID;
    }

    // Get pid
    pid = get_extra_args_from_json(input_json);
	
    if (!pid) {
        write_debug_file(argv[0], "Cannot read 'pid' from data");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

#ifndef WIN32
	char *exec_cmd1[4] = { NULL, NULL, NULL, NULL };

	const char *arg1[4] = { KILL_LINUX, "-9", pid, NULL };
	memcpy(exec_cmd1, arg1, sizeof(exec_cmd1));

	wfd = wpopenv(KILL_LINUX, exec_cmd1, W_BIND_STDERR);
	if (!wfd) {
		write_debug_file(argv[0], "Unable to run kill -9");
	} else {
		wpclose(wfd);
	}
	
#else
	char cmd[OS_MAXSTR + 1];
	snprintf(cmd, OS_MAXSTR, "taskkill.exe /f /pid %s", pid);
	system(cmd);
#endif

    write_debug_file(argv[0], "Ended");

    cJSON_Delete(input_json);

    return OS_SUCCESS;
}

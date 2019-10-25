/*
	luksrku - Tool to remotely unlock LUKS disks using TLS.
	Copyright (C) 2016-2019 Johannes Bauer

	This file is part of luksrku.

	luksrku is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; this program is ONLY licensed under
	version 3 of the License, later versions are explicitly excluded.

	luksrku is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with luksrku; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

	Johannes Bauer <JohannesBauer@gmx.de>
*/

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "luks.h"
#include "log.h"
#include "exec.h"
#include "util.h"
#include "uuid.h"

bool is_luks_device_opened(const char *mapping_name) {
	struct exec_cmd_t cmd = {
		.argv = (const char *[]){
			"dmsetup",
			"status",
			mapping_name,
			NULL,
		},
		.show_output = should_log(LLVL_TRACE),
	};
	struct exec_result_t runresult = exec_command(&cmd);
	return runresult.success && (runresult.returncode == 0);
}

bool open_luks_device(const uint8_t *encrypted_device_uuid, const char *mapping_name, const char *passphrase, unsigned int passphrase_length) {
	char encrypted_device[64];
	strcpy(encrypted_device, "UUID=");
	sprintf_uuid(encrypted_device + 5, encrypted_device_uuid);
	log_msg(LLVL_INFO, "Trying to unlock LUKS mapping %s based on %s", mapping_name, encrypted_device);

	struct exec_cmd_t cmd = {
		.argv = (const char *[]){
			"cryptsetup",
			"luksOpen",
			"-T", "1",
			encrypted_device,
			mapping_name,
			NULL,
		},
		.stdin_data = passphrase,
		.stdin_length = passphrase_length,
		.show_output = should_log(LLVL_DEBUG),
	};
	struct exec_result_t runresult = exec_command(&cmd);
	return runresult.success && (runresult.returncode == 0);
}

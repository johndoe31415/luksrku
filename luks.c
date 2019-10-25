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
	const char *command[] = {
		"dmsetup",
		"status",
		mapping_name,
		NULL,
	};
	struct runresult_t runresult = exec_command(command, should_log(LLVL_TRACE));
	return runresult.success && (runresult.returncode == 0);
}

bool open_luks_device(const uint8_t *encrypted_device_uuid, const char *mapping_name, const char *passphrase_file) {
	char encrypted_device[64];
	strcpy(encrypted_device, "UUID=");
	sprintf_uuid(encrypted_device + 5, encrypted_device_uuid);
	log_msg(LLVL_INFO, "Trying to unlock LUKS mapping %s based on %s", mapping_name, encrypted_device);

	const char *command[] = {
		"cryptsetup",
		"luksOpen",
		"-T", "1",
		"-d", passphrase_file,
		encrypted_device,
		mapping_name,
		NULL,

	};
	struct runresult_t runresult = exec_command(command, should_log(LLVL_DEBUG));
	return runresult.success && (runresult.returncode == 0);
}

static bool wipe_passphrase_file(const char *filename, int length) {
	uint8_t wipe_buf[length];
	memset(wipe_buf, 0, length);

	int fd = open(filename, O_WRONLY);
	if (fd == -1) {
		log_libc(LLVL_ERROR, "Wiping of passphrase file %s failed in open(2)", filename);
		return false;
	}

	if (write(fd, wipe_buf, length) != length) {
		log_libc(LLVL_ERROR, "Wiping of passphrase file %s failed in write(2)", filename);
		close(fd);
		return false;
	}
	close(fd);
	unlink(filename);
	return true;
}

static const char *write_passphrase_file(const void *passphrase, int passphrase_length) {
	//const char *filename = "/dev/shm/luksrku_passphrase.bin";		/* TODO make this variable */
	const char *filename = "/tmp/luksrku_passphrase.bin";
	int fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (fd == -1) {
		log_libc(LLVL_ERROR, "Creation of passphrase file %s failed", filename);
		return NULL;
	}

	if (write(fd, passphrase, passphrase_length) != passphrase_length) {
		log_libc(LLVL_ERROR, "Writing to passphrase file %s failed", filename);
		wipe_passphrase_file(filename, passphrase_length);
		close(fd);
		return NULL;
	}

	close(fd);
	return filename;
}

bool open_luks_device_pw(const uint8_t *encrypted_device_uuid, const char *mapping_name, const char *passphrase, unsigned int passphrase_length) {
	const char *pw_filename = write_passphrase_file(passphrase, passphrase_length);
	if (!pw_filename) {
		return false;
	}
	bool success = open_luks_device(encrypted_device_uuid, mapping_name, pw_filename);
	if (!wipe_passphrase_file(pw_filename, passphrase_length)) {
		log_libc(LLVL_ERROR, "Wiping of passphrase file failed -- treating this unlock as failed (luksOpen %s)", success ? "succeeded" : "also failed");
		success = false;
	}
	return success;
}

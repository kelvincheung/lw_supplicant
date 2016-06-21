/*
 * WPA Supplicant / Example program entrypoint
 * Copyright (c) 2003-2005, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include "includes.h"

#include "common.h"
#include "wpa_supplicant_i.h"

int main(int argc, char *argv[])
{
	int exitcode = 0;
	struct wpa_supplicant *wpa_s = NULL;

	wpa_s = wpa_supplicant_init();
	if (wpa_s == NULL)
		return -1;

	wpa_supplicant_deinit(wpa_s);

	return exitcode;
}

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

AM_CFLAGS = -D_GNU_SOURCE -Wall -lpthread -lcurl -lssh -I$(top_srcdir)/include/compat -I$(top_srcdir)/include -g -funit-at-a-time -std=gnu11

bin_PROGRAMS = mand-fw

mand_fw_SOURCES = fw.c comm.c

DISTCLEANFILES = *~

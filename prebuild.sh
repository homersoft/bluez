#!/bin/bash
./configure CFLAGS=-Og --disable-silent-rules \
	--libdir=/usr/lib/x86_64-linux-gnu/ \
	--libexec=/usr/lib/ \
	--enable-static \
	--enable-debug \
	--enable-tools \
	--enable-cups \
	--enable-datafiles \
	--enable-debug \
	--enable-library \
	--enable-monitor \
	--enable-udev \
	--enable-obex \
	--enable-mesh \
	--enable-client \
	--enable-systemd \
	--enable-threads \
	--enable-sixaxis \
	--enable-experimental \
	--enable-deprecated \
	--enable-testing \
	--enable-btpclient


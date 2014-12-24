#!/bin/sh

rm -rf autom4te.cache config
rm -f configure config.h.in

mkdir -p config

libtoolize -f -c
shtoolize -q all
autoreconf --install --symlink --force

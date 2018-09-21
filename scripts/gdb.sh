#!/bin/bash

ps -ef | grep vconsole
echo
gdb -ex 'set auto-load safe-path /' $@


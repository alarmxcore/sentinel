#!/bin/bash
set -evx

mkdir ~/.alarmxcore

# safety check
if [ ! -f ~/.alarmxcore/.alarmx.conf ]; then
  cp share/alarmx.conf.example ~/.alarmxcore/alarmx.conf
fi

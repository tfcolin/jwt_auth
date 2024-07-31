#!/bin/bash

set -x

ssh-keygen -m pem -t rsa -f $1.pem
ssh-keygen -e -m pem -f $1.pem.pub > temp.pem
mv temp.pem ${1}_pub.pem
rm $1.pem.pub
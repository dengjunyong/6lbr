#!/bin/bash
trap 'exit' SIGINT SIGQUIT SIGKILL

FILENAME="$1"
forever=$2
echo $FILENAME
success=0
fail=0
echo "" > devices.txt.error

function while_read_bottm(){
while read LINE
do
    ping6 -s 8 -c 1 $LINE
#    coap-client -m get -B 5 coap://[$LINE]/hello
    if [ $? -eq 0 ]; then
        ((success++))
        echo $success    success
        echo $fail    fail
    else
        ((fail++))
        echo $success    success
        echo $fail    fail
        echo $LINE >> devices.txt.error
    fi
done < $FILENAME
}

while_read_bottm

if [ $forever -eq 1 ];then
while [ 1 ] ;do
while_read_bottm
done
fi

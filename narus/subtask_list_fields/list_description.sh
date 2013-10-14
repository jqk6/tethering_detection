#!/bin/bash

# ls /data/ychen/narus/bcp/*1.bcp | xargs cat | grep "^##Desc" | awk -F']=UINT64' '{print($2)}' | sort | uniq > output/descriptions.txt
ls /data/ychen/narus/bcp/*.bcp | xargs cat | grep "^##Desc" | sort | uniq > output/descriptions.txt
# ls /data/ychen/narus/bcp/*-0.bcp | xargs cat | grep "^##Desc" | awk -F']=UINT64' '{print($2)}' | sort | uniq > output/descriptions.txt

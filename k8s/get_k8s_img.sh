#!/bin/bash

for x in `kubeadm config images list|sed -e 's/^k8s.gcr.io/gotok8s/g'`
do
        docker pull $x
done

docker images
IFS=$'\n'
for x in `docker images|grep gotok8s`
do
        echo docker tag `echo $x|awk '{print $1":"$2}'` `echo $x|sed -e 's/^gotok8s/k8s.gcr.io/g'|awk '{print $1}'`:`echo $x|awk '{print $2}'` | bash
        echo docker rmi `echo $x|awk '{print $1":"$2}'` | bash -x
done

docker images

#!/bin/bash

for (( i = 1 ; i < 3; i ++ )) ; do
    make_pem_keypair.sh u${i}
    generator_user_add $i u${i} u${i}.pem u${i}_pub.pem > u${i}_add.json
done


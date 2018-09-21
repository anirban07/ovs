kill -9 `ps -ef | grep "vconsole" | awk '{ print $2 }' | head -n 1`

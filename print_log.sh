i=0
cat $1 | while read line
do
    echo $line
    i=$(($i+1))
    # if i > 10, break
    if [ $i -gt 10 ]; then
        break
    fi
done
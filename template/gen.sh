#!/bin/sh


pandoc_md.sh ../arp.md

cp ../arp.html ./arp.html

file=arp.html

begin=`grep "id=\"main\""  $file -n`
if [[ -n "$begin" ]];then
	line=${begin%%:*}
	line=$(($line-1))
	sed -i "1, $line"d $file
fi

finish=`grep "</body>"  $file -n`
if [[ -n "$finish" ]];then
	line=${finish%%:*}
	sed -i "$line,"'$d' $file
fi

cat myhead > $file-tmp
cat $file >> $file-tmp
cat mytail >> $file-tmp

cp $file-tmp $file

rm $file-tmp

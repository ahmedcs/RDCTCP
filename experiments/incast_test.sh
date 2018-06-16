
#!/bin/bash

# 1 : folder path
# 2 : experiment runtime
# 3 :  number of clients per host
# 4 : interval of iperf reporting
# 5 : tcp congestion used
# 6 : # of webpage requests
# 7 : # of concurrent connections
# 8 : # of repetation of apache test 
# 9 : is IQM or normal switch

path="$1/$2-$3-$4-$5/noiqm"

if [ "$6" == "iqm" ]; then
	path="$1/$2-$3-$4-$5/iqm";
fi

if [ "$6" == "wnd" ]; then
	path="$1/$2-$3-$4-$5/wnd";
fi

rm -rf $path;
dsh -c -g cluster "rm -rf $path; dmesg -c"
mkdir -p $path;
dsh -c -g cluster "mkdir -p $path;"

dsh -c -g cluster 'tc qdisc replace dev p1p2 root pfifo limit 1; tc qdisc replace dev p1p2 root bfifo limit 85300; ethtool -K p1p2 tso off gso off gro off; ethtool --offload  p1p2 sg off rx off  tx off; tc qdisc replace dev p1p3 root pfifo limit 1; tc qdisc replace dev p1p3 root bfifo limit 85300; ethtool -K p1p3 tso off gso off gro off; ethtool --offload  p1p3 sg off rx off  tx off; tc qdisc replace dev p1p4 root pfifo limit 1; tc qdisc replace dev p1p4 root bfifo limit 85300; ethtool -K p1p4 tso off gso off gro off; ethtool --offload  p1p4 sg off rx off  tx off;  tc qdisc replace dev em2 root pfifo limit 1; tc qdisc replace dev em2 root bfifo limit 85300; ethtool -K em2 tso off gso off gro off; ethtool --offload  em2 sg off rx off  tx off; ';

if [ "$2" == "dctcp" ]; then
dsh -c -g cluster 'tc qdisc replace dev p1p2 root pfifo limit 1; tc qdisc replace dev p1p2 root red limit 100000 min 30000 max 30001 avpkt 1000  burst 33 ecn bandwidth 930Mbit;';
fi

dsh -c -g cluster "sysctl -w net.ipv4.tcp_congestion_control=$2; sysctl -w net.ipv4.tcp_window_scaling=0;";


dsh -c -M -g cluster "for i in `pgrep iperf`; do kill -9 $i; done";
dsh -c -M -g cluster "for i in `pgrep ab`; do kill -9 $i; done";

echo "all set, start after 10";
sleep 5;

for (( k=1; k<=$5; k++ )); do
tim=`date +"%T"`; 
echo "sleeping N0. $k at : $tim"
j=0
for (( i=7; i<=13; i++ ));
do
a=$(( $j+50 ));
b=$(( $j+8 ));
ssh root@node$i "for ((x=23; x<=25; x++)); do for ((y=8; y<=14; y++)); do  if [ "$b" -ne "\$y" ]; then echo 172.22.1.$a:172.\$x.0.\$y time: $(($(date +"%s%N")/1000000)); ab -n $3 -c $4 -B 172.22.1.$a http://172.\$x.0.\$y/ >> "$path/\$HOSTNAME-\$x-\$y.web" & fi done & done &" &
j=$(( $j+1 ));
done
sleep 5;
done


sleep 5;

for ((i=7; i<=13; i++));
do
scp root@node$i:$path/* $path/;
done

#getting drop information

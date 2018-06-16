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

path="$1/$2-$3-$4-$5-$6-$7-$8/noiqm"

if [ "$9" == "iqm" ]; then
	path="$1/$2-$3-$4-$5-$6-$7-$8/iqm";
fi

if [ "$9" == "wnd" ]; then
	path="$1/$2-$3-$4-$5-$6-$7-$8/wnd";
fi

rm -rf $path;
dsh -c -g cluster "rm -rf $path; dmesg -c"
mkdir -p $path;
dsh -c -g cluster "mkdir -p $path;"

dsh -c -g cluster 'tc qdisc replace dev p1p2 root pfifo limit 1; tc qdisc replace dev p1p2 root bfifo limit 85300; ethtool -K p1p2 tso off gso off gro off; ethtool --offload  p1p2 sg off rx off  tx off; tc qdisc replace dev p1p3 root pfifo limit 1; tc qdisc replace dev p1p3 root bfifo limit 85300; ethtool -K p1p3 tso off gso off gro off; ethtool --offload  p1p3 sg off rx off  tx off; tc qdisc replace dev p1p4 root pfifo limit 1; tc qdisc replace dev p1p4 root bfifo limit 85300; ethtool -K p1p4 tso off gso off gro off; ethtool --offload  p1p4 sg off rx off  tx off;  tc qdisc replace dev em2 root pfifo limit 1; tc qdisc replace dev em2 root bfifo limit 85300; ethtool -K em2 tso off gso off gro off; ethtool --offload  em2 sg off rx off  tx off; ';


dsh -c -g cluster "sysctl -w net.ipv4.tcp_congestion_control=$5; sysctl -w net.ipv4.tcp_window_scaling=0;";

dsh -c -M -g cluster "for i in `pgrep iperf`; do kill -9 $i; done";
dsh -c -M -g cluster "for i in `pgrep ab`; do kill -9 $i; done";

for (( i=1; i<=$3; i++ )); 
do 
dsh -c -M -g cluster "ovs-vsctl add-port ovsbr2 test22$i -- set interface test22$i type=internal; ethtool -K test22$i tso off gso off ";
dsh -c -M -g cluster "ovs-vsctl add-port ovsbr3 test23$i -- set interface test23$i type=internal; ethtool -K test23$i tso off gso off ";
dsh -c -M -g cluster "ovs-vsctl add-port ovsbr4 test24$i -- set interface test24$i type=internal; ethtool -K test24$i tso off gso off ";
dsh -c -M -g cluster "ovs-vsctl add-port ovsbr5 test25$i -- set interface test25$i type=internal; ethtool -K test25$i tso off gso off ";
done

echo "all set, start after 1";
sleep 1;

j=0
for ((i=7; i<=13; i++));
do
a=$(( $j+50 ));
ssh root@node$i "for (( k=1; k<=$3; k++ )); do ifconfig test22\$k 172.22.\$k.$a up; iperf -s -w 1M -B 172.22.\$k.$a & echo iperf -s -w 1M -B 172.22.\$k.$a; done;" &
j=$(( $j+1 ));
done


echo "all set, start after 1";
sleep 1;

m=1
for ((i=7; i<=13; i++));
do
echo $j
a=$(( $j+50 )); b=$(( ($m%7)+50));
ssh root@node$i "for (( x=23; x<=25; x++ )); do for (( k=1; k<=$3; k++ )); do ifconfig test\$x\$k 172.\$x.\$k.$a up; iperf -B 172.\$x.\$k.$a -c 172.22.\$k.$b -t $2 -w 1M -y C -i $4 > "$path/\$HOSTNAME-\$x-\$k.iperf" & done & done;" &
j=$(( $j+1 ));
m=$(( $m+1 ));
done



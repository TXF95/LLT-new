
import sys
import os
import time
import re

from subprocess import Popen,PIPE

user_name="root"
paasswd="1"
user_ip="192.168.50.61"
#user_ip="127.0.0.1"

convenient_privilege=" echo "+paasswd+"|"
link_cmd="ssh -t "+user_name+"@"+user_ip
#link_cmd="ssh "+user_name+"@"+user_ip+convenient_privilege
max_flow_num=100
default_rate=900
prio_queue_num=3
basic_parent="3:"
basic_parent_num=3
map_filter={}
map_filter_flow_id={}
basic_filter_num=49152
default_low_filter_prio=100

def ssh_link():
    result=os.system("%s sudo -S ls" % link_cmd)
    print "result="
    print result

def show_qdisc(dev="s1-eth1",detail=0):
	print dev+" qdisc is ::::::::::::::::::::::::::::::::::::::::::::::::::::"
	if detail:
		os.system("%s sudo -S tc -s qdisc show dev %s " % link_cmd,dev)
	else:
		os.system("%s sudo -S tc qdisc show dev %s " % link_cmd,dev)

def show_class(dev="s1-eth1",detail=0):
	print dev+" class is ::::::::::::::::::::::::::::::::::::::::::::::::::::"
	if detail:
		os.system("%s sudo -S tc -s class show dev %s " % link_cmd,dev)
	else:
		os.system("%s sudo -S tc class show dev %s " % link_cmd,dev)

def show_filter(dev="s1-eth1",detail=0,parent="root"):
	print dev+" filter is ::::::::::::::::::::::::::::::::::::::::::::::::::::"
	if detail:
		os.system("%s sudo -S tc -s filter show dev %s parent %s" % link_cmd,dev,parent)
	else:
		os.system("%s sudo -S tc filter show dev %s parent %s" % link_cmd,dev,parent)



def add_htb(dev="s1-eth1"):
	cmd="echo add htb qdisc"
	for i in range(prio_queue_num):
		parent=basic_parent+str(i+1)
		handle=str(prio_queue_num+1+i)+":"
		tmp_cmd="sudo -S tc qdisc add dev "+dev+" parent "+parent+" handle "+handle+" htb default 30"

		cmd = link_cmd+" "+tmp_cmd
		print cmd
		os.system(cmd)
		map_filter[handle] = 0
		time.sleep(0.1)

	htb_id=basic_parent_num+prio_queue_num
	flow_id=max_flow_num+1
	parent=str(htb_id)+":"
	classid=parent+str(flow_id)
	flowid=classid
	rate=default_rate
	filter_prio=default_low_filter_prio
	ip_src="0.0.0.0"
	src_ip_mask="/0"
	class_cmd="sudo tc class add dev "+dev+" parent "+parent+" classid "+classid+" htb rate "+str(rate)+"mbit burst 15k"
	filter_cmd="sudo -S tc filter add dev "+dev+" protocol ip parent "+parent+" prio "+str(filter_prio)+" u32"+\
				" match ip src "+ip_src+src_ip_mask +\
				" flowid "+flowid
	print "class_cmd="+class_cmd
	print "filter_cmd"+filter_cmd
	class_cmd=link_cmd+" "+class_cmd
	filter_cmd=link_cmd+" "+filter_cmd
	os.system(class_cmd)
	os.system(filter_cmd)



def add_flow_rate_limit(dev="s1-eth1",priority=0,flow_id=0,rate=10,ip_src="0.0.0.0",ip_dst="0.0.0.0",port_src="0",port_dst="0",protocol="TCP",filter_prio=0):
	"""
	dev : the dev need to add rate-limiter
	priority : the flow priority , which is in {0,1,2.....}
	flow_id : used to identify the flow and add classes and filters
	rate : the bandwitch : mbps

	5-tuple:
		ip_src
		ip_dst
		port_src
		port_dst
		protocol
	any_match is :
	ip : 0.0.0.0/0
	port : 0
	protocol : 0


	filter_prio : the priority of filter , 0 is the default and highest priority
	"""
	prio_range=range(prio_queue_num)
	if priority not in prio_range:
		print "priority error"
		return

	htb_id=priority+prio_queue_num+1
	parent=str(htb_id)+":"
	classid=parent+str(flow_id)
	flowid=classid

	class_cmd="sudo tc class add dev "+dev+" parent "+parent+" classid "+classid+" htb rate "+str(rate)+"mbit burst 15k"

	print "class_cmd = "
	print class_cmd
	class_cmd=link_cmd+" "+class_cmd
	os.system(class_cmd)

	ICMP="1"
	TCP="6"
	UDP="17"
	IPV6="41"

	match_protocol="6"
	if protocol == "TCP":
		match_protocol=TCP
	if protocol == "UDP":
		match_protocol=UDP
	if protocol == "ICMP":
		match_protocol=ICMP
	if protocol == "IPV6":
		match_protocol=IPV6

	src_ip_mask="/32"
	dst_ip_mask="/32"
	src_port_mask="0xffff"
	dst_port_mask="0xffff"
	match_protocol_mask="0xff"

	if ip_src=="0.0.0.0":
		src_ip_mask="/0"
	if ip_dst=="0.0.0.0":
		dst_ip_mask="/0"
	if port_src=="0":
		src_port_mask="0x0000"
	if port_dst=="0":
		dst_port_mask="0x0000"
	if protocol=="0":
		match_protocol_mask="0x00"

	filter_cmd="sudo -S tc filter add dev "+dev+" protocol ip parent "+parent+" prio "+str(filter_prio)+" u32"+\
	" match ip src "+ip_src+src_ip_mask +\
	" match ip dst "+ip_dst+dst_ip_mask +\
	" match ip sport "+port_src+" "+src_port_mask +\
	" match ip dport "+port_dst+" "+dst_port_mask +\
	" match ip protocol "+match_protocol+" "+match_protocol_mask +\
	" flowid "+flowid

	print "filter_cmd = "
	print filter_cmd
	filter_cmd=link_cmd+" "+filter_cmd
	os.system(filter_cmd)
	#filter_num=map_filter[parent]
	#map_filter[parent]=filter_num+1
	#map_filter_flow_id[flowid]=filter_num


#tc filter [ add | change | replace | delete ] dev DEV [ parent qdisc-id | root ] \
# protocol protocol prio priority filtertype [ filtertype specific parameters ] flowid flow-id
def delete_flow_rate_limit(dev="s1-eth1",priority=0,flow_id=0):
	"""
	dev : the dev need to add rate-limiter
	priority : the flow priority , which is in {0,1,2.....}
	flow_id : used to identify the flow and add classes and filters
	"""
	htb_id=priority+prio_queue_num+1
	parent=str(htb_id)+":"
	classid=parent+str(flow_id)
	flowid=classid

	filter_cmd="tc filter show dev "+dev+" parent "+parent

	#print "filter_cmd = "
	#print filter_cmd
	filter_cmd=link_cmd+" "+filter_cmd
	show_result=os.popen(filter_cmd).read()

	del_filter=re.search(r'filter protocol ip pref (.*) u32.*flowid '+flowid,show_result,re.M)
	if del_filter:
		print "find the filter,and num is "+str(del_filter.group(1))
		del_prio=del_filter.group(1)
		del_filter_cmd="sudo tc filter del dev "+dev+" parent "+parent+" prio "+del_prio
		del_filter_cmd=link_cmd+" "+del_filter_cmd
		os.system(del_filter_cmd)
		print "filter delete"
	else:
		print "no filter match, check your input"

	class_cmd="tc class show dev "+dev+" parent "+parent
	class_cmd=link_cmd+" "+class_cmd
	show_result=os.popen(class_cmd).read()
	del_class=re.search(r'class htb '+classid+' root .* rate (.*) ceil.*',show_result,re.M)

	if del_class:
		class_rate=del_class.group(1)
		print "find class, rate = "+class_rate
		del_class_cmd="sudo tc class del dev "+dev+" classid "+classid
		del_class_cmd=link_cmd+" "+del_class_cmd
		os.system(del_class_cmd)
		print "class delete"
	else:
		print "no class match, check your input"


def main():
    #ssh_link()
    #example
    add_htb("s1-eth1")

    #print map_filter_flow_id

    add_flow_rate_limit("s1-eth1",priority=0,flow_id=1,rate=150,\
    					ip_src="10.0.0.3",\
    					ip_dst="10.0.0.1",\
    					port_src="0",\
    					port_dst="5002",\
    					protocol="TCP")

    add_flow_rate_limit("s1-eth1",priority=1,flow_id=7,rate=50,\
    					ip_src="10.0.0.3",\
    					ip_dst="10.0.0.1",\
    					port_src="0",\
    					port_dst="5010",\
    					protocol="TCP")

    add_flow_rate_limit("s1-eth1",priority=1,flow_id=4,rate=150,\
    					ip_src="10.0.0.3",\
    					ip_dst="10.0.0.1",\
    					port_src="0",\
    					port_dst="5020",\
    					protocol="TCP")



    add_flow_rate_limit("s1-eth1",priority=1,flow_id=3,rate=250,\
    					ip_src="10.0.0.3",\
    					ip_dst="10.0.0.1",\
    					port_src="0",\
    					port_dst="5001",\
    					protocol="TCP")

    add_flow_rate_limit("s1-eth1",priority=2,flow_id=5,rate=350,\
    					ip_src="10.0.0.3",\
    					ip_dst="10.0.0.1",\
    					port_src="0",\
    					port_dst="5003",\
    					protocol="TCP")


    #delete_flow_rate_limit("s1-eth1",priority=0,flow_id=7)
    #show_qdisc("s1-eth1")
    #show_class("s1-eth1")
    #show_filter("s1-eth1")
if __name__ == '__main__':
	main()

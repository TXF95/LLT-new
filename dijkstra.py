# -*- coding: utf-8 -*-
# dijkstra算法实现，有向图和路由的源点作为函数的输入，最短路径最为输出

from collections import defaultdict
link_capacity = 50


def short_path(src, dst, src_links, need, ip_flow_speed_dict):
    if src == dst:
        return []
    result = defaultdict(lambda: defaultdict(lambda: None))
    distance = defaultdict(lambda: defaultdict(lambda: None))

    # the node is checked
    seen = [src]

    # the distance to src
    distance[src] = 0

    w = 0  # weight
    # bw_bps = bw * 1000000  # translate Mbps to bps
    # self.logger.debug("speed : %s", str(self.network_monitor.get_port_speed()))
    # self.logger.debug("qos_ip_bw : %s", str(self.qos_ip_bw))

    while len(seen) < len(src_links):
        node = seen[-1]
        if node == dst:
            break
        for (temp_src, temp_dst) in src_links[node]:
            if temp_dst not in seen:
                # if (bw != 0) and (LINK_CAPACITY < bw_bps):
                #     continue
                w = round(cal_weight(temp_src, temp_dst, need, src_links), 5)
                if (distance.get(temp_dst) is None) or (distance.get(temp_dst) > distance.get(temp_src) + w):
                    distance[temp_dst] = distance.get(temp_src) + w
                    # result = {"dpid":(link_src, src_port, link_dst, dst_port)}
                    result[temp_dst] = (temp_src, temp_dst)
        min_node = None
        min_path = 999
        # get the min_path node
        for temp_node in distance:
            if (temp_node not in seen) and (distance[temp_node] is not None):
                if distance.get(temp_node) < min_path:
                    min_node = temp_node
                    min_path = distance[temp_node]
        if min_node is None:
            break
        seen.append(min_node)
        if distance.get(dst) is not None:
            # 输出目的交换机对应的权重（各条链路上权重之和）
            print("route's weight: " + str(distance.get(dst)))
    path = []

    if dst not in result:
        return None

    while (dst in result) and (result[dst] is not None):
        path = [result[dst][1]] + path
        path = [result[dst][0]] + path
        dst = result[dst][0]
    # self.logger.info("path : %s", str(path))
    # 路径结果输出
    return path


def cal_weight(temp_src, temp_dst, need, src_links):
    link_remain = float(link_capacity -src_links[temp_src].get((temp_src, temp_dst)))
    if link_remain == 0:
        weight = 999
    print(abs(link_remain - need))
    if abs(link_remain - need) >= 1:
        if link_remain > need:
            weight = float(1 / link_remain)
        elif link_remain < need:
            tnow = cal_tnow(temp_src, temp_dst, need - link_remain, need, ip_flow_speed_dict)
            weight = float((link_remain + tnow) / need + tnow)
    elif abs(link_remain - need) < 1:
        weight = 1
    return weight

def cal_tnow(temp_src, temp_dst, link_now, need, ip_flow_speed_dict):
    ip_to_speed = {}
    flow_ip_info_dict1 = {}
    flow_ip_info_dict2 = {}

    for key in ip_flow_speed_dict:
        if key[0] == int(temp_src):
            flow_ip_info_dict1[key] = ip_flow_speed_dict.get(key)
        elif key[0] == int(temp_dst):
            flow_ip_info_dict2[key] = ip_flow_speed_dict.get(key)

    for key1 in flow_ip_info_dict1:
        for key2 in flow_ip_info_dict2:
            if key1[1] == key2[1] and key1[2] == key2[2]:
                ip_key = (key1[1], key1[2])
                speed = flow_ip_info_dict1.get(key1)
                ip_to_speed[ip_key] = speed
    speed_list_tmp = []
    # sort_ip_to_speed = sorted(ip_to_speed.items(), key=lambda x: x[1])
    for key in ip_to_speed:
        speed_list_tmp.append(ip_to_speed.get(key))

    speed_list_tmp.sort()
    if speed_list_tmp is None:
        return 0
    if speed_list_tmp and speed_list_tmp[0] >= need:
        return 999

    speed_sum_tmp = 0

    speed_list = []
    for speed in speed_list_tmp:
        if speed < need:
            speed_sum_tmp = speed + speed_sum_tmp
            speed_list.append(speed)
            if speed_sum_tmp >= link_now:
                break
    speed_list.sort(reverse=True)
    speed_sum = 0
    for speed in speed_list:
        speed_sum = speed + speed_sum
        if speed_sum >= link_now:
            break
    if link_now <= speed_sum < need:
        return speed_sum
    else:
        return 999


if __name__ == '__main__':
    # 路径的带宽占用情况
    '''
    src_links = {18: {(18, 16): 15.3, (18, 17): 0},
                 16: {(16, 15): 15, (16, 18): 15.3},
                 15: {(15, 19): 15.031, (15, 26): 0, (15, 16): 15, (15, 17): 0},
                 19: {(19, 27): 15.61, (19, 15): 15.031},
                 17: {(17, 15): 0, (17, 18): 0},
                 26: {(26, 27): 0, (26, 15): 0, (26, 28): 0},
                 27: {(27, 19): 15.61, (27, 26): 0},
                 28: {(28, 26): 0}
                 }
    # 交换机对应的每条流的带宽占用情况
    ip_flow_speed_dict = {(18, '10.0.0.1', '10.0.0.2'):15.3,
                          (16, '10.0.0.1', '10.0.0.2'):15,
                          (15, '10.0.0.1', '10.0.0.2'): 15.031,
                          (19, '10.0.0.1', '10.0.0.2'): 15.61,
                          (27, '10.0.0.1', '10.0.0.2'): 15,
                          }
    '''
    src_links = {18: {(18, 16): 34.78, (18, 17): 35.234},
                 16: {(16, 15): 34.685, (16, 18): 34.78},
                 15: {(15, 19): 34.2, (15, 26): 35, (15, 16): 35.685, (15, 17): 34.9996},
                 19: {(19, 27): 35.02, (19, 15): 34.2},
                 17: {(17, 15): 34.9996, (17, 18): 35.234},
                 26: {(26, 27): 44.2475, (26, 15): 35, (26, 28): 9.871},
                 27: {(27, 19): 35.02, (27, 26): 44.2475},
                 28: {(28, 26): 9.871}
                 }

    '''ip_flow_speed_dict = {(18, '10.0.0.1', '10.0.0.2'): 15.1, (18, '10.0.0.11', '10.0.0.31'): 10.12,
                          (18, '10.0.0.12', '10.0.0.22'): 25.89, (18, '10.0.0.13', '10.0.0.33'): 20,
                          (16, '10.0.0.1', '10.0.0.2'): 15.28, (16, '10.0.0.13', '10.0.0.33'): 19.8,
                          (17, '10.0.0.11', '10.0.0.31'): 9.63, (17, '10.0.0.12', '10.0.0.22'): 25.2,
                          (15, '10.0.0.1', '10.0.0.2'): 14.7, (15, '10.0.0.11', '10.0.0.31'): 9.68,
                          (15, '10.0.0.12', '10.0.0.22'): 25, (15, '10.0.0.13', '10.0.0.33'): 19.01,
                          (19, '10.0.0.1', '10.0.0.2'): 15, (19, '10.0.0.13', '10.0.0.33'): 19.23,
                          (26, '10.0.0.11', '10.0.0.31'): 9.52, (26, '10.0.0.12', '10.0.0.22'): 24.32,
                          (26, '10.0.0.13', '10.0.0.33'): 19.45,
                          (27, '10.0.0.1', '10.0.0.2'): 15, (27, '10.0.0.12', '10.0.0.22'): 25,
                          (27, '10.0.0.13', '10.0.0.33'): 19.654,(27, '10.0.0.13', '10.0.0.23'): 20,
                          (28, '10.0.0.11', '10.0.0.31'): 10,(28, '10.0.0.13', '10.0.0.33'): 20,
                          }'''
    ip_flow_speed_dict = {(18, '10.0.0.1', '10.0.0.2'): 15, (18, '10.0.0.11', '10.0.0.31'): 10,
                          (18, '10.0.0.12', '10.0.0.22'): 25, (18, '10.0.0.13', '10.0.0.33'): 20,
                          (16, '10.0.0.1', '10.0.0.2'): 15, (16, '10.0.0.13', '10.0.0.33'): 20,
                          (17, '10.0.0.11', '10.0.0.31'): 10, (17, '10.0.0.12', '10.0.0.22'): 25,
                          (15, '10.0.0.1', '10.0.0.2'): 15, (15, '10.0.0.11', '10.0.0.31'): 10,
                          (15, '10.0.0.12', '10.0.0.22'): 25, (15, '10.0.0.13', '10.0.0.33'): 20,
                          (19, '10.0.0.1', '10.0.0.2'): 15, (19, '10.0.0.13', '10.0.0.33'): 20,
                          (26, '10.0.0.11', '10.0.0.31'): 10, (26, '10.0.0.12', '10.0.0.22'): 25,
                          (26, '10.0.0.13', '10.0.0.33'): 20,
                          (27, '10.0.0.1', '10.0.0.2'): 15, (27, '10.0.0.12', '10.0.0.22'): 25,
                          (27, '10.0.0.13', '10.0.0.33'): 20,
                          (28, '10.0.0.11', '10.0.0.31'): 10,(28, '10.0.0.13', '10.0.0.33'): 20,
                          }
    # 最新来的流所需要的带宽
    need = 20
    src_sw = 18
    dst_sw = 27
    path = short_path(src_sw, dst_sw, src_links, need, ip_flow_speed_dict)  # 查找从源点0开始带其他节点的最短路径
    print(path)

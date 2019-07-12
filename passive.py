# encoding=UTF-8
import shlex
import re
import os
import datetime
import csv
from subprocess import Popen, PIPE, STDOUT
from signal import SIGPIPE, SIG_DFL, signal
import operator


g_root_dirname = '/sf/log/network_subhealth/network_subhealth_hrh/'

"""
    何瑞虎
    2019.4.25
    被动工具采样脚本
"""

"""
    popen封装获取shell返回结果result和错误码errno
    输入: 
        cmd_list(列表形式，按'|'分隔元素)
    举例:
        shell_pipeline(['ls -l','grep "hello"']) <-> ls -l | grep "hello"
"""
def shell_pipeline(cmd_list, split_lines=False):
    args_list = []
    pipe_last = None
    for cmd in cmd_list:
        args = shlex.split(cmd)
        args_list.append(args)
    args_list_len = len(args_list)

    for index in range(0, args_list_len, 1):
        if index == 0:
            pipe_last = Popen(args_list[index], stdin=PIPE, stdout=PIPE, stderr=STDOUT,
                              preexec_fn=lambda: signal(SIGPIPE, SIG_DFL))
        else:
            pstdout = pipe_last.stdout
            pipe_last = Popen(args_list[index], stdin=pstdout, stdout=PIPE, stderr=STDOUT)
    return_code = pipe_last.wait()
    result = pipe_last.communicate()
    output = result[0].decode().strip('\n')
    if split_lines is True:
        output = output.splitlines()
    return output, return_code

"""
    将要获取的信息和需要使用的工具进行匹配
    输入：
        需要获取的信息列表
    返回：
        工具为key，要用其获取的信息为value的字典
"""

def match_tool(message_needed_list):
    # 命令可获取的所有信息
    tool_default_dict = {'ss'        : ['State', 'Recv-Q', 'Send-Q', 'Local_Address', 'Peer_Address', 'wscale', 'rto', 'rtt', 'ato', 'cwnd', 'ssthresh', 'rcv_rtt', 'rcv_space'],
                         'nicstat'   : ['proto', 'InKB', 'OutKB', 'InSeg', 'OutSeg', 'Reset', 'AttF', 'ReTX', 'InConn', 'OutCon', 'Drops', 'InDG', 'OutDG', 'InErr', 'OutErr', 'Int', 'RdKB', 'WrKB', 'RdPkt', 'WrPkt', 'IErr', 'OErr', 'Coll', 'NoCP', 'Defer', 'rUtil', 'wUtil'],
                         'netstat'   : ['PID', 'Protocol', 'Send_Q', 'Recv_Q', 'State', 'MTU', 'Met', 'RX_OK', 'RX_ERR', 'RX_DRP', 'RX_OVR', 'TX_OK', 'TX_ERR', 'TX_DRP', 'TX_OVR', 'Flg', 'Ip', 'Icmp', 'IcmpMsg', 'Tcp', 'Udp', 'UdpLite', 'TcpExt', 'IpExt'],
                         'mtr'       : ['route', 'Loss', 'Drop', 'Rcv', 'Snt', 'Last', 'Best', 'Avg', 'Wrst', 'StDev', 'Gmean', 'Jttr', 'Javg', 'Jmax', 'Jint', 'rtt'],
                         'traceroute': ['route', 'rtt'],
                         'ping'      : ['IP', 'rtt', 'Protocol', 'ttl', 'Snt', 'Rcv', 'Loss', 'min_rtt', 'avg_rtt', 'max_rtt', 'mdev_rtt'],
                         'snmp'      : ['interface', 'ip', 'icmp', 'tcp', 'udp']
                         }

    # 实际需要每个命令获取的信息
    tool_need_dict = {'ss'        : [],
                      'nicstat'   : [],
                      'netstat'   : [],
                      'mtr'       : [],
                      'traceroute': [],
                      'ping'      : [],
                      'snmp'      : []
                      }

    """
        for循环           ：遍历tool_default_dict字典，匹配每个工具需要获取的信息，保存到tool_need_dict字典中
        tool              ：遍历到的工具 
        tool_message_mixed：工具能获取的所有信息和需要获取信息的交集 
    """
    for tool in tool_default_dict.keys():
        tool_message_mixed = set(tool_default_dict[tool]) & set(message_needed_list)
        if tool_message_mixed:
            if not tool_need_dict[tool]:
                tool_need_dict[tool] = list(tool_message_mixed)
            else:
                tool_need_dict[tool] = list(tool_message_mixed | set(tool_need_dict[tool]))
    return tool_need_dict


"""
    判断路径或文件是否存在，不存在时创建
    输入：
        路径或文件名
        举例：/sf/log/network_subhealth/network_subhealth_hrh/log/ss/filter/10.110.128.128_ss_nti_filter_2019_05_15_09_29_16.csv
    返回值：
        1：文件本就存在
        0：文件是由该函数创建，之前不存在
"""
def touch_file(filename):
    return_number = 0
    path_name     = os.path.dirname(filename)
    # 如果路径不存在，先创建路径，再创建文件
    if not os.path.exists(path_name):
        os.makedirs(path_name)
        os.mknod(filename)
    # 如果路径存在，文件不存在，只创建文件
    elif not os.path.exists(filename):
        os.mknod(filename)
    # 路径文件都存在，将返回值置为1，表示文件非本函数创建的
    else:
        return_number = 1
    return return_number


"""
    以csv文件的形式保存格式化的数据
    输入：
        log_filename  :文件名
        message_header：文件的头部
        file_data     ：文件内容（可以是字典或者列表）
"""
def message_save_csv_log(log_filename, message_header, file_data):
    if not file_data:
        return
    # 获取文件的存在状态（原来就存在还是新创建）
    file_exist_flag = touch_file(log_filename)

    with open(log_filename, mode='a+') as log_fd:
        writer = csv.DictWriter(log_fd, message_header)
        # 文件为新创建时需要写入文件头
        if 0 == file_exist_flag:
            writer.writeheader()

        # 当列表中的元素的数据类型已经是字典时，直接进行写入，不用再将两个列表合并成一个字典
        if isinstance(file_data[0], dict):
            if len(file_data) == 1:
                writer.writerow(file_data)
            else:
                writer.writerows(file_data)
            return

        # 当列表中的元素数据类型不是列表，表示该列表为一维列表，这时将其转化为二维列表
        new_return_list = [file_data]
        if isinstance(file_data[0], list):
            new_return_list = file_data

        for element in new_return_list:
            write_dict = list_to_dict(message_header,element)
            writer.writerow(write_dict)



"""
    对字符串进行替换，并分割为列表
    输入：
        object    ：原字符串
        src_value ：原字符串中要被替换的关键字，默认为None
        dest_value：要替换成的关键字，默认为None
        delimiter ：字符串分割成列表时所使用的分割符，默认为None（按照不等量空格分割）
        opt       ：要对该字符串进行处理的函数名，默认值为None，目前只有一个可选函数为‘sub’，可以进行增量
    返回：
        原字符串进行处理之后形成的列表
"""
def network_subhealth_re(object, src_value=None, dest_value=None, delimiter=None, opt=None):
    re_result = object
    if opt is not None:
        if operator.eq(opt, 'sub'):
            re_result = re.sub(src_value, dest_value, object)
    return re_result.split(delimiter)


"""
    对一个元素为字符串的列表中的每个元素进行替换和分割，最终得到一个二维列表
    该函数内部调用了network_subhealth_re()函数对每个元素进行操作
    输入：
        src_list  ：要进行处理的原列表
        src_value ：要被替换的关键字，默认为None
        dest_value：要替换成的关键字，默认为None
        delimiter ：对原列表中每个元素进行分割时使用的分割符，默认为None（按照不等量空格分割）
        opt       ：要对每个元素进行处理的函数名，默认值为None，目前只有一个可选函数为‘sub’，可以进行增量
    返回：
        原列表进行处理之后的二维列表
"""
def network_subhealth_filter(src_list, src_value=None, dest_value=None, delimiter=None, opt=None):
    filter_list = []
    for line in src_list:
        filter_line = network_subhealth_re(line, src_value, dest_value, delimiter, opt)
        filter_list.append(filter_line)
    return filter_list



"""
    对一个列表按照下标进行分割，当spilt_index为None时，取原列表从start到end这一段，split_index为整型值时，将原列表分割成两段
    输入：
        split_list ：要进行分割的原列表
        start      ：起始下标，默认为0
        end        ：结束下标，默认为0
        split_index：需要分割成两个列表时，该值作为前列表的尾，后列表的头，默认为None
    返回：
        spilt_index为None时，返回截取的列表
        不为None时，返回两个列表组成的元组
"""
def list_split(split_list, start=0, end=0, split_index=None):
    full_list = split_list
    range_set = set(range(start, end))
    if range_set.issubset(set(range(0, len(split_list)))):
        if split_index is not None:
            before_index_list = split_list[start : split_index]
            behind_index_list = split_list[split_index : end]
            return (before_index_list, behind_index_list)
        full_list = split_list[start : end]
    return full_list



"""
    将两个列表转化为一个字典
    输入：
        key_list  ：字典键的列表
        value_list：字典值的列表
    返回：
        组合成的字典
"""
def list_to_dict(key_list, value_list):
    new_dict = {}
    if len(key_list) != len(value_list):
        print ('key_len != value_len')
    for key, value in zip(key_list, value_list):
        new_dict[key] = value
    return new_dict

"""
    给一个二维列表中的指定位置插入元素
    输入：
        src_list：要插入元素的二维列表
        message_add_list：元素为元组的列表，每个元组中0号下标表示要插入的位置，1号下标表示要插入的值
            举例：message_add_list = [(0, src_ip), (0, time_stamp)]
    返回：
"""
def list_insert(src_list, message_add_list):
    new_list = []
    for line in src_list:
        for element in message_add_list:
            if element[0] in range(0, len(src_list)):
                line.insert(element[0], element[1])
        new_list.append(line)
    return new_list



"""
    数据持久化保存到文件中
    输入：
        log_filename  : 要写入的文件名
        return_list   : 要写入文件的消息，以列表形式传参，列表中的每个元素为文件中的一行
        message_header: 文件写入信息的头部内容，表示每个数据代表什么意思
"""
def message_save_log(log_filename, return_list, message_header=None):
    # 获取文件的存在状态（原来就存在还是新创建）
    file_exist_flag = touch_file(log_filename)

    with open(log_filename, 'a+') as log_fd:
        # 文件为新创建时需要写入文件头
        if 0 == file_exist_flag and message_header is not None:
            log_fd.write(','.join(message_header) + '\n')
        for line in return_list:
            log_fd.write(line + '\n')


"""
   mtr命令处理函数，获取mtr执行结果，进行格式化，持久化
   输入：
    mtr_needed_info_set：mtr命令要获取的信息
    IP：执行mtr命令时使用的IP，测试本主机到IP的连通性，时延等信息
"""
def mtr_handle(mtr_needed_info_set, IP):
    cmd_list           = ['mtr' + ' ' + IP + ' ' + '-r -c 10 -i 0.01 -o LDRSNBAWVGJMXI', 'grep -vE \"HOST|2019|\?\?\?\"']
    return_list, errno = shell_pipeline(cmd_list, split_lines=True)
    print ('\'%s\' errno: %s' % (cmd_list, str(errno)))
    # 获取时间戳
    time_stamp     = datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    # 拼接日志文件名
    log_filename   = g_root_dirname + '/log/mtr/filter/' + IP + '_mtr_filter_' + time_stamp + '.csv'
    # 信息内容（文件头部）
    message_header = ['timestamp', 'src_ip', 'HOP', 'HOST', 'Loss', 'Drop', 'Rcv', 'Snt', 'Last', 'Best', 'Avg', 'Wrst', 'StDev', 'Gmean', 'Jttr', 'Javg', 'Jmax', 'Jint']
    filter_list    = network_subhealth_filter(return_list)

    new_filter_list = []
    for line in filter_list:
        line[0] = line[0].strip('.')
        new_filter_list.append(line)

    message_add_list = [(0, src_ip), (0, time_stamp)]
    new_filter_list  = list_insert(new_filter_list, message_add_list)

    message_save_csv_log(log_filename, message_header, new_filter_list)


"""
    ss命令获取到的数据专用的格式化函数，将ss命令获取到的信息处理成我们希望的格式化数据，并返回
    输入：
        return_list   ：执行ss命令得到的未经处理的数据
        message_header：文件头部，在这里的用处为：根据header匹配数据，得到可用于csv库持久化的字典
    输出：
        元素为字典的列表
"""
def ss_filter(return_list, message_header, time_stamp):
    filter_list = []
    (header_odd_list, header_even_list) = list_split(message_header, start=0, end=len(message_header), split_index=7)

    # 相邻两行合并成一行，根据空格分割成一个列表
    for index in range(0, len(return_list), 2):
        merge_line = return_list[index].strip('\n') + return_list[index + 1].strip()
        merge_line = network_subhealth_re(merge_line)

        even_line_dict = {}
        (before_index_list, behind_index_list) = list_split(merge_line, end=len(merge_line), split_index=5)

        before_index_list.insert(0, src_ip)
        before_index_list.insert(0, time_stamp)
        # 取出列表前五个元素（原来第一行的数据），和对应的header合并成一个字典
        odd_line_dict = list_to_dict(header_odd_list,before_index_list)

        # 取出列表第五个之后的元素（原来第二行的数据）， 和对应的header合并成一个字典
        for element in behind_index_list:
            if ':' in element:
                element_list = network_subhealth_re(element, delimiter=':')
                even_line_dict[element_list[0]] = element_list[-1]

        # 将两个字典合并成一个，添加到一个列表中
        odd_line_dict.update(even_line_dict)
        filter_list.append(odd_line_dict)
    return filter_list



"""
    ss命令处理函数，将执行ss命令得到的数据处理成格式化的数据，并进行持久化
    该函数调用了ss_filter()函数，进行格式化
    输入：
        ss_needed_info_set：需要用ss命令获取的数据
        IP：表明ss命令获取的是哪台主机上的数据
"""
def ss_handle(ss_needed_info_list, IP):
    cmd_list       = ['ss -nti4', 'grep -vE \"State\"']
    return_list, errno  = shell_pipeline(cmd_list, split_lines=True)
    print ('\'%s\' errno: %s' % (cmd_list, str(errno)))

    time_stamp     = datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    log_filename   = g_root_dirname + '/log/ss/filter/' + IP + '_ss_nti_filter_' + time_stamp + '.csv'
    message_header = ['timestamp', 'src_ip', 'State', 'Recv-Q', 'Send-Q', 'Local_Address', 'Peer_Address', 'wscale', 'rto', 'rtt', 'ato', 'cwnd', 'ssthresh', 'rcv_rtt', 'rcv_space']
    filter_list    = ss_filter(return_list, message_header, time_stamp)
    message_save_csv_log(log_filename, message_header, filter_list)



"""
    nicstat命令处理函数，对执行nicstat命令获取到的数据进行格式化，持久化
    输入：
        nicstat_needed_info_set：需要用nicstat命令获取的信息
        IP：表明nicstat命令获取的是哪台主机上的信息
"""
def nicstat_handle(nicstat_needed_info_set, IP):
    cmd_list   = ['nicstat -aUp']
    time_stamp = datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    return_list, errno = shell_pipeline(cmd_list, split_lines=True)
    print ('\'%s\' errno: %s' % (cmd_list, str(errno)))

    message_header_list = [['timestamp', 'src_ip', 'proto', 'InKB', 'OutKB', 'InSeg', 'OutSeg', 'Reset', 'AttF', 'ReTX', 'InConn', 'OutCon', 'Drops'], ['timestamp', 'src_ip', 'proto','InDG', 'OutDG', 'InErr', 'OutErr'], ['timestamp', 'src_ip', 'Int', 'RdKB', 'WrKB', 'RdPkt', 'WrPkt', 'IErr', 'OErr', 'Coll', 'NoCP', 'Defer', 'rUtil', 'wUtil']]
    filename_parameter  = ['tcp', 'udp', 'interface']
    range_list = [(0, 1), (1, 2), (2, len(return_list))]

    new_return_list = []
    for line in return_list:
        line = network_subhealth_re(object=line, delimiter=':')
        line = list_split(split_list=line, start=1, end=len(line))
        new_return_list.append(line)

    message_add_list = [(0, src_ip), (0, time_stamp)]
    new_filter_list = list_insert(new_return_list, message_add_list)

    for range_index, header, parameter in zip(range_list, message_header_list, filename_parameter):
        temp_list    = list_split(new_filter_list, start=range_index[0], end=range_index[1])
        log_filename = g_root_dirname + '/log/nicstat/filter/' + IP + '_nicstat_aUp_' + parameter + '_filter_' + time_stamp + '.csv'
        message_save_csv_log(log_filename, header, temp_list)


"""
    netstat命令处理函数，对执行netstat命令获取到的数据进行格式化，持久化
    输入：
        netstat_needed_info_set：需要用netstat命令获取的信息，也决定了该命令执行时需要添加的参数
        IP：表明netstat命令获取的是哪台主机上的信息
"""
def netstat_handle(netstat_needed_info_set, IP):
    """
        'i'    : -i参数可获取的信息
        'an': -natp4参数可获取的信息
        's'    : -s参数可获取的信息
    """
    netstat_default_message_dict = {
        'i'     : {'MTU', 'Met', 'RX_OK', 'RX_ERR', 'RX_DRP', 'RX_OVR', 'TX_OK', 'TX_ERR', 'TX_DRP', 'TX_OVR', 'Flg'},
         'an': {'PID', 'Protocol', 'Send_Q', 'Recv_Q', 'IP', 'State'},
         's'    : {'Ip', 'Icmp', 'IcmpMsg', 'Tcp', 'Udp', 'UdpLite', 'TcpExt', 'IpExt'}
         }

    # 不同参数拥有的不同文件头部
    message_header_dict = {
        'i':['timestamp', 'src_ip', 'Iface', 'MTU', 'Met', 'RX-OK', 'RX-ERR', 'RX-DRP', 'RX-OVR', 'TX-OK', 'TX-ERR', 'TX-DRP', 'TX-OVR', 'Flg'],
        'an':['timestamp', 'src_ip', 'Proto', 'Recv-Q', 'Send-Q', 'Local_Address:port', 'Foreign_Address:port', 'State']
        }
    # tool_parameter: 工具的参数
    for tool_parameter in netstat_default_message_dict.keys():
        if (netstat_needed_info_set & netstat_default_message_dict[tool_parameter]):
            cmd_list      = ['netstat -' + tool_parameter, 'grep -viE \"Kernel|Iface|unix|Proto|Active\"']
            return_list, errno = shell_pipeline(cmd_list, split_lines=True)
            print ('\'%s\' errno: %s' % (cmd_list, str(errno)))

            time_stamp     = datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
            log_filename   = g_root_dirname + '/log/netstat/filter/' + IP + '_netstat_' + tool_parameter + '_filter_' + time_stamp + '.csv'
            message_header = message_header_dict[tool_parameter]

            filter_list = network_subhealth_filter(return_list)

            message_add_list = [(0, src_ip), (0, time_stamp)]
            new_filter_list = list_insert(filter_list, message_add_list)
            message_save_csv_log(log_filename, message_header, new_filter_list)


"""
    traceroute命令处理函数，执行命令->获取数据->处理数据->保存数据
    输入：
        traceroute_needed_info_set：需要用traceroute命令获取的信息
        IP：traceroute命令执行时的对端IP
"""

def traceroute_handle(traceroute_needed_info_set, IP):
    cmd_list      = ['traceroute -n ' + IP, 'grep -vE \"traceroute|\*\"']
    return_list, errno = shell_pipeline(cmd_list, split_lines=True)
    print ('\'%s\' errno: %s' % (cmd_list, str(errno)))

    time_stamp     = datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    log_filename   = g_root_dirname + '/log/traceroute/filter/' + IP + '_traceroute_filter_' + time_stamp + '.csv'
    message_header = ['timestamp', 'src_ip', 'HOP', 'dest_IP', 'rtt1', 'rtt2', 'rtt3']

    filter_list    = network_subhealth_filter(return_list, src_value='\(|\)|\sms', dest_value='',  opt='sub')
    message_add_list = [(0, src_ip), (0, time_stamp)]
    new_filter_list = list_insert(filter_list, message_add_list)

    message_save_csv_log(log_filename, message_header, new_filter_list)



"""
    ping命令处理函数，执行命令->获取数据->处理数据->保存数据
    输入：
        ping_needed_info_set：需要用ping命令获取的信息
        IP：执行ping命令的对端IP
"""
def ping_handle(ping_needed_info_set, IP):
    cmd_list = ['ping' + ' ' + IP + ' ' + '-i 0.01 -c 10', 'grep -vE \"PING|statistics|packets|rtt|^$\"']
    return_list, errno = shell_pipeline(cmd_list, split_lines=True)
    print ('\'%s\' errno: %s' % (cmd_list, str(errno)))

    time_stamp     = datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    log_filename   = g_root_dirname + '/log/ping/filter/' + IP + '_ping_filter_' + time_stamp + '.csv'
    message_header = ['timestamp', 'src_ip', 'pkt_size', 'dest_IP', 'icmp_req', 'ttl', 'rtt']

    filter_list    = network_subhealth_filter(return_list, src_value='bytes|from|:|ms|=|icmp_req|ttl|time', dest_value='',  opt='sub')
    message_add_list = [(0, src_ip), (0, time_stamp)]
    new_filter_list = list_insert(filter_list, message_add_list)

    message_save_csv_log(log_filename, message_header, new_filter_list)



"""
    snmp命令处理函数，目前只实现了保存原始数据，未对其进行格式化
    输入：
        snmp_needed_info_set：需要用snmp获取的信息
        IP：表明snmp命令获取的是哪台主机的信息
"""
def snmp_handle(snmp_needed_info_set, IP):
    snmp_tree = 'iso.org.dod.internet.mgmt.mib-2.'
    snmp_needed_info_list = list(snmp_needed_info_set)
    for snmp_info in snmp_needed_info_list:
        cmd_list       = ['snmpwalk -v2c -c public ' + IP + ' ' + snmp_tree + snmp_info]
        result, errno  = shell_pipeline(cmd_list)
        print ('\'%s\' errno: %s' % (cmd_list, str(errno)))

        time_stamp     = datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        log_filename   = g_root_dirname + 'log/snmp/raw/' + IP + '_snmpwalk_' + snmp_info + '_raw_' + time_stamp + '.csv'
        raw_message_list = result.splitlines()
        message_save_log(log_filename, raw_message_list)



"""
    根据match_tool（）的返回值选择相应的命令处理函数
    输入：
        tool_need_dict：key为工具名称，value为该工具要获取的信息，是match_tool的返回值
        remote_ip     ：探测型工具执行命令时指定的远端IP
        localhost_ip  ：本机IP，表明统计型工具所统计的信息时哪台主机的信息
"""
def choose_tool(tool_need_dict, remote_ip, src_ip):
    for tool in tool_need_dict.keys():
        tool_message_list = tool_need_dict[tool]
        # 当该工具需要获取的信息为空时，直接跳过,不为空时才进入if里面的语句
        if tool_message_list:
            tool_func = tool + '_handle'
            # 对应函数需要两个参数的工具名称列表
            two_parameter_func_list = ['snmp', 'mtr', 'traceroute', 'ping', 'paping', 'tcpping']
            if tool in two_parameter_func_list:
                globals()[tool_func](set(tool_message_list), remote_ip)
            else:
                globals()[tool_func](set(tool_message_list), src_ip)


if __name__ == '__main__':
    # 需要获取的信息列表
    message_needed_list = ['Int', 'rtt', 'PID', 'MTU']
    remote_ip = '10.211.3.200'
    src_ip = '10.110.128.110'
    tool_need_dict = match_tool(message_needed_list)
    print tool_need_dict
    choose_tool(tool_need_dict, remote_ip, src_ip)

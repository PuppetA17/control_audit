#!/bin/bash
##############################################################
# File Name: iptables.sh
# Version: V1.0
# Author: dingwenhao
# Organization: www.greencheng.com
# Created Time: 2019-10-17 13:49:26
# Description: 对项目的日志进行分析,在指定时间内请求达到指定次
#              数后通过iptables对ip进行封禁,封禁周期后解除封禁
##############################################################
. /etc/init.d/functions
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/root/bin"

#项目路径
BASE_PATH="$(cd `dirname $0`;pwd)"

#配置文件路径
BASE_CONF_PATH="${BASE_PATH}/settings.conf"

#载入项目配置
source ${BASE_CONF_PATH}

#IP正则文件
ip_rex_file=${BASE_PATH}/.ip_rex.conf

#时间正则文件
time_rex_file=${BASE_PATH}/.time_rex.conf

#项目日志路径
log_path=${log_dir}${log_name}

#封禁日志路径
BASE_LOG_PATH="${BASE_PATH}/log/"

#封禁审计日志路径
control_disable_audit_log_file="${BASE_LOG_PATH}control_disable_audit.log"

#解封审计日志路径
control_enable_audit_log_file="${BASE_LOG_PATH}control_enable_audit.log"

#日IP封禁清理存储路径
clean_ip_log_file="${BASE_LOG_PATH}.clean_ip.log"

#有效时间IP临时写入文件
disable_tmp_file="${BASE_LOG_PATH}.disable_ip_tmp.text.swp"

#当前时间
now_time=$(date "+%F %H:%M:%S")

#偏移量记录文件
offset_file=${BASE_LOG_PATH}${log_name}.registry

#偏移日志临时写入文件
offset_tmp_file=${BASE_LOG_PATH}.offset_log.text.swp

#判断路径是否存在
[ ! -d $log_dir ] && mkdir -p $log_dir
[ ! -f $log_path ] && echo "cannot access $log_path: No such file or directory"
[ ! -d $BASE_LOG_PATH ] && mkdir -p $BASE_LOG_PATH
[ ! -f $clean_ip_log_file ] && touch $clean_ip_log_file

#获取ip与时间正则
[ ! -f $ip_rex_file -o -z "$(cat $ip_rex_file)" ] && exit 1
[ ! -f $time_rex_file -o -z "$(cat $time_rex_file)" ] && exit 1
ip_rex=$(cat $ip_rex_file)
time_rex=$(cat $time_rex_file)

#定义检测函数
function check(){
    if [ $RETVAL -ne 0 ]
    then
        action "$1" /bin/false
    else
        action "$1" /bin/true
    fi
}

#时间检测函数
function check_time(){
    #获取访问时间
    access_time=$1
    #获取有效时间
    viald_time=$2
    #获取访问时间戳
    access_time_sec=$(date -d "${access_time}" +%s)
    #获取有效时间戳
    viald_time_sec=$(date -d "-${viald_time}min" +%s)
    #获取当前时间戳
    date_now_sec=$(date +%s)
    #当前时间对比有效时间戳
    diff_vaild_time=$(expr $date_now_sec - ${viald_time_sec})
    #当前时间对比访问时间时间戳
    diff_access_time=$(expr $date_now_sec - $access_time_sec)
    #如果访问时间的有效时间戳在有效时间内则正常返回
    [ $diff_access_time -le $diff_vaild_time ] && return 0
}

#获取IP数组进行去重排序,拿到封禁IP数组进行封禁
function sort_array(){
    #获取ip数组
    ip_access_array=${access_array[@]}
    #将ip数组进行去除排序，写入临时文件
    echo $ip_access_array|awk '{for(i=1;i<=NF;i++)S[$i]++}END{for(k in S)print S[k],k}'|sort -rn >$disable_tmp_file
    #定义数组索引起始
    array_index=0
    #循环存放去重后的数组的临时文件
    while read line
    do
        #获取访问次数
        sort_access_count=$(echo $line|awk '{print $1}')
        #获取访问ip
        sort_access_ip=$(echo $line|awk '{print $NF}')
        #将访问次数达到封禁阈值的IP添加至封禁数组
        if [ $sort_access_count -gt $disable_count ]
        then
            iptables_disable $sort_access_ip $sort_access_count
            if [ $? -eq 0 ]
            then
                #封禁成功写入封禁审计
                printf "[%s]\tip地址: %s\t访问次数: %s\t动作: 封禁\t状态: 成功\n" "$now_time" $sort_access_ip $sort_access_count >>$control_disable_audit_log_file
                #封禁成功写入清洗ip的日志
                printf "[%s] %s\n" "$now_time" $sort_access_ip >>$clean_ip_log_file
            else
                #封禁失败写入封禁审计
                printf "[%s]\tip地址: %s\t访问次数: %s\t动作: 封禁\t状态: 失败\n" "$now_time" $sort_access_ip $sort_access_count >>$control_disable_audit_log_file
            fi
        fi
        #索引自增
        ((array_index++))
    done <$disable_tmp_file
    #封禁完毕删除临时文件
    [ -f $disable_tmp_file ] && /bin/rm $disable_tmp_file &>/dev/null
}

#偏移量初始化
function init_offset(){
    #如果没有偏移文件则创建,并设置初始值
    if [ ! -f $offset_file ]
    then
        touch $offset_file
        echo 1 >$offset_file
    else
        #如果偏移文件为空则设置初始值
        offset_num=$(cat ${offset_file})
        if [ -z "$offset_num" ]
        then
            echo 1 >$offset_file
        else
            #如果文件小于1则设置初始值
            if [ "$offset_num" -lt 1 ]
            then
                echo 1 >$offset_file
            fi
        fi
    fi
}

#设置偏移量
function set_offset(){
    #获取日志文件长度
    file_totle_size=$(wc -l $log_path|awk '{print $1}')
    #如果日志文件小于1则设置初始值
    if [ $file_totle_size -lt 1 ]
    then
        echo 1 >$offset_file
    else
        #设置偏移量为日志文件长度+1
        let file_totle_size=file_totle_size+1
        echo $file_totle_size >$offset_file
    fi
}

#获取有效时间内的IP数组
function build_access_array(){
    #初始化偏移量
    init_offset
    #获取offset偏移量
    offset_num=$(cat $offset_file)
    #定义数组索引起始
    array_index=0
    #将偏移日志写入临时偏移文件
    sed -n "$offset_num,$"p $log_path >$offset_tmp_file
    #循环日志文件
    while read line
    do
        #获取访问时间
        access_time=$(echo $line|eval $time_rex)
        #获取访问ip
        access_ip=$(echo $line|eval $ip_rex)
        #判断ip是否已被封禁
        check_ip $access_ip
        #如果ip已被封禁则跳过当前ip
        [ $? -eq 0 ] || continue
        #检测访问时间是否在有效时间内
        check_time "$access_time" "$vaild_min"
        #如果访问时间是在有效时间内则将访问IP加入数组
        [ $? -eq 0 ] && access_array[${array_index}]=$access_ip
        #索引自增
        ((array_index++))
    done <$offset_tmp_file
    >$offset_tmp_file 
    #设置偏移量
    set_offset
}

#根据封禁数组封禁IP
function iptables_disable(){
    #获取封禁IP
    disable_ip=$1
    #通过iptables对ip进行封禁
    iptables -t filter -I INPUT -s $disable_ip -j DROP
}

#根据解封数组解封IP
function iptables_clean(){
    #获取解封IP
    clean_ip=$1
    #通过iptables对ip进行解封
    iptables -t filter -D INPUT -s $clean_ip -j DROP
}

#获取ip是否已存在于iptables
function check_ip(){
    #获取当前ip
    active_ip=$1
    #判断IP是否已被封禁
    count=$(iptables -nL|grep -oc ${active_ip})
    #如果IP已被封禁则正常返回
    [ $count -eq 0 ] && return 0
}


#获取解封IP数组进行解封
function clean_ip(){
    #时间转换
    let banned_cycle_time=banned_cycle_time*60
    while read line
    do
        #获取ip封禁时间
        get_disable_time=$(echo $line|sed -r 's#\[(.*)\]\s+(.*)$#\1#g')
        #获取封禁ip
        get_disable_ip=$(echo $line|sed -r 's#\[(.*)\]\s+(.*)$#\2#g')
        #判断ip是否已被封禁
        check_ip $get_disable_ip
        #如果ip未被封禁则跳过当前ip
        [ $? -eq 0 ] && continue
        #判断封禁时间是否满足封禁周期
        check_time "$get_disable_time" "$banned_cycle_time"
        #对满足周期的ip进行清理
        [ $? -eq 0 ] || { 
            #将满足封禁周期的ip进行解封
            iptables_clean $get_disable_ip $get_disable_time
            if [ $? -eq 0 ]
            then
                #解封成功写入封禁审计
                printf "[%s]\tip地址: %s\t封禁时间: %s\t动作: 解封\t状态: 成功\n" "$now_time" $get_disable_ip "$get_disable_time" >>$control_enable_audit_log_file
                sed -i "/$get_disable_ip/d" $clean_ip_log_file
            else
                #解封失败写入封禁审计
                printf "[%s]\tip地址: %s\t封禁时间: %s\t动作: 解封\t状态: 失败\n" "$now_time" $get_disable_ip "$get_disable_time" >>$control_enable_audit_log_file
            fi
        }
    done <$clean_ip_log_file
}

function main(){
    #获取有效时间内的IP数组
    build_access_array &&\
    #对IP进行去重,将符合条件的IP进行封禁
    sort_array access_array &&\
    #对符合条件的IP进行解封
    clean_ip
    RETVAL=$?
}

main
exit $RETVAL

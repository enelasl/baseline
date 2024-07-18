check_point="账号口令-2.2:检查是否设置口令最小长度 "
print_check_point  "$check_point"
passminlen=`cat /etc/login.defs | grep PASS_MIN_LEN | grep -v ^#`
print_info "'PASS_MIN_LEN 应大于等于 8'"
print_info "$passminlen"
if [ -n "$passminlen" ]; then
  days=`echo $passminlen | awk '{print $2}'`
  if [ "$days" -lt 8 ]; then
	echo "2.2	检查是否设置口令最小长度	重要	建议调整	密码长度过短会增加密码被爆破风险，按照企业密码管理要求与等级保护标准，口令长度最小值应为8位。此检查项建议调整	>=8	$days	FAIL		" >> "$csvFile"
      print_fail
  else
	echo "2.2	检查是否设置口令最小长度	重要	建议调整	密码长度过短会增加密码被爆破风险，按照企业密码管理要求与等级保护标准，口令长度最小值应为8位。此检查项建议调整	>=8	$days	TRUE		" >> "$csvFile"
      print_pass
  fi
else
  echo "2.2	检查是否设置口令最小长度	重要	建议调整	密码长度过短会增加密码被爆破风险，按照企业密码管理要求与等级保护标准，口令长度最小值应为8位。此检查项建议调整	>=8	null	FAIL		" >> "$csvFile"
  print_fail
fi
print_dot_line


check_point="账号口令-2.4:检查设备密码复杂度策略 "
print_check_point  "$check_point"
print_info "'系统应设置密码复杂度策略，避免设置账号弱口令'"

print_info "此部分要求不一，请手工检查/etc/pam.d/system-auth或/etc/security/pwquality.conf文件配置"
print_info "此处检查内容为，密码长度至少20位，并且存在大写字母、小写字母、特殊字符、数字至少一个的要求来检测的"

print_info "检查/etc/pam.d/system-auth，如下："
flag=0
info=`cat /etc/pam.d/system-auth | grep password | grep requisite`
print_info "$info"
#line=`cat /etc/pam.d/system-auth | grep password | grep pam_cracklib.so | grep -v ^#`
if [ -n "$info" ]; then
    # minlen:密码字符串长度，dcredit数字字符个数，ucredit大写字符个数，ocredit特殊字符个数，lcredit小写字符个数
    #minlen=`echo $info | awk -F 'minlen=' '{print $2}' | awk -F ' ' '{print $1}'`
    dcredit=`echo $info | awk -F 'dcredit=' '{print $2}' | awk -F '' '{print $2}'`
    ucredit=`echo $info | awk -F 'ucredit=' '{print $2}' | awk -F '' '{print $2}'`
    ocredit=`echo $info | awk -F 'ocredit=' '{print $2}' | awk -F '' '{print $2}'`
    lcredit=`echo $info | awk -F 'lcredit=' '{print $2}' | awk -F '' '{print $2}'`
echo "$dcredit"
    if [ "$ucredit" -ge 1 ] && [ "$lcredit" -ge 1 ] && [ "$ocredit" -ge 1 ]; then
        print_info "ucredit => ""[ $ucredit ]"
        print_info "ocredit => ""[ $ocredit ]"
        print_info "lcredit => ""[ $lcredit ]"
        flag=1
    fi
fi
# 以下检查/etc/security/pwquality.conf文件中的内容
# minlen为密码字符串长度，minclass为字符类别
print_info "检查/etc/security/pwquality.conf，如下:"
line_minlen=`cat /etc/security/pwquality.conf | grep minlen | grep -v ^#`
line_minclass=`cat /etc/security/pwquality.conf | grep minclass | grep -v ^#`

if [ -n "$line_minlen" ] && [ -n "$line_minclass" ]; then
	minlen=`echo "$line_minlen" | awk -F "=" '{print $2}' | awk '{gsub(/^\s+|\s+$/， "");print}'`
	minclass=`echo "$line_minclass" | awk -F "=" '{print $2}' | awk '{gsub(/^\s+|\s+$/， "");print}'`
	if [ "$minlen" -ge 20 ] && [ "$minclass" -ge 4 ];then
    	print_info "minlen =>"" [ $minlen ]"
    	print_info "minclass =>"" [ $minclass ]"
    	flag=1
    fi
fi
if [ "$flag" -eq 1 ]; then
	echo "2.4	检查设备密码复杂度策略	重要	建议调整	密码复杂度过低会增加密码被爆破风险，按照企业密码管理要求与等级保护标准，密码复杂度应包含特殊字符、大小写字母。此检查项建议调整	至少有1个大写字母、1个小写字母、1个数字、1个特殊字符	null	TRUE	 	" >> "$csvFile"
	print_pass
else
	echo "2.4	检查设备密码复杂度策略	重要	建议调整	密码复杂度过低会增加密码被爆破风险，按照企业密码管理要求与等级保护标准，密码复杂度应包含特殊字符、大小写字母。此检查项建议调整	至少有1个大写字母、1个小写字母、1个数字、1个特殊字符	null	FAIL	 	" >> "$csvFile"
	print_fail
fi



check_point="其他配置-6.2:检查是否设置grub密码"
print_check_point  "$check_point"
grub=`cat /boot/grub/menu.lst`
if [ -n "$grub" ]; then
	print_info "系统引导器为grub！"
	grub_pass=`echo $grub | grep password`
	if [ -n "$grub_pass" ]; then
		echo "6.2	检查是否设置系统引导管理器密码	可选	自行判断	应根据引导器不同类型设置引导管理器密码。此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	$grub_pass	TRUE		" >> "$csvFile"
		
		print_pass
	else
		echo "6.2	检查是否设置系统引导管理器密码	可选	自行判断	应根据引导器不同类型设置引导管理器密码。此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	$grub_pass	FAIL		" >> "$csvFile"
		
		print_fail
	fi
fi



check_point="账号口令-2.3:检查是否设置口令过期警告天数 "

print_check_point  "$check_point"
passwarn=`cat /etc/login.defs | grep PASS_WARN_AGE | grep -v ^#`
print_info "'PASS_WARN_AGE 应大于等于 30'"
print_info "$passwarn"
if [ -n "$passwarn" ]; then
  days=`echo $passwarn | awk '{print $2}'`
  if [ "$days" -lt 30 ]; then
	echo "2.3	检查是否设置口令过期警告天数	重要	建议调整	除入域服务器超管账号分段管理无需配置外，应配置密码过期提醒策略防止密码过期无法登陆。此检查项建议调整	>=30	20	FAIL	 	" >> "$csvFile"
      
      print_fail
  else
	echo "2.3	检查是否设置口令过期警告天数	重要	建议调整	除入域服务器超管账号分段管理无需配置外，应配置密码过期提醒策略防止密码过期无法登陆。此检查项建议调整	>=30	20	TRUE	 	">> "$csvFile"
      
      print_pass
  fi
else
	echo "2.3	检查是否设置口令过期警告天数	重要	建议调整	除入域服务器超管账号分段管理无需配置外，应配置密码过期提醒策略防止密码过期无法登陆。此检查项建议调整	>=30	20	FAIL	 	" >> "$csvFile"
  
  print_fail
fi
print_dot_line



check_point="账号口令-2.1：检查是否设置口令生存周期"

print_check_point  "$check_point"
#在文件etc/login.defs中搜索pass_max_days的值，并且去掉#自开头的值
#grep -v ^#    ------>  不匹配以#开头的行
passmax=`cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^#`
print_info "'PASS_MAX_DAYS 应介于1~90'"

print_info "$passmax"
if [ -n "$passmax" ]; then
	days=`echo $passmax | awk '{print $2}'`

	if [ "$days" -gt 90 ]; then
		echo "2.1	检查是否以设置口令生存周期	重要	建议调整	长期不修改密码会增加密码暴露风险，除入域服务器或服务器超管账号分段管理无需配置外，应对服务器密码最长使用期限进行限制。此检查项建议调整	<=90	$days	FAIL	 	 " >> "$csvFile"
		
		print_fail
	else
		
		print_pass
		echo "2.1	检查是否以设置口令生存周期	重要	建议调整	长期不修改密码会增加密码暴露风险，除入域服务器或服务器超管账号分段管理无需配置外，应对服务器密码最长使用期限进行限制。此检查项建议调整	<=90	$days	TRUE	 	 " >> "$csvFile"
	fi
else
	
	print_fail
	echo "2.1	检查是否以设置口令生存周期	重要	建议调整	长期不修改密码会增加密码暴露风险，除入域服务器或服务器超管账号分段管理无需配置外，应对服务器密码最长使用期限进行限制。此检查项建议调整	<=90	无此配置	FAIL	 	 " >> "$csvFile"
fi
print_dot_line



check_point="认证授权-3.2:检查重要目录或文件权限设置"
echo "3.2	检查重要目录或文件权限设置	一般	自行判断	需检查重要目录或文件权限设置是否合规，保障系统安全性，此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	参考子项	参考子项		" >> "$csvFile"

print_check_point  "$check_point"

print_info "检查重要目录或文件权限设置"

#!/bin/bash

files_to_check=(
    "/etc/xinetd.conf"
    "/etc/inetd.conf"
    "/var/log/messages"
    "/boot"
    "/usr/src"
    "/lib/modules"
    "/usr/lib/modules"
    "/var/log/audit"
)
print_info() {
    echo "$1" >&2
}
print_pass() {
    echo "通过" >&2
}
print_fail() {
    echo "失败" >&2
}
print_white() {
    echo "$1" >&2
}
results=()
for file in "${files_to_check[@]}"; do
    if [ -f "$file" ]; then
        file_stat=$(stat -c %a "$file")
        print_info "${file}的权限应该大于等于600，实际为：===> $file_stat"
        if [ "$file_stat" -ge 600 ]; then
            results+=("{\"file\":\"$file\",\"category\":\"一般\",\"judgment\":\"自行判断\",\"reference\":\"参考父项3.2\",\"expected\":\">=600\",\"actual\":\"$file_stat\",\"result\":\"TRUE\"}")
            print_pass
        else
            results+=("{\"file\":\"$file\",\"category\":\"一般\",\"judgment\":\"自行判断\",\"reference\":\"参考父项3.2\",\"expected\":\">=600\",\"actual\":\"$file_stat\",\"result\":\"FAIL\"}")
            print_fail
        fi
    else
        results+=("{\"file\":\"$file\",\"category\":\"一般\",\"judgment\":\"自行判断\",\"reference\":\"参考父项3.2\",\"expected\":\">=600\",\"actual\":\"文件不存在\",\"result\":\"TRUE\"}")
        print_white "文件不存在！"
    fi
done
# 输出JSON格式的结果
echo "["
for ((i=0; i<${#results[@]}; i++)); do
    echo "${results[i]}"
    if [ $i -lt $((${#results[@]} - 1)) ]; then
        echo ","
    fi
done
echo "]"



check_point="日志审计-4.2:检查安全事件日志配置"
print_check_point  "$check_point"
print_info "'设备应配置日志功能，记录对与设备相关的安全事件'"
tmp=`cat /etc/rsyslog.conf | grep -v ^#`
print_info "/etc/rsyslog.conf 文件中 /var/log/messages 的配置如下所示:"
print_info "$tmp"
if [ -n "$tmp" ]; then
	echo "4.2	检查安全事件日志配置	可选	建议调整	应对安全时间日志文件进行配置。此检查项建议调整	参考《Linux安全配置基线》对应章节	$tmp	TRUE		" >> "$csvFile"	
  print_pass
else
	echo "4.2	检查安全事件日志配置	可选	建议调整	应对安全时间日志文件进行配置。此检查项建议调整	参考《Linux安全配置基线》对应章节	$tmp	FAIL		" >> "$csvFile"
  print_fail
fi
print_dot_line














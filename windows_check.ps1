#3.4 检查是否已正确配置帐户锁定时间
$ResetLockoutCount = Get-Content -path config.cfg | findstr ResetLockoutCount
if($ResetLockoutCount -ne $null){

	$config = Get-Content -path config.cfg
	for ($i=0; $i -lt $config.Length; $i++)
	{
		$config_line = $config[$i] -split "="
		if(($config_line[0] -eq "ResetLockoutCount "))
		{
			$config_line[1] = $config_line[1].Trim(' ')
			$test34 = $config_line[1]
			#2021/04/28 修改标准值为[5,8]
			if(($config_line[1] -ge "5") -and ($config_line[1] -le "8"))
			{
				#$data.code = "1"
				$projectdata = @{"true"="3.4 检查是否已正确配置帐户锁定时间 >=1  $test34 TRUE";}
				echo "3.4	检查是否已正确配置帐户锁定时间	可选	建议调整	用户登录失败次数过多应对服务器登录进行锁定，防止密码被爆破到风险。此检查项建议调整	[5,8]	$test34	TRUE		" >> $file_name
				$data['project']+=$projectdata
			}
			else
			{
				#$data.code = "0"
				$projectdata = @{"fail"="3.4 检查是否已正确配置帐户锁定时间 >=1 $test34 FAIL";}
				echo "3.4	检查是否已正确配置帐户锁定时间	可选	建议调整	用户登录失败次数过多应对服务器登录进行锁定，防止密码被爆破到风险。此检查项建议调整	[5,8]	$test34	FAIL		" >> $file_name
				$data['project']+=$projectdata
			}
		}

	}

}
else{
	$projectdata = @{"manual"="3.4 检查是否已正确配置帐户锁定时间 >=1 $test34 MANUAL";}
	echo "3.4	检查是否已正确配置帐户锁定时间	可选	建议调整	用户登录失败次数过多应对服务器登录进行锁定，防止密码被爆破到风险。此检查项建议调整	[5,8]	null	MANUAL		" >> $file_name
	$data['project']+=$projectdata
}

#3.5 检查是否已正确配置帐户锁定阈值
$LockoutBadCount = Get-Content -path config.cfg | findstr LockoutBadCount
if($LockoutBadCount -ne $null){

	$config = Get-Content -path config.cfg
	for ($i=0; $i -lt $config.Length; $i++)
	{
		$config_line = $config[$i] -split "="
		if(($config_line[0] -eq "LockoutBadCount "))
		{
			$config_line[1] = $config_line[1].Trim(' ')
			$test35 = $config_line[1]
			#2021/04/28修改标准值为5
			if(($config_line[1] -eq "5"))
			{
				#$data.code = "1"
				$projectdata = @{"true"="3.5 检查是否已正确配置帐户锁定阈值 5 $test35 TRUE";}
				echo "3.5	检查是否已正确配置帐户锁定阈值	可选	建议调整	用户登录失败次数过多应对服务器登录进行锁定，防止密码被爆破到风险。此检查项建议调整	5	$test35	TRUE		" >> $file_name
				$data['project']+=$projectdata
			}
			else
			{
				#$data.code = "0"
				#$data.code = "0"
				$projectdata = @{"fail"="3.5 检查是否已正确配置帐户锁定阈值 5 $test35 FAIL";}
				echo "3.5	检查是否已正确配置帐户锁定阈值	可选	建议调整	用户登录失败次数过多应对服务器登录进行锁定，防止密码被爆破到风险。此检查项建议调整	5	$test35	FAIL		" >> $file_name
				$data['project']+=$projectdata
			}
		}

	}

}
else{
	$projectdata = @{"manual"="3.5 检查是否已正确配置帐户锁定阈值 5 $test35 MANUAL";}
	echo "3.5	检查是否已正确配置帐户锁定阈值	可选	建议调整	用户登录失败次数过多应对服务器登录进行锁定，防止密码被爆破到风险。此检查项建议调整	5	null	MANUAL		" >> $file_name
	$data['project']+=$projectdata
}

#7.7 检查是否已启用并正确配置屏幕保护程序
#屏幕自动保护程序
echo "7.7	检查是否已启用并正确配置屏幕保护程序	可选	建议调整	在无操作到一段时间内，系统应开启屏幕保护程序。此检查项建议调整	参考子项	参考子项	参考子项		" >> $file_name
$Key = 'HKEY_CURRENT_USER\Control Panel\Desktop'
$name = "ScreenSaveActive"
$config = (Get-ItemProperty -Path "Registry::$Key" -ErrorAction Stop).$name
if($config -eq "1"){
    $projectdata = @{"true"="7.7.1 检查是否已启用并正确配置屏幕保护程序 1 $config TRUE";}
	echo "7.7.1	检查是否已启用并正确配置屏幕保护程序	可选	建议调整	详情参考父项7.7	1	$config	TRUE		" >> $file_name
	$data['project']+=$projectdata
}
else{
    $projectdata = @{"fail"="7.7.1 检查是否已启用并正确配置屏幕保护程序 1 $config FAIL";}
	echo "7.7.1	检查是否已启用并正确配置屏幕保护程序	可选	建议调整	详情参考父项7.7	1	$config	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
#检查屏幕保护程序等待时间
$Key = 'HKEY_CURRENT_USER\Control Panel\Desktop'
$name = "ScreenSaveTimeOut"
$config = (Get-ItemProperty -Path "Registry::$Key" -ErrorAction Stop).$name
if($config -le 300)
        {
            $projectdata = @{"true"="7.7.2 检查屏幕保护程序等待时间  <=300 $config TRUE";}
			echo "7.7.2	检查屏幕保护程序等待时间	可选	建议调整	详情参考父项7.7	<=300	$config	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="7.7.2 检查屏幕保护程序等待时间 <=300 $config FAIL";}
			echo "7.7.2	检查屏幕保护程序等待时间	可选	建议调整	详情参考父项7.7	<=300	$config	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
#检查是否已启用在恢复时显示登陆界面
$Key = 'HKEY_CURRENT_USER\Control Panel\Desktop'
$name = "ScreenSaverIsSecure"
$config = (Get-ItemProperty -Path "Registry::$Key" -ErrorAction Stop).$name
if($config -eq "1")
        {
            $projectdata = @{"true"="7.7.3 检查是否已启用在恢复时显示登陆界面  TRUE";}
			echo "7.7.3	检查是否已启用在恢复时显示登陆界面	可选	建议调整	详情参考父项7.7	1	$config	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="7.7.3 检查是否已启用在恢复时显示登陆界面  FAIL";}
			echo "7.7.3	检查是否已启用在恢复时显示登陆界面	可选	建议调整	详情参考父项7.7	1	$config	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
#7.3 检查是否已启用“不显示最后的用户名”策略
$all = $all +1
$reg = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$name = 'dontdisplaylastusername'
$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
#echo "$config"
if ($config -eq 1){
	$projectdata = @{"true"="7.3 检查是否已启用不显示最后的用户名 1 $config TRUE";}
	echo "7.3	检查是否已启用不显示最后的用户名	可选	建议调整	应配置该策略防止用户名信息泄露。此检查项建议调整	1	$config	TRUE		" >> $file_name
	$data['project']+=$projectdata
}else{
	$projectdata = @{"fail"="7.3 检查是否已启用不显示最后的用户名 1 $config FAIL";}
	echo "7.3	检查是否已启用不显示最后的用户名	可选	建议调整	应配置该策略防止用户名信息泄露。此检查项建议调整	1	$config	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
#7.16 检查是否已禁用“登录时无须按 Ctrl+Alt+Del”策略
$all = $all +1
$Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$Name = 'disablecad'
$config = (Get-ItemProperty -Path "Registry::$Key" -ErrorAction Stop).$Name
#echo "$config"
   if($config -eq 0)
        {
            $projectdata = @{"true"="7.14 检查是否已禁用登录时无须按Ctrl+Alt+Del 0 $config TRUE";}
			echo "7.14	检查是否已禁用登录时无须按Ctrl+Alt+Del	可选	建议调整	攻击者可能会安装看似标准的登录对话框的特洛伊木马程序，并捕获用户密码。此检查项建议调整	0	$config	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="7.14 检查是否已禁用登录时无须按Ctrl+Alt+Del 0 $config FAIL";}
			echo "7.14	检查是否已禁用登录时无须按Ctrl+Alt+Del	可选	建议调整	攻击者可能会安装看似标准的登录对话框的特洛伊木马程序，并捕获用户密码。此检查项建议调整	0	$config	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
#7.9 检查是否已关闭Windows自动播放
$all = $all +1
$projectdata = @{"manual"="7.9 检查是否已关闭Windows自动播放(请管理员自查)  MANUAL";}
echo "7.9	检查是否已关闭Windows自动播放(请管理员自查)	可选	自行判断	极客中通过恶意代码写在U盘上，如果系统开启了自动播放功能，那么只要这些U盘插入在服务器上，该服务器就会感染到U盘上到病毒。此项建议系统管理员根据系统情况自行判断	启用	null	MANUAL		" >> $file_name
$data['project']+=$projectdata
#7.10 检查是否已关闭不必要的服务-DHCP Client
$all = $all +1
$dhcp = get-service | findstr /c:'DHCP Client' | findstr Running
if($dhcp -eq $null){
	$projectdata = @{"true"="7.10 检查是否已关闭不必要的服务-DHCPClient null $dhcp TRUE";}
	echo "7.1 0	检查是否已关闭不必要的服务-DHCPClient	可选	自行判断	攻击者可以伪造DHCP服务器，提供错误到信息给客户端到网卡。也可以伪造MAC地址，持续发送Discovery包，耗尽IP地址池，如无使用必要，请关闭此服务。此项建议系统管理员根据系统情况自行判断	null	$dhcp	TRUE		" >> $file_name
	$data['project']+=$projectdata
}
else{
	$projectdata = @{"true"="7.10 检查是否已关闭不必要的服务-DHCPClient null $dhcp FAIL";}
	echo "7.1 0	检查是否已关闭不必要的服务-DHCPClient	可选	自行判断	攻击者可以伪造DHCP服务器，提供错误到信息给客户端到网卡。也可以伪造MAC地址，持续发送Discovery包，耗尽IP地址池，如无使用必要，请关闭此服务。此项建议系统管理员根据系统情况自行判断	null	$dhcp	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
#6.3 检查是否已开启Windows防火墙
$all = $all +1
$projectdata = @{"manual"="6.3 检查是否已开启Windows防火墙(请管理员自查)  MANUAL";}
echo "6.3	检查是否已开启Windows防火墙(请管理员自查)	可选	自行判断	服务器应开启防火墙检测和抵御外部威胁，考虑到部分服务器反向代理情况。此项建议系统管理员根据系统情况自行判断	已启用	null	MANUAL		" >> $file_name
$data['project']+=$projectdata
#6.1 检查是否已修改默认的远程rdp服务端口
$all = $all +1
$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'

$name = 'PortNumber'
$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
#echo "$config"
if ($config -ne 3389){
	$projectdata = @{"true"="6.1 检查是否已修改默认的远程rdp服务端口 !=3389 $config TRUE";}
	echo "6.1	检查是否已正确配置安全日志	可选	自行判断	应修改默认RDP端口，避免windows默认端口被猜测，此项建议系统管理员根据系统情况自行判断	!=3389	$config	TRUE		" >> $file_name
	$data['project']+=$projectdata
}else{
	$projectdata = @{"fail"="6.1 检查是否已修改默认的远程rdp服务端口 !=3389 $config FAIL";}
	echo "6.1	检查是否已正确配置安全日志	可选	自行判断	应修改默认RDP端口，避免windows默认端口被猜测，此项建议系统管理员根据系统情况自行判断	!=3389	$config	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
#4.8 检查是否已删除可匿名访问的共享和命名管道
$all = $all +1
$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\services\LanmanServer\Parameters'
#可匿名访问的命名管道
$name = 'NullSessionPipes'
#可匿名访问的共享
$name2 = 'NullSessionShares'
$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
$config2 = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name2
<# $a = $config.Length
$b = $config2.Length
echo "$a"
echo "$b" #>
$test48 = $config.Length
$test48_1 = $config2.Length

if (($config.Length -eq 0) -and ($config2.Length -eq 0)){
	$projectdata = @{"true"="4.8 检查是否已删除可匿名访问的共享和命名管道 0，0	$test48,$test48_1 TRUE";}
	echo "4.8	检查是否已删除可匿名访问的共享和命名管道	可选	建议调整	启用此策略配置将未经过身份验证到用户限制为对除NullSessionPipes和NullSessionShares注册表项中列出的所有服务器管道和共享文件夹以外的所有服务器管道和共享文件夹到空回话访问，减少空会话漏洞风险。此检查项建议调整	0,0	$test48,$test48_1	TRUE		" >> $file_name
	$data['project']+=$projectdata
}else{
	$projectdata = @{"fail"="4.8 检查是否已删除可匿名访问的共享和命名管道 0，0	$test48,$test48_1 FAIL";}
	echo "4.8	检查是否已删除可匿名访问的共享和命名管道	可选	建议调整	启用此策略配置将未经过身份验证到用户限制为对除NullSessionPipes和NullSessionShares注册表项中列出的所有服务器管道和共享文件夹以外的所有服务器管道和共享文件夹到空回话访问，减少空会话漏洞风险。此检查项建议调整	0,0	$test48,$test48_1	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
#4.2 检查是否已限制SAM匿名用户连接
$all = $all +1
$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
$name = 'restrictanonymous'
$name2 = 'restrictanonymoussam'
$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
$config2 = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name2

if (($config -eq "1") -and ($config2 -eq "1")){
	$projectdata = @{"true"="4.2 检查是否已限制SAM匿名用户连接 restrictanonymous:$config/restrictanonymoussam:$config2 TRUE";}
	echo "4.2	检查是否已限制SAM匿名用户连接	可选	建议调整	未经授权到用户可以匿名列出账户名，存在社交工程共计或尝试猜测密码到风险。此检查项建议调整	restrictanonymous:1/restrictanonymoussam:1	restrictanonymous:$config/restrictanonymoussam:$config2	TRUE		" >> $file_name
	
	$data['project']+=$projectdata
}else{
	$projectdata = @{"fail"="4.2 检查是否已限制SAM匿名用户连接 restrictanonymous:$config/restrictanonymoussam:$config2 FAIL";}
	echo "4.2	检查是否已限制SAM匿名用户连接	可选	建议调整	未经授权到用户可以匿名列出账户名，存在社交工程共计或尝试猜测密码到风险。此检查项建议调整	restrictanonymous:1/restrictanonymoussam:1	restrictanonymous:$config/restrictanonymoussam:$config2	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
#4.1 检查是否已删除可远程访问的注册表路径和子路经
$all = $all +1
$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths'
$name = 'Machine'
$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction stop).$name
$test41 = $config
if ($config -ne $null){
	$projectdata = @{"fail"="4.1 检查是否已删除可远程访问的注册表路径和子路经 null $test41 FAIL";}
	echo "4.1	检查是否已删除可远程访问的注册表路径和子路经	可选	自行判断	注册表是设备配置信息到数据库，其中大部分信息是敏感到，恶意用户可以使用它来促进未授权活动。此项建议系统管理员根据系统情况自行判断	null	$test41	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
else{
	$projectdata = @{"true"="4.1 检查是否已删除可远程访问的注册表路径和子路经 null $test41 TRUE";}
	echo "4.1	检查是否已删除可远程访问的注册表路径和子路经	可选	自行判断	注册表是设备配置信息到数据库，其中大部分信息是敏感到，恶意用户可以使用它来促进未授权活动。此项建议系统管理员根据系统情况自行判断	null	$test41	TRUE		" >> $file_name
	$data['project']+=$projectdata
}
#7.6 检查是否已禁用Windows硬盘默认共享
$all = $all +1
$syn = get-itemproperty -path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" | findstr DontDisplayLockedUserId
if ($syn -ne $null){
	$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters'

	$name = 'AutoShareServer'
	$name1 = 'AutoShareWks'
	$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
	$config1 = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name1
	#echo "$config"
	if (($config -eq 0) -and ($config1 -eq 0)){
		$projectdata = @{"true"="7.6 检查是否已禁用Windows硬盘默认共享  0,0 $congif,$config1 TRUE";}
		echo "7.6	检查是否已禁用Windows硬盘默认共享	可选	自行判断	（适用非域环境）部分操作系统提供了默认共享功能，如果服务器联网，那么网络上到任何人都可以通过共享盘，随意访问该电脑。此项建议系统管理员根据系统情况自行判断	0,0	$config,$config1	TRUE		" >> $file_name
		$data['project']+=$projectdata
	}else{
		$projectdata = @{"fail"="7.6 检查是否已禁用Windows硬盘默认共享 0,0 $congif,$config1 FAIL";}
		echo "7.6	检查是否已禁用Windows硬盘默认共享	可选	自行判断	（适用非域环境）部分操作系统提供了默认共享功能，如果服务器联网，那么网络上到任何人都可以通过共享盘，随意访问该电脑。此项建议系统管理员根据系统情况自行判断	0,0	$config,$config1	FAIL		" >> $file_name
		$data['project']+=$projectdata
	}
}
else{
	$projectdata = @{"fail"="7.6 检查是否已禁用Windows硬盘默认共享(请按照基线文档执行用例) 0,0 $syn FAIL";}
	echo "7.6	检查是否已禁用Windows硬盘默认共享	可选	自行判断	（适用非域环境）部分操作系统提供了默认共享功能，如果服务器联网，那么网络上到任何人都可以通过共享盘，随意访问该电脑。此项建议系统管理员根据系统情况自行判断	0,0	$syn	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
#3.1 检查是否已正确配置密码最长使用期限策略
$all = $all +1
$MaximumPasswordAge = Get-content -path config.cfg | findstr MaximumPasswordAge
if($MaximumPasswordAge -ne $null){
	$config = Get-Content -path config.cfg

	for ($i=0; $i -lt $config.Length; $i++)
	{
		$config_line = $config[$i] -split "="
		if(($config_line[0] -eq "MaximumPasswordAge "))
		{
			$config_line[1] = $config_line[1].Trim(' ')
			$test = $config_line[1]
			if($config_line[1] -le "90")
			{
				#$data.code = "1"
				$projectdata = @{"true"="3.1 检查是否已正确配置密码最长使用期限策略 <=90 $test TRUE";}
				echo "3.1	检查是否已正确配置密码最长使用期限策略	可选	建议调整	长期不修改密码辉增加密码暴露风险，除入域服务器或服务器超管账号已分段无需配置外，应对服务器密码最长使用期限进行限制。此检查项建议调整	<=90	$test	TRUE		" >> $file_name
				$data['project']+=$projectdata

			}
			else
			{
				#$data.code = "0"
				$projectdata = @{"fail"="3.1 检查是否已正确配置密码最长使用期限策略 FAIL";}
				echo "3.1	检查是否已正确配置密码最长使用期限策略	可选	建议调整	长期不修改密码辉增加密码暴露风险，除入域服务器或服务器超管账号已分段无需配置外，应对服务器密码最长使用期限进行限制。此检查项建议调整	<=90	$test	FAIL		" >> $file_name
				$data['project']+=$projectdata
			}
		}
	}
}

else{
	$projectdata = @{"manual"="3.1 检查是否已正确配置密码最长使用期限策略 >=8  MANUAL";}
	echo "3.1	检查是否已正确配置密码最长使用期限策略	可选	建议调整	长期不修改密码辉增加密码暴露风险，除入域服务器或服务器超管账号已分段无需配置外，应对服务器密码最长使用期限进行限制。此检查项建议调整	<=90	null	MANUAL		" >> $file_name
	$data['project']+=$projectdata
}
#3.2 检查是否已配置密码长度最小值
$all = $all +1
$MinimumPasswordLength = Get-content -path config.cfg | findstr MinimumPasswordLength
if($MinimumPasswordLength -ne $null){

	$config = Get-Content -path config.cfg
	for ($i=0; $i -lt $config.Length; $i++)
	{
		$config_line = $config[$i] -split "="
		if(($config_line[0] -eq "MinimumPasswordLength "))
		{
			$config_line[1] = $config_line[1].Trim(' ')
			$test32 = $config_line[1]
			if($config_line[1] -ge "8")
			{
				#$data.code = "1"
				$projectdata = @{"true"="3.2 检查是否已配置密码长度最小值 >=8 $test32 TRUE";}
				echo "3.2	检查是否已配置密码长度最小值	可选	建议调整	密码长度过短会增加密码被爆破风险，按照企业密码管理要求与等级保护标准，密码长度最小值为8位。此检查项建议调整	>=8	$test32	TRUE		" >> $file_name
				$data['project']+=$projectdata
			}
			else
			{
				#$data.code = "0"
				$projectdata = @{"fail"="3.2 检查是否已配置密码长度最小值 >=8 $test32 FAIL";}
				echo "3.2	检查是否已配置密码长度最小值	可选	建议调整	密码长度过短会增加密码被爆破风险，按照企业密码管理要求与等级保护标准，密码长度最小值为8位。此检查项建议调整	>=8	$test32	FAIL		" >> $file_name
				$data['project']+=$projectdata
			}
		}
	}
}
else{
	$projectdata = @{"manual"="3.2 检查是否已配置密码长度最小值 >=8 $test32 MANUAL";}
	echo "3.2	检查是否已配置密码长度最小值	可选	建议调整	密码长度过短会增加密码被爆破风险，按照企业密码管理要求与等级保护标准，密码长度最小值为8位。此检查项建议调整	>=8	null	MANUAL		" >> $file_name
	$data['project']+=$projectdata
}
#3.3 检查是否已正确配置“强制密码历史"
$all = $all +1
$PasswordHistorySize = Get-content -path config.cfg | findstr PasswordHistorySize
if($PasswordHistorySize -ne $null){



	$config = Get-Content -path config.cfg
	for ($i=0; $i -lt $config.Length; $i++)
	{
		$config_line = $config[$i] -split "="
		if(($config_line[0] -eq "PasswordHistorySize "))
		{
			$config_line[1] = $config_line[1].Trim(' ')
			$test33 = $config_line[1]
			if($config_line[1] -ge "2")
			{
				#$data.code = "1"
				$projectdata = @{"true"="3.3 检查是否已正确配置`强制密码历史` >=2 $test33 TRUE";}
				echo "3.3	检查是否已正确配置`强制密码历史`	可选	建议调整	短期内使用历史密码会增加密码可猜测风险，同时参考等级保护标准，密码修改应不与近期修改相同。此检查项建议调整	>=2	$test33	TRUE		" >> $file_name
				$data['project']+=$projectdata
			}
			else
			{
				#$data.code = "0"
				$projectdata = @{"fail"="3.3 检查是否已正确配置`强制密码历史` >=2 $test33 FAIL";}
				echo "3.3	检查是否已正确配置`强制密码历史`	可选	建议调整	短期内使用历史密码会增加密码可猜测风险，同时参考等级保护标准，密码修改应不与近期修改相同。此检查项建议调整	>=2	$test33	FAIL		" >> $file_name
				$data['project']+=$projectdata
			}
		}
	}
}
else{
	$projectdata = @{"manual"="3.3 检查是否已正确配置`强制密码历史` >=2 $test33 MANUAL";}
	echo "3.3	检查是否已正确配置`强制密码历史`	可选	建议调整	短期内使用历史密码会增加密码可猜测风险，同时参考等级保护标准，密码修改应不与近期修改相同。此检查项建议调整	>=2	$test33	MANUAL		" >> $file_name
	$data['project']+=$projectdata
}
#5.4 检查是否已正确配置安全日志
$all = $all +1
$reg = 'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\services\eventlog\Security'
#按需要覆盖事件
$name = 'Retention'
#日志最大大小
$name1 = 'MaxSize'
$config = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name
$config1 = (Get-ItemProperty -Path "Registry::$reg" -ErrorAction Stop).$name1
#echo "$config1"
if (($config -eq 0) -and ($config1 -ge 8388608)){
	$projectdata = @{"true"="5.4 检查是否已正确配置安全日志 0,>=8388608 $config,$config1 TRUE";}
	echo "5.4	检查是否已正确配置安全日志	可选	建议调整	服务器排错与维护是服务器开发必不可少到部分，故对日志文件到配置与管理尤为重要。此检查项建议调整	0,>=8388608	$config,$config1	TRUE		" >> $file_name
	$data['project']+=$projectdata
}else{
	$projectdata = @{"fail"="5.4 检查是否已正确配置安全日志 0,>=8388608 $config,$config1 FAIL";}
	echo "5.4	检查是否已正确配置安全日志	可选	建议调整	服务器排错与维护是服务器开发必不可少到部分，故对日志文件到配置与管理尤为重要。此检查项建议调整	0,>=8388608	$config,$config1	FAIL		" >> $file_name
	$data['project']+=$projectdata
}
#5.1 检查是否已正确配置审核（日志记录策略）
echo "5.1	检查是否已正确配置审核（日志记录策略）	可选	建议调整	服务器排错与维护是服务器开发必不可少到部分，故对日志文件到配置与管理尤为重要。此检查项建议调整	参考子项	参考子项	参考子项			" >> $file_name
$all = $all +1
#审核策略更改
 $config = Get-Content -path config.cfg
 for ($i=0; $i -lt $config.Length; $i++)
 {
    $config_line = $config[$i] -split "="
    if(($config_line[0] -eq "AuditSystemEvents "))
    {
        $config_line[1] = $config_line[1].Trim(' ')
		$test511 = $config_line[1]
        if($config_line[1] -eq "3")
        {
            $projectdata = @{"true"="5.1.1 检查审核策略更改 3 $test511 TRUE";}
			echo "5.1.1	审核策略更改	可选	建议调整	详情参考父项5.1	3	$test511	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="5.1.1 检查审核策略更改 3 $test511 FAIL";}
			echo "5.1.1	审核策略更改	可选	建议调整	详情参考父项5.1	3	$test511	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
    }
  }
#审核登陆事件
 $config = Get-Content -path config.cfg
 for ($i=0; $i -lt $config.Length; $i++)
 {
    $config_line = $config[$i] -split "="
    if(($config_line[0] -eq "AuditLogonEvents "))
    {
        $config_line[1] = $config_line[1].Trim(' ')
		$test512 = $config_line[1]
        if($config_line[1] -eq "3")
        {
            $projectdata = @{"true"="5.1.2 检查审核登陆事件  3 $test512 TRUE";}
			echo "5.1.2	检查审核登陆事件	可选	建议调整	详情参考父项5.1	3	$test512	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="5.1.2 检查审核登陆事件  3 $test512 FAIL";}
			echo "5.1.2	检查审核登陆事件	可选	建议调整	详情参考父项5.1	3	$test512	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
    }
  }
 #审核对象访问
  $config = Get-Content -path config.cfg
 for ($i=0; $i -lt $config.Length; $i++)
 {
    $config_line = $config[$i] -split "="
    if(($config_line[0] -eq "AuditObjectAccess "))
    {
        $config_line[1] = $config_line[1].Trim(' ')
		$test513 = $config_line[1]
        if($config_line[1] -eq "3")
        {
            $projectdata = @{"true"="5.1.3 检查审核对象访问  3 $test513 TRUE";}
			echo "5.1.3	检查审核对象访问	可选	建议调整	详情参考父项5.1	3	$test513	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="5.1.3 检查审核对象访问  3 $test513 FAIL";}
			echo "5.1.3	检查审核对象访问	可选	建议调整	详情参考父项5.1	3	$test513	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
    }
  }

 #审核进程跟踪
  $config = Get-Content -path config.cfg
 for ($i=0; $i -lt $config.Length; $i++)
 {
    $config_line = $config[$i] -split "="
    if(($config_line[0] -eq "AuditProcessTracking "))
    {
        $config_line[1] = $config_line[1].Trim(' ')
		$test514 = $config_line[1]
        if($config_line[1] -eq "3")
        {
            $projectdata = @{"true"="5.1.4 检查审核进程跟踪  3 $test514 TRUE";}
			echo "5.1.4	检查审核进程跟踪	可选	建议调整	详情参考父项5.1	3	$test514	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="5.1.4 检查审核进程跟踪  3 $test514 FAIL";}
			echo "5.1.4	检查审核进程跟踪	可选	建议调整	详情参考父项5.1	3	$test514	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
    }
  }
#审核目录服务访问
$config = Get-Content -path config.cfg
for ($i=0; $i -lt $config.Length; $i++)
 {
    $config_line = $config[$i] -split "="
    if(($config_line[0] -eq "AuditDSAccess "))
    {
        $config_line[1] = $config_line[1].Trim(' ')
		$test515 = $config_line[1]
        if($config_line[1] -eq "3")
        {
            $projectdata = @{"true"="5.1.5 检查审核目录服务访问 3 $test515 TRUE";}
			echo "5.1.5	检查审核目录服务访问	可选	建议调整	详情参考父项5.1	3	$test515	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="5.1.5 检查审核目录服务访问 3 $test515 FAIL";}
			echo "5.1.5	检查审核目录服务访问	可选	建议调整	详情参考父项5.1	3	$test515	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
    }
  }
#审核特权使用
$config = Get-Content -path config.cfg
for ($i=0; $i -lt $config.Length; $i++)
 {
    $config_line = $config[$i] -split "="
    if(($config_line[0] -eq "AuditPrivilegeUse "))
    {
        $config_line[1] = $config_line[1].Trim(' ')
		$test516 = $config_line[1]
        if($config_line[1] -eq "3")
        {
            $projectdata = @{"true"="5.1.6 检查审核特权使用 3 $test516 TRUE";}
			echo "5.1.6	检查审核特权使用	可选	建议调整	详情参考父项5.1	3	$test516	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="5.1.6 检查审核特权使用 3 $test516 FAIL";}
			echo "5.1.6	检查审核特权使用	可选	建议调整	详情参考父项5.1	3	$test516	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
    }
  }
#审核系统事件
$config = Get-Content -path config.cfg
for ($i=0; $i -lt $config.Length; $i++)
 {
    $config_line = $config[$i] -split "="
    if(($config_line[0] -eq "AuditSystemEvents "))
    {
        $config_line[1] = $config_line[1].Trim(' ')
		$test517 = $config_line[1]
        if($config_line[1] -eq "3")
        {
            $projectdata = @{"true"="5.1.7 检查审核系统事件 3 $test517 TRUE";}
			echo "5.1.7	检查审核系统事件	可选	建议调整	详情参考父项5.1	3	$test517	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="5.1.7 检查审核系统事件 3 $test517 FAIL";}
			echo "5.1.7	检查审核系统事件	可选	建议调整	详情参考父项5.1	3	$test517	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
    }
}
#审核帐户登陆事件
$config = Get-Content -path config.cfg
for ($i=0; $i -lt $config.Length; $i++)
 {
    $config_line = $config[$i] -split "="
    if(($config_line[0] -eq "AuditAccountLogon "))
    {
        $config_line[1] = $config_line[1].Trim(' ')
		$test518 = $config_line[1]
		#“2”是windows2016，改为“3”尝试
        if($config_line[1] -eq "3")
        {
            $projectdata = @{"true"="5.1.8 检查审核帐户登陆事件 3 $test518 TRUE";}
			echo "5.1.8	检查审核帐户登陆事件	可选	建议调整	详情参考父项5.1	3	$test518	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="5.1.8 检查审核帐户登陆事件 3 $test518 FAIL";}
			echo "5.1.8	检查审核帐户登陆事件	可选	建议调整	详情参考父项5.1	3	$test518	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
    }
}
#审核帐户管理
$config = Get-Content -path config.cfg
for ($i=0; $i -lt $config.Length; $i++)
 {
    $config_line = $config[$i] -split "="
    if(($config_line[0] -eq "AuditAccountManage "))
    {
        $config_line[1] = $config_line[1].Trim(' ')
		$test519 = $config_line[1]
        if($config_line[1] -eq "3")
        {
            $projectdata = @{"true"="5.1.9 检查审核帐户管理 3  $test519 TRUE";}
			echo "5.1.9	检查审核帐户管理	可选	建议调整	详情参考父项5.1	3	$test519	TRUE		" >> $file_name
			$data['project']+=$projectdata
        }
        else
        {
            $projectdata = @{"fail"="5.1.9 检查审核帐户管理 3 $test519 FAIL";}
			echo "5.1.9	检查审核帐户管理	可选	建议调整	详情参考父项5.1	3	$test519	FAIL		" >> $file_name
			$data['project']+=$projectdata
        }
    }
}
# 关闭常见的危险端口
echo "正在关闭常见的危险端口，请稍候… "
echo. 
echo "正在关闭135,139,445端口…" 
netsh advfirewall firewall add rule name="135_139_445" protocol=TCP dir=in localport=135,139,445 action=block
echo "正在关闭137,138端口…" 
netsh advfirewall firewall add rule name="137_138" protocol=UDP dir=in localport=137,138 action=block
echo "常见的危险端口已经关闭。" 
echo. 



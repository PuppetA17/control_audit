control_audit是一个ddos防护工具
由于防护脚本大同小异,为减少大家工作量,特提供了一个符合基本需求的防护工具提供大家使用
settings.conf配置完毕后添加至crontab即可

目录结构
control_audit
|-- control_audit.sh			#工具启动文件    
|-- settings.conf			#防护配置文件
|-- log					#防护日志审计,工具启动后生成
|____|-- control_disable_audit.log      #封禁日志,封禁后生成
     |-- control_enable_audit.log       #解封日志,解封后生成
     |-- **registry                     #项目日志偏移记录,当需要从头读取文件内容时清空该文件

目前所支持的日志时间格式
1、时间格式为time_iso8601
2、1970-01-01 00:00:00
2、1970/01/01 00:00:00


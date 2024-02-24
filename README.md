# 项目介绍

k8s中集群内部网络访问助手

# 编译

`cargo build --release`

# 平台支持

+ Windows(amd64)
+ Linux(amd64|musl)

# 使用介绍

需要首先用uvcertificate生成认证文件，然后将uvserver放置于集群内部，uvclient放置于客户机上（uvclient需要管理员权限，因为需要创建虚拟网卡tun设备）

正常工作的文件列表如下

uvserver
```
cert.pem
key.pem
server-config.yml
uvserver
```

uvclient
```
cert.pem
client-config.yml
uvclient.exe
wintun.dll
```

uvclient-socks5
```
cert.pem
s5client-config.yml
uvclient-socks5.exe
```

其中uvserver放置于集群内部，uvclient与uvclient-socks5可任选一个

# 声明

使用本软件务必遵守当地使用法律，任何滥用本软件的行为与作者无关

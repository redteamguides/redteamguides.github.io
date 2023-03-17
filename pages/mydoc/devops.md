---
title: DevOps
sidebar: mydoc_sidebar
permalink: devops.html
folder: mydoc
---

# DevOps

Here are a few commands and methods for privilege escalation and lateral movement:


## Misconfigured container

If a container is not properly configured, it may be possible to escalate privileges to root or access sensitive data. To do this, you could try to run a command like 

```
docker exec -it --privileged <container_name> /bin/bash
```

to gain root access.


## SSH key compromise

If an attacker is able to compromise an SSH key, they can use it to gain access to additional systems. To do this, you could try to use a command like 

```
ssh -i <path_to_key> <username>@<ip_address>
```

to log in to another system using the compromised key.



## Password brute-forcing

If a password is weak, it may be possible to guess it using a brute-force attack. Tools like Hydra or Medusa can be used for this purpose.



## Port forwarding

If a system is configured to allow port forwarding, an attacker can use it to access additional systems or services. To do this, you could use a command like 

```
ssh -L <local_port>:<remote_host>:<remote_port> <username>@<ip_address>
```

to forward a local port to a remote system.




## Exploiting Misconfigured Kubernetes RBAC

In Kubernetes, Role-Based Access Control (RBAC) is used to define the level of access each user or service account has to resources. If a cluster's RBAC is not configured properly, attackers could potentially escalate their privileges. One way to exploit misconfigured RBAC is by creating a custom role with elevated permissions and assigning it to a service account. This could be done using the following command:


```
kubectl create clusterrolebinding privileged-role --clusterrole=cluster-admin --serviceaccount=<namespace>:<serviceaccount>
```



## Exploiting Weak Permissions on CI/CD Tools

In a DevOps pipeline, Continuous Integration/Continuous Deployment (CI/CD) tools such as Jenkins or GitLab are often used to automate the build and deployment process. If the permissions on these tools are not properly configured, attackers could potentially exploit them to escalate their privileges. For example, an attacker could modify the Jenkinsfile to add a shell command that would run with elevated privileges:


```
stage('Build') {
  steps {
    sh 'sudo <command>'
  }
}
```



## Exploiting Weak AWS IAM Permissions

In an AWS environment, Identity and Access Management (IAM) is used to control access to resources. If the IAM permissions are not properly configured, attackers could potentially escalate their privileges. One way to exploit weak IAM permissions is by creating a new IAM user or role with elevated permissions and then assuming that role using the AWS CLI. This could be done using the following command:

```
aws sts assume-role --role-arn <role-arn> --role-session-name <session-name>
```




## Container Breakouts

Attackers can exploit vulnerabilities in containers to escape from the container and execute code on the host machine with elevated privileges. Some examples of container breakout techniques include the use of kernel exploits, mounting of the host file system, or exploiting misconfigurations in the container runtime.




## Misconfigured Access Control

Inadequate access controls can allow attackers to escalate privileges by exploiting permissions that are not properly configured. This can include using a service account with too many privileges, or exploiting misconfigured RBAC rules.


## Code Injection

Attackers can inject malicious code into the pipeline or an application in order to escalate privileges. For example, an attacker can inject code into a script that is executed by an application, allowing them to execute arbitrary commands on the target system.

```
# Example 1: Using SUDO to escalate privileges

sudo /bin/bash

# Example 2: Exploiting a misconfigured SUID binary

chmod u+s /usr/bin/newuid
/usr/bin/newuid

# Example 3: Using a kernel exploit to escalate privileges

./exploit
```




{% include links.html %}

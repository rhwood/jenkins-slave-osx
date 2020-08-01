⚠️ __I no longer use Jenkins, so am not maintaining this project.__ Please open an issue if you are interested in maintaining this project.

# Jenkins Slave for OS X

Scripts to create and run a [Jenkins](http://jenkins-ci.org) slave via [Java Web Start](https://wiki.jenkins-ci.org/display/JENKINS/Distributed+builds#Distributedbuilds-LaunchslaveagentviaJavaWebStart) (JNLP) on OS X as a Launch Daemon.



## Quick Start
`bash <( curl -L https://raw.github.com/rhwood/jenkins-slave-osx/master/install.sh )`



## Features
OS X slaves created with this script:
* Start on system boot
* Run as an independent user
* Use an independent Java Truststore for self-signed certificates (so your Jenkins master can use a self-signed certificate, and you do not have to instruct the slave to trust all certificates regardless of source)
* Use an independent OS X Keychain for secrets



## Install
`bash <( curl -L https://raw.github.com/rhwood/jenkins-slave-osx/master/install.sh ) [options]`

The install script has the following options:
* `--java-args="ARGS"` to specify any optional java arguments. *Optional;* the installer does not test these arguments.
* `--master=URL` to specify the Jenkins Master on the command line. *Optional;* the installer prompts for this if not specified on the command line.
* `--node=NAME` to specify the Slave's node name. *Optional;* this defaults to the OS X hostname and is verified by the installer.
* `--user=NAME` to specify the Jenkins user who authenticates the slave. *Optional;* this defaults to your username on the OS X slave and is verified by the installer.



## Update
Simply rerun the installer. It will reinstall the scripts, but use existing configuration settings.



## Configuration
The file ``Library/Preferences/org.jenkins-ci.slave.jnlp.conf`` in ``/var/lib/jenkins`` (assuming an installation in the default location) can be used to configure this service with these options:
* `JAVA_ARGS` specifies any optional java arguments to be passed to the slave. This may be left blank.
* `JENKINS_SLAVE` specifies the node name for the slave. This is required.
* `JENKINS_MASTER` specifies the URL for the Jenkins master. This is required.
* `JENKINS_USER` specifies the Jenkins user used to bind the master to the slave. This is required.
* `HTTP_PORT` specifies the nonstandard port used to communicate with the Jenkins master. This may be left blank for port 80 (http) or 443 (https).
These settings are initially set by the installation script, and only need to be changed if that script is invalidated. The slave must be restarted for changes to take effect.

## Adding Developer Certificates
Building application targets for iOS requires that your iPhone Developer certificates be available to the Jenkins slave.

1. Export the Certificate and Key from Keychain for your developer profiles.
2. `sudo cp /path/to/exported-keys-and-certificates /var/lib/jenkins`
3. For each certificate and key:
   `sudo -i -u jenkins /var/lib/jenkins/security.sh add-apple-certificate --certificate=/var/lib/jenkins/name-of-exported-cert`
4. Delete the exported certificate file if is not password protected.

## Adding Server Certificates
If you decide to secure the Jenkins master, or need to add additional certificates for the slave to trust the Jenkins master, you only need (assuming your service account is "jenkins", and your CA is StartSSL.com) from a command line:

1. `sudo launchctl unload /Library/LaunchDaemons/org.jenkins-ci.slave.jnlp.plist`
2. `sudo -i -u jenkins`
3. `curl -O http://www.startssl.com/certs/ca.crt`
4. `./security.sh add-java-certificate --authority --alias=root-ca --certificate=./ca.crt`
5. `curl -O http://www.startssl.com/certs/sub.class1.server.ca.crt`
6. `./security.sh add-java-certificate --alias=ca-server --certificate=./sub.class1.server.ca.crt`
7. `rm ./*ca.crt`
8. `exit`
9. `sudo launchctl load /Library/LaunchDaemons/org.jenkins-ci.slave.jnlp.plist`

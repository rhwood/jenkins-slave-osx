# jenkins-slave-osx

Scripts to create and run a [Jenkins](http://jenkins-ci.org) JNLP slave on OS X as a Launch Daemon.

## Features
OS X slaves created with this script:
* Start on system boot
* Runs as an independent user
* Use a Java Truststore for self-signed certificates (so your Jenkins master can use a self-signed certificate, and you do not have to instruct the slave to trust all certificates regardless of source)
* Use the OS X Keychain for secrets

## Install
`bash <( curl -L https://raw.github.com/rhwood/jenkins-slave-osx/master/install.sh )`

The install script can take the following arguments:
* `--certificate=/path/to/cert.cer` to install either a self-signed certificate for the Jenkins master, or the root certificate of the CA that signed the Jenkins master certificate
* `--master=URL` to specify the Jenkins Master on the command line

## Update
Simply rerun the installer. It will recognize an existing configuration and simply update if needed.

## Configuration
The following file in ``/var/lib/jenkins`` (assuming you installed this service in the default location) can be used to configure this service:
``Library/Preferences/org.jenkins-ci.slave.jnlp.conf``

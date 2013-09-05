#!/bin/bash
#
# Install the Jenkins JNLP slave LaunchDaemon on OS X
#
# See https://github.com/rhwood/jenkins-slave-osx for usage

set -u

SERVICE_USER=${SERVICE_USER:-"jenkins"}
SERVICE_HOME=${SERVICE_HOME:-"/var/lib/${SERVICE_USER}"}
SERVICE_CONF=${SERVICE_HOME}/Library/Preferences/org.jenkins-ci.slave.jnlp.conf
MASTER_NAME=""					# set default to jenkins later
MASTER_USER=""					# set default to `whoami` later
MASTER=""
MASTER_HTTP_PORT=""
SLAVE_NODE=""
SLAVE_TOKEN=""
OSX_KEYCHAIN="login.keychain"
OSX_KEYCHAIN_PASS=""
JAVA_ARGS=${JAVA_ARGS:-""}
INSTALL_TMP=`mktemp -d -q -t org.jenkins-ci.slave.jnlp`
DOWNLOADS_PATH=https://raw.github.com/rhwood/jenkins-slave-osx/master

function create_user() {
	# see if user exists
	if dscl /Local/Default list /Users | grep -q ${SERVICE_USER} ; then
		echo "Using pre-existing service account ${SERVICE_USER}"
		SERVICE_HOME=`dscl /Local/Default read /Users/${SERVICE_USER} NFSHomeDirectory | awk '{print $2}'`
		return 0
	fi
	echo "Creating service account ${SERVICE_USER}..."
	# create jenkins group
	NEXT_GID=$((`dscl /Local/Default list /Groups gid | awk '{ print $2 }' | sort -n | grep -v ^[5-9] | tail -n1` + 1))
	sudo dscl /Local/Default create /Groups/${SERVICE_USER}
	sudo dscl /Local/Default create /Groups/${SERVICE_USER} PrimaryGroupID $NEXT_GID
	sudo dscl /Local/Default create /Groups/${SERVICE_USER} Password \*
	sudo dscl /Local/Default create /Groups/${SERVICE_USER} RealName 'Jenkins Node Service'
	# create jenkins user
	NEXT_UID=$((`dscl /Local/Default list /Users uid | awk '{ print $2 }' | sort -n | grep -v ^[5-9] | tail -n1` + 1))
	sudo dscl /Local/Default create /Users/${SERVICE_USER}
	sudo dscl /Local/Default create /Users/${SERVICE_USER} UniqueID $NEXT_UID
	sudo dscl /Local/Default create /Users/${SERVICE_USER} PrimaryGroupID $NEXT_GID
	sudo dscl /Local/Default create /Users/${SERVICE_USER} UserShell /bin/bash
	sudo dscl /Local/Default create /Users/${SERVICE_USER} NFSHomeDirectory ${SERVICE_HOME}
	sudo dscl /Local/Default create /Users/${SERVICE_USER} Password \*
	sudo dscl /Local/Default create /Users/${SERVICE_USER} RealName 'Jenkins Node Service'
	sudo dseditgroup -o edit -a ${SERVICE_USER} -t user ${SERVICE_USER}
}

function install_files() {
	# create the jenkins home dir
	if [ ! -d ${SERVICE_HOME} ] ; then
		sudo mkdir ${SERVICE_HOME}
	fi
	# download the LaunchDaemon
	sudo curl --silent --url ${DOWNLOADS_PATH}/org.jenkins-ci.slave.jnlp.plist -o ${SERVICE_HOME}/org.jenkins-ci.slave.jnlp.plist
	sudo sed -i '' "s#\${JENKINS_HOME}#${SERVICE_HOME}#g" ${SERVICE_HOME}/org.jenkins-ci.slave.jnlp.plist
	sudo sed -i '' "s#\${JENKINS_USER}#${SERVICE_USER}#g" ${SERVICE_HOME}/org.jenkins-ci.slave.jnlp.plist
	sudo rm -f /Library/LaunchDaemons/org.jenkins-ci.slave.jnlp.plist
	sudo install -o root -g wheel -m 644 ${SERVICE_HOME}/org.jenkins-ci.slave.jnlp.plist /Library/LaunchDaemons/org.jenkins-ci.slave.jnlp.plist
	# download the jenkins JNLP slave script
	sudo curl --silent --url ${DOWNLOADS_PATH}/slave.jnlp.sh -o ${SERVICE_HOME}/slave.jnlp.sh
	sudo chmod 755 ${SERVICE_HOME}/slave.jnlp.sh
	# download the jenkins JNLP security helper script
	sudo curl --silent --url ${DOWNLOADS_PATH}/security.sh -o ${SERVICE_HOME}/security.sh
	sudo chmod 755 ${SERVICE_HOME}/security.sh
	# jenkins should own jenkin's home directory and all its contents
	sudo chown -R ${SERVICE_USER}:${SERVICE_USER} ${SERVICE_HOME}
	# create a logging space
	if [ ! -d /var/log/${SERVICE_USER} ] ; then
		sudo mkdir /var/log/${SERVICE_USER}
		sudo chown ${SERVICE_USER}:wheel /var/log/${SERVICE_USER}
	fi
}

function process_args {
	if [ -f ${SERVICE_CONF} ]; then
		sudo chmod 666 ${SERVICE_CONF}
		source ${SERVICE_CONF}
		sudo chmod 400 ${SERVICE_CONF}
		SLAVE_NODE=${SLAVE_NODE:-$JENKINS_SLAVE}
		MASTER=${MASTER:-$JENKINS_MASTER}
		MASTER_HTTP_PORT=${HTTP_PORT}
		MASTER_USER=${MASTER_USER:-$JENKINS_USER}
	fi
	if [ -f ${SERVICE_HOME}/Library/.keychain_pass ]; then
		sudo chmod 666 ${SERVICE_HOME}/Library/.keychain_pass
		source ${SERVICE_HOME}/Library/.keychain_pass
		sudo chmod 400 ${SERVICE_HOME}/Library/.keychain_pass
	fi
	while [ $# -gt 0 ]; do
		case $1 in
			--node=*) SLAVE_NODE=${1#*=} ;;
			--user=*) MASTER_USER=${1#*=} ;;
			--master=*) MASTER=${1#*=} ;;
			--java-args=*) JAVA_ARGS=${1#*=} ;;
		esac
		shift
	done
}

function configure_daemon {
	if [ -z $MASTER ]; then
		MASTER=${MASTER:-"http://jenkins"}
		echo
		read -p "URL for Jenkins master [$MASTER]: " RESPONSE
		MASTER=${RESPONSE:-$MASTER}
	fi
	while ! curl -k --location --url ${MASTER}/jnlpJars/slave.jar --silent --fail --output ${INSTALL_TMP}/slave.jar ; do
		echo "Unable to connect to Jenkins at ${MASTER}"
		read -p "URL for Jenkins master: " MASTER
	done
	MASTER_NAME=`echo $MASTER | cut -d':' -f2 | cut -d'.' -f1 | cut -d'/' -f3`
	PROTOCOL=`echo $MASTER | cut -d':' -f1`
	MASTER_HTTP_PORT=`echo $MASTER | cut -d':' -f3`
	if 	[ "$PROTOCOL" == "$MASTER" ] ; then
		PROTOCOL="http"
		MASTER_HTTP_PORT=`echo $MASTER | cut -d':' -f2`
		[ -z $MASTER_HTTP_PORT ] || MASTER="${PROTOCOL}://`echo $MASTER | cut -d':' -f2`"
	else
		[ -z $MASTER_HTTP_PORT ] || MASTER="${PROTOCOL}:`echo $MASTER | cut -d':' -f2`"
	fi
	[ ! -z $MASTER_HTTP_PORT ] && MASTER_HTTP_PORT=":${MASTER_HTTP_PORT}"
	if [ -z $SLAVE_NODE ]; then
		SLAVE_NODE=${SLAVE_NODE:-`hostname -s | tr '[:upper:]' '[:lower:]'`}
		echo
		read -p "Name of this slave on ${MASTER_NAME} [$SLAVE_NODE]: " RESPONSE
		SLAVE_NODE=${RESPONSE:-$SLAVE_NODE}
	fi
	if [ -z $MASTER_USER ]; then
		[ "${SERVICE_USER}" != "jenkins" ] && MASTER_USER=${SERVICE_USER} || MASTER_USER=`whoami`
		echo
		read -p "Account that ${SLAVE_NODE} connects to ${MASTER_NAME} as [${MASTER_USER}]: " RESPONSE
		MASTER_USER=${RESPONSE:-$MASTER_USER}
	fi
	echo
	echo "${MASTER_USER}'s API token is required to authenticate a JNLP slave."
	echo "The API token is listed at ${MASTER}${MASTER_HTTP_PORT}/user/${MASTER_USER}/configure"
	read -p "API token for ${MASTER_USER}: " SLAVE_TOKEN
	while ! curl -k --url ${MASTER}${MASTER_HTTP_PORT}/user/${MASTER_USER} --user ${MASTER_USER}:${SLAVE_TOKEN} --silent --head --fail --output /dev/null ; do
		echo "Unable to authenticate ${MASTER_USER} with this token"
		read -p "API token for ${MASTER_USER}: " SLAVE_TOKEN
	done
	OSX_KEYCHAIN_PASS=${OSX_KEYCHAIN_PASS:-`env LC_CTYPE=C tr -dc "a-zA-Z0-9-_" < /dev/urandom | head -c 20`}
	create_keychain
	sudo -i -u ${SERVICE_USER} ${SERVICE_HOME}/security.sh set-password --password=${SLAVE_TOKEN} --account=${MASTER_USER} --service=${SLAVE_NODE}
	KEYSTORE_PASS=`sudo -i -u ${SERVICE_USER} ${SERVICE_HOME}/security.sh get-password --account=${SERVICE_USER} --service=java_truststore`
	KEYSTORE_PASS=${KEYSTORE_PASS:-`env LC_CTYPE=C tr -dc "a-zA-Z0-9-_" < /dev/urandom | head -c 20`}
	sudo -i -u ${SERVICE_USER} ${SERVICE_HOME}/security.sh set-password --password=${KEYSTORE_PASS} --account=${SERVICE_USER} --service=java_truststore
	if [ "$PROTOCOL" == "https" ]; then
		echo "
If the certificate for ${MASTER_NAME} is not trusted by Java, you will need 
to install public certificates required for Java to trust ${MASTER_NAME}.
NOTE: The installer is not capable of testing that Java trusts ${MASTER_NAME}.

If ${MASTER_NAME} has a self-signed certifate, the public certificate
must be imported. If the certificate for ${MASTER_NAME} is signed by
a certificate authority, you may need to import both the root and server CA
certificates.

To install certificates, you will need to:
1) copy or download the certificates into ${SERVICE_HOME}
2) use the following command:
sudo -i -u ${SERVICE_USER} ${SERVICE_HOME}/security.sh add-java-certificate \
--alias=AN_ALIAS --certificate=/path/to/certificate
If the certificate is a Root CA cert, add the --ca-cert flag to the above
command.
"
	fi
	create_ssh_keys
	configure_github
	echo
	echo "
If you need to do additional tasks to setup ${SERVICE_USER}, you can
sudo -i -u ${SERVICE_USER}
in Terminal to open a shell running as ${SERVICE_USER}
"
}

function create_ssh_keys {
	if [ ! -f ${SERVICE_HOME}/.ssh/id_rsa ]; then
		echo "
Do you wish to create SSH keys for this ${SERVICE_USER}? These keys will be
suitable for GitHub, amoung other services. Keys generated at this point will
not be protected by a password.
"
		read -p "Create SSH keys? (yes/no) [yes]" CONFIRM
		CONFIRM=${CONFIRM:-yes}
		if [[ "${CONFIRM}" =~ ^[Yy] ]] ; then
			sudo -i -u ${SERVICE_USER} ssh-keygen -t rsa -N \'\' -f ${SERVICE_HOME}/.ssh/id_rsa -C "${SERVICE_USER}@${SLAVE_NODE}"
		fi
		echo "
You will need to connect to each SSH host as ${SERVICE_USER} to add the host
to the known_hosts file to allow the service to use SSH. This can be done
using the following command:
sudo -i -u ${SERVICE_USER} ssh account@service

To get ${SERVICE_USER}'s public key to add to a service to allow SSH:
sudo -i -u ${SERVICE_USER} cat ${SERVICE_HOME}/.ssh/id_rsa.pub
"
	fi
}

function configure_github {
	read -p "Will this slave need to connect to GitHub? (yes/no) [no]" CONFIRM
	CONFIRM=${CONFIRM:-no}
	if [[ "${CONFIRM}" =~ ^[Yy] ]] ; then
		echo "Attempting to SSH to GitHub... You may be prompted to trust github.com."
		sudo -i -u ${SERVICE_USER} ssh -T git@github.com
		RESULT=$?
		if [ $RESULT -eq 255 ] ; then
			echo "
You need to add the ssh keys to the GitHub account that Jenkins uses

Copy the following key to https://github.com/settings/ssh after you have
logged into GitHub as the user that Jenkins connects to GitHub as
"
			sudo -i -u ${SERVICE_USER} cat ${SERVICE_HOME}/.ssh/id_rsa.pub
		fi
	fi
}

function configure_adc {
	read -p "Will this slave need Apple Developer Certificates? (yes/no) [yes]" CONFIRM
	CONFIRM=${CONFIRM:-yes}
	if [[ "${CONFIRM}" =~ ^[Yy] ]] ; then
		echo "Importing WWDR intermediate certificate..."
		sudo -i -u ${SERVICE_USER} curl  --silent --remote-name --url https://developer.apple.com/certificationauthority/AppleWWDRCA.cer
		sudo -i -u ${SERVICE_USER} ${SERVICE_HOME}/security.sh add-apple-certificate --certificate=${SERVICE_HOME}/AppleWWDRCA.cer
		sudo -i rm ${SERVICE_HOME}/AppleWWDRCA.cer
		echo "
You will need to import your own developer certificates following these steps:
1) Export the Certificate and Key from Keychain for your developer profiles.
2) sudo cp /path/to/exported-keys-and-certificates ${SERVICE_HOME}
3) For each certificate and key (this is a single multiline command):
   sudo -i -u ${SERVICE_USER} ${SERVICE_HOME}/security.sh \
   add-apple-certificate --certificate=${SERVICE_HOME}/name-of-exported-cert
"
	fi
}

function create_keychain {
	local KEYCHAINS=${SERVICE_HOME}/Library/Keychains
	if [ ! -d ${KEYCHAINS} ]; then
		sudo mkdir -p ${KEYCHAINS}
		sudo chown -R ${SERVICE_USER}:${SERVICE_USER} ${KEYCHAINS}
	fi
	if [ ! -f ${KEYCHAINS}/${OSX_KEYCHAIN} ]; then
		sudo -i -u ${SERVICE_USER} security create-keychain -p ${OSX_KEYCHAIN_PASS} ${OSX_KEYCHAIN}
		if [ -f ${KEYCHAINS}/.keychain_pass ]; then
			sudo chmod 666 ${KEYCHAINS}/.keychain_pass
		fi
		sudo chmod 777 ${KEYCHAINS}
		sudo echo "OSX_KEYCHAIN_PASS=${OSX_KEYCHAIN_PASS}" > ${KEYCHAINS}/.keychain_pass
		sudo chown -R ${SERVICE_USER}:${SERVICE_USER} ${KEYCHAINS} 
		sudo chmod 400 ${KEYCHAINS}/.keychain_pass
		sudo chmod 755 ${KEYCHAINS}
	fi
	echo "
The OS X Keychain password for ${SERVICE_USER} is ${OSX_KEYCHAIN_PASS}
You will need to copy this into the Jenkins configuration on ${MASTER_NAME}
for every project that will be compiled on this slave, or copy a special
per-project Keychain to ${SERVICE_HOME}/Library/Keychains.

Note that the login Keychain for ${SERVICE_USER} contains secrets needed for
${SLAVE_NODE} to connect to ${MASTER_NAME}.
"
}

function write_config {
	sudo mkdir -p `dirname ${SERVICE_CONF}`
	sudo chmod 777 `dirname ${SERVICE_CONF}`
	if [ -f ${SERVICE_CONF} ]; then
		sudo chmod 666 ${SERVICE_CONF}
	fi
	[[ "$MASTER_HTTP_PORT" =~ ^: ]] && MASTER_HTTP_PORT=${MASTER_HTTP_PORT#":"}
	:> ${SERVICE_CONF}
	echo "JENKINS_SLAVE=${SLAVE_NODE}" >> ${SERVICE_CONF}
	echo "JENKINS_MASTER=${MASTER}" >> ${SERVICE_CONF}
	echo "HTTP_PORT=${MASTER_HTTP_PORT}" >> ${SERVICE_CONF}
	echo "JENKINS_USER=${MASTER_USER}" >> ${SERVICE_CONF}
	echo "JAVA_ARGS=${JAVA_ARGS}" >> ${SERVICE_CONF}
	sudo chmod 755 `dirname ${SERVICE_CONF}`
	sudo chmod 644 ${SERVICE_CONF}
	sudo chown -R ${SERVICE_USER}:${SERVICE_USER} ${SERVICE_HOME}
}

function start_daemon {
	echo "
The Jenkins JNLP Slave service is installed

This service can be started using the command
    sudo launchctl load /Library/LaunchDaemons/org.jenkins-ci.slave.jnlp.plist
and stopped using the command
    sudo launchctl unload /Library/LaunchDaemons/org.jenkins-ci.slave.jnlp.plist

This service logs to /var/log/${SERVICE_USER}/org.jenkins-ci.slave.jnlp.log
"
	read -p "Start the slave service now (yes/no) [yes]? " CONFIRM
	CONFIRM=${CONFIRM:-"yes"}
	if [[ "${CONFIRM}" =~ ^[Yy] ]] ; then
		sudo launchctl load -F /Library/LaunchDaemons/org.jenkins-ci.slave.jnlp.plist
		echo
		read -p "Open Console.app to view logs now (yes/no) [yes]? " CONFIRM
		CONFIRM=${CONFIRM:-"yes"}
		if [[ "${CONFIRM}" =~ ^[Yy] ]] ; then
			open /var/log/${SERVICE_USER}/org.jenkins-ci.slave.jnlp.log
		fi
	fi
}

function cleanup {
	rm -rf ${INSTALL_TMP}
	exit $1
}

echo "
        _          _   _              _ _  _ _    ___   ___ _              
     _ | |___ _ _ | |_(_)_ _  ___  _ | | \| | |  | _ \ / __| |__ ___ _____ 
    | || / -_) ' \| / / | ' \(_-< | || | .\` | |__|  _/ \__ \ / _\` \ V / -_)
     \__/\___|_||_|_\_\_|_||_/__/  \__/|_|\_|____|_|   |___/_\__,_|\_/\___|

This script will download, install, and configure a Jenkins JNLP Slave on OS X.

You must be an administrator on the system you are installing the Slave on,
since this installer will add a user to the system and then configure the slave
as that user.

A Java Development Kit (JDK) must be installed prior to installing the Jenkins
JNLP Slave.

During the configuration, you will be prompted for necessary information. The
suggested or default response will be in brackets [].
"
read -p "Continue (yes/no) [yes]? " CONFIRM
CONFIRM=${CONFIRM:-"yes"}
if [[ "${CONFIRM}" =~ ^[Yy] ]] ; then
	echo
	echo "Verifying that you may use sudo. You may be prompted for your password"
	if ! sudo -v ; then
		echo "Unable to use sudo. Aborting installation"
		cleanup 1
	fi
	create_user
	process_args $@
	echo "Installing files..."
	install_files
	echo "Configuring daemon..."
	configure_daemon
	configure_adc
	write_config
	start_daemon
else
	echo "Aborting installation"
	cleanup 1
fi

cleanup 0

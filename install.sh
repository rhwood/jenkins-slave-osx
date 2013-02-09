#!/bin/bash
#
# Install the Jenkins JNLP slave LaunchDaemon on OS X

set -u

SERVICE_USER=${SERVICE_USER:-"jenkins"}
SERVICE_HOME=${SERVICE_HOME:-"/var/lib/${SERVICE_USER}"}
SERVICE_CONF=${SERVICE_HOME}/Library/Preferences/org.jenkins-ci.slave.jnlp.conf
MASTER_NAME=""							# set default to jenkins later
MASTER_USER=""							# set default to `whoami` later
MASTER=""
MASTER_PORT=""
MASTER_CERT=""
MASTER_CA=""
SLAVE_NODE=""
SLAVE_TOKEN=""
DEV_PROFILE=""
OSX_KEYCHAIN="org.jenkins-ci.slave.jnlp.keychain"
OSX_KEYCHAIN_PASS=""
JAVA_ARGS=${JAVA_ARGS:-""}
INSTALL_TMP=`mktemp -d -q -t org.jenkins-ci.slave.jnlp`

function create_user() {
	# see if user exists
	if dscl /Local/Default list /Users | grep -q ${SERVICE_USER} ; then
		echo "Using pre-existing service account ${SERVICE_USER}"
		SERVICE_HOME=`dscl /Local/Default read /Users/Jenkins NFSHomeDirectory | awk '{print $2}'`
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
	sudo curl --silent --url https://raw.github.com/rhwood/jenkins-slave-osx/master/org.jenkins-ci.slave.jnlp.plist -o ${SERVICE_HOME}/org.jenkins-ci.slave.jnlp.plist
	sudo sed -i '' "s#\${JENKINS_HOME}#${SERVICE_HOME}#g" ${SERVICE_HOME}/org.jenkins-ci.slave.jnlp.plist
	sudo sed -i '' "s#\${JENKINS_USER}#${SERVICE_USER}#g" ${SERVICE_HOME}/org.jenkins-ci.slave.jnlp.plist
	sudo rm -f /Library/LaunchDaemons/org.jenkins-ci.slave.jnlp.plist
	sudo ln -s ${SERVICE_HOME}/org.jenkins-ci.slave.jnlp.plist /Library/LaunchDaemons/org.jenkins-ci.slave.jnlp.plist
	# download the jenkins JNLP slave script
	sudo curl --silent --url https://raw.github.com/rhwood/jenkins-slave-osx/master/slave.jnlp.sh -o ${SERVICE_HOME}/slave.jnlp.sh
	sudo chmod 755 ${SERVICE_HOME}/slave.jnlp.sh
	# download the jenkins JNLP security helper script
	sudo curl --silent --url https://raw.github.com/rhwood/jenkins-slave-osx/master/security.sh -o ${SERVICE_HOME}/security.sh
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
			--jnlp-port=*) MASTER_PORT=${1#*=} ;;
			--master-cert=*) MASTER_CERT=${1#*=} ;;
			--master-ca=*) MASTER_CA=${1#*=} ;;
			--profile=*) DEV_PROFILE=${1#*=} ;;
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
	while ! curl --location --url ${MASTER}/jnlpJars/slave.jar --silent --fail --output ${INSTALL_TMP}/slave.jar ; do
		echo "Unable to connect to Jenkins at ${MASTER}"
		read -p "URL for Jenkins master: " MASTER
	done
	MASTER_NAME=`echo $MASTER | cut -d':' -f2 | cut -d'.' -f1 | cut -d'/' -f3`
	PROTOCOL=`echo $MASTER | cut -d':' -f1`
	[ "$PROTOCOL" != "$MASTER" ] || PROTOCOL="http"
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
	echo "The API token is listed at ${MASTER}/user/${MASTER_USER}/configure"
	read -p "API token for ${MASTER_USER}: " SLAVE_TOKEN
	while ! curl --url ${MASTER}/user/${MASTER_USER} --user ${MASTER_USER}:${SLAVE_TOKEN} --silent --head --fail --output /dev/null ; do
		echo "Unable to authenticate ${MASTER_USER} with this token"
		read -p "API token for ${MASTER_USER}: " SLAVE_TOKEN
	done
	OSX_KEYCHAIN_PASS=${OSX_KEYCHAIN_PASS:-`env LC_CTYPE=C tr -dc "a-zA-Z0-9-_\$\?" < /dev/urandom | head -c 20`}
	KEYSTORE_PASS=`env LC_CTYPE=C tr -dc "a-zA-Z0-9-_\$\?" < /dev/urandom | head -c 20`
	if [ "$PROTOCOL" == "https" ]; then
		sudo -i -u ${SERVICE_USER} curl --location --url ${MASTER}/jnlpJars/slave.jar --silent --output ${SERVICE_HOME}/slave.jar
		if sudo -i -u ${SERVICE_USER} java -jar ${SERVICE_HOME}/slave.jar -jnlpUrl ${MASTER}/computer/${SLAVE_NODE}/slave-agent.jnlp -jnlpCredentials ${MASTER_USER}:${SLAVE_TOKEN} 2>&1 | grep -q '\-noCertificateCheck' ; then
			echo "need certs"
			if [[ -z $MASTER_CERT && -z $MASTER_CA ]]; then
				echo
				echo "The certificate for ${MASTER_NAME} is not trusted by java"
				read -p "Does ${MASTER_NAME} have a self-signed certificate? (yes/no) [yes]? " CONFIRM
				CONFIRM=${CONFIRM:-"yes"}
				if [[ "${CONFIRM}" =~ ^[Yy] ]]; then
					echo "${MASTER_NAME}'s public certificate needs to be imported"
					read -p "Path to certificate: " MASTER_CERT
				else
					echo "The root CA that signed ${MASTER_NAME}'s public certificate needs to be imported"
					read -p "Path to certificate: " MASTER_CA
				fi
			fi
			if [ ! -z $MASTER_CERT ]; then
				while [ ! -f $MASTER_CERT ]; do
					echo "Unable to read ${MASTER_CERT}"
					read -p "Path to certificate: " MASTER_CERT
				done
				sudo -i -u ${SERVICE_USER} keytool -import -alias jenkins-cert -file ${MASTER_CERT} -keystore ${SERVICE_HOME}/.keystore -storepass ${KEYSTORE_PASS}
			fi
			if [ ! -z $MASTER_CA ]; then
				while [ ! -f $MASTER_CA ]; do
					echo "Unable to read ${MASTER_CA}"
					read -p "Path to certificate: " MASTER_CA
				done
				sudo -i -u ${SERVICE_USER} keytool -import -alias jenkins-ca -file ${MASTER_CA} -keystore ${SERVICE_HOME}/.keystore -storepass ${KEYSTORE_PASS}
			fi
			sudo -i -u ${SERVICE_USER} ${SERVICE_HOME}/security.sh --keychain-pass=${OSX_KEYCHAIN_PASS} --keychain=${OSX_KEYCHAIN} --password=${KEYSTORE_PASS} --account=jenkins --service=java_truststore
		fi
	fi
	
}

function write_config {
	sudo mkdir -p `dirname ${SERVICE_CONF}`
	sudo chmod 777 `dirname ${SERVICE_CONF}`
	if [ -f ${SERVICE_CONF} ]; then
		sudo chmod 666 ${SERVICE_CONF}
	fi
	:> ${SERVICE_CONF}
	echo "JENKINS_SLAVE=${SLAVE_NODE}" >> ${SERVICE_CONF}
	echo "JENKINS_MASTER=${MASTER}" >> ${SERVICE_CONF}
	echo "JENKINS_PORT=${MASTER_PORT}" >> ${SERVICE_CONF}
	echo "JENKINS_USER=${MASTER_USER}" >> ${SERVICE_CONF}
	echo "JAVA_ARGS=${JAVA_ARGS}" >> ${SERVICE_CONF}
	sudo chmod 755 `dirname ${SERVICE_CONF}`
	sudo chmod 644 ${SERVICE_CONF}
	sudo chown -R ${SERVICE_USER}:${SERVICE_USER} ${SERVICE_HOME}
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

During the configuration, you will be prompted for nessessary information. The
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
	write_config
else
	echo "Aborting installation"
	cleanup 1
fi

cleanup 0
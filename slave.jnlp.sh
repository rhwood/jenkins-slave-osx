#!/bin/bash

JENKINS_HOME=`dirname $0`
JENKINS_CONF=${JENKINS_HOME}/Library/Preferences/org.jenkins-ci.slave.jnlp.conf
JENKINS_SLAVE=`hostname -s | tr '[:upper:]' '[:lower:]'`
JENKINS_MASTER=http://jenkins
HTTP_PORT=''
JENKINS_USER=''
JENKINS_TOKEN=''
JAVA_ARGS='-Djava.awt.headless=true'
JAVA_ARGS_LOG=''
JAVA_TRUSTSTORE=${JENKINS_HOME}/.keystore
JAVA_TRUSTSTORE_PASS=''

# called when unloaded by launchctl
function unload() {
	PID=`cat ${JENKINS_HOME}/.slave.pid`
	if [ "$PID" != "" ]; then
		kill $PID
		wait $PID
	fi
	echo
	echo "Stopping at `date`"
	echo
	exit 0
}

# launchctl sends SIGTERM to unload a daemon
# trap SIGTERM to be able to gracefully cleanup
trap "unload" HUP INT TERM

if [ -f ${JENKINS_CONF} ]; then
	chmod 400 ${JENKINS_CONF}
	source ${JENKINS_CONF}
fi

[ ! -z $HTTP_PORT ] && HTTP_PORT=":${HTTP_PORT}"
JENKINS_JNLP_URL=${JENKINS_MASTER}${HTTP_PORT}/computer/${JENKINS_SLAVE}/slave-agent.jnlp

echo
echo "Starting at `date`"
echo

# Download slave.jar. This ensures that everytime this daemon is loaded, we get the correct slave.jar
# from the Master. We loop endlessly to get the jar, so that if we start before networking, we ensure
# the jar gets loaded anyway.
echo "Getting slave.jar from ${JENKINS_MASTER}"
RESULT=-1
while [ true ]; do
	curl --url ${JENKINS_MASTER}${HTTP_PORT}/jnlpJars/slave.jar -o ${JENKINS_HOME}/slave.jar
	RESULT=$?
	if [ $RESULT -eq 0 ]; then
		break
	else
		sleep 60
	fi
done

echo "Launching slave process at ${JENKINS_JNLP_URL}"
RESULT=-1
# If we use a trustStore for the Jenkins Master certificates, we need to pass it
# and its password to the java process that runs the slave. The password is stored
# in the OS X Keychain that we use for other purposes.
if [[ -f $JAVA_TRUSTSTORE ]]; then
	JAVA_TRUSTSTORE_PASS=$( ${JENKINS_HOME}/security.sh get-password --account=`whoami` --service=java_truststore )
	JAVA_ARGS_LOG="${JAVA_ARGS} -Djavax.net.ssl.trustStore=${JAVA_TRUSTSTORE} -Djavax.net.ssl.trustStorePassword=********"
	JAVA_ARGS="${JAVA_ARGS} -Djavax.net.ssl.trustStore=${JAVA_TRUSTSTORE} -Djavax.net.ssl.trustStorePassword=${JAVA_TRUSTSTORE_PASS}" 
fi
# The user and API token are required for Jenkins >= 1.498
if [ ! -z ${JENKINS_USER} ]; then
	JENKINS_TOKEN=$( ${JENKINS_HOME}/security.sh get-password --account=${JENKINS_USER} --service=${JENKINS_SLAVE} )
	JENKINS_USER="-jnlpCredentials ${JENKINS_USER}:"
fi
echo "Calling java ${JAVA_ARGS_LOG} -jar ${JENKINS_HOME}/slave.jar -jnlpUrl ${JENKINS_JNLP_URL} ${JENKINS_USER}********"
java ${JAVA_ARGS} -jar ${JENKINS_HOME}/slave.jar -jnlpUrl ${JENKINS_JNLP_URL} ${JENKINS_USER}${JENKINS_TOKEN} &
echo $! > ${JENKINS_HOME}/.slave.pid
wait `cat ${JENKINS_HOME}/.slave.pid`
unload

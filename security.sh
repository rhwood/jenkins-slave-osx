#!/bin/bash
#
# Tool to get and set certificates and passwords for the Jenkins JNLP Slave
#
# This tool takes the commands:
# set-password --account=ACCOUNT --service=SERVICE --password=PASSWORD
# get-password --account=ACCOUNT --service=SERVICE
# add-java-certificate --alias=ALIAS --certificate=/path/to/certificate

OSX_KEYCHAIN="org.jenkins-ci.slave.jnlp.keychain"
OSX_KEYCHAIN_PASS=""
JAVA_KEYSTORE=~/Library/Keychains/org.jenkins-ci.slave.jnlp.jks
ACCOUNT=""
SERVICE=""
PASSWORD=""
CERTIFICATE=""
ALIAS=""
COMMAND=""
CACERT=""

if [ -f ~/Library/Keychains/.keychain_pass ]; then
	chmod 400 ~/Library/Keychains/.keychain_pass
	source ~/Library/Keychains/.keychain_pass
fi

while [ $# -gt 0 ]; do
	case $1 in
		set-password|get-password|add-java-certificate)
			COMMAND=$1
			;;
		--keychain-password=*)
			OSX_KEYCHAIN_PASS=${1#*=}
			;;
		--keychain=*)
			OSX_KEYCHAIN=${1#*=}
			;;
		--account=*)
			ACCOUNT=${1#*=}
			;;
		--service=*)
			SERVICE=${1#*=}
			;;
		--password=*)
			PASSWORD=${1#*=}
			;;
		--certificate=*)
			CERTIFICATE=${1#*=}
			;;
		--authority)
			CA_CERT="-trustcacert"
			;;
		--alias=*)
			ALIAS=${1#*=}
			;;
		*)
			echo "Unknown option $1" 1>&2
			;;
	esac
	shift
done

if [[ -z $COMMAND || -z $OSX_KEYCHAIN || -z $OSX_KEYCHAIN_PASS ]]; then
	exit 2
fi

if [ ! -f ~/Library/Keychains/${OSX_KEYCHAIN} ]; then
	exit 1
fi

security unlock-keychain -p ${OSX_KEYCHAIN_PASS} ${OSX_KEYCHAIN}
if [ "$COMMAND" == "set-password" ]; then
	if [[ ! -z $ACCOUNT && ! -z $SERVICE && ! -z $PASSWORD ]]; then
		security add-generic-password -U -w ${PASSWORD} -a ${ACCOUNT} -s ${SERVICE} ${OSX_KEYCHAIN}
	fi
elif [ "$COMMAND" == "get-password" ]; then
	if [[ ! -z $ACCOUNT && ! -z $SERVICE ]]; then
		security find-generic-password -w -a ${ACCOUNT} -s ${SERVICE} ${OSX_KEYCHAIN}
	fi
elif [ "$COMMAND" == "add-java-certificate" ]; then
	if [[ ! -z $ALIAS && -f $CERTIFICATE ]]; then
		KEYSTORE_PASS=$( security find-generic-password -w -a `whoami` -s java_truststore ${OSX_KEYCHAIN} )
		keytool -importcert ${CA_CERT} -alias ${ALIAS} -file ${CERTIFICATE} -keystore ${JAVA_KEYSTORE} -storepass ${KEYSTORE_PASS}
	fi
fi
security lock-keychain ${OSX_KEYCHAIN}

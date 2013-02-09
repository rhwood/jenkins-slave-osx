#!/bin/bash

OSX_KEYCHAIN="org.jenkins-ci.slave.jnlp.keychain"
OSX_KEYCHAIN_PASS=""
ACCOUNT=""
SERVICE=""
PASSWORD=""

while [ $# -gt 0 ]; do
	case $1 in
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
	esac
	shift
done

if [[ -z $OSX_KEYCHAIN || -z $OSX_KEYCHAIN_PASS ]]; then
	exit 1
fi

security unlock-keychain -p ${OSX_KEYCHAIN_PASS} ${OSX_KEYCHAIN}
if [[ ! -z $ACCOUNT && ! -z $SERVICE && ! -z $PASSWORD ]]; then
	security add-generic-password -w ${PASSWORD} -a ${ACCOUNT} -s ${SERVICE} ${OSX_KEYCHAIN}
fi
security lock-keychain ${OSX_KEYCHAIN}
#!/bin/bash

## Check if system is based on yum or apt-get
char="."
debug='>> /var/log/socfortress-installation.log 2>&1'
MANAGER="logs.socfortress.co"
WAZUH_MAJOR="4.2"
WAZUH_VER="4.2.5"
WAZUH_REV="1"
CUSTOMER="SOCFORTRESS"
USERNAME=""
PASSWORD=""
WAZUH_KIB_PLUG_REV="1"
ow=""
WAZUHPORTREG="1515"
WAZUHPORTLOG="1514"
VELOMANAGER="velo.socfortress.co"
VELOPORT="8000"
TIMEOUT="1"
repogpg="https://packages.wazuh.com/key/GPG-KEY-WAZUH"
repobaseurl="https://packages.wazuh.com/4.x"
resources="https://packages.wazuh.com/resources/${WAZUH_MAJOR}"

if [ -n "$(command -v yum)" ]; then
    sys_type="yum"
    sep="-"
elif [ -n "$(command -v zypper)" ]; then
    sys_type="zypper"   
    sep="-"  
elif [ -n "$(command -v apt-get)" ]; then
    sys_type="apt-get"   
    sep="="
fi

## Prints information
logger() {

    now=$(date +'%m/%d/%Y %H:%M:%S')
    case $1 in 
        "-e")
            mtype="ERROR:"
            message="$2"
            ;;
        "-w")
            mtype="WARNING:"
            message="$2"
            ;;
        *)
            mtype="INFO:"
            message="$1"
            ;;
    esac
    echo $now $mtype $message
}

rollBack() {

    if [ -z "${uninstall}" ]; then
        logger -w "Cleaning the installation" 
    fi   
    
    if [ -n "${wazuhinstalled}" ]; then
        logger -w "Removing the Wazuh agent..."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove wazuh-agent -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove wazuh-agent ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge wazuh-agent -y ${debug}"
        fi 
        eval "rm -rf /var/ossec/ ${debug}"
    fi     

    if [ -n "${veloinstalled}" ]; then
        logger -w "Removing Velo..."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove velociraptor-client -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove velociraptor-client ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge velociraptor-client -y ${debug}"
        fi 
        eval "rm -rf /etc/velociraptor/ ${debug}"
    fi

    if [ -n "${yarainstalled}" ]; then
        logger -w "Removing Yara..."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove epel-release autoconf libtool openssl-devel file-devel jansson jansson-devel flex bison byacc git -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove automake libtool make gcc pkg-config git ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge automake libtool make gcc pkg-config git -y ${debug}"
        fi 
        eval "rm -rf /opt/yara* ${debug}"
        eval "rm -rf /root/yara_update_rules.sh ${debug}"
    fi

    if [ -n "${osqueryinstalled}" ]; then
        logger -w "Removing Osquery.."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove osquery -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove opendistroforelasticsearch-kibana ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge osquery -y ${debug}"
        fi 
        eval "rm -rf /etc/osquery/ ${debug}"
    fi

    if [ -n "${packetbeatinstalled}" ]; then
        logger -w "Removing Packetbeat.."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove packetbeat -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove opendistroforelasticsearch-kibana ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge packetbeat -y ${debug}"
        fi 
        eval "rm -rf /etc/packetbeat/ ${debug}"
    fi

    if [ -n "${clamavinstalled}" ]; then
        logger -w "Removing Clamav.."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove clamav-server clamav-data clamav-update clamav-filesystem clamav clamav-scanner-systemd clamav-devel clamav-lib clamav-server-systemd -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove opendistroforelasticsearch-kibana ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge clamav clamav-daemon -y ${debug}"
        fi 
        eval "rm -rf /root/scripts/clamscan.sh ${debug}"
        eval "rm -rf /etc/freshclam.conf ${debug}"
        eval "rm -rf /etc/clamd.d/scan.conf ${debug}"
    fi

    if [ -z "${uninstall}" ]; then    
        logger -w "Installation cleaned. Check the /var/log/socfortress-installation.log file to learn more about the issue."
    fi

}

checkArch() {

    arch=$(uname -m)

    if [ ${arch} != "x86_64" ]; then
        logger -e "Uncompatible system. This script must be run on a 64-bit system."
        exit 1;
    fi
    
}

startService() {

    if [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
        eval "systemctl daemon-reload ${debug}"
        eval "systemctl enable $1.service ${debug}"
        eval "systemctl start $1.service ${debug}"
        if [  "$?" != 0  ]; then
            logger -e "${1^} could not be started."
            rollBack
            exit 1;
        else
            logger "${1^} started"
        fi  
    elif [ -n "$(ps -e | egrep ^\ *1\ .*init$)" ]; then
        eval "chkconfig $1 on ${debug}"
        eval "service $1 start ${debug}"
        eval "/etc/init.d/$1 start ${debug}"
        if [  "$?" != 0  ]; then
            logger -e "${1^} could not be started."
            rollBack
            exit 1;
        else
            logger "${1^} started"
        fi     
    elif [ -x /etc/rc.d/init.d/$1 ] ; then
        eval "/etc/rc.d/init.d/$1 start ${debug}"
        if [  "$?" != 0  ]; then
            logger -e "${1^} could not be started."
            rollBack
            exit 1;
        else
            logger "${1^} started"
        fi             
    else
        logger -e "${1^} could not start. No service found on the system."
        exit 1;
    fi

}

## Show script usage
getHelp() {

   echo ""
   echo "Usage: $0 arguments"
   echo -e "\t-o   | --overwrite Overwrite the existing installation"
   echo -e "\t-r   | --uninstall Remove the installation"
   echo -e "\t-v   | --verbose Shows the complete installation output"
   echo -e "\t-i   | --ignore-health-check Ignores the health-check"
   echo -e "\t-h   | --help Shows help"
   exit 1 # Exit script after printing help

}

## Install the required packages for the installation
installPrerequisites() {
    logger "Installing all necessary utilities for the installation..."

    if [ ${sys_type} == "yum" ]; then
        eval "yum install curl unzip wget libcap telnet jq -y ${debug}"
    elif [ ${sys_type} == "zypper" ]; then
        eval "zypper -n install curl unzip wget ${debug}"         
        eval "zypper -n install libcap-progs ${debug} || zypper -n install libcap2 ${debug}"
    elif [ ${sys_type} == "apt-get" ]; then
        eval "apt-get update -q $debug"
        eval "apt-get install apt-transport-https curl unzip wget libcap2-bin net-tools jq -y ${debug}"        
    fi

    if [  "$?" != 0  ]; then
        logger -e "Prerequisites could not be installed"
        exit 1;
    else
        logger "Done"
    fi          
}

## Add the Wazuh repository
addWazuhrepo() {
    logger "Adding the Wazuh repository..."

    if [ ${sys_type} == "yum" ]; then
        eval "rpm --import ${repogpg} ${debug}"
        eval "echo -e '[wazuh]\ngpgcheck=1\ngpgkey=${repogpg}\nenabled=1\nname=EL-\$releasever - Wazuh\nbaseurl='${repobaseurl}'/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo ${debug}"
    elif [ ${sys_type} == "zypper" ]; then
        eval "rpm --import ${repogpg} ${debug}"
        eval "echo -e '[wazuh]\ngpgcheck=1\ngpgkey=${repogpg}\nenabled=1\nname=EL-\$releasever - Wazuh\nbaseurl='${repobaseurl}'/yum/\nprotect=1' | tee /etc/zypp/repos.d/wazuh.repo ${debug}"            
    elif [ ${sys_type} == "apt-get" ]; then
        eval "curl -s ${repogpg} --max-time 300 | apt-key add - ${debug}"
        eval "echo "deb '${repobaseurl}'/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list ${debug}"
        eval "apt-get update -q ${debug}"
    fi    

    logger "Done" 
}

## Wazuh agent
installWazuh() {
    
    logger "Installing the Wazuh Agent..."
    if [ ${sys_type} == "zypper" ]; then
        eval "WAZUH_MANAGER='$MANAGER' WAZUH_AGENT_GROUP='$CUSTOMER' zypper -n install wazuh-agent=${WAZUH_VER}-${WAZUH_REV} ${debug}"
    else
        eval "WAZUH_MANAGER='$MANAGER' WAZUH_AGENT_GROUP='$CUSTOMER' ${sys_type} install wazuh-agent${sep}${WAZUH_VER}-${WAZUH_REV} -y ${debug}"
        echo "logcollector.remote_commands=1" >> /var/ossec/etc/local_internal_options.conf
        echo "wazuh_command.remote_commands=1" >> /var/ossec/etc/local_internal_options.conf
        eval "echo '<ossec_config>
    <client>
    <server>
      <address>$MANAGER</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>ubuntu, ubuntu20, ubuntu20.04</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
  </client>
  </ossec_config>' > /var/ossec/etc/ossec.conf"
    fi
    if [  "$?" != 0  ]; then
        logger -e "Wazuh installation failed"
        rollBack
        exit 1;
    else
        wazuhinstalled="1"
        logger "Done"
    fi   
    startService "wazuh-agent"

}

## Velo Install
installVelo() {
    
    logger "Installing the Velo Agent..."
    if [ ${sys_type} == "yum" ]; then
        eval "wget https://github.com/socfortress/Demo/CUSTOMERS/raw/main/$CUSTOMER/velociraptor_0.6.2-1_client.rpm -O /opt/velociraptor_0.6.2-1_client.rpm ${debug}"
        eval "rpm -i /opt/velociraptor_0.6.2-1_client.rpm ${debug}"
    else
        eval "wget https://github.com/socfortress/Demo/CUSTOMERS/raw/main/$CUSTOMER/velociraptor_0.6.2-1_client.socfortress.deb -O /opt/velociraptor_0.6.2-1_client.deb ${debug}"
        eval "dpkg -i /opt/velociraptor_0.6.2-1_client.deb ${debug}"
    fi
    if [  "$?" != 0  ]; then
        logger -e "Velo installation failed"
        rollBack
        exit 1;
    else
        veloinstalled="1"
        logger "Done"
    fi   
    startService "velociraptor_client"

}

## Yara Install
installYara() {
    
    logger "Installing Yara..."
    if [ ${sys_type} == "yum" ]; then
        eval "yum install epel-release autoconf libtool openssl-devel file-devel jansson jansson-devel flex bison byacc git -y ${debug}"
        eval "wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.1.3.tar.gz -O /opt/v4.1.3.tar.gz ${debug}"
        eval "tar xzf /opt/v4.1.3.tar.gz --directory /opt/ ${debug}"
        eval "/opt/yara-4.1.3/bootstrap.sh ${debug}"
        eval "/opt/yara-4.1.3/configure --enable-cuckoo --enable-magic --enable-dotnet ${debug}"
        eval "/opt/yara-4.1.3/make ${debug}"
        eval "/opt/yara-4.1.3/make install ${debug}"
        eval "git clone https://github.com/Neo23x0/signature-base.git /opt/yara-4.1.3/ ${debug}"
        eval "wget https://raw.githubusercontent.com/socfortress/CUSTOMERS/main/$CUSTOMER/yara_update_rules.sh -O /root/yara_update_rules.sh ${debug}"
        eval "chmod +x /root/yara_update_rules.sh ${debug}"
        eval "echo "0 0 1 * * /bin/bash /root/yara_update_rules.sh" >> /etc/crontab ${debug}"
        eval "echo "0 */3 * * * /usr/bin/bash /var/ossec/active-response/bin/yara_full_scan.sh" >> /etc/crontab ${debug}"
    else
        eval "apt-get install automake libtool make gcc pkg-config git -y ${debug}"
        eval "wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.1.3.tar.gz -O /opt/v4.1.3.tar.gz ${debug}"
        eval "tar xzf /opt/v4.1.3.tar.gz --directory /opt/ ${debug}"
        eval "/opt/yara-4.1.3/bootstrap.sh ${debug}"
        eval "/opt/yara-4.1.3/configure --enable-cuckoo --enable-magic --enable-dotnet ${debug}"
        eval "/opt/yara-4.1.3/make ${debug}"
        eval "/opt/yara-4.1.3/make install ${debug}"
        eval "git clone https://github.com/Neo23x0/signature-base.git /opt/yara-4.1.3/ ${debug}"
        eval "wget https://raw.githubusercontent.com/socfortress/CUSTOMERS/main/$CUSTOMER/yara_update_rules.sh -O /root/yara_update_rules.sh ${debug}"
        eval "chmod +x /root/yara_update_rules.sh ${debug}"
        eval "echo "0 0 1 * * /bin/bash /root/yara_update_rules.sh" >> /etc/crontab ${debug}"
        eval "echo "0 */3 * * * /usr/bin/bash /var/ossec/active-response/bin/yara_full_scan.sh" >> /etc/crontab ${debug}"
    fi
    if [  "$?" != 0  ]; then
        logger -e "Yara installation failed"
        rollBack
        exit 1;
    else
        yarainstalled="1"
        logger "Done"
    fi   

}

## OSQUERY Install
installOsquery() {
    
    logger "Installing the Osquery Agent..."
    if [ ${sys_type} == "yum" ]; then
        eval "curl -L https://pkg.osquery.io/rpm/GPG | tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery ${debug}"
        eval "yum-config-manager --add-repo https://pkg.osquery.io/rpm/osquery-s3-rpm.repo ${debug}"
        eval "yum-config-manager --enable osquery-s3-rpm ${debug}"
        eval "yum install osquery -y ${debug}"
        eval "wget https://raw.githubusercontent.com/socfortress/CUSTOMERS/main/$CUSTOMER/osquery.conf -O /etc/osquery/osquery.conf ${debug}"
    else
        eval "export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B ${debug}"
        eval "apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys $OSQUERY_KEY ${debug}"
        eval "add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main' ${debug}"
        eval "apt-get update ${debug}"
        eval "apt-get install osquery ${debug}"
        eval "wget https://raw.githubusercontent.com/socfortress/CUSTOMERS/main/$CUSTOMER/osquery.conf -O /etc/osquery/osquery.conf ${debug}"
    fi
    if [  "$?" != 0  ]; then
        logger -e "Osquery installation failed"
        rollBack
        exit 1;
    else
        osqueryinstalled="1"
        logger "Done"
    fi   

}

## Packetbeat Install
installPacketbeat() {
    
    logger "Installing the Packetbeat Agent..."
    if [ ${sys_type} == "yum" ]; then
        eval "wget https://artifacts.elastic.co/downloads/beats/packetbeat/packetbeat-7.16.3-x86_64.rpm -O /opt/packetbeat-7.16.3-x86_64.rpm ${debug}"
        eval "rpm -i /opt/packetbeat-7.16.3-x86_64.rpm ${debug}"
        eval "wget https://raw.githubusercontent.com/socfortress/CUSTOMERS/main/$CUSTOMER/packetbeat.yml -O /etc/packetbeat/packetbeat.yml ${debug}"
    else
        eval "wget https://artifacts.elastic.co/downloads/beats/packetbeat/packetbeat-7.16.3-amd64.deb -O /opt/packetbeat-7.16.3-amd64.deb ${debug}"
        eval "dpkg -i /opt/packetbeat-7.16.3-amd64.deb ${debug}"
        eval "wget https://raw.githubusercontent.com/socfortress/CUSTOMERS/main/$CUSTOMER/packetbeat.yml -O /etc/packetbeat/packetbeat.yml ${debug}"
    fi
    if [  "$?" != 0  ]; then
        logger -e "Packetbeat installation failed"
        rollBack
        exit 1;
    else
        packetbeatinstalled="1"
        logger "Done"
    fi   
    startService "packetbeat"

}

## ClamAV Install
installClamav() {
    
    logger "Installing the ClamAV..."
    if [ ${sys_type} == "yum" ]; then
        eval "yum install clamav-server clamav-data clamav-update clamav-filesystem clamav clamav-scanner-systemd clamav-devel clamav-lib clamav-server-systemd -y ${debug}"
        eval "freshclam ${debug}"
        eval "echo "@hourly /bin/freshclam --quiet" >> /etc/crontab ${debug}"
        eval "echo "/home/
/opt/
/usr/bin/
/etc/
/usr/sbin/" > /opt/scanfolders.txt ${debug}"
        eval "wget https://raw.githubusercontent.com/socfortress/CUSTOMERS/main/$CUSTOMER/Freshclam.conf -O /etc/freshclam.conf ${debug}"
        eval "wget https://raw.githubusercontent.com/socfortress/CUSTOMERS/main/$CUSTOMER/scan.conf -O /etc/clamd.d/scan.conf ${debug}"
        eval "mkdir /root/scripts/ ${debug}"
        eval "wget https://raw.githubusercontent.com/socfortress/CUSTOMERS/main/$CUSTOMER/clamscan.sh -O /root/scripts/clamscan.sh ${debug}"
        eval "chmod +x /root/scripts/clamscan.sh ${debug}"
        eval "echo "0 8 * * * /root/scripts/clamscan.sh" >> /etc/crontab ${debug}"
    else
        eval "apt-get update -y ${debug}"
        eval "apt-get install clamav clamav-daemon -y ${debug}"
        eval "freshclam ${debug}"
        eval "echo "@hourly /bin/freshclam --quiet" >> /etc/crontab ${debug}"
        eval "echo "/home/
/opt/
/usr/bin/
/etc/
/usr/sbin/" > /opt/scanfolders.txt ${debug}"
        eval "wget https://raw.githubusercontent.com/socfortress/CUSTOMERS/main/$CUSTOMER/Freshclam.conf -O /etc/freshclam.conf ${debug}"
        eval "wget https://raw.githubusercontent.com/socfortress/CUSTOMERS/main/$CUSTOMER/scan.conf -O /etc/clamd.d/scan.conf ${debug}"
        eval "mkdir /root/scripts/ ${debug}"
        eval "https://raw.githubusercontent.com/socfortress/CUSTOMERS/main/$CUSTOMER/clamscan.sh -O /root/scripts/clamscan.sh ${debug}"
        eval "chmod +x /root/scripts/clamscan.sh ${debug}"
        eval "echo "0 8 * * * /root/scripts/clamscan.sh" >> /etc/crontab ${debug}"
    fi
    if [  "$?" != 0  ]; then
        logger -e "ClamAV installation failed"
        rollBack
        exit 1;
    else
        clamavinstalled="1"
        logger "Done"
    fi   

}

## Auditctl Install
installAuditctl() {
    
    logger "Installing auditctl..."
    if [ ${sys_type} == "yum" ]; then
        eval "wget https://raw.githubusercontent.com/socfortress/CUSTOMERS/main/$CUSTOMER/auditd.conf -O /etc/audit/rules.d/audit.rules ${debug}" 
        eval "auditctl -R /etc/audit/rules.d/audit.rules ${debug}"
    else
        eval "wget https://raw.githubusercontent.com/socfortress/CUSTOMERS/main/$CUSTOMER/auditd.conf -O /etc/audit/rules.d/audit.rules ${debug}"
        eval "auditctl -R /etc/audit/rules.d/audit.rules ${debug}"
    fi
    if [  "$?" != 0  ]; then
        logger -e "Auditctl installation failed"
        exit 1;
    else
        auditctlinstalled="1"
        logger "Done"
    fi   

}

checkInstalled() {
    
    if [ "${sys_type}" == "yum" ]; then
        wazuhinstalled=$(yum list installed 2>/dev/null | grep wazuh-agent)
    elif [ "${sys_type}" == "zypper" ]; then
        wazuhinstalled=$(zypper packages --installed-only | grep wazuh-agent | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        wazuhinstalled=$(apt list --installed  2>/dev/null | grep wazuh-agent)
    fi    

    if [ -n "${wazuhinstalled}" ]; then
        if [ ${sys_type} == "zypper" ]; then
            wazuhversion=$(echo ${wazuhinstalled} | awk '{print $11}')
        else
            wazuhversion=$(echo ${wazuhinstalled} | awk '{print $2}')
        fi    
    fi

    if [ "${sys_type}" == "yum" ]; then
        veloinstalled=$(systemctl status velociraptor_client 2>/dev/null | grep loaded)
    elif [ "${sys_type}" == "zypper" ]; then
        veloinstalled=$(zypper packages --installed-only | grep opendistroforelasticsearch | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        veloinstalled=$(systemctl status velociraptor_client 2>/dev/null | grep loaded)
    fi 

    if [ -n "${veloinstalled}" ]; then
        if [ ${sys_type} == "zypper" ]; then
            veloversion=$(echo ${veloinstalled} | awk '{print $11}')
        else
            veloversion=$(echo ${veloinstalled} | awk '{print $2}')
        fi  
    fi
    YARAFILE=/root/yara_update_rules.sh
    yarainstalled=$(test -f $YARAFILE && echo "$FILE exists.")

    if [ -n "${yarainstalled}" ]; then
        if [ ${sys_type} == "zypper" ]; then
            yaraversion=$(echo ${yarainstalled} | awk '{print $11}')
        else
            yaraversion=$(echo ${yarainstalled} | awk '{print $2}')
        fi  
    fi    

    if [ "${sys_type}" == "yum" ]; then
        osqueryinstalled=$(yum list installed 2>/dev/null | grep osquery)
    elif [ "${sys_type}" == "zypper" ]; then
        osqueryinstalled=$(zypper packages --installed-only | grep osquery | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        osqueryinstalled=$(apt list --installed  2>/dev/null | grep osquery)
    fi 

    if [ -n "${osqueryinstalled}" ]; then
        if [ ${sys_type} == "zypper" ]; then
            osqueryversion=$(echo ${osqueryinstalled} | awk '{print $11}')
        else
            osqueryversion=$(echo ${osqueryinstalled} | awk '{print $2}')
        fi  
    fi  

    if [ "${sys_type}" == "yum" ]; then
        packetbeatinstalled=$(yum list installed 2>/dev/null | grep packetbeat)
    elif [ "${sys_type}" == "zypper" ]; then
        packetbeatinstalled=$(zypper packages --installed-only | grep packetbeat | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        packetbeatinstalled=$(apt list --installed  2>/dev/null | grep packetbeat)
    fi 

    if [ -n "${packetbeatinstalled}" ]; then
        if [ ${sys_type} == "zypper" ]; then
            packetbeatversion=$(echo ${packetbeatinstalled} | awk '{print $11}')
        else
            packetbeatversion=$(echo ${packetbeatinstalled} | awk '{print $2}')
        fi  
    fi

    if [ "${sys_type}" == "yum" ]; then
        clamavinstalled=$(yum list installed 2>/dev/null | grep clamav)
    elif [ "${sys_type}" == "zypper" ]; then
        clamavinstalled=$(zypper packages --installed-only | grep clamav | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        clamavinstalled=$(apt list --installed  2>/dev/null | grep clamav)
    fi 

    if [ -n "${clamavinstalled}" ]; then
        if [ ${sys_type} == "zypper" ]; then
            clamavversion=$(echo ${clamavinstalled} | awk '{print $11}')
        else
            clamavversion=$(echo ${clamavinstalled} | awk '{print $2}')
        fi  
    fi

    if [ -z "${wazuhinstalled}" ] && [ -z "${veloinstalled}" ] && [ -z "${yarainstalled}" ] && [ -z "${osqueryinstalled}" ] && [ -z "${packetbeatinstalled}" ] && [ -z "${clamavinstalled}" ] && [ -n "${uninstall}" ]; then 
        logger -e "No SOCFortress components were found on the system."
        exit 1;        
    fi

    if [ -n "${wazuhinstalled}" ] || [ -n "${veloinstalled}" ] || [ -n "${yarainstalled}" ] || [ -n "${osqueryinstalled}" ] || [ -n "${packetbeatinstalled}" ] || [ -n "${clamavinstalled}" ]; then 
        if [ -n "${ow}" ]; then
             overwrite
        
        elif [ -n "${uninstall}" ]; then
            logger -w "Removing the installed items"
            rollBack
        else
            logger -e "All the SOCFortress componets were found on this host. If you want to overwrite the current installation, run this script back using the option -o/--overwrite. NOTE: This will erase all the existing configuration and data."
            exit 1;
        fi
    fi          

}

overwrite() {  
    rollBack
    addWazuhrepo
    installPrerequisites
    if [ -n "${wazuhinstalled}" ]; then
        installWazuh
    fi
    if [ -n "${veloinstalled}" ]; then
        installVelo
    fi    
    if [ -n "${yarainstalled}" ]; then
        installYara
    fi
    if [ -n "${osqueryinstalled}" ]; then
        installOsquery
    fi    
    if [ -n "${packetbeatinstalled}" ]; then
        installPacketbeat
    fi   
    if [ -n "${clamavinstalled}" ]; then
        installClamav
    fi   
    checkInstallation     
}

networkCheck() {
    connectionReg=$(telnet $MANAGER $WAZUHPORTREG | grep Connected | awk '{print $1}')
    if [ ${connectionReg} != "Connected" ]; then
        logger -e "No internet connection to $MANAGER on $WAZUHPORTREG. To perform an offline installation, please run this script with the option -d/--download-packages in a computer with internet access, copy the wazuh-packages.tar file generated on this computer and run again this script."
        exit 1;
    fi
    connectionLog=$(telnet $MANAGER $WAZUHPORTLOG | grep Connected | awk '{print $1}')
    if [ ${connectionReg} != "Connected" ]; then
        logger -e "No internet connection to $MANAGER on $WAZUHPORTREG. To perform an offline installation, please run this script with the option -d/--download-packages in a computer with internet access, copy the wazuh-packages.tar file generated on this computer and run again this script."
        exit 1;
    fi
    connectionVelo=$(telnet $VELOMANAGER $VELOPORT | grep Connected | awk '{print $1}')
    if [ ${connectionReg} != "Connected" ]; then
        logger -e "No internet connection to $VELOMANAGER on $VELOPORT. To perform an offline installation, please run this script with the option -d/--download-packages in a computer with internet access, copy the wazuh-packages.tar file generated on this computer and run again this script."
        exit 1;
    fi

}

main() {

    if [ "$EUID" -ne 0 ]; then
        logger -e "This script must be run as root."
        exit 1;
    fi   

    checkArch
    touch /var/log/socfortress-installation.log

    if [ -n "$1" ]; then      
        while [ -n "$1" ]
        do
            case "$1" in 
            "-i"|"--ignore-healthcheck") 
                ignore=1          
                shift 1
                ;; 
            "-v"|"--verbose") 
                verbose=1          
                shift 1
                ;; 
            "-o"|"--overwrite")  
                ow=1 
                shift 1     
                ;;  
            "-r"|"--uninstall")  
                uninstall=1 
                shift 1     
                ;;                                                              
            "-h"|"--help")        
                getHelp
                ;;                                         
            *)
                getHelp
            esac
        done    

        if [ -n "${verbose}" ]; then
            debug='2>&1 | tee -a /var/log/socfortress-installation.log'
        fi

        if [ -n "${uninstall}" ]; then
            checkInstalled
            exit 0;
        fi        
        
        if [ -n "${ignore}" ]; then
            logger -w "Health-check ignored."    
            checkInstalled
        else
            checkInstalled        
        fi         
        networkCheck   
        installPrerequisites
        addWazuhrepo
        installWazuh
        installVelo
        installOsquery
        installPacketbeat
        installClamav
        installAuditctl
           
    else
        networkCheck
        checkInstalled
        installPrerequisites
        addWazuhrepo
        installWazuh
        installVelo
        installOsquery
        installPacketbeat
        installClamav
        installAuditctl 
    fi

}

main "$@"


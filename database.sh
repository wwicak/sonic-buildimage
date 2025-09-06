#!/bin/bash

# single instance containers are still supported (even though it might not look like it)
# if no instance number is passed to this script, $DEV will simply be unset, resulting in docker
# commands being sent to the base container name. E.g. `docker start database$DEV` simply starts
# the container `database` if no instance number is passed since `$DEV` is not defined
link_namespace() {
    # Makes namespace of a docker container available in
    # /var/run/netns so it can be managed with iproute2

    mkdir -p /var/run/netns
    PID="$(docker inspect -f '{{.State.Pid}}' "${DOCKERNAME}")"

    PIDS=`ip netns pids "$NET_NS" 2>/dev/null`
    if [ "$?" -eq "0" ]; then # namespace exists
        if `echo $PIDS | grep --quiet -w $PID`; then # namespace is correctly linked
            return 0
        else # if it's incorrectly linked remove it
            ip netns delete $NET_NS
        fi
    fi

    ln -s /proc/$PID/ns/net /var/run/netns/$NET_NS
}

function updateSyslogConf()
{
    # On multiNPU platforms, change the syslog target ip to docker0 ip to allow logs from containers
    # running on the namespace to reach the rsyslog service running on the host
    # Also update the container name
    if [[ ($NUM_ASIC -gt 1) ]]; then
        TARGET_IP=$(docker network inspect bridge --format='{{(index .IPAM.Config 0).Gateway}}')
        CONTAINER_NAME="$DOCKERNAME"
        TMP_FILE="/tmp/rsyslog.$CONTAINER_NAME.conf"
        python -c "import jinja2, os; paths=['/usr/share/sonic/templates']; loader = jinja2.FileSystemLoader(paths); env = jinja2.Environment(loader=loader, trim_blocks=True); template_file='/usr/share/sonic/templates/rsyslog-container.conf.j2'; template = env.get_template(os.path.basename(template_file)); data=template.render({\"target_ip\":\"$TARGET_IP\",\"container_name\":\"$CONTAINER_NAME\"}); print(data)" > $TMP_FILE
        docker cp $TMP_FILE ${DOCKERNAME}:/etc/rsyslog.conf
        rm -rf $TMP_FILE
    fi
}
function ebtables_config()
{
    if [[ "$DEV" && $DATABASE_TYPE != "dpudb" ]]; then
        # Install ebtables filter in namespaces on multi-asic.
        ip netns exec $NET_NS ebtables-restore < /etc/ebtables.filter.cfg
    else
        if [[ ! ($NUM_ASIC -gt 1) ]]; then
            # Install ebtables filter in host for single asic.
            ebtables-restore < /etc/ebtables.filter.cfg
        fi
    fi
}

function getMountPoint()
{
    echo $1 | python -c "import sys, json, os; mnts = [x for x in json.load(sys.stdin)[0]['Mounts'] if x['Destination'] == '/usr/share/sonic/hwsku']; print('' if len(mnts) == 0 else os.path.abspath(mnts[0]['Source']))" 2>/dev/null
}

function getBootType()
{
    # same code snippet in files/scripts/syncd.sh
    case "$(cat /proc/cmdline)" in
    *SONIC_BOOT_TYPE=warm*)
        TYPE='warm'
        ;;
    *SONIC_BOOT_TYPE=fastfast*)
        TYPE='fastfast'
        ;;
    *SONIC_BOOT_TYPE=express*)
        TYPE='express'
        ;;
    *SONIC_BOOT_TYPE=fast*|*fast-reboot*)
        TYPE='fast'
        ;;
    *)
        TYPE='cold'
    esac
    echo "${TYPE}"
}

function preStartAction()
{
    WARM_DIR=/host/warmboot
    if [ "$DATABASE_TYPE" != "chassisdb" ]; then
        if [[ ("$BOOT_TYPE" == "warm" || "$BOOT_TYPE" == "fastfast" || "$BOOT_TYPE" == "express" || "$BOOT_TYPE" == "fast")  && -f $WARM_DIR/dump.rdb ]]; then
            # Load redis content from /host/warmboot/dump.rdb
            docker cp $WARM_DIR/dump.rdb database$DEV:/var/lib/redis/dump.rdb
        else
            # Create an emtpy file and overwrite any RDB if already there
            echo -n > /tmp/dump.rdb
            docker cp /tmp/dump.rdb database$DEV:/var/lib/redis/
            docker cp /tmp/dump.rdb database$DEV:/var/lib/redis_bmp/
        fi
    fi
    updateSyslogConf
}

function setPlatformLagIdBoundaries()
{
    docker exec -i ${DOCKERNAME} $SONIC_DB_CLI CHASSIS_APP_DB SET "SYSTEM_LAG_ID_START" "$lag_id_start"
    docker exec -i ${DOCKERNAME} $SONIC_DB_CLI CHASSIS_APP_DB SET "SYSTEM_LAG_ID_END" "$lag_id_end"
    docker exec -i ${DOCKERNAME} $SONIC_DB_CLI CHASSIS_APP_DB EVAL "
    local start_id = tonumber(ARGV[1])
    local end_id = tonumber(ARGV[2])
    for id = start_id,end_id do
        redis.call('rpush','SYSTEM_LAG_IDS_FREE_LIST', tostring(id))
    end" 0 $lag_id_start $lag_id_end
}
function waitForAllInstanceDatabaseConfigJsonFilesReady()
{
    if [ ! -z "$DEV" ]; then
	cnt=0
	SONIC_DB_GLOBAL_JSON="/var/run/redis/sonic-db/database_global.json"
	if [ -f "$SONIC_DB_GLOBAL_JSON" ]; then
            # Create a separate python script to get a list of location of all instance database_config.json file
            redis_database_cfg_list=`/usr/bin/python -c "import sys; import os; import json; f=open(sys.argv[1]); \
            		    global_db_dir = os.path.dirname(sys.argv[1]); data=json.load(f); \
                            print(\" \".join([os.path.normpath(global_db_dir+'/'+elem['include']) \
                            for elem in data['INCLUDES'] if 'namespace' in elem])); f.close()" $SONIC_DB_GLOBAL_JSON`
            for file  in $redis_database_cfg_list
            do
		while [ ! -f $file ]
		do
                    sleep 1
                    cnt=$(( $cnt + 1))
                    if [ $cnt -ge 60 ]; then
			echo "Error: $file not found"
			break
                    fi
		done
            done
        fi
        # Delay a second to allow all instance database_config.json files to be completely generated and fully accessible.
        # This delay is needed to make sure that the database_config.json files are correctly rendered from j2 template
        # files ( renderning takes some time )
        sleep 1
    fi
}

function postStartAction()
{
    midplane_ip=""
    CHASSISDB_CONF="/usr/share/sonic/device/$PLATFORM/chassisdb.conf"
    [ -f $CHASSISDB_CONF ] && source $CHASSISDB_CONF
    if [[ "$DEV" && $DATABASE_TYPE != "dpudb" ]]; then
        # Enable the forwarding on eth0 interface in namespace.
        SYSCTL_NET_CONFIG="/etc/sysctl.d/sysctl-net.conf"
        docker exec -i database$DEV sed -i -e "s/^net.ipv4.conf.eth0.forwarding=0/net.ipv4.conf.eth0.forwarding=1/;
                                               s/^net.ipv6.conf.eth0.forwarding=0/net.ipv6.conf.eth0.forwarding=1/" $SYSCTL_NET_CONFIG
        docker exec -i database$DEV sysctl --system -e
        link_namespace $DEV


        if [[ -n "$midplane_subnet" ]]; then
           # Use /16 for loopback interface
           ip netns exec "$NET_NS" ip addr add 127.0.0.1/16 dev lo
           ip netns exec "$NET_NS" ip addr del 127.0.0.1/8 dev lo

           slot_id=$(python3 -c 'import sonic_platform.platform; platform_chassis = sonic_platform.platform.Platform().get_chassis(); print(platform_chassis.get_my_slot())' 2>/dev/null)
           supervisor_slot_id=$(python3 -c 'import sonic_platform.platform; platform_chassis = sonic_platform.platform.Platform().get_chassis(); print(platform_chassis.get_supervisor_slot())' 2>/dev/null)

           # Create eth1 in database instance
           if [[ "${slot_id}" == "${supervisor_slot_id}" ]]; then
                   ip link add name ns-eth1"$NET_NS" type veth peer name eth1@"$NET_NS"
                   ip link set dev eth1@"$NET_NS" master br1
                   ip link set dev eth1@"$NET_NS" up
                   # For chassis system where Linux bridge is used on supervisor for midplane communication
                   # assign alternate name as eth1-midplane for generic design
                   ip link property add dev br1 altname eth1-midplane
           else
                   ip link add name ns-eth1"$NET_NS" link eth1-midplane type macvlan mode bridge
           fi

           # Create eth1 in database instance
           ip link set dev ns-eth1"$NET_NS" netns "$NET_NS"
           ip netns exec "$NET_NS" ip link set ns-eth1"$NET_NS" name eth1

           if [[ -n "$lc_ip_offset" ]]; then
	       # Use ip offset provided by platform vendor via chassisdb.conf to prevent any conflict
	       # with any platform IP range, e.g., LC eth1-midplane IP.
               ip_offset=$lc_ip_offset
           else
	       # If Vendor has not provided an ip offset, Use 10 as default offset. Platform vendor should
	       # ensure there is no conflict with platform IP range for any slot.
               ip_offset=10
           fi

           # Configure IP address and enable eth1
           slot_ip_address=`echo $midplane_subnet | awk -F. '{print $1 "." $2}'`.$slot_id.$(($DEV + $ip_offset))
           slot_subnet_mask=${midplane_subnet#*/}
           ip netns exec "$NET_NS" ip addr add $slot_ip_address/$slot_subnet_mask dev eth1
           ip netns exec "$NET_NS" ip link set dev eth1 up

           # Don't run for supervisor
           if [[ "${slot_id}" != "${supervisor_slot_id}" ]]; then
                   midplane_ip=$slot_ip_address
           fi

           # Allow localnet routing on the new interfaces if midplane is using a
           # subnet in the 127/8 range.
           if [[ "${midplane_subnet#127}" != "$midplane_subnet" ]]; then
              ip netns exec "$NET_NS" bash -c "echo 1 > /proc/sys/net/ipv4/conf/eth1/route_localnet"
           fi
       fi
    fi
    # Setup ebtables configuration
    # chassisdb starts before database starts, bypass the PING check since other
    # databases are not availbale until database container is ready.
    # also chassisdb doesn't support warm/fast reboot, its dump.rdb is deleted
    # at service startup time, nothing need to be done here.
    if [[ "$DATABASE_TYPE" != "chassisdb" ]]; then
        # Wait until supervisord and redis starts. This change is needed
        # because now database_config.json is jinja2 templated based
        # and by the time file gets generated if we do redis ping
        # then we catch python exception of file not valid
        # that comes to syslog which is unwanted so wait till database
        # config is ready and then ping
	# sonic-db-cli try to initialize the global database. If in multiasic platform, inital global
        # database will try to access to all other instance database-config.json. If other instance
        # database-config.json files are not ready yet, it will generate the sonic-db-cli core files.
	waitForAllInstanceDatabaseConfigJsonFilesReady
        until [[ ($(docker exec -i database$DEV pgrep -x -c supervisord) -gt 0) && ($($SONIC_DB_CLI PING | grep -c PONG) -gt 0) &&
                 ($(docker exec -i database$DEV sonic-db-cli PING | grep -c PONG) -gt 0) ]]; do
          sleep 1;
        done

        if [[ ("$BOOT_TYPE" == "warm" || "$BOOT_TYPE" == "fastfast" || "$BOOT_TYPE" == "express" || "$BOOT_TYPE" == "fast") && -f $WARM_DIR/dump.rdb ]]; then
            # retain the dump file from last boot for debugging purposes
            mv $WARM_DIR/dump.rdb $WARM_DIR/dump.rdb.old
        else
            # If there is a config_db.json dump file, load it.
            if [ -r /etc/sonic/config_db$DEV.json ]; then

                if [ -r /etc/sonic/init_cfg.json ]; then
                    $SONIC_CFGGEN -j /etc/sonic/init_cfg.json -j /etc/sonic/config_db$DEV.json --write-to-db
                else
                    $SONIC_CFGGEN -j /etc/sonic/config_db$DEV.json --write-to-db
                fi
            fi

            if [[ "$BOOT_TYPE" == "fast" ]]; then
                # Flush ASIC DB. On fast-boot there should be nothing in there.
                # In the older versions there has been an issue where a queued FDB event might get into ASIC_DB causing syncd crash at boot.
                $SONIC_DB_CLI ASIC_DB FLUSHDB
                # this is the case when base OS version does not support fast-reboot with reconciliation logic (dump.rdb is absent)
                # In this case, we need to set the flag to indicate fast-reboot is in progress. Set the key to expire in 3 minutes
                $SONIC_DB_CLI STATE_DB SET "FAST_REBOOT|system" "1" "EX" "180"
            fi
        fi

        if [ -e /tmp/pending_config_migration ] || [ -e /tmp/pending_config_initialization ]; then
            # this is first boot to a new image, config-setup execution is pending.
            # for warmboot case, DB is loaded but migration is still pending
            # For firstbboot/fast/cold reboot case, DB contains nothing at this point
            # unset CONFIG_DB_INITIALIZED to indicate pending config load and migration
            # This flag will be set to "1" after DB migration/initialization is completed as part of config-setup
            $SONIC_DB_CLI CONFIG_DB SET "CONFIG_DB_INITIALIZED" "0"
        else
            $SONIC_DB_CLI CONFIG_DB SET "CONFIG_DB_INITIALIZED" "0"
            # this is not a first time boot to a new image. Datbase container starts w/ old pre-existing config
            if [[ -x /usr/local/bin/db_migrator.py ]]; then
                # Migrate the DB to the latest schema version if needed
                if [ -z "$DEV" ]; then
                    /usr/local/bin/db_migrator.py -o migrate
                fi
            fi
            # set CONFIG_DB_INITIALIZED to indicate end of config load and migration
            $SONIC_DB_CLI CONFIG_DB SET "CONFIG_DB_INITIALIZED" "1"
        fi

        # In SUP, enforce CHASSIS_APP_DB.tsa_enabled to be in sync with BGP_DEVICE_GLOBAL.STATE.tsa_enabled
        if [[ -z "$DEV" ]] && [[ -f /etc/sonic/chassisdb.conf ]] && [[ $disaggregated_chassis -ne 1 ]]; then
           tsa_cfg="$($SONIC_DB_CLI CONFIG_DB HGET "BGP_DEVICE_GLOBAL|STATE" "tsa_enabled")"
           if [[ -n "$tsa_cfg" ]]; then
              docker exec -i ${DOCKERNAME} $SONIC_DB_CLI CHASSIS_APP_DB HMSET "BGP_DEVICE_GLOBAL|STATE" tsa_enabled ${tsa_cfg}
              OP_CODE=$?
              if [ $OP_CODE -ne 0 ]; then
                echo "Err: Cmd failed (exit code $OP_CODE). CHASSIS_APP_DB and CONFIG_DB may be incosistent wrt tsa_enabled"
              fi
           fi
        fi

        # Add redis UDS to the redis group and give read/write access to the group
        REDIS_BMP_SOCK="/var/run/redis/redis_bmp.sock"
        chgrp -f redis $REDIS_BMP_SOCK && chmod -f 0760 $REDIS_BMP_SOCK
        REDIS_SOCK="/var/run/redis${DEV}/redis.sock"
    else
        until [[ ($(docker exec -i ${DOCKERNAME} pgrep -x -c supervisord) -gt 0) &&
                 ($(docker exec -i ${DOCKERNAME} $SONIC_DB_CLI CHASSIS_APP_DB PING | grep -c True) -gt 0) ]]; do
           sleep 1
        done
        if [[ -n "$lag_id_start" && -n "$lag_id_end" ]]; then
           setPlatformLagIdBoundaries
        fi
        REDIS_SOCK="/var/run/redis-chassis/redis_chassis.sock"
    fi
    chgrp -f redis $REDIS_SOCK && chmod -f 0760 $REDIS_SOCK

    if [[ $DEV && $midplane_ip ]]; then
        IFS=_ read ip port < <(jq -r '.INSTANCES | [.redis.hostname, .redis.port] | join("_")' /var/run/redis$DEV/sonic-db/database_config.json)
        bound_ips=$(redis-cli --raw -h $ip -p $port config get bind | sed -n '2,2 p')
        redis-cli -h $ip -p $port config set bind "$bound_ips $midplane_ip"
        redis-cli -h $ip -p $port config rewrite
    fi
    /etc/resolvconf/update-libc.d/update-containers ${DOCKERNAME} &
}

start() {
    # Obtain boot type from kernel arguments
    BOOT_TYPE=`getBootType`

    # Obtain our platform as we will mount directories with these names in each docker
    PLATFORM=${PLATFORM:-`$SONIC_CFGGEN -H -v DEVICE_METADATA.localhost.platform`}

    # Parse the device specific asic conf file, if it exists
    ASIC_CONF=/usr/share/sonic/device/$PLATFORM/asic.conf
    if [ -f "$ASIC_CONF" ]; then
        source $ASIC_CONF
    fi

    # Default rsyslog target IP for single ASIC platform
    SYSLOG_TARGET_IP=127.0.0.1
    if [[ ($NUM_ASIC -gt 1) ]]; then
        SYSLOG_TARGET_IP=$(docker network inspect bridge --format='{{(index .IPAM.Config 0).Gateway}}')
    fi

    PLATFORM_ENV_CONF=/usr/share/sonic/device/$PLATFORM/platform_env.conf
    if [ -f "$PLATFORM_ENV_CONF" ]; then
        source $PLATFORM_ENV_CONF
    fi
    # Don't mount HWSKU in database container.
    HWSKU=""
    MOUNTPATH=""

    DOCKERCHECK=`docker inspect --type container ${DOCKERNAME} 2>/dev/null`
    if [ "$?" -eq "0" ]; then
        DOCKERMOUNT=""
        if [ x"$DOCKERMOUNT" == x"$MOUNTPATH" ]; then
            CONTAINER_EXISTS="yes"
            preStartAction
            echo "Starting existing ${DOCKERNAME} container"
            docker start ${DOCKERNAME}
            postStartAction
            exit $?
        fi

        # docker created with a different HWSKU, remove and recreate
        echo "Removing obsolete ${DOCKERNAME} container with HWSKU $DOCKERMOUNT"
        docker rm -f ${DOCKERNAME}
    fi

    echo "Creating new ${DOCKERNAME} container"
    if [ "$DATABASE_TYPE" != "chassisdb" ]; then
        if [ -z "$DEV" ]; then
            # if database_global exists in old_config, use it; otherwise use the default one in new image
            if [ -f /etc/sonic/old_config/database_global.json ]; then
                echo "Use database_global.json from old system..."
                mv /etc/sonic/old_config/database_global.json /etc/sonic/
            fi
        fi
        # if database_config exists in old_config, use it; otherwise use the default one in new image
        if [ -f /etc/sonic/old_config/database_config$DEV.json ]; then
            echo "Use database_config.json from old system..."
            mv /etc/sonic/old_config/database_config$DEV.json /etc/sonic/
        fi
    fi

    # In Multi ASIC platforms the global database config file database_global.json will exist.
    # Parse the file and get the include path for the database_config.json files used in
    # various namesapces. The database_config paths are relative to the DIR of SONIC_DB_GLOBAL_JSON.
    SONIC_DB_GLOBAL_JSON="/var/run/redis/sonic-db/database_global.json"
    if [ -f "$SONIC_DB_GLOBAL_JSON" ]; then
        # TODO Create a separate python script with the below logic and invoke it here.
        redis_dir_list=`/usr/bin/python -c "import sys; import os; import json; f=open(sys.argv[1]); \
                        global_db_dir = os.path.dirname(sys.argv[1]); data=json.load(f); \
                        print(\" \".join([os.path.normpath(global_db_dir+'/'+elem['include']).partition('sonic-db')[0]\
                        for elem in data['INCLUDES'] if 'namespace' in elem or 'container_name' in elem ])); f.close()" $SONIC_DB_GLOBAL_JSON`
    fi
    start_chassis_db=0
    chassis_db_address=""
    chassisdb_config="/usr/share/sonic/device/$PLATFORM/chassisdb.conf"
    [ -f $chassisdb_config ] && source $chassisdb_config
    DB_OPT=" -v /var/run/redis-chassis:/var/run/redis-chassis:ro "
    if [[ "$start_chassis_db" != "1" ]] && [[ -z "$chassis_db_address" ]]; then
        DB_OPT=""
    else
        DB_OPT=$DB_OPT" --add-host=redis_chassis.server:$chassis_db_address "
    fi

    if [[ -z "$DEV" || $DATABASE_TYPE == "dpudb" ]]; then
        NET="host"

        # For Multi-ASIC platform we have to mount the redis paths for database instances running in different
        # namespaces, into the single instance dockers like snmp, pmon on linux host. These global dockers
        # will need to get/set tables from databases in different namespaces.
        # /var/run/redis0 ---> mounted as --> /var/run/redis0
        # /var/run/redis1 ---> mounted as --> /var/run/redis1 .. etc
        # The below logic extracts the base DIR's where database_config.json's for various namespaces exist.
        # redis_dir_list is a string of form "/var/run/redis0/ /var/run/redis1/ /var/run/redis2/"
        if [ "$DATABASE_TYPE" == "chassisdb" ]; then
            DB_OPT=${DB_OPT/redis-chassis:ro/redis-chassis:rw}
            DB_OPT=$DB_OPT"  -v /var/run/redis-chassis:/var/run/redis:rw "
            DB_OPT=$DB_OPT" --env DATABASE_TYPE=$DATABASE_TYPE"
        else
            DB_OPT=$DB_OPT" -v /var/run/redis$DEV:/var/run/redis:rw "
            DB_OPT=$DB_OPT" --env DATABASE_TYPE=$DATABASE_TYPE "
            DB_OPT=$DB_OPT" --env NUM_DPU=$NUM_DPU "
            DB_OPT=$DB_OPT" --env IS_DPU_DEVICE=$IS_DPU_DEVICE "
            if [[ "$DEV" ]]; then
                DB_OPT=$DB_OPT" -v /var/run/redis$DEV:/var/run/redis$DEV:rw "
            fi
        fi
    else
        # This part of code is applicable for Multi-ASIC platforms. Here we mount the namespace specific
        # redis directory into the docker running in that namespace. Below eg: is for namespace "asic1"
        # /var/run/redis1 ---> mounted as --> /var/run/redis1
        # redis_dir_list is a string of form "/var/run/redis0/ /var/run/redis1/ /var/run/redis2/"
        if [ -n "$redis_dir_list" ]; then
            id=`expr $DEV + 1`
            redis_dir=`echo $redis_dir_list | cut -d " " -f $id`
            REDIS_MNT=$REDIS_MNT" -v $redis_dir:$redis_dir:rw "
        fi
        NET="bridge"
        DB_OPT=$DB_OPT" -v /var/run/redis$DEV:/var/run/redis:rw "
    fi

    NAMESPACE_ID="$DEV"
    if [[ $DATABASE_TYPE == "dpudb" ]]; then
        NAMESPACE_ID=""
    fi
    docker create -t --security-opt apparmor=unconfined --security-opt=systempaths=unconfined -v /etc/sonic:/etc/sonic:ro -v /etc/localtime:/etc/localtime:ro \
        --net=$NET \
        -e RUNTIME_OWNER=local \
        --uts=host \
	--tmpfs /var/log/supervisor:rw \
        -v /src:/src:ro -v /debug:/debug:rw \
        --log-opt max-size=2M --log-opt max-file=5 \
        $DB_OPT \
        $REDIS_MNT \
        -v /etc/fips/fips_enable:/etc/fips/fips_enable:ro \
        -v /usr/share/sonic/device/$PLATFORM:/usr/share/sonic/platform:ro \
        -v /usr/share/sonic/templates/rsyslog-container.conf.j2:/usr/share/sonic/templates/rsyslog-container.conf.j2:ro \
        --tmpfs /tmp \
        --tmpfs /var/tmp \
        --env "NAMESPACE_ID"="$NAMESPACE_ID" \
        --env "NAMESPACE_PREFIX"="$NAMESPACE_PREFIX" \
        --env "NAMESPACE_COUNT"="$NUM_ASIC" \
        --env "DEV"="$DEV" \
        --env "CONTAINER_NAME"=$DOCKERNAME \
        --env "SYSLOG_TARGET_IP"=$SYSLOG_TARGET_IP \
        --env "PLATFORM"=$PLATFORM \
        --name=$DOCKERNAME \
        docker-database-dbg:latest \
        || {
            echo "Failed to docker run" >&1
            exit 4
    }

    preStartAction
    docker start $DOCKERNAME
    postStartAction
}

wait() {
    /usr/bin/docker-rs wait $DOCKERNAME
}

stop() {
    docker stop $DOCKERNAME
    if [[ "$DEV" && $DATABASE_TYPE != "dpudb" ]]; then
        ip netns delete "$NET_NS"
    fi
}

kill() {
    docker kill $DOCKERNAME
    if [[ "$DEV" && $DATABASE_TYPE != "dpudb" ]]; then
        ip netns delete "$NET_NS"
    fi
}

DOCKERNAME=database
OP=$1
DEV=$2 # namespace/device number to operate on
if [ "$DEV" == "chassisdb" ]; then
      DATABASE_TYPE="chassisdb"
      DOCKERNAME=$DOCKERNAME"-chassis"
      unset DEV
fi

if [[ "$DEV" == *"dpu"* ]]; then
    DATABASE_TYPE="dpudb"
fi
NAMESPACE_PREFIX="asic"
DOCKERNAME=$DOCKERNAME$DEV
CONTAINER_EXISTS="no"
if [[ "$DEV" && $DATABASE_TYPE != "dpudb" ]]; then
    NET_NS="$NAMESPACE_PREFIX$DEV" #name of the network namespace

    SONIC_CFGGEN="sonic-cfggen -n $NET_NS"
    SONIC_DB_CLI="sonic-db-cli -n $NET_NS"
 else
    NET_NS=""
    SONIC_CFGGEN="sonic-cfggen"
    SONIC_DB_CLI="sonic-db-cli"
fi

# read SONiC immutable variables
[ -f /etc/sonic/sonic-environment ] && . /etc/sonic/sonic-environment

case "$1" in
    start|wait|stop|kill)
        $1
        ;;
    *)
        echo "Usage: $0 {start namespace(optional)|wait namespace(optional)|stop namespace(optional)}"
        exit 1
        ;;
esac

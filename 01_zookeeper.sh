# Install JRE

yum -y install java-1.8.0-openjdk.x86_64

cat > /etc/profile.d/jdk.sh <<EOF
export JAVA_HOME=/usr/lib/jvm/jre-1.8.0-openjdk
export JRE_HOME=/usr/lib/jvm/jre
EOF

source /etc/profile.d/jdk.sh

# Install zookeeper

cd /opt/src
wget http://apache.org/dist/zookeeper/current/zookeeper-3.4.10.tar.gz
wget http://apache.org/dist/zookeeper/current/zookeeper-3.4.10.tar.gz.md5sum

md5sum zookeeper-3.4.10.tar.gz

tar -zxf zookeeper-3.4.10.tar.gz -C /opt/
ln -s /opt/zookeeper-3.4.10 /opt/zookeeper

cat > /etc/profile.d/zookeeper.sh <<EOF
export PATH=/opt/zookeeper:/opt/zookeeper/bin:\$PATH
export ZOOKEEEPER_HOME=/opt/zookeeper:\$ZOOKEEEPER_HOME/bin
EOF

# Create group with system GUID 

( getent group zookeeper || groupadd -r zookeeper ) || exit 1

# Create user
if id zookeeper >/dev/null 2>&1; then 
   # Set primary user group 
   usermod -g zookeeper zookeeper || exit 1 
else 
   # Create user with system UID and with home directory 
   useradd -r -g zookeeper -s /bin/false zookeeper || exit 1 
fi

chown -R zookeeper:zookeeper /opt/zookeeper-3.4.10

# Create data directoty and config

mkdir -p /data/zookeeper/data
chown -R zookeeper:zookeeper /data/zookeeper

cat > /opt/zookeeper/conf/zookeeper.properties <<EOF
# The number of milliseconds of each tick
tickTime=2000
# The number of ticks that the initial 
# synchronization phase can take
initLimit=10
# The number of ticks that can pass between 
# sending a request and getting an acknowledgement
syncLimit=5
# the directory where the snapshot is stored.
# do not use /tmp for storage, /tmp here is just 
# example sakes.
dataDir=/data/zookeeper/data
# the port at which the clients will connect
clientPort=2181

# the maximum number of client connections.
# increase this if you need to handle more clients
maxClientCnxns=900
#
# Be sure to read the maintenance section of the 
# administrator guide before turning on autopurge.
#
# http://zookeeper.apache.org/doc/current/zookeeperAdmin.html#sc_maintenance
#
# The number of snapshots to retain in dataDir
autopurge.snapRetainCount=10
# Purge task interval in hours
# Set to "0" to disable auto purge feature
autopurge.purgeInterval=24
EOF

# Create systemd unit and start zookeeper

cat > /etc/systemd/system/zookeeper.service <<EOF

[Unit]
Description=Apache Zookeeper server
Documentation=http://zookeeper.apache.org
Requires=network.target remote-fs.target
After=network.target remote-fs.target

[Service]
Type=forking
User=zookeeper
Group=zookeeper
ExecStart=/opt/zookeeper/bin/zkServer.sh start /opt/zookeeper/conf/zookeeper.properties
ExecStop=/opt/zookeeper/bin/zkServer.sh stop
ExecReload=/opt/zookeeper/bin/zkServer.sh restart
WorkingDirectory=/data/zookeeper/

[Install]
WantedBy=multi-user.target

EOF

systemctl enable zookeeper.service
systemctl start zookeeper.service

# check zookeeper

echo ruok | nc 127.0.0.1 2181
#imok

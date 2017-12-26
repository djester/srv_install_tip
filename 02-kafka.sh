### Install Kafka

# Check JDK installed

java -version

# Get kafka

cd /opt/src
wget http://apache-mirror.rbc.ru/pub/apache/kafka/1.0.0/kafka_2.11-1.0.0.tgz
tar -xzf kafka_2.11-1.0.0.tgz -C /opt/

ln -s /opt/kafka_2.11-1.0.0 /opt/kafka

# Create group with system GUID 

( getent group kafka || groupadd -r kafka ) || exit 1

# Create user
if id kafka >/dev/null 2>&1; then 
   # Set primary user group 
   usermod -g kafka kafka || exit 1 
else 
   # Create user with system UID and with home directory 
   useradd -r -g kafka -s /bin/false kafka || exit 1 
fi

chown -R kafka:kafka /opt/kafka_2.11-1.0.0
chown -R kafka:kafka /opt/kafka

mkdir -p /data/log/kafka
chown kafka:kafka /data/log/kafka

# Create systemd unit

cat > /etc/systemd/system/kafka.service <<EOF

[Unit]
Description=Apache Kafka server (broker)
Documentation=http://kafka.apache.org/documentation.html
Requires=network.target remote-fs.target
After=network.target remote-fs.target zookeeper.service

[Service]
Type=simple
User=kafka
Group=kafka

Environment=JAVA_HOME=/etc/alternatives/jre
Environment="KAFKA_HEAP_OPTS=-Xmx256M -Xms128M"
Environment="KAFKA_JVM_PERFORMANCE_OPTS=-XX:+UseG1GC -XX:MaxGCPauseMillis=20 -XX:InitiatingHeapOccupancyPercent=35 -XX:+ExplicitGCInvokesConcurrent"

ExecStart=/opt/kafka/bin/kafka-server-start.sh /opt/kafka/config/server.properties
ExecStop=/opt/kafka/bin/kafka-server-stop.sh

Restart=on-failure
SyslogIdentifier=kafka

[Install]
WantedBy=multi-user.target

EOF

systemctl enable kafka.service
systemctl start kafka.service



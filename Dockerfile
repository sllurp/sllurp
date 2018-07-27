FROM python:3

RUN pip install paho-mqtt
COPY ./ /sllurp
WORKDIR /sllurp
RUN python setup.py install

CMD sllurp inventory $ANT_ADDR -r -X $TX_POWER -t $INTERVAL --mqtt-broker $MQTT_BROKER --mqtt-topic $MQTT_TOPIC --mode-identifier $MODE

FROM golang:1.12-alpine 

#COPY tags.csv /
#COPY tags.gob / 

RUN apk add curl
RUN apk add git 

#Install Dep
RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh


RUN go get github.com/hanyangzhao/golemu
WORKDIR $GOPATH/src/github.com/hanyangzhao/golemu
RUN dep ensure 
RUN go install
#WORKDIR /

CMD golemu server --reportInterval $REPORT_INTERVAL

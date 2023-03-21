FROM nucuriel/netutils

WORKDIR /work

COPY ktun .

RUN chmod +x ./ktun

CMD ./ktun
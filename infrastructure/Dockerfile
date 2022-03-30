FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive

SHELL ["/bin/bash", "-c"]
RUN apt-get update -y && \
    apt-get install -y build-essential libssl-dev libffi-dev python3-dev python3-pip git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --create-home --shell /bin/bash cf-user

WORKDIR /home/cf-user
USER cf-user
ENV PATH /home/cf-user/.local/bin:$PATH
RUN git clone -b develop/1.1 https://github.com/Azure/counterfit.git
RUN cd counterfit && pip3 install -U .[dev]

# Initialize textattack
RUN echo "########################"
RUN python3 -m counterfit
RUN echo "########################"

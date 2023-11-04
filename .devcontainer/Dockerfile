FROM ruby:3.2.2

SHELL ["/bin/bash", "-c"]

ARG username=vscode
ARG userUID=1000
ARG userGID=${userUID}
ARG sshPasswd
ARG timeZone=America/Sao_Paulo

ENV SSH_PASSWD=${sshPasswd} \
	USERNAME=${username} \
	LANG=en_US.UTF-8 \
	LANGUAGE=en_US:en \
	LC_ALL=en_US.UTF-8 \
	DEBIAN_FRONTEND=noninteractive

RUN set -eux \
	&& apt-get update \
	&& apt install -y \
	curl \
	ca-certificates \
	apt-transport-https \
	gettext \
	software-properties-common \
	unzip \
	zip \
	make \
	sudo \
	locales \
	vim \
	gpg \
	apt-utils \
	gpg-agent \
	git \
	xz-utils \
	tzdata \
	openssh-server \
	bash-completion

RUN set -eux \
	&& locale-gen en_US.UTF-8 \
	&& ln -sf /usr/share/zoneinfo/${timeZone} /etc/localtime

RUN set -eux \
	&& useradd --uid ${userUID} -m -s /bin/bash ${USERNAME}

RUN mkdir -p /src/workspace \
	/commandhistory \
	/home/${USERNAME}/.ssh \
	/home/${USERNAME}/.ssh-localhost \
	/home/${USERNAME}/.vscode-server \
	/home/${USERNAME}/.vscode-server-insiders \
	&& chown -R ${USERNAME}:${USERNAME} /home/${USERNAME} /src/workspace \
	&& chmod 777 -R /home/${USERNAME} /src/workspace \
	&& chmod 700 /home/${USERNAME}/.ssh \
	&& touch /commandhistory/.bash_history \
	&& chown -R ${USERNAME} /commandhistory \
	&& echo ${USERNAME} ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/${USERNAME} \
	&& chmod 0440 /etc/sudoers.d/${USERNAME} \
	&& echo "set -o history" >> "/home/${USERNAME}/.bashrc" \
	&& echo "export HISTCONTROL=ignoredups:erasedups" >> "/home/${USERNAME}/.bashrc" \
	&& echo "PROMPT_COMMAND=\"${PROMPT_COMMAND:+$PROMPT_COMMAND$'\n'}history -a; history -c; history -r\"" >> "/home/${USERNAME}/.bashrc"

USER ${USERNAME}

COPY files/sshd_config /home/${USERNAME}/.ssh/sshd_config

RUN set -eux \
	&& ssh-keygen -q -N "" -t ecdsa -b 521 -f /home/${USERNAME}/.ssh/ssh_host_ecdsa_key

WORKDIR /src/workspace

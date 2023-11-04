#!/usr/bin/env bash
set -e

_credentials() {
    sudo cp -R /tmp/.ssh-localhost/* ~/.ssh
}

_permissions() {
    sudo chown -R $(whoami):$(whoami) /src/workspace ~/.ssh
    sudo chmod 400 ~/.ssh/*
}

_git() {
    git config --global core.editor vim
}

_main() {
    _credentials
    _permissions
    _git
}

_main "$@"

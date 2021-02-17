#!/bin/bash

# Deploy RPMS
# ===========
#
# Copies RPM artifacts to a repository server.
#
# Parameters must be set was env variables:
# - `SRC_DIR`: source directory location of rpm.
# - `SRC_PATTERN`: pattern from rpm file names to copy.
# - `RPM_HOST`: Host name of the rpm repository.
# - `RPM_USER`: User name of log in to host.
# - `RPM_DIR`: Destination directory of the rpm repository.
# - `RPM_CHOWN`: User/group for chown command.
# - `RPM_CHMOD`: File permissions for chmod command. 
scp ${SRC_DIR}/${SRC_PATTERN} ${RPM_USER}@${RPM_HOST}:${RPM_DIR}
ssh -t ${RPM_USER}@${RPM_HOST} 'sudo -u root sh -c "cd ${RPM_DIR} && \
    chown ${RPM_CHOWN} ${SRC_PATTERN} && \
    chmod ${RPM_CHMOD} ${SRC_PATTERN} && \
    createrepo ."'
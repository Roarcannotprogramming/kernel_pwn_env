#!/bin/bash
echo "export PATH=$PATH:/root/corescripts" >> /root/.bashrc
echo "set auto-load safe-path /" >> /root/.gdbinit

# sleep forever
tail -f /dev/null
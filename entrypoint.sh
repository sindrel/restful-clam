#!/bin/bash
echo "RESTful Clam is starting. Updating the virus database and starting the ClamAV daemon might take some time."

# Update antivirus databases
if [[ ! -v NO_FRESHCLAM_ON_STARTUP ]]; then
    freshclam
fi

# Run freshclam as daemon, check for updates twice a day
freshclam -d -c 2 &

# Start ClamAV daemon
clamd &

# Start application
/go/bin/restful-clam
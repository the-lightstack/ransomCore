#!/usr/bin/bash

# Check if arg is supplied
if [ $# -eq 0 ]
    then
    echo "Supply Arguments."
    echo "Possible: init/update"
    exit 1
fi    


echo "Default vagrant id is '175e7b0'"
if [ $1 = "init" ]
    then

    echo -n "Vagrant id to copy to: "
    read id

    echo "Setting up client/server dir inside vm"

    vagrant ssh -c "mkdir /home/vagrant/RansomCore && mkdir /home/vagrant/RansomCore/client && mkdir /home/vagrant/RansomCore/server" $id

    echo "Copying over files..."
    vagrant upload ./client /home/vagrant/RansomCore/client $id
    vagrant upload ./server /home/vagrant/RansomCore/server $id

    echo "Job done!"
    exit 0

fi

if [ $1 = "update" ]
    then 

    echo -n "Vagrant id to update: "
    read id

    echo "Copying over files..."
    vagrant upload ./client /home/vagrant/RansomCore/client $id
    vagrant upload ./server /home/vagrant/RansomCore/server $id

    echo "Job done!"
    exit 0

fi

if [ $1 = "win-update" ]
    then 

    echo -n "Vagrant id to update: "
    read id

    echo "Copying over files..."
    vagrant upload ./client C:\\vagrant\\client $id
    vagrant upload ./server C:\\vagrant\\server $id

    echo "Job done!"
    exit 0

fi


echo "invalid argument supplied"
exit 1

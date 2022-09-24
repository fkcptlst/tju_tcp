pack_tju_tcp(){
    echo 'make cleaning and packing...'
    echo ''
    cd /mnt/d/network_proj/tju_tcp && make clean
    cd .. && zip handin.zip ./tju_tcp/src ./tju_tcp/src/* ./tju_tcp/inc ./tju_tcp/inc/* ./tju_tcp/build ./tju_tcp/build/* ./tju_tcp/Makefile
    mv ./handin.zip ./tju_tcp
    echo ''
    echo 'pack complete, please upload /vagrant/tju_tcp/handin.zip to autolab'
}


if command -v zip; then 
    pack_tju_tcp
else 
    echo 'zip not found, installing zip'
    sudo apt install zip -y 
    pack_tju_tcp
fi

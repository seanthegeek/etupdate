# etupdate
Updates the Emerging Threats open ruleset for Suricata. Fuuture versions may work with the ET Pro ruleset as well. 

## Installing

    $ sudo git clone https://github.com/seanthegeek/etupdate.git
    $ sudo cp etupdate/etupdate /usr/sbin
    $ sudo /usr/sbin/etupdate.py -V
    
Edit the `crontab`:

    $ sudo crontab -e

Add the line:

    42 * * * * /usr/sbin/etupdate

This will run `etupdate` every 42 minutes after each hour. You should probably change `42` to some other minute, so everyone following this tutorial doesn't query Emerging Threats for updates at the exact same time.


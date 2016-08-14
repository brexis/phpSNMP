<?php
  error_reporting(E_ALL);
  require('snmp.php');

  $snmp = new snmp();
  $snmp->timeout = 1;

  echo "v1: ";
  $snmp->version = SNMP_VERSION_1;
  print_r($snmp->get('localhost', '.1.3.6.1.2.1.1.3.0'));

  echo "v2: ";
  $snmp->version = SNMP_VERSION_2C;
  print_r($snmp->get('localhost', '.1.3.6.1.2.1.1.3.0'));

  echo "v3: ";
  $snmp->version = SNMP_VERSION_3;
  print_r($snmp->get('localhost', '.1.3.6.1.2.1.1.3.0', array('v3_flags'=>SNMP_AUTH_PRIV, 'v3_user'=>'jellofish',
                                                              'v3_auth'=>'qxplne45', 'v3_priv'=>'rvnsiq45')));



/*


1. Make sure the snmpd is not running and insert the following command to create a user:

# net-snmp-config --create-snmpv3-user -a my_password my_user


2. Setup net-snmpd with the following command:

# snmpconf -i -g basic_setup


3. Test the config

# snmpget -v3 -u my_user -l authNoPriv -a MD5 -A my_password localhost sysUpTime.0

*/
?>

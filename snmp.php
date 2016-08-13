<?php
/**
 * phpsnmp - a PHP SNMP library
 *
 * Copyright (C) 2004 David Eder <david@eder,us>
 *
 * Based on snmp - a Python SNMP library
 * Copyright (C) 2003 Unicity Pty Ltd <libsnmp@unicity.com.au>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * @author David Eder <david@eder.us>
 * @copyright 2004 David Eder
 * @package phpSNMP
 * @version .7
 */

/**
 */
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc1155.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc1157.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc1902.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc1905.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc2104.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc3411.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc3412.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc3414.php');

define('SNMP_VERSION_1',  0);
define('SNMP_VERSION_2',  1);
define('SNMP_VERSION_2C', 1);
define('SNMP_VERSION_2U', 2); // doesn't work yet
define('SNMP_VERSION_3',  3); // doesn't work yet

/**
 * SNMP
 *
 * @package phpSNMP
 */
class snmp
{
  var $version = SNMP_VERSION_1;	// version can be SNMP_VERSION_1, SNMP_VERSION_2C, SNMP_VERSION_3
  var $timeout = 10.0;			// timeout in seconds for waiting for a return packet
  var $default_security;		// default security parameters

 /**
  * Constructor
  */
  function snmp()
  {
    $this->default_security = array('community'=>'public', 'v3_flags'=>SNMP_NOAUTH_NOPRIV, 'v3_security_model'=>SNMP_SECURITY_USM,
                                    'v3_engine_id'=>'', 'v3_engine_boots'=>0, 'v3_engine_time'=>0, 'v3_user'=>'', 'v3_auth'=>'',
                                    'v3_priv'=>'', 'v3_context_engine_id'=>'', 'v3_context_name'=>'');
  }

 /**
  * get an oid from a single host
  *
  * @param string $host hostnames or ip addresses
  * @param mixed $target varbind array or oid (oids must be numeric)
  * @param array $security parameters
  * @return array in the format $oid=>$value
  */
  function get($host, $target, $security=NULL)
  {
    if(is_array($target))
      $varbind = $target;
    else
      $varbind = $this->build_varbind($target);

    $ret = $this->exec($host, 'get', $this->build_packet($varbind, $security, 'get'), $security);

    return array_shift($ret);
  }

 /**
  * get an oid from multiple hosts
  *
  * @param array $hosts hostnames or ip addresses
  * @param mixed $target varbind array or oid (oids must be numeric)
  * @param array $security parameters
  * @return array in the format $ip=>array($oid=>$value)
  */
  function multi_get($hosts, $target, $security=NULL)
  {
    if(is_array($target))
      $varbind = $target;
    else
      $varbind = $this->build_varbind($target);
    return $this->exec($hosts, 'get', $this->build_packet($varbind, $security, 'get'), $security);
  }

 /**
  * bulk get oids from a single host
  *
  * @param string $host hostname or ip address
  * @param array $oids (oids must be numeric)
  * @param array $security parameters
  * @return array in the format $oid=>$value
  */
  function bulk_get($host, $oids, $security=NULL)
  {
    $varbind = $this->build_varbind($oids);

    $ret = $this->exec($host, 'getbulk', $this->build_packet($varbind, $security, 'getbulk'), $security);

    return array_shift($ret);
  }

 /**
  * bulk get oids from a mulitple hosts
  *
  * @param string $hosts hostnames or ip addresses
  * @param array $oids (oids must be numeric)
  * @param array $security parameters
  * @return array in the format $oid=>$value
  */
  function multi_bulk_get($hosts, $oids, $security=NULL)
  {
    $varbind = $this->build_varbind($oids);
    return $this->exec($hosts, 'getbulk', $this->build_packet($varbind, $security, 'getbulk'), $security);
  }

 /**
  * walk an oid
  *
  * @param string $host hostnames or ip addresses
  * @param string $oid (oids must be numeric)
  * @param array $security parameters
  * @return array in the format $ip=>array($oid=>$value)
  */
  function walk($host, $oid, $security=NULL)
  {
    $varbind = $this->build_varbind($oid);

    $ret = $this->exec($host, 'getnext', $this->build_packet($varbind, $security, 'getnext'), $security, $oid);

    return array_shift($ret);
  }

 /**
  * walk an oid on multiple hosts
  *
  * @param array $hosts hostnames or ip addresses
  * @param sring $oid (oids must be numeric)
  * @param array $security parameters
  * @return array in the format $ip=>array($oid=>$value)
  */
  function multi_walk($hosts, $oid, $security=NULL)
  {
    $varbind = $this->build_varbind($oid);
    return $this->exec($hosts, 'getnext', $this->build_packet($varbind, $security, 'getnext'), $security, $oid);
  }

 /**
  * set a variable
  *
  * @param string $host hostname or ip address
  * @param mixed $target varbind array or oid (oids must be numeric)
  * @param mixed $value to set
  * @param string $type 'i' = integer; 't' = time ticks; 'x' = hex string; 's' = string; 'a' = IP address; 'o' = object ID; 'n' = null value
  * @param array $security parameters
  */
  function set($host, $target, $value=0, $type='i', $security=NULL)
  {
    if(is_array($target))
      $varbind = $target;
    else
      $varbind = $this->build_varbind($target, $value, $type);
    $this->exec($host, 'set', $this->build_packet($varbind, $security, 'set'), $security);
  }

 /**
  * set a variable
  *
  * @param array $hosts hostnames or ip addresses
  * @param mixed $target varbind array or oid (oids must be numeric)
  * @param mixed $value to set
  * @param string $type 'i' = integer; 't' = time ticks; 'x' = hex string; 's' = string; 'a' = IP address; 'o' = object ID; 'n' = null value
  * @param array $security parameters
  */
  function multi_set($hosts, $target, $value=0, $type='i', $security=NULL)
  {
    $this->set($hosts, $target, $value, $type, $security);
  }

 /**
  * send a trap
  *
  * @param string $manager hostname or ip address of the manager
  * @param array $security parameters
  * @param array $varbinds created by build_varbind
  * @param string $enterprise oid (oids must be numeric) of the object generating the trap (this is only for version 1)
  * @param string $agent hostname or ip address of the agent generating the trap (this is only for version 1)
  * @param integer $trap_type from TRAP_COLDSTART, TRAP_WARMSTART, TRAP_LINKDOWN, TRAP_LINKUP,
  *                                TRAP_AUTH_FAIL, TRAP_EGP_NEIGHBOR_LOSS, TRAP_ENTERPRISE_SPECIFIC
  *                                (this is only for version 1)
  * @param integer $specific_trap_type (this is only for version 1)
  * @param integer $timestamp time since last restart (this is only for version 1)
  */
  function trap($manager, $security, $varbind, $enterprise='', $agent='', $trap_type=0, $specific_trap_type=0, $timestamp=0)
  {
    if(is_null($security))
      $security = $this->default_security;
    elseif(!is_array($security))
    {
      $s = $this->default_security;
      $s['community'] = $security;
      $security = $s;
    }

    if($this->version == SNMP_VERSION_1)
    {
      $pdu = new rfc1157_TrapPDU(new rfc1155_ObjectID($enterprise), new rfc1155_NetworkAddress($agent),
                                 new rfc1157_GenericTrap($trap_type), new rfc1155_Integer($specific_trap_type),
                                 new rfc1155_TimeTicks($timestamp), $varbind);
      $msg = new rfc1157_Message(SNMP_VERSION_1, $security['community'], $pdu);
      $contents = $msg->encodeContents();
      $packet = chr(0x30) . $msg->encodeLength(strlen($contents)) . $contents;
    }
    elseif($this->version == SNMP_VERSION_2C || $this->version == SNMP_VERSION_3)
      $packet = $this->build_packet($varbind, $security, 'trap');
    else
    {
      trigger_error("Unknown SNMP version [{$this->version}]", E_USER_WARNING);
      return;
    }

    $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
    @socket_sendto($socket, $packet, strlen($packet), 0, $manager, 162);
  }

 /**
  * build a variable binding
  *
  * @param string $oid (oids must be numeric)
  * @param mixed $value to set
  * @param string $type 'i' = integer; 't' = time ticks; 'x' = hex string; 's' = string; 'a' = IP address; 'o' = object ID; 'n' = null value
  * @return array varbind
  */
  function build_varbind($oid, $value=0, $type='n')
  {
    if(!is_array($oid)) $oid = array($oid);

    if(!is_array($value))
    {
      $val = $value;
      $value = array();
      foreach(array_keys($oid) as $i)
        $value[$i] = $val;
    }
    if(!is_array($type))
    {
      $t = $type;
      $type = array();
      foreach(array_keys($oid) as $i)
        $type[$i] = $t;
    }

    $varbind = array();
    foreach($oid as $i=>$o)
    {
      switch($type[$i])
      {
        case 'i': // integer
          $varbind[] = new rfc1157_VarBind(new rfc1155_ObjectID($o), new rfc1155_Integer($value[$i]));
          break;
        case 't': // time ticks
          $varbind[] = new rfc1157_VarBind(new rfc1155_ObjectID($o), new rfc1155_TimeTicks($value[$i]));
          break;
        case 'x': // hex string
          $varbind[] = new rfc1157_VarBind(new rfc1155_ObjectID($o), new rfc1155_OctetString(hexbin($value[$i])));
          break;
        case 's': // string
          $varbind[] = new rfc1157_VarBind(new rfc1155_ObjectID($o), new rfc1155_OctetString($value[$i]));
          break;
        case 'a': // ip address
          $varbind[] = new rfc1157_VarBind(new rfc1155_ObjectID($o), new rfc1155_IPAddress($value[$i]));
          break;
        case 'o': // object id
          $varbind[] = new rfc1157_VarBind(new rfc1155_ObjectID($o), new rfc1155_ObjectID($value[$i]));
          break;
        case 'n': // null value
          $varbind[] = new rfc1157_VarBind(new rfc1155_ObjectID($o), new rfc1155_Null());
          break;
        default:
          trigger_error("Unknown type $type", E_USER_WARNING);
          $varbind[] = new rfc1157_VarBind(new rfc1155_ObjectID($o), new rfc1155_Null());
      }
    }
    return $varbind;
  }

 /**
  * execute a poll on hosts
  *
  * @param mixed $target
  * @param string $community string
  * @param string $type is either get, getnext, or set
  * @param string $value to use for set
  * @param string $value_type to use for set
  * @return string packet
  */
  function build_packet($varbind, $security=array('community'=>'public'), $type='get')
  {
    if(is_null($security))
      $security = $this->default_security;
    elseif(!is_array($security))
    {
      $s = $this->default_security;
      $s['community'] = $security;
      $security = $s;
    }

    if($this->version == SNMP_VERSION_1)
    {
      if($type == 'get')
        $pdu = new rfc1157_Get($this->assignRequestID(), 0, 0, $varbind);
      elseif($type == 'getnext')
        $pdu = new rfc1157_GetNext($this->assignRequestID(), 0, 0, $varbind);
      elseif($type == 'set')
        $pdu = new rfc1157_Set($this->assignRequestID(), 0, 0, $varbind);
      else
      {
        trigger_error("Unknown request type: $type", E_USER_WARNING);
        return '';
      }
      $msg = new rfc1157_Message(SNMP_VERSION_1, $security['community'], $pdu);
    }
    elseif($this->version == SNMP_VERSION_2C || $this->version == SNMP_VERSION_3)
    {
      $request_id = $this->assignRequestID();
      if($type == 'get')
        $pdu = new rfc1905_Get($request_id, 0, 0, $varbind);
      elseif($type == 'getnext')
        $pdu = new rfc1905_GetNext($request_id, 0, 0, $varbind);
      elseif($type == 'set')
        $pdu = new rfc1905_Set($request_id, 0, 0, $varbind);
      elseif($type == 'getbulk')
        $pdu = new rfc1905_GetBulk($request_id, count($varbind), 1, $varbind);
      elseif($type == 'inform')
        $pdu = new rfc1905_Inform($request_id, 0, 0, $varbind);
      elseif($type == 'trap')
        $pdu = new rfc1905_Trap($request_id, 0, 0, $varbind);
      elseif($type == 'report')
        $pdu = new rfc1905_Report($request_id, 0, 0, $varbind);
      else
      {
        trigger_error("Unknown request type: $type", E_USER_WARNING);
        return '';
      }
      if($this->version == SNMP_VERSION_2C)
        $msg = new rfc1905_Message(SNMP_VERSION_2C, $security['community'], $pdu);
      else
      {
        $header = new rfc3412_Header($request_id, $security['v3_flags'], $security['v3_security_model']);
        $security = new rfc3411_USM($security['v3_engine_id'], $security['v3_engine_boots'], $security['v3_engine_time'],
                                    $security['v3_user'], $security['v3_auth'], $security['v3_priv']);

        $scopedpdu = new rfc3412_ScopedPDU($security['v3_context_engine_id'], $security['v3_context_name'], $pdu);
        $msg = new rfc3412_Message(SNMP_VERSION_3, $header, $security, $scopedpdu);
      }
    }
    else
    {
      trigger_error("Unknown SNMP version {$this->version}", E_USER_WARNING);
      return '';
    }

    $contents = $msg->encodeContents();
    return chr(0x30) . $msg->encodeLength(strlen($contents)) . $contents;
  }

 /**
  * execute a poll on hosts
  *
  * @param array $hosts hostnames or ip addresses
  * @param string $type is either get, getnext, or set
  * @param string $packet to send
  * @param array $security parameters
  * @param string $stop
  * @return array in the format $ip=>array($oid=>$value)
  */
  function exec($hosts, $type, $packet, $security=array('community'=>'public'), $stop='')
  {
    $queue = array();
    $buffer = $port = NULL;
    $ret = array();

    // add each host to the queue
    if(!is_array($hosts))
      $hosts = array($hosts);
    foreach($hosts as $host)
    {
      if(ip2long($host) == -1) $host = gethostbyname($host); // we don't like hostnames
      $queue[] = array($packet, $host);
      $ret[$host] = array();
    }

    // create a message to decode with
    if($this->version == SNMP_VERSION_1)
      $msg = new rfc1157_Message();
    elseif($this->version == SNMP_VERSION_2C)
      $msg = new rfc1905_Message();
    else
    {
      trigger_error("Unknown SNMP version {$this->version}", E_USER_WARNING);
      return array();
    }

    $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
    socket_set_nonblock($socket);

    $sent = 0;
    $received = 0;
    $t = $this->microtime();
    $block_state = 0; // 0 = nonblock, 1 = block, 2 = failed block
    while(count($queue))
    {
      do
      {
        if(count($queue))
        {
          // send next queue entry
          $entry = array_shift($queue);
          if(strlen($entry[0]))
          {
            if($block_state == 1)
            {
              socket_set_nonblock($socket);
              $block_state = 0;
            }
            @socket_sendto($socket, $entry[0], strlen($entry[0]), 0, $entry[1], 161);
            $sent++;
            $t = $this->microtime();
          }
        }
        elseif($block_state == 0)
        {
          // we are done sending, try to set state to blocking I/O with a timeout
          if(@socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, array('sec'=>floor($this->timeout), 'usec'=>0)))
          {
            socket_set_block($socket);
            $block_state = 1;
          }
          else
            $block_state = 2;
        }
        elseif($block_state == 2) // sleep if we failed to set a timeout
        {
          usleep(10000);
        }

        $buffer = $rhost = NULL;
        @socket_recvfrom($socket, $buffer, 4096, 0, $rhost, $port);
        if($buffer != '' && isset($ret[$rhost]))
        {
          $received++;
          // decode and store packet
          $msg = $msg->decode($buffer);
          if($msg->data->errorStatus->value)
            trigger_error($msg->data->errorStatus->toString(), E_USER_WARNING);
          foreach($msg->data->varBindList->value as $val)
          {
            $oid = $val->objectID->toString();
            if(($stop == '' || strpos(' '. $oid, $stop) != 0) && !isset($ret[$rhost][$oid]))
            {
              if($type == 'getnext')
                $queue[] = array($this->build_packet($this->build_varbind($oid), $security, 'getnext'), $rhost);
              $ret[$rhost][$oid] = $val->objectValue->toString();
            }
          }
        }
      } while($sent != $received && $this->microtime() - $t <= $this->timeout);
    }
    return $ret;
  }

 /**
  * Assign a unique requestID
  *
  * @return integer a request id
  */
  function assignRequestID()
  {
    static $nextRequestID = 0;
    if($nextRequestID == 0 || $nextRequestID >= 2147483647) $nextRequestID = mt_rand();
    return $nextRequestID++;
  }

 /**
  * Get microtime as a float
  *
  * @return float microtime
  */
  function microtime()
  {
    list($usec, $sec) = explode(' ', microtime());
    return ((float)$usec + (float)$sec);
  }
}
?>

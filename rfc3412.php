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
 * @subpackage rfc1155
 * @version .7
 */

/**
 */

require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc1155.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc1905.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc3411.php');

define('SNMP_NOAUTH_NOPRIV', 0);
define('SNMP_AUTH_NOPRIV',   1);
define('SNMP_AUTH_PRIV',     3);

define('SNMP_SECURITY_ANY',  0);
define('SNMP_SECURITY_V1',   1);
define('SNMP_SECURITY_V2C',  2);
define('SNMP_SECURITY_USM',  3);

/**
 * SNMP v3 Message
 *
 * @package phpSNMP
 * @subpackage rfc3412
 */
class rfc3412_Message extends rfc1155_Sequence
{
  var $version;
  var $header;
  var $security;
  var $scoped_pdu;

 /**
  * Constructor
  *
  * @param integer $version
  * @param rfc3412_Header $header
  * @param rfc3414_USM $security
  * @param rfc3412_ScopedPDU $scopedpdu
  */
  function rfc3412_Message($version=3, $header=NULL, $security=NULL, $scopedpdu=NULL)
  {
    parent::rfc1155_Sequence();

    $this->version = new rfc1155_Integer($version);
    $this->header = $header;
    $this->security = new rfc1155_OctetString($security->encodeContents());
    $this->scoped_pdu = $scopedpdu;

    $this->value = aray($this->version, $this->header, $this->security, $this->scoped_pdu);
  }

 /**
  * Decode Stream
  *
  * decode() an octet stream into a sequence of Asn1Objects
  *
  * @param string $stream
  * @return rfc3412_Message
  */
  function decode($stream)
  {
    $objectList = parent::decode($stream);
    if(count($objectList) != 1)
      trigger_error('Malformed Message: More than one object decoded.', E_USER_WARNING);
    if(count($objectList[0]->value) != 4)
      trigger_error('Malformed Message: Incorrect sequence length ' . count($objectList[0]->value), E_USER_WARNING);

    $this->version = $objectList[0]->value[0];
    $this->header = $objectList[0]->value[1];
    $this->security = $objectList[0]->value[2];
    $this->scoped_pdu = $objectList[0]->value[3];
    return $this;
  }
}

/**
 * SNMP v3 Message Header
 *
 * @package phpSNMP
 * @subpackage rfc3412
 */
class rfc3412_Header extends rfc1155_Sequence
{
  var $msgid;
  var $maxsize;
  var $flags;
  var $security;

 /**
  * Constructor
  *
  * @param integer $msgid
  * @param string $flags
  * @param string $security
  */
  function rfc3412_Header($msgid, $flags=SNMP_NOAUTH_NOPRIV, $security=SNMP_SECURITY_USM)
  {
    parent::rfc1155_Sequence();

    $this->msgid = new rfc1155_Integer($msgid);
    $this->maxsize = new rfc1155_Integer(65535); // must be 484..2147483647
    $this->flags = new rfc1155_OctetString($flags); // noAuthNoPriv(0), authNoPriv(1), authPriv(3)
    $this->security = new rfc1155_Integer($security); // any(0), v1(1), v2c(2), usm(3)

    $this->value = array($this->msgid, $this->maxsize, $this->flags, $this->security);
  }

 /**
  * Decode Stream
  *
  * decode() an octet stream into a sequence of Asn1Objects
  *
  * @param string $stream
  * @return rfc3412_Header
  */
  function decode($stream)
  {
    $objectList = parent::decode($stream);
    if(count($objectList) != 1)
      trigger_error('Malformed Message: More than one object decoded.', E_USER_WARNING);
    if(count($objectList[0]->value) != 4)
      trigger_error('Malformed Message: Incorrect sequence length ' . count($objectList[0]->value), E_USER_WARNING);

    $this->id = $objectList[0]->value[0];
    $this->maxsize = $objectList[0]->value[1];
    $this->flags = $objectList[0]->value[2];
    $this->security = $objectList[0]->value[3];
    return $this;
  }
}

/**
 * SNMP v3 Scoped PDU
 *
 * @package phpSNMP
 * @subpackage rfc3412
 */
class rfc3412_ScopedPDU extends rfc1155_Sequence
{
  var $id;
  var $name;
  var $data;

 /**
  * Constructor
  *
  * @param string $engineid
  * @param string $name
  * @param rfc1905_PDU $data
  */
  function rfc3412_ScopedPDU($engineid, $name, $data)
  {
    parent::rfc1155_Sequence();

    $this->id = new rfc3411_EngineID($engineid);
    $this->name = new rfc1155_OctetString($name);
    $this->data = $data;

    $this->value = array($this->id, $this->name, $this->data);
  }

 /**
  * Decode Stream
  *
  * decode() an octet stream into a sequence of Asn1Objects
  *
  * @param string $stream
  * @return rfc3412_ScopedPDU
  */
  function decode($stream)
  {
    $objectList = parent::decode($stream);
    if(count($objectList) != 1)
      trigger_error('Malformed Message: More than one object decoded.', E_USER_WARNING);
    if(count($objectList[0]->value) != 3)
      trigger_error('Malformed Message: Incorrect sequence length ' . count($objectList[0]->value), E_USER_WARNING);

    $this->id = $objectList[0]->value[0];
    $this->name = $objectList[0]->value[1];
    $this->data = $objectList[0]->value[2];
    return $this;
  }
}
?>

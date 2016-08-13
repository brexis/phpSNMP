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
 * @subpackage rfc1157
 * @version .7
 */

/**
 */
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc1155.php');

define('ASN_TAG_GET',                   0x00);
define('ASN_TAG_GETNEXT',               0x01);
define('ASN_TAG_RESPONSE',              0x02);
define('ASN_TAG_SET',                   0x03);
define('ASN_TAG_TRAP',                  0x04);

$ASN_TAG_DICT[0xa0] = 'rfc1157_Get';
$ASN_TAG_DICT[0xa1] = 'rfc1157_GetNext';
$ASN_TAG_DICT[0xa2] = 'rfc1157_Response';
$ASN_TAG_DICT[0xa3] = 'rfc1157_Set';
$ASN_TAG_DICT[0xa4] = 'rfc1157_TrapPDU';

/**
 * Error Status
 *
 * @package phpSNMP
 * @subpackage rfc1157
 */
class rfc1157_ErrorStatus extends rfc1155_Integer
{
  var $errString;
  var $errNum;

 /**
  * Constructor
  *
  * @param integer $value
  */
  function rfc1157_ErrorStatus($value)
  {
    parent::rfc1155_Integer($value);
    $this->errString = array('No Error', 'Response message would have been too large', 'There is no such variable name in this MIB',
                             'The value given has the wrong type', 'Object is Read Only', 'An unknown error occurred');
    $this->errNum = array('noError'=>0, 'tooBig'=>1, 'noSuchName'=>2, 'badValue'=>3, 'readOnly'=>4, 'genErr'=>5);
  }

 /**
  * ToString
  *
  * @return string value of this object
  */
  function toString()
  {
    return $this->errString[$this->value];
  }

 /**
  * Get Error
  *
  * @return string
  */
  function get_error()
  {
    return $this->errString[$this->value];
  }
}

/**
 * Variable Binding
 *
 * This binds a name to an object
 *
 * @package phpSNMP
 * @subpackage rfc1157
 */
class rfc1157_VarBind extends rfc1155_Sequence
{
 /**
  * Constructor
  *
  * @param rfc1155_ObjectID $name
  * @param rfc1155_Asn1Object $value
  */
  function rfc1157_VarBind($name=NULL, $value=NULL)
  {
    if($name && !is_a($name, 'rfc1155_ObjectID'))
      trigger_error('name must be an rfc1155_ObjectID', E_USER_WARNING);
    if($value && !is_a($value, 'rfc1155_Asn1Object'))
      trigger_error('value must be an rfc1155_Asn1Object', E_USER_WARNING);
    parent::rfc1155_Sequence(array($name, $value));
    $this->objectID = $name;
    $this->objectValue = $value;
  }
}

/**
 * Variable Binding List
 *
 * A Sequence of VarBinds
 *
 * @package phpSNMP
 * @subpackage rfc1157
 */
class rfc1157_VarBindList extends rfc1155_SequenceOf
{
 /**
  * Constructor
  *
  * @param array $value of rfc1157_VarBind
  */
  function rfc1157_VarBindList($value=array())
  {
    parent::rfc1155_SequenceOf('rfc1157_VarBind', $value);
  }
}

/**
 * Message
 *
 * A Message is the base comms type for all SNMP messages
 *
 * @package phpSNMP
 * @subpackage rfc1157
 */
class rfc1157_Message extends rfc1155_Sequence
{
  var $version;
  var $community;
  var $data;

 /**
  * Constructor
  *
  * @param integer $version
  * @param string $community
  * @param mixed $data
  */
  function rfc1157_Message($version=0, $community='public', $data=NULL)
  {
    parent::rfc1155_Sequence();
    $this->version = new rfc1155_Integer($version);
    $this->community = new rfc1155_OctetString($community);
    $this->data = $data;
    $this->value = array($this->version, $this->community, $this->data);
  }

 /**
  * Decode Stream
  *
  * decode() an octet stream into a sequence of Asn1Objects
  *
  * @param string $stream
  * @return rfc1157_Message
  */
  function decode($stream)
  {
    $objectList = parent::decode($stream);
    if(count($objectList) != 1)
      trigger_error('Malformed Message: More than one object decoded.', E_USER_WARNING);
    if(count($objectList[0]->value) != 3)
      trigger_error('Malformed Message: Incorrect sequence length ' . count($objectList[0]->value), E_USER_WARNING);

    $this->version = $objectList[0]->value[0];
    $this->community = $objectList[0]->value[1];
    $this->data = $objectList[0]->value[2];
    return $this;
  }
}

/**
 * PDU
 *
 * Base clss for a non-trap PDU
 *
 * @package phpSNMP
 * @subpackage rfc1157
 */
class rfc1157_PDU extends rfc1155_Sequence
{
  // Base class for a non-trap PDU
  var $requestID;
  var $errorStatus;
  var $errorIndex;
  var $varBindList;

 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $errorStatus
  * @param integer $errorIndex
  * @param array $varBindList
  */
  function rfc1157_PDU($requestID=0, $errorStatus=0, $errorIndex=0, $varBindList=array())
  {
    /* this allows you to create a new object with no arguments, arguments of the class ultimately desired (eg Integer)
       or, to make like easier, it will convert basic strings and ints into the ultimately desired objects. */

    parent::rfc1155_Sequence();
    $this->asnTagClass = ASN_TAG_CLASS_CONTEXT;

    $this->requestID = new rfc1155_Integer($requestID);
    $this->errorStatus = new rfc1157_ErrorStatus($errorStatus);
    $this->errorIndex = new rfc1155_Integer($errorIndex);
    $this->varBindList = new rfc1157_VarBindList($varBindList);

    $this->value = array($this->requestID, $this->errorStatus, $this->errorIndex, $this->varBindList);
  }

 /**
  * Decode into a PDU Object
  *
  * @param string $stream
  * @return rfc1157_PDU
  */
  function decodeContents($stream)
  {
    $objectList = parent::decodeContents($stream);

    if(count($this->value) != 4)
      trigger_error('Malformed PDU: Incorrect length ' . count($this->value), E_USER_WARNING);

    // Build things with the correct type
    $myVarList = array();
    foreach($objectList->value[3]->value as $item)
      $myVarList[] = new rfc1157_VarBind($item->value[0], $item->value[1]);
    return new rfc1157_PDU(intval($objectList->value[0]->value), intval($objectList->value[1]->value), intval($objectList->value[2]->value), $myVarList);
  }
}

/**
 * GET request
 *
 * A Get Request PDU
 *
 * @package phpSNMP
 * @subpackage rfc1157
 */
class rfc1157_Get extends rfc1157_PDU
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $errorStatus
  * @param integer $errorIndex
  * @param array $varBindList
  */
  function rfc1157_Get($requestID=0, $errorStatus=0, $errorIndex=0, $varBindList=array())
  {
    parent::rfc1157_PDU($requestID, $errorStatus, $errorIndex, $varBindList);
    $this->asnTagNumber = ASN_TAG_GET;
  }
}

/**
 * GETNEXT request
 *
 * A GetNext Request PDU
 *
 * @package phpSNMP
 * @subpackage rfc1157
 */
class rfc1157_GetNext extends rfc1157_PDU
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $errorStatus
  * @param integer $errorIndex
  * @param array $varBindList
  */
  function rfc1157_GetNext($requestID=0, $errorStatus=0, $errorIndex=0, $varBindList=array())
  {
    parent::rfc1157_PDU($requestID, $errorStatus, $errorIndex, $varBindList);
    $this->asnTagNumber = ASN_TAG_GETNEXT;
  }
}

/**
 * RESPONSE request
 *
 * A Response PDU
 *
 * @package phpSNMP
 * @subpackage rfc1157
 */
class rfc1157_Response extends rfc1157_PDU
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $errorStatus
  * @param integer $errorIndex
  * @param array $varBindList
  */
  function rfc1157_Response($requestID=0, $errorStatus=0, $errorIndex=0, $varBindList=array())
  {
    parent::rfc1157_PDU($requestID, $errorStatus, $errorIndex, $varBindList);
    $this->asnTagNumber = ASN_TAG_GET;
  }
}

/**
 * SET request
 *
 * A Set Request PDU
 *
 * @package phpSNMP
 * @subpackage rfc1157
 */
class rfc1157_Set extends rfc1157_PDU
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $errorStatus
  * @param integer $errorIndex
  * @param array $varBindList
  */
  function rfc1157_Set($requestID=0, $errorStatus=0, $errorIndex=0, $varBindList=array())
  {
    parent::rfc1157_PDU($requestID, $errorStatus, $errorIndex, $varBindList);
    $this->asnTagNumber = ASN_TAG_SET;
  }
}

define('TRAP_COLDSTART', 0);
define('TRAP_WARMSTART', 1);
define('TRAP_LINKDOWN', 2);
define('TRAP_LINKUP', 3);
define('TRAP_AUTH_FAIL', 4);
define('TRAP_EGP_NEIGHBOR_LOSS', 5);
define('TRAP_ENTERPRISE_SPECIFIC', 6);

/**
 * Generic Trap
 *
 * @package phpSNMP
 * @subpackage rfc1157
 */
class rfc1157_GenericTrap extends rfc1155_Integer
{
  var $genericTraps;

 /**
  * Constructor
  *
  * @param integer $value
  */
  function rfc1157_GenericTrap($value)
  {
    parent::rfc1155_Integer($value);
  }
}

/**
 * Trap PDU
 *
 * @package phpSNMP
 * @subpackage rfc1157
 */
class rfc1157_TrapPDU extends rfc1155_Sequence
{
  var $enterprise;
  var $agentAddr;
  var $genericTrap;
  var $specificTrap;
  var $varBindList;

 /**
  * Constructor
  *
  * @param rfc1155_ObjectID $enterprise
  * @param rfc1155_NetworkAddress $agentAddr
  * @param rfc1157_GenericTrap $genericTrap
  * @param rfc1155_Integer $specificTrap
  * @param rfc1155_TimeTicks $timestamp
  * @param array $varBindList
  */
  function rfc1157_TrapPDU($enterprise=NULL, $agentAddr=NULL, $genericTrap=NULL, $specificTrap=NULL, $timestamp=NULL, $varBindList=NULL)
  {
    parent::rfc1155_Sequence();
    $this->asnTagClass = ASN_TAG_CLASS_CONTEXT;
    $this->asnTagNumber = ASN_TAG_TRAP;

    $this->enterprise = $enterprise;					// ObjectID
    $this->agentAddr = $agentAddr;					// NetworkAddress
    $this->genericTrap = $genericTrap;					// GenericTrap
    $this->specificTrap = $specificTrap;				// Integer
    $this->timestamp = $timestamp;					// TimeTicks
    $this->varBindList = new rfc1157_VarBindList($varBindList);		// VarBindList

    $this->value = array($this->enterprise, $this->agentAddr, $this->genericTrap, $this->specificTrap, $this->timestamp, $this->varBindList);
  }

 /**
  * Decode into a Get PDU Object
  *
  * @param string $stream
  * @return rfc1157_TrapPDU
  */
  function decodeContents($stream)
  {
    $objectList = parent::decodeContents($stream);
    if(count($this->value) != 6)
      trigger_error('Malformed TrapPDU: Incorrect length ' . count($this->value), E_USER_WARNING);

    // Build things with the correct type
    $myVarList = new rfc1157_VarBindList();
    foreach($objectList[5] as $item)
      $myVarList->value[] = new rfc1157_VarBind($item[0], $item[1]);

    return new rfc1157_TrapPDU($objectList[0], $objectList[1], intval($objectList[2]), intval($objectList[3]), $objectList[4], $myVarList);
  }
}
?>

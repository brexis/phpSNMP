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
 * @subpackage rfc1905
 * @version .7
 */

/**
 */
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc1155.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc1157.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc1902.php');

define('MAX_BINDINGS', 2147483647);

define('ASN_TAG_GETBULK', 	0x05);
define('ASN_TAG_INFORM', 	0x06);
define('ASN_TAG_TRAPV2', 	0x07);
define('ASN_TAG_REPORT', 	0x08);

$ASN_TAG_DICT[0xa2] = 'rfc1905_Response';
$ASN_TAG_DICT[0xa5] = 'rfc1905_GetBulk';
$ASN_TAG_DICT[0xa6] = 'rfc1905_Inform';
$ASN_TAG_DICT[0xa7] = 'rfc1905_TrapV2';
$ASN_TAG_DICT[0xa8] = 'rfc1905_Report';

// ucd-snmp returns context-specific values at time
define('ASN_TAG_NO_SUCH_OBJECT',	0x80);
define('ASN_TAG_NO_SUCH_INSTANCE',	0x81);
define('ASN_TAG_END_OF_MIB_VIEW',	0x82);
$ASN_TAG_DICT[0x80] = 'rfc1905_NoSuchObject';
$ASN_TAG_DICT[0x81] = 'rfc1905_NoSuchInstance';
$ASN_TAG_DICT[0x82] = 'rfc1905_EndOfMibView';

/**
 * No Such Object
 *
 * This is a special type for ucd-snmp
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_NoSuchObject extends rfc1155_Null
{
  function rfc1905_NoSuchObject()
  {
    parent::rfc1155_Null();
    $this->asnTagNumber = ASN_TAG_NO_SUCH_OBJECT;
  }

 /**
  * ToString
  *
  * @return string value of this object
  */
  function toString()
  {
    return 'No such Object';
  }
}

/**
 * No Such Instance
 *
 * This is a special type for ucd-snmp
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_NoSuchInstance extends rfc1155_Null
{
 /**
  * Constructor
  */
  function rfc1905_NoSuchInstance()
  {
    parent::rfc1155_Null();
    $this->asnTagNumber = ASN_TAG_NO_SUCH_INSTANCE;
  }

 /**
  * ToString
  *
  * @return string value of this object
  */
  function toString()
  {
    return 'No such Instance';
  }
}

/**
 * End Of MIB View
 *
 * This is a special type for ucd-snmp
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_EndOfMibView extends rfc1155_Null
{
 /**
  * Constructor
  */
  function rfc1905_EndOfMibView()
  {
    parent::rfc1155_Null();
    $this->asnTagNumber = ASN_TAG_END_OF_MIB_VIEW;
  }

 /**
  * ToString
  *
  * @return string value of this object
  */
  function toString()
  {
    return 'End of MIB';
  }
}

/**
 * Variable Binding List
 *
 * An SNMPv2 VarBindList has a maximum size of MAX_BINDINGS
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_VarBindList extends rfc1157_VarBindList
{
 /**
  * Constructor
  *
  * @param array $value
  */
  function rfc1905_VarBindList($value=array())
  {
    if(count($value) > MAX_BINDINGS)
      trigger_error('A VarBindList must be shorter than ' . MAX_BINDINGS, E_USER_WARNING);
    parent::rfc1157_VarBindList($value);
  }
}

/**
 * Message
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_Message extends rfc1157_Message
{
 /**
  * Constructor
  *
  * @param integer $version
  * @param string $community
  * @param mixed $data
  */
  function rfc1905_Message($version=1, $community='public', $data=NULL)
  {
    parent::rfc1157_Message($version, $community, $data);
  }
}

/**
 * Error Status
 *
 * An SNMPv2 Error status
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_ErrorStatus extends rfc1157_ErrorStatus
{
 /**
  * Constructor
  *
  * @param integer $value
  */
  function rfc1905_ErrorStatus($value)
  {
    parent::rfc1157_ErrorStatus($value);

    # add to the SNMPv1 error strings
    $this->errString[6] = 'Access is not permitted';
    $this->errString[7] = 'Type is incorrect';
    $this->errString[8] = 'Length is incorrect';
    $this->errString[9] = 'Encoding is incorrect';
    $this->errString[10] = 'Value is incorrect';
    $this->errString[11] = 'No creation';
    $this->errString[12] = 'Value is inconsistent';
    $this->errString[13] = 'Resourse Unavailable';
    $this->errString[14] = 'Commit Failed';
    $this->errString[15] = 'Undo Failed';
    $this->errString[16] = 'Authorization Error';
    $this->errString[17] = 'Not Writable';
    $this->errString[18] = 'Inconsistent Name';

    $this->errNum[6]  = 'noAccess';
    $this->errNum[7]  = 'wrongType';
    $this->errNum[8]  = 'wrongLength';
    $this->errNum[9]  = 'wrongEncoding';
    $this->errNum[10] = 'wrongValue';
    $this->errNum[11] = 'noCreation';
    $this->errNum[12] = 'inconsistentValue';
    $this->errNum[13] = 'resourceUnavailable';
    $this->errNum[14] = 'commitFailed';
    $this->errNum[15] = 'undoFailed';
    $this->errNum[16] = 'authorizationError';
    $this->errNum[17] = 'notWritable';
    $this->errNum[18] = 'inconsistentName';
  }
}

/**
 * PDU
 *
 * SNMPv2 PDUs are very similar to SNMPv1 PDUs
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_PDU extends rfc1157_PDU
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $errorStatus
  * @param integer $errorIndex
  * @param array $varBindList
  */
  function rfc1905_PDU($requestID=0, $errorStatus=0, $errorIndex=0, $varBindList=array())
  {
    parent::rfc1157_PDU();
    $this->asnTagClass = ASN_TAG_CLASS_CONTEXT;

    if($errorIndex > MAX_BINDINGS)
      trigger_error('errorIndex must be <= ' . MAX_BINDINGS, E_USER_WARNING);

    $this->requestID = new rfc1902_Integer32($requestID);
    $this->errorStatus = new rfc1905_ErrorStatus($errorStatus);
    $this->errorIndex = new rfc1155_Integer($errorIndex);
    $this->varBindList = new rfc1905_VarBindList($varBindList);

    $this->value = array($this->requestID, $this->errorStatus, $this->errorIndex, $this->varBindList);
  }

/*
#    def decodeContents(self, stream):
#        """ Decode into a PDU object
#        """
#        objectList = Sequence.decodeContents(self, stream)
#        if len(self.value) != 4:
#            raise PDUError('Malformed PDU: Incorrect length %d' % len(self.value) )
#
#        # Build things with the correct types
#        for item in objectList[3]:
#            myVarList.append( VarBind(item[0], item[1]) )
#
#        return self.__class__( int(objectList[0]), int(objectList[1]), int(objectList[2]), myVarList)
*/
}

/**
 * Bulk PDU
 *
 * BulkPDU is a new type of PDU specifically for doing GetBulk requests in SNMPv2.
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_BulkPDU extends rfc1155_Sequence
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $nonRepeaters
  * @param integer $maxRepetitions
  * @param array $varBindList
  */
  function rfc1905_BulkPDU($requestID=0, $nonRepeaters=0, $maxRepetitions=0, $varBindList=array())
  {
    parent::rfc1155_Sequence();
    $this->asnTagClass = ASN_TAG_CLASS_CONTEXT;

    if($nonRepeaters > MAX_BINDINGS)
      trigger_error('nonRepeaters must be <= ' . MAX_BINDINGS, E_USER_WARNING);
    if($maxRepetitions > MAX_BINDINGS)
      trigger_error('nonRepeaters must be <= ' . MAX_BINDINGS, E_USER_WARNING);

    $this->requestID = new rfc1902_Integer32($requestID);
    $this->nonRepeaters = new rfc1155_Integer($nonRepeaters);
    $this->maxRepetitions = new rfc1155_Integer($maxRepetitions);
    $this->varBindList = new rfc1905_VarBindList($varBindList);

    $this->value = array($this->requestID, $this->nonRepeaters, $this->maxRepetitions, $this->varBindList);
  }

 /**
  * Decode Contents
  *
  * Decode octet stream
  *
  * @param string $stream
  * @return rfc1905_BulkPDU
  */
  function decodeContents($stream) // Decode into a BulkPDU object
  {
    $objectList = parent::decodeContents($stream);
    if(count($this->value) != 4)
      trigger_error('Malformed BulkPDU: Incorrect length ' . count($this->value), E_USER_WARNING);

    // Build things with the correct types
    foreach($objectList[3] as $item)
      $myVarList[] = new VarBind($item[0], $item[1]);

    return new rfc1905_BulkPDU(intval($objectList[0]), intval($objectList[1]), intval($objectList[2]), $myVarList);
  }
}

/**
 * Get Request
 *
 * An SNMPv2 Get Request PDU
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_Get extends rfc1905_PDU
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $errorStatus
  * @param integer $errorIndex
  * @param array $varBindList
  */
  function rfc1905_Get($requestID=0, $errorStatus=0, $errorIndex=0, $varBindList=array())
  {
    parent::rfc1905_PDU($requestID, $errorStatus, $errorIndex, $varBindList);
    $this->asnTagNumber = ASN_TAG_GET;
  }
}

/**
 * Get Next Request
 *
 * An SNMPv2 Get Next Request PDU
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_GetNext extends rfc1905_PDU
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $errorStatus
  * @param integer $errorIndex
  * @param array $varBindList
  */
  function rfc1905_GetNext($requestID=0, $errorStatus=0, $errorIndex=0, $varBindList=array())
  {
    parent::rfc1905_PDU($requestID, $errorStatus, $errorIndex, $varBindList);
    $this->asnTagNumber = ASN_TAG_GETNEXT;
  }
}

/**
 * Response
 *
 * An SNMPv2 Response PDU
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_Response extends rfc1905_PDU
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $errorStatus
  * @param integer $errorIndex
  * @param array $varBindList
  */
  function rfc1905_Response($requestID=0, $errorStatus=0, $errorIndex=0, $varBindList=array())
  {
    parent::rfc1905_PDU($requestID, $errorStatus, $errorIndex, $varBindList);
    $this->asnTagNumber = ASN_TAG_RESPONSE;
  }
}

/**
 * Set Request
 *
 * An SNMPv2 set Request PDU
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_Set extends rfc1905_PDU
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $errorStatus
  * @param integer $errorIndex
  * @param array $varBindList
  */
  function rfc1905_Set($requestID=0, $errorStatus=0, $errorIndex=0, $varBindList=array())
  {
    parent::rfc1905_PDU($requestID, $errorStatus, $errorIndex, $varBindList);
    $this->asnTagNumber = ASN_TAG_SET;
  }
}

/**
 * Get Bulk Request
 *
 * An SNMPv2 Get Bulk Request PDU
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_GetBulk extends rfc1905_BulkPDU
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $nonRepeaters
  * @param integer $maxRepetitions
  * @param array $varBindList
  */
  function rfc1905_GetBulk($requestID=0, $nonRepeaters=0, $maxRepetitions=0, $varBindList=array())
  {
    parent::rfc1905_BulkPDU($requestID, $nonRepeaters, $maxRepetitions, $varBindList);
    $this->asnTagNumber = ASN_TAG_GETBULK;
  }
}

/**
 * Inform
 *
 * An SNMPv2 Inform PDU
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_Inform extends rfc1905_PDU
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $errorStatus
  * @param integer $errorIndex
  * @param array $varBindList
  */
  function rfc1905_Inform($requestID=0, $errorStatus=0, $errorIndex=0, $varBindList=array())
  {
    parent::rfc1905_PDU($requestID, $errorStatus, $errorIndex, $varBindList);
    $this->asnTagNumber = ASN_TAG_INFORM;
  }
}

/**
 * Trap
 *
 * An SNMPv2 Trap PDU
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_Trap extends rfc1905_PDU
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $errorStatus
  * @param integer $errorIndex
  * @param array $varBindList
  */
  function rfc1905_Trap($requestID=0, $errorStatus=0, $errorIndex=0, $varBindList=array())
  {
    parent::rfc1905_PDU($requestID, $errorStatus, $errorIndex, $varBindList);
    $this->asnTagNumber = ASN_TAG_TRAPV2;
  }
}

/**
 * Report
 *
 * An SNMPv2 Report PDU
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_Report extends rfc1905_PDU
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $errorStatus
  * @param integer $errorIndex
  * @param array $varBindList
  */
  function rfc1905_Report($requestID=0, $errorStatus=0, $errorIndex=0, $varBindList=array())
  {
    parent::rfc1905_PDU($requestID, $errorStatus, $errorIndex, $varBindList);
    $this->asnTagNumber = ASN_TAG_REPORT;
  }
}
?>

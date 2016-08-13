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
 * @subpackage rfc1902
 * @version .7
 */

/**
 */
define('ASN_TAG_COUNTER64',	0x06);

require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc1155.php');

/*** These tags are commented because they don't add any funcionality and conflict with rfc1155 codes ***/

// $ASN_TAG_DICT[0x02] = 'rfc1902_Integer32';
// $ASN_TAG_DICT[0x41] = 'rfc1902_Counter32';
// $ASN_TAG_DICT[0x42] = 'rfc1902_Guage32';
$ASN_TAG_DICT[0x46] = 'rfc1902_Counter64';

/**
 * Integer32
 *
 * A 32 bit integer
 *
 * @package phpSNMP
 * @subpackage rfc1902
 */
class rfc1902_Integer32 extends rfc1155_Integer
{
 /**
  * Constructor
  *
  * @param integer $value
  */
  function rfc1902_Integer32($value)
  {
    $this->MINVAL = -2147483648;
    $this->MAXVAL = 2147483648;
    parent::rfc1155_Integer($value);
  }
}

/**
 * Counter32
 *
 * A 32 bit counter
 *
 * @package phpSNMP
 * @subpackage rfc1902
 */
class rfc1902_Counter32 extends rfc1155_Counter
{
 /**
  * Constructor
  *
  * @param integer $value
  */
  function rfc1902_Counter32($value)
  {
    parent::rfc1155_Counter($value);
  }
}

/**
 * Guage32
 *
 * A 32 bit guage
 *
 * @package phpSNMP
 * @subpackage rfc1902
 */
class rfc1902_Guage32 extends rfc1155_Guage
{
 /**
  * Constructor
  *
  * @param integer $value
  */
  function rfc1902_Guage32($value)
  {
    parent::rfc1155_Guage($value);
  }
}

/**
 * Counter64
 *
 * A 64 bit counter
 *
 * @package phpSNMP
 * @subpackage rfc1902
 */
class rfc1902_Counter64 extends rfc1155_Counter
{
 /**
  * Constructor
  *
  * @param integer $value
  */
  function rfc1902_Counter64($value=0)
  {
    $this->MINVAL = 0;
    $this->MAXVAL = 18446744073709551615;
    $this->asnTagClass = ASN_TAG_COUNTER64;
    parent::rfc1155_Counter($value);
  }
}

/**
 * Octet String
 *
 * An SNMP v2 OctetString must be between 0 and 65535 bytes in length
 *
 * @package phpSNMP
 * @subpackage rfc1902
 */
class rfc1902_OctetString extends rfc1155_OctetString
{
 /**
  * Constructor
  *
  * @param string $value
  */
  function rfc1902_OctetString($value)
  {
    if(strlen($value) > 65535)
      trigger_error('OctetString must be shorter than 65535 bytes', E_USER_WARNING);
    parent::rfc1155_OctetString($value);
  }
}
?>

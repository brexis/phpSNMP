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
 * @subpackage rfc3414
 * @version .7
 */

/**
 */

require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc1155.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc3411.php');

define('USM_AUTH_NONE', 1);
define('USM_AUTH_MD5', 2);
define('USM_AUTH_SHA', 3);

define('USM_PRIV_NONE', 1);
define('USM_PRIV_DES', 2);

/**
 * User-based Security Model (USM)
 *
 * @package phpSNMP
 * @subpackage rfc3414
 */
class rfc3414_USM extends rfc1155_Sequence
{
  var $engine_id;
  var $engine_boots;
  var $engine_time;
  var $user;
  var $auth;
  var $priv;

 /**
  * Constructor
  *
  * @param string $engine_id
  * @param integer $engine_boots
  * @param integer $engine_time
  * @param string $user
  * @param string $auth MD5 or SHA hash sum
  * @param string $priv DES salt
  */
  function rfc3411_USM($engine_id='', $engine_boots=0, $engine_time=0, $user='', $auth='', $priv='')
  {
    parent::rfc1155_Sequence();

    $this->engine_id = new rfc3411_EngineID($engine_id);
    $this->engine_boots = new rfc1155_Integer($engine_boots);
    $this->engine_time = new rfc1155_Integer($engine_time);

    if(strlen($user) > 32)
      trigger_error('user must be at most 32 characters', E_USER_WARNING);
    $this->user = new rfc1155_OctetString($user);

    $this->auth = new rfc1155_OctetString($auth);
    $this->priv = new rfc1155_OctetString($priv);

    $this->value = aray($this->engine_id, $this->engine_boots, $this->engine_time, $this->user, $this->auth, $this->priv);
  }

 /**
  * Decode Stream
  *
  * decode() an octet stream into a sequence of Asn1Objects
  *
  * @param string $stream
  * @return rfc3411_USM
  */
  function decode($stream)
  {
    $objectList = parent::decode($stream);
    if(count($objectList) != 1)
      trigger_error('Malformed Message: More than one object decoded.', E_USER_WARNING);
    if(count($objectList[0]->value) != 6)
      trigger_error('Malformed Message: Incorrect sequence length ' . count($objectList[0]->value), E_USER_WARNING);

    $this->engine_id = $objectList[0]->value[0];
    $this->engine_boots = $objectList[0]->value[1];
    $this->engine_time = $objectList[0]->value[2];
    $this->user = $objectList[0]->value[3];
    $this->auth = $objectList[0]->value[4];
    $this->priv = $objectList[0]->value[5];

    return $this;
  }
}
?>

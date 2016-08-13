<?php

  function HMAC($data, $key, $hash_function='md5', $block_size=64)
  {
    $innerText = str_pad($key, $block_size, chr(0)) ^ str_repeat(chr(0x36), $block_size);
    $innerHash = pack('H*', $hash_function($innerText . $data));
    return pack('H*', $hash_function((str_pad($key, $block_size, chr(0)) ^ str_repeat(chr(0x5c), $block_size)) . $innerHash));
  }

?>

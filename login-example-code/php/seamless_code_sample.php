<?php

// PHP requirements:
// - PHP >=5.3
// - mcrypt PHP module
// - hash PHP module (to use SHA1)
// - curl PHP module

//////////////////////////////////////////////////////////////////////////////////////////////
// secrets exchanged privately offline with Autodata
//
$customer_id = 'XXXX';
//Where "XXXX" is the Customer_id provided 
//
$product_id = 'YYYY';
//Where "YYYY" is the Product_id provided 
//
$user_id = 'ZZZZ';
//Where "ZZZZ" is the User_id provided 
//
$encryption_key = 'WWWW';
//Where "WWWW" is the encryption key provided
//
$encryption_iv = substr($encryption_key, 0, 32);
$encryption_method = MCRYPT_RIJNDAEL_128;
$encryption_mode = MCRYPT_MODE_CBC;
$request_token_url = 'https://sts.autodata-group.com/requestToken';


//////////////////////////////////////////////////////////////////////////////////////////////
// Prepare XML data to be sent for token request
//
// Prepare XML's body content data
$body_xml = <<<EOT
<Resource name="Session"> 
  <HostAddress>10.0.0.1</HostAddress> 
  <DestinationAddress>10.0.0.2</DestinationAddress> 
  <CustomerID>$customer_id</CustomerID> 
  <ProductID>$product_id</ProductID> 
  <AccessLevel></AccessLevel> 
  <MID></MID> 
  <Category></Category> 
  <UserID>$user_id</UserID> 
</Resource>
EOT;

// calculate XML body's length (used later in header section)
$body_xml_length = strlen($body_xml);


// ENCRYPTION
// The encryption keys need to be hexadecimal
$encryption_key = pack('H*', $encryption_key);
$encryption_iv = pack('H*', $encryption_iv);

// Encrypt XML body
$body_xml_encrypted = mcrypt_encrypt($encryption_method, $encryption_key, utf8_encode($body_xml), $encryption_mode, $encryption_iv);
// Convert bytes into hexadecimal string, this needs to be provided using upper case as specified in seamless integration documentation
$body_xml_encrypted = strtoupper(bin2hex($body_xml_encrypted));

// create header SHA1 signature
$sha1 = strtoupper(bin2hex(sha1(hex2bin($body_xml_encrypted), true)));
// Encrypt signature (using the same method as the XML body) 
$header_signature = mcrypt_encrypt($encryption_method, $encryption_key, utf8_encode($sha1), $encryption_mode, $encryption_iv);
// Convert bytes into hexadecimal string, this needs to be provided using upper case as specified in seamless integration documentation
$header_signature = strtoupper(bin2hex($header_signature));


// Prepare XML header
$header_xml = <<<EOT
  <CustomerID>$customer_id</CustomerID> 
  <Signature>$header_signature</Signature> 
  <PlainTextLength>$body_xml_length</PlainTextLength> 
  <Version>1.0</Version>
EOT;

// This is the final XML that can be sent to request token
$final_xml = <<<EOT
<Payload>
  <Header>$header_xml</Header>
  <Body>$body_xml_encrypted</Body>
</Payload>
EOT;


//////////////////////////////////////////////////////////////////////////////////////////////
// Send payload to Autodata
//
//

//Open connection
$ch = curl_init();

// set CURL params
//
curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);  
// TRUE to retrieve response data

curl_setopt($ch, CURLOPT_HEADER, TRUE); 
// TRUE to get response headers as well 

curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: text/xml')); 
// Send customer headers with content type

curl_setopt($ch, CURLOPT_FOLLOWLOCATION, TRUE);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
curl_setopt($ch, CURLOPT_POST, TRUE); 
// TRUE as some POST data will be send

curl_setopt($ch, CURLOPT_POSTFIELDS, $final_xml); 
// POST data

curl_setopt($ch, CURLOPT_URL, $request_token_url); 
// This is the URL required for sending the POST request


// Send POST request
$response = curl_exec($ch);

// Collect response data
$result = array();
$result['http_code'] = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$result['headers'] = substr($response, 0, curl_getinfo($ch, CURLINFO_HEADER_SIZE));
$result['body'] = substr( $response, curl_getinfo($ch, CURLINFO_HEADER_SIZE));


// Close connection
curl_close($ch);



//////////////////////////////////////////////////////////////////////////////////////////////
// Read and encode response from Autodata
//
//
$xml = new SimpleXMLElement($result['body']);
$response_body_string = mcrypt_decrypt($encryption_method, $encryption_key, hex2bin($xml->Body), $encryption_mode, $encryption_iv);
// sample decoded response is XML like this:
// <Response>
//   <SessionToken>token</SessionToken>
//   <RedirectUrl>http://seamlesslink</RedirectUrl>
//   <EndUserId>GA2</EndUserId>
// </Response$response_body_xml = new SimpleXMLElement($response_body_string);

echo "seamless link is: " . $response_body_xml->RedirectUrl;


<?php

//Set to your time zone in phone
date_default_timezone_set('America/Sao_Paulo');

$time = time();
$deviceID = "e2Yb9_TFSVs:APA91bHNwUIrZtooBzLirgPs8KxdlZbxp4ybmBdX4i8DxiGQnAK_lpXnVX8YFLKYRW6Zd_XJG1sizbFAfD-sABwc8OymK8sv4MwZ5bzGw6wcTZWicti6JU3zTSbEIha65xvr1Xb7Sz7N-52";
$secret = "8eaab60d-e782-4986-9537-bc02773edd20-5";
$secret = md5($secret.$time);

// USING GET
#echo file_get_contents("http://51.161.105.75/gatewaysms/?to=".urlencode("+5511955939550")."&text=".urlencode("Teste")."&secret=$secret&time=$time&deviceID=".urlencode($deviceID));

$url = "http://51.161.105.75/gatewaysms/?to=".urlencode("+5511955939550")."&text=".urlencode("Teste")."&secret=$secret&time=$time&deviceID=".urlencode($deviceID)."";

// with POST, you don't need urlencode

	$curl = curl_init($url);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    $msg = curl_exec($curl);
	$respArray = json_decode($msg, true);
	$status = $respArray['success'];
	echo $msg.'</br>';
	echo $status;
    curl_close($curl);

?>
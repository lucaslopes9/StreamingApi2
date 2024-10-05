<?php

// RECEIVING MESSAGE
$number = urldecode($_POST['number']);
$message = urldecode($_POST['message']);
// type = received / sent / delivered / USSD
$type = urldecode($_POST['type']);

if(!empty($number) && !empty($message) && !empty($type)){
    // Processa o SMS recebido aqui
    // $tipo enviado = sucesso / Falha genérica / Sem serviço / PDU nula / Rádio desligado
    // $tipo entregue = sucesso / falha
    die('DONE');
}


// ENVIANDO MENSAGEM

$to = urldecode($_REQUEST['to']);
$text = urldecode($_REQUEST['text']);
$secret = urldecode($_REQUEST['secret']);
$token = urldecode($_REQUEST['deviceID']);
$sim = urldecode($_REQUEST['sim'])*1;
//Tempo necessário se você usar MD5
$time = $_REQUEST['time'];

/**
  * FAÇAM
  * Chave do servidor Firebase nas configurações
  * https://console.firebase.google.com/
  */
$firebasekey =  "AAAAIF5Dsnc:APA91bEqNHdLSfWH_tdSjPr7CHM53EASrzZzRETUdNAM5P7SE55bPV_tQnoJHU9r4FqaIcdX21BzWuTsLYzbn-m6l7EE6qK6vZB_PyfphFxI13mWPPmw48jGrNHh7fEdY6k4zuhbcVh7";

if(isset($_GET['debug']) && count($_REQUEST)>1)
	file_put_contents("log.txt",json_encode($_REQUEST)."\n\n",FILE_APPEND);

if(empty($to) || empty($text) || empty($secret) || empty($token)){
    readfile("info.txt");
    die();
}

$result = sendPush($token,$secret,$time,$to, $text, $sim);

if(isset($_GET['debug']) && count($_REQUEST)>1)
	file_put_contents("log.txt",$result."\n\n",FILE_APPEND);
echo $result;

function sendPush($token, $secret, $time, $to, $message, $sim=0) {
    global $firebasekey;
    $url = 'https://fcm.googleapis.com/fcm/send';

    $fields = array (
            'to' => $token,
            'data' => array (
                "to" => $to,
                "time" => $time,
                "secret" => $secret,
                "message" => $message,
                "sim" => $sim,
            )
    );
    $fields = json_encode ( $fields );

    $headers = array (
            'Authorization: key=' . $firebasekey,
            'Content-Type: application/json'
    );

    $ch = curl_init ();
    curl_setopt ( $ch, CURLOPT_URL, $url );
    curl_setopt ( $ch, CURLOPT_POST, true );
    curl_setopt ( $ch, CURLOPT_HTTPHEADER, $headers );
    curl_setopt ( $ch, CURLOPT_RETURNTRANSFER, true );
    curl_setopt ( $ch, CURLOPT_POSTFIELDS, $fields );

    $result = curl_exec ( $ch );

    curl_close ( $ch );

    return $result;
}

<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('StatusOnline', 'StatusDesconectado', 'StatusFalhado', 'StatusLogs', 'StatusReshare');
$VerificarAcesso = VerificarAcesso('status', $ColunaAcesso);
$StatusOnline = $VerificarAcesso[0];
$StatusDesconectado = $VerificarAcesso[1];
$StatusFalhado = $VerificarAcesso[2];
$StatusLogs = $VerificarAcesso[3];
$StatusReshare = $VerificarAcesso[4];

if( ($StatusOnline == 'S') || ($StatusDesconectado == 'S') || ($StatusFalhado == 'S') || ($StatusLogs == 'S') || ($StatusReshare == 'S') ){

$ip = empty($_POST['ip']) ? '' : $_POST['ip'];
$usuario = empty($_POST['usuario']) ? '' : $_POST['usuario'];

if(empty($ip)){
	echo MensagemAlerta($_TRA['erro'], $_TRA['ipeuco'], "danger");
}
elseif(empty($usuario)){
	echo MensagemAlerta($_TRA['erro'], $_TRA['UCO'], "danger");
}
else{
	
	echo VerificarIPStatus($ip, $usuario);
	echo "<script type=\"text/javascript\" src=\"js/plugins.js\"></script>";

}
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}
?>
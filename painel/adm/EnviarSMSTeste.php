<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('TesteVisualizar');
$VerificarAcesso = VerificarAcesso('teste', $ColunaAcesso);
$TesteVisualizar = $VerificarAcesso[0];
 
if($TesteVisualizar == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
	$usuario = (isset($_POST['usuario'])) ? $_POST['usuario'] : '';
	$mensagem = (isset($_POST['mensagem'])) ? $_POST['mensagem'] : '';
	
	$CadUserOnline = InfoUser(2);
	$ArvoreAdminOnline = ArvoreAdminRev($CadUserOnline);
	$ArvoreAdminOnline[] = $CadUserOnline;
	$VerificarSMSLibComputador = VerificarSMSLibComputador($CadUserOnline);
	
	$SQLUser = "SELECT CadUser, celular FROM teste WHERE usuario = :usuario";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':usuario', $usuario, PDO::PARAM_STR);
	$SQLUser->execute();
	$LnUser = $SQLUser->fetch();
	$celular = $LnUser['celular'];
	
	if(empty($celular)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cuco'], "danger");
	}
	elseif(is_numeric(LimparCelular($celular)) == false){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cdcan'], "danger");
	}
	elseif(empty($mensagem)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['meuco'], "danger");
	}
	elseif(!in_array($LnUser['CadUser'], $ArvoreAdminOnline)) {
		echo MensagemAlerta($_TRA['erro'], str_replace("USER_TAG",$usuario,$_TRA['npounpav']), "danger");
	}
	elseif($VerificarSMSLibComputador == 1){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cucdsesa'], "danger");
	}
	elseif($VerificarSMSLibComputador == 2){
		echo MensagemAlerta($_TRA['erro'], $_TRA['acsaesbrode'], "danger");
	}
	else{
		
	
	$EnviarSMS = EnviarSMS($CadUserOnline, $mensagem, $celular);
		
	
	if($EnviarSMS == 1){
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['secs'], "success", "index.php?p=teste");
	}
	else{
		echo MensagemAlerta($_TRA['erro'], $_TRA['oueaeospfvsnetmt'], "danger");
	}
				
			
	
		
	}
}

}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}

?>
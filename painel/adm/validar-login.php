<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
global $_TRA;

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
$usuario = (isset($_POST['usuario'])) ? $_POST['usuario'] : '';
$senha = (isset($_POST['senha'])) ? $_POST['senha'] : '';
$captcha = (isset($_POST['captcha'])) ? $_POST['captcha'] : '';
$CaptchaP = (isset($_COOKIE['CaptchaP'])) ? $_COOKIE['CaptchaP'] : '';
	
$SQL = "SELECT status FROM captcha";
$SQL = $painel_geral->prepare($SQL);
$SQL->execute();
$Ln = $SQL->fetch();
$CaptchaStatus = $Ln['status'];
	
	if (!is_curl_installed()) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['apqoprdenaidc'], "danger");
	}
	elseif(empty($usuario)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['UCO'], "danger");
	}
	elseif(empty($senha)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['SCO'], "danger");
	}
	elseif( empty($captcha) && ($CaptchaStatus == "S") ) {
		echo MensagemAlerta($_TRA['erro'], "Captcha é um campo obrigatório!", "danger");
	}
	elseif( empty($CaptchaP) && ($CaptchaStatus == "S") ){
		echo MensagemAlerta($_TRA['erro'], "Captcha inválido", "danger");
	}
	elseif( ($CaptchaP != $captcha) && ($CaptchaStatus == "S") ){
		echo MensagemAlerta($_TRA['erro'], "Captcha inválido", "danger");
	}
	elseif(ValidarUsuario($usuario, $senha) == true){
		echo Redirecionar('index.php?p=inicio');
	} 
	else{
		echo MensagemAlerta($_TRA['erro'], $_TRA['USI'], "danger");
	}
}

?>
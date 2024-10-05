<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('SMSModeloAdicionar');
$VerificarAcesso = VerificarAcesso('sms_modelo', $ColunaAcesso);
$SMSModeloAdicionar = $VerificarAcesso[0];
 
if($SMSModeloAdicionar == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
	$tipo = (isset($_POST['tipo'])) ? $_POST['tipo'] : '';
	$assunto = (isset($_POST['assunto'])) ? $_POST['assunto'] : '';
	$mensagem = (isset($_POST['mensagem'])) ? $_POST['mensagem'] : '';
	
	if(empty($tipo)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['teuco'], "danger");
	}
	elseif(empty($assunto)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['aeuco'], "danger");
	}
	elseif(empty($mensagem)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['meuco'], "danger");
	}
	else{
	
	$CadUser = InfoUser(2);
	$SQL = "INSERT INTO sms_modelo (
			CadUser,
			tipo,
            assunto,
            mensagem
            ) VALUES (
            :CadUser,
			:tipo,
            :assunto,
			:mensagem
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->bindParam(':tipo', $tipo, PDO::PARAM_STR);
	$SQL->bindParam(':assunto', $assunto, PDO::PARAM_STR);
	$SQL->bindParam(':mensagem', $mensagem, PDO::PARAM_STR);
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", "index.php?p=sms-modelo");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['adcs'], "success", "index.php?p=sms-modelo");
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
<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('SMSModeloEditar');
$VerificarAcesso = VerificarAcesso('sms_modelo', $ColunaAcesso);
$SMSModeloEditar = $VerificarAcesso[0];
 
if($SMSModeloEditar == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
	$id = (isset($_POST['id'])) ? $_POST['id'] : '';
	$tipo = (isset($_POST['tipo'])) ? $_POST['tipo'] : '';
	$assunto = (isset($_POST['assunto'])) ? $_POST['assunto'] : '';
	$mensagem = (isset($_POST['mensagem'])) ? $_POST['mensagem'] : '';
		
	if(empty($id)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
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
	$SQL = "UPDATE sms_modelo SET
			tipo = :tipo,
			assunto = :assunto,
			mensagem = :mensagem
            WHERE CadUser = :CadUser AND id = :id";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':tipo', $tipo, PDO::PARAM_STR); 
	$SQL->bindParam(':assunto', $assunto, PDO::PARAM_STR); 
	$SQL->bindParam(':mensagem', $mensagem, PDO::PARAM_STR); 
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQL->bindParam(':id', $id, PDO::PARAM_INT); 
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", "index.php?p=sms-modelo");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcs'], "success", "index.php?p=sms-modelo");
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
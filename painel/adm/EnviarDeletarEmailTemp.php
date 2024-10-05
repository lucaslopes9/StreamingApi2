<?php
	include("conexao.php");
	include_once("functions.php");
	include_once(Idioma(1));
	if(ProtegePag() == true){
	global $_TRA;
	
	$ColunaAcesso = array('OpcoesEmailTemporario');
	$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
	$OpcoesEmailTemporario = $VerificarAcesso[0];

	if($OpcoesEmailTemporario == 'S'){

	if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
	$id = (isset($_POST['id'])) ? $_POST['id'] : '';

	if(empty($id)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	else{
	
	$CadUser = InfoUser(2);
	$SQL = "DELETE FROM emailtemporario WHERE id = :id";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':id', $id, PDO::PARAM_INT); 
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", "index.php?p=email-temporario");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ecs'], "success", "index.php?p=email-temporario");
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
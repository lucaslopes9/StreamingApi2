<?php
	include("conexao.php");
	include_once("functions.php");
	include_once(Idioma(1));
	if(ProtegePag() == true){
	global $_TRA;
	
	$AcessoUser = InfoUser(3);
	if( ($AcessoUser == 1) || ($AcessoUser == 2) ){

	if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
	$id = (isset($_POST['id'])) ? $_POST['id'] : '';

	if(empty($id)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	else{
	
	$CadUser = InfoUser(2);
	$SQL = "DELETE FROM bit WHERE id = :id AND CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':id', $id, PDO::PARAM_INT); 
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQL->execute();
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", "index.php?p=bit");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ecs'], "success", "index.php?p=bit");
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
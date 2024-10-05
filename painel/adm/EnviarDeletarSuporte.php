<?php
	include("conexao.php");
	include_once("functions.php");
	include_once(Idioma(1));
	if(ProtegePag() == true){
	global $_TRA;

	if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
	$SelectBox = (isset($_POST['SelectBox'])) ? $_POST['SelectBox'] : '';

	if(empty($SelectBox)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	else{
	
	$CadUser = InfoUser(2);
	for($i = 0; $i < count($SelectBox); $i++){
	$SQL = "DELETE FROM suporte WHERE id = :id AND UserEmissor = :UserEmissor OR id = :id AND UserReceptor = :UserReceptor";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':id', $SelectBox[$i], PDO::PARAM_INT);
	$SQL->bindParam(':UserEmissor', $CadUser, PDO::PARAM_STR);
	$SQL->bindParam(':UserReceptor', $CadUser, PDO::PARAM_STR);
	$SQL->execute(); 
	}
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ecs'], "success", "index.php?p=suporte");
	}
		
		
	}
	}
	
	}else{
		echo Redirecionar('login.php');
	}
?>
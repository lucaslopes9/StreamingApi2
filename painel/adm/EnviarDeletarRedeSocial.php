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
	
	$redesocial = "";
	$CadUser = InfoUser(2);
		
	if($id == "whatsapp"){
		$redirecionar = "whatsapp";
		$SQL = "UPDATE rede_social SET
			whatsapp = :whatsapp
			WHERE CadUser = :CadUser";
		$SQL = $painel_geral->prepare($SQL);
		$SQL->bindParam(':whatsapp', $redesocial, PDO::PARAM_STR);
		$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
		$SQL->execute();
	}
	elseif($id == "facebook"){
		$redirecionar = "facebook";
		$SQL = "UPDATE rede_social SET
			facebook = :facebook
			WHERE CadUser = :CadUser";
		$SQL = $painel_geral->prepare($SQL);
		$SQL->bindParam(':facebook', $redesocial, PDO::PARAM_STR);
		$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
		$SQL->execute();
	}
	elseif($id == "telegram"){
		$redirecionar = "telegram";
		$SQL = "UPDATE rede_social SET
			telegram = :telegram
			WHERE CadUser = :CadUser";
		$SQL = $painel_geral->prepare($SQL);
		$SQL->bindParam(':telegram', $redesocial, PDO::PARAM_STR);
		$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
		$SQL->execute();
	}
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", "index.php?p=".$redirecionar."");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ecs'], "success", "index.php?p=".$redirecionar."");
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
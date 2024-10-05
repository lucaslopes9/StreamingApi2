<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
	
$AcessoUser = InfoUser(3);
if( ($AcessoUser == 1) || ($AcessoUser == 2) ){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	 
$usuario = (isset($_POST['usuario'])) ? trim($_POST['usuario']) : '';
$api = (isset($_POST['api'])) ? trim($_POST['api']) : '';
$CadUser = InfoUser(2);
	
	if(empty($CadUser)){
		echo MensagemAlerta($_TRA['erro'], "Como você fez isso?", "danger");
	}
	elseif(empty($usuario)){
		echo MensagemAlerta($_TRA['erro'], "Usuário é um campo obrigatório!", "danger");
	}
	elseif(empty($api)){
		echo MensagemAlerta($_TRA['erro'], "Api Key é um campo obrigatório!", "danger");
	}
	else{
		
	$SQLBit = "SELECT id FROM bit WHERE CadUser = :CadUser";
	$SQLBit = $painel_geral->prepare($SQLBit);
	$SQLBit->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLBit->execute();
	$TotalBit = count($SQLBit->fetchAll());
		
	if($TotalBit == 0){
		$SQL = "INSERT INTO bit (
				CadUser,
				usuario,
				api
            ) VALUES (
				:CadUser,
				:usuario,
				:api
			)";
		$SQL = $painel_geral->prepare($SQL);
		$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
		$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		$SQL->bindParam(':api', $api, PDO::PARAM_STR); 
		$SQL->execute(); 
		
	}
	else{
		$SQL = "UPDATE bit SET
			usuario = :usuario,
			api = :api
			WHERE CadUser = :CadUser";
		$SQL = $painel_geral->prepare($SQL);
		$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		$SQL->bindParam(':api', $api, PDO::PARAM_STR); 
		$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
		$SQL->execute();
	}
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], "Bit.ly configurado com sucesso!", "success", "index.php?p=bit");
	}
		
		
			}
		}
	}
}
?>
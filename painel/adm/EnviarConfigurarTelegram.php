<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
	
$AcessoUser = InfoUser(3);
if( ($AcessoUser == 1) || ($AcessoUser == 2) ){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	 
$RedeSocial = (isset($_POST['RedeSocial'])) ? trim($_POST['RedeSocial']) : '';
$CadUser = InfoUser(2);
	
	if(empty($CadUser)){
		echo MensagemAlerta($_TRA['erro'], "Como você fez isso?", "danger");
	}
	elseif(empty($RedeSocial)){
		echo MensagemAlerta($_TRA['erro'], "Telegram é um campo obrigatório!", "danger");
	}
	else{
		
	$SQLRede = "SELECT id FROM rede_social WHERE CadUser = :CadUser";
	$SQLRede = $painel_geral->prepare($SQLRede);
	$SQLRede->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLRede->execute();
	$TotalRede = count($SQLRede->fetchAll());
		
	if($TotalRede == 0){
		$SQL = "INSERT INTO rede_social (
				CadUser,
				telegram
            ) VALUES (
				:CadUser,
				:telegram
			)";
		$SQL = $painel_geral->prepare($SQL);
		$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
		$SQL->bindParam(':telegram', $RedeSocial, PDO::PARAM_STR); 
		$SQL->execute(); 
		
	}
	else{
		$SQL = "UPDATE rede_social SET
			telegram = :telegram
			WHERE CadUser = :CadUser";
		$SQL = $painel_geral->prepare($SQL);
		$SQL->bindParam(':telegram', $RedeSocial, PDO::PARAM_STR);
		$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
		$SQL->execute();
	}
				
	
		
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], "Telegram configurado com sucesso!", "success", "index.php?p=telegram");
	}
		
		
			}
		}
	}
}
?>
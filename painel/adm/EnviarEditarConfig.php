<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
global $_TRA;
if(ProtegePag() == true){

$ColunaAcesso = array('ServidorcspConfig');
$VerificarAcesso = VerificarAcesso('servidorcsp', $ColunaAcesso);
$ServidorcspConfig = $VerificarAcesso[0];
 
if($ServidorcspConfig == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
$iplock = (isset($_POST['iplock'])) ? $_POST['iplock'] : '';
$EditarSenha = (isset($_POST['EditarSenha'])) ? $_POST['EditarSenha'] : '';
$EditarDeskeys = (isset($_POST['EditarDeskeys'])) ? $_POST['EditarDeskeys'] : '';
$EditarIP = (isset($_POST['EditarIP'])) ? $_POST['EditarIP'] : '';
	
	if(empty($EditarSenha)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['sxuco'], "danger");
	}
	elseif(empty($EditarDeskeys)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['deuco'], "danger");
	}
	elseif(is_numeric($EditarDeskeys) == false){
		echo MensagemAlerta($_TRA['erro'], $_TRA['dedcan'], "danger");
	}
	elseif( empty($EditarIP) && ($iplock == "S")){
		echo MensagemAlerta($_TRA['erro'], $_TRA['ipuco'], "danger");
	}
	else{
		
	$SQL = "SELECT id FROM painel_config";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->execute();
	$Total = count($SQL->fetchAll());
	
	if($Total > 0){
	$SQL = "UPDATE painel_config SET
			senha = :senha,
			deskeys = :deskeys,
			ip = :ip,
			iplock = :iplock";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':senha', $EditarSenha, PDO::PARAM_STR); 
	$SQL->bindParam(':deskeys', $EditarDeskeys, PDO::PARAM_STR); 
	$SQL->bindParam(':ip', $EditarIP, PDO::PARAM_STR);
	$SQL->bindParam(':iplock', $iplock, PDO::PARAM_STR);
	$SQL->execute(); 
	}else{
	$SQL = "INSERT INTO painel_config (
			senha,
            deskeys,
            ip,
			iplock
            ) VALUES (
            :senha, 
			:deskeys, 
			:ip,
			:iplock
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':senha', $EditarSenha, PDO::PARAM_STR);
	$SQL->bindParam(':deskeys', $EditarDeskeys, PDO::PARAM_STR);
	$SQL->bindParam(':ip', $EditarIP, PDO::PARAM_STR);
	$SQL->bindParam(':iplock', $iplock, PDO::PARAM_STR);
	$SQL->execute(); 
	}
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcs'], "success", "index.php?p=csp");
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
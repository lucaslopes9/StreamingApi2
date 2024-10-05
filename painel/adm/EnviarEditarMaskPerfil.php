<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('OpcoesMascaraURL');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesMascaraURL = $VerificarAcesso[0];

if($OpcoesMascaraURL == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
	$id = (isset($_POST['id'])) ? $_POST['id'] : '';
	$PerfilCSP = (isset($_POST['PerfilCSP'])) ? $_POST['PerfilCSP'] : '';
	$Nome = (isset($_POST['Nome'])) ? $_POST['Nome'] : '';
	$Url = (isset($_POST['Url'])) ? $_POST['Url'] : '';
	$Porta = (isset($_POST['Porta'])) ? $_POST['Porta'] : '';
	$CadUser = InfoUser(2);
	
	$SQLMask = "SELECT perfil FROM mascaraurl WHERE perfil = :perfil AND CadUser = :CadUser AND id != :id";
	$SQLMask = $painel_geral->prepare($SQLMask);
	$SQLMask->bindParam(':perfil', $PerfilCSP, PDO::PARAM_STR);
	$SQLMask->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLMask->bindParam(':id', $id, PDO::PARAM_STR);
	$SQLMask->execute();
	$TotalMask = count($SQLMask->fetchAll());
	
	if($TotalMask > 0){
		echo MensagemAlerta($_TRA['erro'], $_TRA['jeumdpapep'], "danger");
	}
	elseif(empty($PerfilCSP)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['peuco'], "danger");
	}
	elseif(empty($Nome)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['nuco'], "danger");
	}
	elseif(empty($Url)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['urluco'], "danger");
	}
	elseif(empty($Porta)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['puco'], "danger");
	}
	elseif(is_numeric($Porta) == false){
		echo MensagemAlerta($_TRA['erro'], $_TRA['pordcan'], "danger");
	}
	else{
		
	$SQL = "UPDATE mascaraurl SET
			perfil = :perfil,
			nome = :nome,
			url = :url,
			porta = :porta
            WHERE CadUser = :CadUser AND id = :id";
	$SQL = $painel_geral->prepare($SQL);                                  
	$SQL->bindParam(':perfil', $PerfilCSP, PDO::PARAM_STR); 
	$SQL->bindParam(':nome', $Nome, PDO::PARAM_STR); 
	$SQL->bindParam(':url', $Url, PDO::PARAM_STR);
	$SQL->bindParam(':porta', $Porta, PDO::PARAM_INT);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->bindParam(':id', $id, PDO::PARAM_INT);
	$SQL->execute();
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcs'], "success", "index.php?p=mascara-perfil");
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
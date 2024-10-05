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
	
	$PerfilCSP = (isset($_POST['PerfilCSP'])) ? $_POST['PerfilCSP'] : '';
	$Nome = (isset($_POST['Nome'])) ? $_POST['Nome'] : '';
	$Url = (isset($_POST['Url'])) ? $_POST['Url'] : '';
	$Porta = (isset($_POST['Porta'])) ? $_POST['Porta'] : '';
	$CadUser = InfoUser(2);
	
	$SQLMask = "SELECT perfil FROM mascaraurl WHERE perfil = :perfil AND CadUser = :CadUser";
	$SQLMask = $painel_geral->prepare($SQLMask);
	$SQLMask->bindParam(':perfil', $PerfilCSP, PDO::PARAM_STR);
	$SQLMask->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
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
		
	$SQL = "INSERT INTO mascaraurl (
			CadUser,
            perfil,
            nome,
			url,
			porta
            ) VALUES (
            :CadUser,
            :perfil,
            :nome,
			:url,
			:porta
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_INT);
	$SQL->bindParam(':perfil', $PerfilCSP, PDO::PARAM_INT);
	$SQL->bindParam(':nome', $Nome, PDO::PARAM_STR);
	$SQL->bindParam(':url', $Url, PDO::PARAM_STR);
	$SQL->bindParam(':porta', $Porta, PDO::PARAM_INT);
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['adcs'], "success", "index.php?p=mascara-perfil");
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
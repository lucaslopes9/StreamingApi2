<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('OpcoesEmailTeste');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesEmailTeste = $VerificarAcesso[0];

if($OpcoesEmailTeste == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
	$EmailEmail = (isset($_POST['EmailEmail'])) ? $_POST['EmailEmail'] : '';
	$EmailID = (isset($_POST['EmailID'])) ? $_POST['EmailID'] : '';
	$CadUser = InfoUser(2);
	
	$SQL = "SELECT id FROM email_teste WHERE CadUser = :CadUser AND email = :email AND id != :id";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQL->bindParam(':email', $EmailEmail, PDO::PARAM_STR); 
	$SQL->bindParam(':id', $EmailID, PDO::PARAM_INT);
	$SQL->execute();	
	$TotalEmail = count($SQL->fetchAll());
	
	if(empty($EmailID)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	elseif(empty($EmailEmail)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['euco'], "danger");
	}
	elseif(substr_count($EmailEmail, "@") == 0 || substr_count($EmailEmail, ".") == 0){
		echo MensagemAlerta($_TRA['erro'], $_TRA['fdei'], "danger");
	}
	elseif($TotalEmail > 0){
		echo MensagemAlerta($_TRA['erro'], $_TRA['eeeu'], "danger");
	}
	else{
			
	$SQL = "UPDATE email_teste SET
			email = :email
            WHERE CadUser = :CadUser AND id = :id";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':email', $EmailEmail, PDO::PARAM_STR); 
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQL->bindParam(':id', $EmailID, PDO::PARAM_INT); 
	$SQL->execute(); 

	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", "index.php?p=email-teste");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcs'], "success", "index.php?p=email-teste");
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
<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

//Status do Servidor
$ColunaStatusServer = array('OpcoesEmailTemporario');
$VerificarStatusServer = VerificarAcesso('opcoes', $ColunaStatusServer);
$OpcoesEmailTemporario = $VerificarStatusServer[0];

if($OpcoesEmailTemporario == 'S'){

$Email = (isset($_POST['Email'])) ? $_POST['Email'] : '';

	$SQL = "SELECT email FROM emailtemporario WHERE email = :email";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':email', $Email, PDO::PARAM_STR);
	$SQL->execute();
	$TotalEmail = count($SQL->fetchAll());	
	
	if($TotalEmail > 0){
		echo MensagemAlerta($_TRA['erro'], $_TRA['eetjesc'], "danger");
	}
	elseif(empty($Email)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['euco'], "danger");
	}
	elseif( !empty($Email) && substr_count($Email, "@") == 0 || !empty($Email) && substr_count($Email, ".") == 0) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['dei'], "danger");
	}
	else{	
	
	$CadUser = InfoUser(2);
	$SQL = "INSERT INTO emailtemporario (
			email
            ) VALUES (
			:email
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':email', $Email, PDO::PARAM_STR);
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['etacs'], "success", "index.php?p=email-temporario");
	}
		
		
	}

}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	

?>
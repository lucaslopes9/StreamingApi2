<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('OpcoesEmailTemporario');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesEmailTemporario = $VerificarAcesso[0];

if($OpcoesEmailTemporario == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
	$ID = (isset($_POST['ID'])) ? $_POST['ID'] : '';
	$Email = (isset($_POST['Email'])) ? $_POST['Email'] : '';
	$CadUser = InfoUser(2);
	
	$SQL = "SELECT email FROM emailtemporario WHERE email = :email AND id != :id";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':id', $ID, PDO::PARAM_INT);
	$SQL->bindParam(':email', $Email, PDO::PARAM_STR);
	$SQL->execute();
	$TotalEmail = count($SQL->fetchAll());	
	
	if($TotalEmail > 0){
		echo MensagemAlerta($_TRA['erro'], $_TRA['eetjesc'], "danger");
	}
	elseif(empty($ID)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	elseif(empty($Email)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['euco'], "danger");
	}
	elseif( !empty($Email) && substr_count($Email, "@") == 0 || !empty($Email) && substr_count($Email, ".") == 0) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['dei'], "danger");
	}
	else{
	
	$SQL = "UPDATE emailtemporario SET
			email = :email
            WHERE id = :id";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':email', $Email, PDO::PARAM_STR); 
	$SQL->bindParam(':id', $ID, PDO::PARAM_INT); 
	$SQL->execute(); 

	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", "index.php?p=email-temporario");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcs'], "success", "index.php?p=email-temporario");
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
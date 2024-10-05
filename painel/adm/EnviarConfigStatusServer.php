<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

//Status do Servidor
$ColunaStatusServer = array('OpcoesStatusServer');
$VerificarStatusServer = VerificarAcesso('opcoes', $ColunaStatusServer);
$AdminStatusServer = $VerificarStatusServer[0];

if($AdminStatusServer == 'S'){

$Status = (isset($_POST['Status'])) ? $_POST['Status'] : 'N';
$Email = (isset($_POST['Email'])) ? $_POST['Email'] : '';
$Celular = (isset($_POST['Celular'])) ? $_POST['Celular'] : '';

	if(empty($Status)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['Statuseuco'], "danger");
	}
	elseif( ($Status == "S") && empty($Email) || ($Status == "S") && empty($Celular) ){
		echo MensagemAlerta($_TRA['erro'], $_TRA['eoucdsp'], "danger");
	}
	elseif( !empty($Email) && substr_count($Email, "@") == 0 || !empty($Email) && substr_count($Email, ".") == 0) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['dei'], "danger");
	}
	elseif( !empty($Celular) && (is_numeric(LimparCelular($Celular)) == false) ){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cdcan'], "danger");
	}
	else{	

	$SQLUrlT = "SELECT id FROM status_servidor";
	$SQLUrlT = $painel_geral->prepare($SQLUrlT);
	$SQLUrlT->execute();
	$TotalUrlT = count($SQLUrlT->fetchAll());	
	
	if($TotalUrlT > 0){
	$SQL = "UPDATE status_servidor SET
			status = :status,
			celular = :celular,
			email = :email";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':status', $Status, PDO::PARAM_STR); 
	$SQL->bindParam(':celular', $Celular, PDO::PARAM_STR); 
	$SQL->bindParam(':email', $Email, PDO::PARAM_STR); 
	$SQL->execute();
	}
	else{	
	$SQL = "INSERT INTO status_servidor (
			status,
			celular,
			email
            ) VALUES (
			:status,
			:celular,
			:email
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':status', $Status, PDO::PARAM_STR); 
	$SQL->bindParam(':celular', $Celular, PDO::PARAM_STR); 
	$SQL->bindParam(':email', $Email, PDO::PARAM_STR); 
	$SQL->execute(); 
	}
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ccs'], "success", "index.php?p=inicio");
	}
		
		
	}

}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	

?>
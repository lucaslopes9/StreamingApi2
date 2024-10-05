<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

//Status do Servidor
$ColunaStatusServer = array('OpcoesBackup');
$VerificarStatusServer = VerificarAcesso('opcoes', $ColunaStatusServer);
$AdminStatusServer = $VerificarStatusServer[0];

if($AdminStatusServer == 'S'){

$Status = (isset($_POST['Status'])) ? $_POST['Status'] : 'N';
$Email = (isset($_POST['Email'])) ? $_POST['Email'] : '';
$Tempo = (isset($_POST['Tempo'])) ? $_POST['Tempo'] : '';

	if(empty($Status)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['Statuseuco'], "danger");
	}
	elseif(empty($Tempo)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['teeuco'], "danger");
	}
	elseif( ($Status == "S") && empty($Email) ){
		echo MensagemAlerta($_TRA['erro'], $_TRA['euco'], "danger");
	}
	elseif( !empty($Email) && substr_count($Email, "@") == 0 || !empty($Email) && substr_count($Email, ".") == 0) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['dei'], "danger");
	}
	else{	

	$SQLUrlT = "SELECT id FROM backup";
	$SQLUrlT = $painel_geral->prepare($SQLUrlT);
	$SQLUrlT->execute();
	$TotalUrlT = count($SQLUrlT->fetchAll());	
	
	$HorarioInserir = time() + (3600 * $Tempo);
	
	if($TotalUrlT > 0){
	$SQL = "UPDATE backup SET
			status = :status,
			tempo = :tempo,
			horario = :horario,
			email = :email";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':status', $Status, PDO::PARAM_STR); 
	$SQL->bindParam(':tempo', $Tempo, PDO::PARAM_STR); 
	$SQL->bindParam(':horario', $HorarioInserir, PDO::PARAM_STR); 
	$SQL->bindParam(':email', $Email, PDO::PARAM_STR);
	$SQL->execute();
	}
	else{	
	$SQL = "INSERT INTO backup (
			status,
			tempo,
			horario,
			email
            ) VALUES (
			:status,
			:tempo,
			:horario,
			:email
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':status', $Status, PDO::PARAM_STR); 
	$SQL->bindParam(':tempo', $Tempo, PDO::PARAM_STR); 
	$SQL->bindParam(':horario', $HorarioInserir, PDO::PARAM_STR); 
	$SQL->bindParam(':email', $Email, PDO::PARAM_STR);
	$SQL->execute(); 
	}
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ccs'], "success", "index.php?p=backup");
	}
		
		
	}

}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	

?>
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
$Server = (isset($_POST['Server'])) ? $_POST['Server'] : '';
$Tempo = (isset($_POST['Tempo'])) ? $_POST['Tempo'] : '';

	if(empty($Status)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['Statuseuco'], "danger");
	}
	elseif(empty($Tempo)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['teeuco'], "danger");
	}
	elseif(empty($Server)){
		echo MensagemAlerta($_TRA['erro'], 'Servidor é um campo obrigatório!', "danger");
	}
	else{	

	$SQLUrlT = "SELECT id FROM backup_automatizado";
	$SQLUrlT = $painel_geral->prepare($SQLUrlT);
	$SQLUrlT->execute();
	$TotalUrlT = count($SQLUrlT->fetchAll());	
	
	$HorarioInserir = time() + (3600 * $Tempo);
	
	if($TotalUrlT > 0){
	$SQL = "UPDATE backup_automatizado SET
			status = :status,
			tempo = :tempo,
			horario = :horario,
			server = :server";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':status', $Status, PDO::PARAM_STR); 
	$SQL->bindParam(':tempo', $Tempo, PDO::PARAM_STR); 
	$SQL->bindParam(':horario', $HorarioInserir, PDO::PARAM_STR); 
	$SQL->bindParam(':server', $Server, PDO::PARAM_STR);
	$SQL->execute();
	}
	else{	
	$SQL = "INSERT INTO backup_automatizado (
			status,
			tempo,
			horario,
			server
            ) VALUES (
			:status,
			:tempo,
			:horario,
			:server
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':status', $Status, PDO::PARAM_STR); 
	$SQL->bindParam(':tempo', $Tempo, PDO::PARAM_STR); 
	$SQL->bindParam(':horario', $HorarioInserir, PDO::PARAM_STR); 
	$SQL->bindParam(':server', $Server, PDO::PARAM_STR);
	$SQL->execute(); 
	}
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ccs'], "success", "index.php?p=backup-automatizado");
	}
		
		
	}

}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	

?>
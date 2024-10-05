<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$EditarStatus = (isset($_POST['EditarStatus'])) ? $_POST['EditarStatus'] : 'N';
$EditarTempo = (isset($_POST['EditarTempo'])) ? $_POST['EditarTempo'] : '';
$EditarCopia = (isset($_POST['EditarCopia'])) ? $_POST['EditarCopia'] : 'N';
$EditarEmail = (isset($_POST['EditarEmail'])) ? $_POST['EditarEmail'] : '';
$CadUser = InfoUser(2);

	$bloqueado = "N";
	$SQLTempo = "SELECT tempo FROM tempoteste WHERE id = :id AND bloqueado = :bloqueado";
	$SQLTempo = $painel_geral->prepare($SQLTempo);
	$SQLTempo->bindParam(':id', $EditarTempo, PDO::PARAM_STR);
	$SQLTempo->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLTempo->execute();
	$LnTempo = $SQLTempo->fetch();

	if(empty($CadUser)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	elseif(empty($EditarTempo)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['teeuco'], "danger");
	}
	elseif( empty($LnTempo) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['ttsned'], "danger");
	}
	elseif( ($EditarCopia == "S") && substr_count($EditarEmail, "@") == 0 || ($EditarCopia == "S") && substr_count($EditarEmail, ".") == 0) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['dei'], "danger");
	}
	else{	
	$EditarTempo = $LnTempo['tempo'];
	
	$SQLUrlT = "SELECT id FROM urlteste WHERE CadUser = :CadUser";
	$SQLUrlT = $painel_geral->prepare($SQLUrlT);
	$SQLUrlT->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLUrlT->execute();
	$TotalUrlT = count($SQLUrlT->fetchAll());	
	
	if($TotalUrlT > 0){
	$SQL = "UPDATE urlteste SET
			status = :status,
			tempo = :tempo,
			cemail = :cemail,
			email = :email
       	 	WHERE CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':status', $EditarStatus, PDO::PARAM_STR); 
	$SQL->bindParam(':tempo', $EditarTempo, PDO::PARAM_STR); 
	$SQL->bindParam(':cemail', $EditarCopia, PDO::PARAM_STR); 
	$SQL->bindParam(':email', $EditarEmail, PDO::PARAM_STR); 
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQL->execute();
	}
	else{	
	$SQL = "INSERT INTO urlteste (
			CadUser,
			status,
            tempo,
            cemail,
			email
            ) VALUES (
			:CadUser,
			:status,
            :tempo,
            :cemail,
			:email
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQL->bindParam(':status', $EditarStatus, PDO::PARAM_STR); 
	$SQL->bindParam(':tempo', $EditarTempo, PDO::PARAM_STR); 
	$SQL->bindParam(':cemail', $EditarCopia, PDO::PARAM_STR); 
	$SQL->bindParam(':email', $EditarEmail, PDO::PARAM_STR); 
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
	echo Redirecionar('login.php');
}	

?>
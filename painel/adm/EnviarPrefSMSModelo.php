<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('SMSModeloPreferencias');
$VerificarAcesso = VerificarAcesso('sms_modelo', $ColunaAcesso);
$SMSModeloPreferencias = $VerificarAcesso[0];
 
if($SMSModeloPreferencias == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
	$Pref1 = (isset($_POST['Pref1'])) ? $_POST['Pref1'] : '';
	$Pref2 = (isset($_POST['Pref2'])) ? $_POST['Pref2'] : '';
	$Pref3 = (isset($_POST['Pref3'])) ? $_POST['Pref3'] : '';
	$Pref4 = (isset($_POST['Pref4'])) ? $_POST['Pref4'] : '';
	
	if(empty($Pref1)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['daeuco'], "danger");
	}
	elseif(empty($Pref2)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['ddeeuco'], "danger");
	}
	elseif(empty($Pref3)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['veuco'], "danger");
	}
	elseif(empty($Pref4)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['reuco'], "danger");
	}
	else{
	
	$CadUser = InfoUser(2);
	$SQL = "SELECT id FROM sms_preferencias WHERE CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->execute();
	$Total = count($SQL->fetchAll());
	
	if($Total > 0){
	$SQL = "UPDATE sms_preferencias SET
			DadosDeAcesso = :DadosDeAcesso,
			DadosDeAcessoTeste = :DadosDeAcessoTeste,
			Vencimento = :Vencimento,
			Renovacao = :Renovacao
            WHERE CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':DadosDeAcesso', $Pref1, PDO::PARAM_STR); 
	$SQL->bindParam(':DadosDeAcessoTeste', $Pref2, PDO::PARAM_STR); 
	$SQL->bindParam(':Vencimento', $Pref3, PDO::PARAM_STR); 
	$SQL->bindParam(':Renovacao', $Pref4, PDO::PARAM_STR); 
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQL->execute(); 
	}
	else{
	$SQL = "INSERT INTO sms_preferencias (
			CadUser,
			DadosDeAcesso,
            DadosDeAcessoTeste,
            Vencimento,
			Renovacao
            ) VALUES (
            :CadUser,
			:DadosDeAcesso,
            :DadosDeAcessoTeste,
            :Vencimento,
			:Renovacao
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->bindParam(':DadosDeAcesso', $Pref1, PDO::PARAM_STR);
	$SQL->bindParam(':DadosDeAcessoTeste', $Pref2, PDO::PARAM_STR);
	$SQL->bindParam(':Vencimento', $Pref3, PDO::PARAM_STR);
	$SQL->bindParam(':Renovacao', $Pref4, PDO::PARAM_STR);
	$SQL->execute(); 
	}
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", "index.php?p=sms-modelo");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcs'], "success", "index.php?p=sms-modelo");
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
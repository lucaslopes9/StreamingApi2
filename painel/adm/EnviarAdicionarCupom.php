<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('OpcoesCupom');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesCupom = $VerificarAcesso[0];
if($OpcoesCupom == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
	$Dias = (isset($_POST['Dias'])) ? $_POST['Dias'] : '';
	$EditarPerfil = (isset($_POST['EditarPerfil'])) ? $_POST['EditarPerfil'] : '';
	$CadUser = InfoUser(2);
	
	if(empty($Dias)){
		echo MensagemAlerta($_TRA['erro'], "Dias é um campo obrigatório!", "danger");
	}
	elseif(is_numeric($Dias) == false){
		echo MensagemAlerta($_TRA['erro'], "Dias deve conter apenas números!", "danger");
	}
	elseif(empty($CadUser)){
		echo MensagemAlerta($_TRA['erro'], "Como você fez isso?", "danger");
	}
	elseif( empty($EditarPerfil) ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['sepmup'], "danger");
	}
	else{
		
	$Dias = trim($Dias);
	$GerarCupom = strtoupper(GerarCupom());
		
	$profile = trim(implode("", $EditarPerfil));
	$EditarPerfil = empty($profile) ? "" : $profile;
	
	$CriadoEm = time();
	$SQL = "INSERT INTO cupom (
			CadUser,
			CriadoEm,
			Cupom,
            dias,
			perfil
            ) VALUES (
            :CadUser,
			:CriadoEm,
			:Cupom,
            :dias,
			:perfil
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->bindParam(':CriadoEm', $CriadoEm, PDO::PARAM_STR);
	$SQL->bindParam(':Cupom', $GerarCupom, PDO::PARAM_STR);
	$SQL->bindParam(':dias', $Dias, PDO::PARAM_STR);
	$SQL->bindParam(':perfil', $EditarPerfil, PDO::PARAM_STR);
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", "index.php?p=cupom");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['adcs'], "success", "index.php?p=cupom");
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
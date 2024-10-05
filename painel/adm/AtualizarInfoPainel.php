<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));

if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('TemplateInfo');
$VerificarAcesso = VerificarAcesso('template', $ColunaAcesso);
$TemplateInfo = $VerificarAcesso[0];

if($TemplateInfo == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
	$NomePainel = (isset($_POST['NomePainel'])) ? $_POST['NomePainel'] : 'CSPainel';
	$LegendaPainel = (isset($_POST['LegendaPainel'])) ? $_POST['LegendaPainel'] : 'Gerenciador de Painel';
		
	$SQL = "SELECT id FROM site_config";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->execute();
	$Total = count($SQL->fetchAll());
	
	if($Total > 0){
	$SQL = "UPDATE site_config SET
			NomePainel = :NomePainel,
			LegendaPainel = :LegendaPainel";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':NomePainel', $NomePainel, PDO::PARAM_INT);
	$SQL->bindParam(':LegendaPainel', $LegendaPainel, PDO::PARAM_INT);
	$SQL->execute(); 
	}
	else{
	$SQL = "INSERT INTO site_config (
			NomePainel,
			LegendaPainel
            ) VALUES (
			:NomePainel,
			:LegendaPainel
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':NomePainel', $NomePainel, PDO::PARAM_STR);
	$SQL->bindParam(':LegendaPainel', $LegendaPainel, PDO::PARAM_STR);
	$SQL->execute(); 
	}
	
	$_SESSION['NomePainel'] = $NomePainel;
	$_SESSION['LegendaPainel'] = $LegendaPainel;
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['lecs'], "success", "index.php?p=info");
	}
		
}

}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}

?>
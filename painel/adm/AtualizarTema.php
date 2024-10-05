<?php
include("conexao.php");
include_once("functions.php");

if(ProtegePag() == true){
	
$ColunaAcesso = array('TemplateTema');
$VerificarAcesso = VerificarAcesso('template', $ColunaAcesso);
$TemplateTema = $VerificarAcesso[0];

if($TemplateTema == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
	$tema = (isset($_POST['tema'])) ? $_POST['tema'] : '';
	$_SESSION['TemaPainel'] = $tema;
	
	$SQL = "SELECT id FROM site_config";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->execute();
	$Total = count($SQL->fetchAll());
	
	if($Total > 0){
	$SQL = "UPDATE site_config SET
			TemaPainel = :TemaPainel";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':TemaPainel', $tema, PDO::PARAM_INT);
	$SQL->execute(); 
	}
	else{
	$SQL = "INSERT INTO site_config (
			TemaPainel
            ) VALUES (
			:TemaPainel
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':TemaPainel', $tema, PDO::PARAM_STR);
	$SQL->execute(); 
	}
	
	echo Redirecionar('index.php?p=temas');
		
}

}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}

?>
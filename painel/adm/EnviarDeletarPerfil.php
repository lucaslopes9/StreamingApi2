<?php
	include("conexao.php");
	include_once("functions.php");
	include_once(Idioma(1));
	if(ProtegePag() == true){
	global $_TRA;
	
	$ColunaAcesso = array('PerfilExcluir');
	$VerificarAcesso = VerificarAcesso('perfil', $ColunaAcesso);
	$PerfilExcluir = $VerificarAcesso[0];

	if($PerfilExcluir == 'S'){

	if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
	$id = (isset($_POST['id'])) ? $_POST['id'] : '';

	if(empty($id)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	else{
		
	$SQLPerfil = "SELECT valorcsp FROM perfil WHERE id = :id";
	$SQLPerfil = $painel_geral->prepare($SQLPerfil);
	$SQLPerfil->bindParam(':id', $id, PDO::PARAM_INT); 
	$SQLPerfil->execute();
	$LnPerfil = $SQLPerfil->fetch();
	$valorcsp = $LnPerfil['valorcsp'];
	
	DeletarPerfil($valorcsp, "admin");
	DeletarPerfil($valorcsp, "rev");
	DeletarPerfil($valorcsp, "usuario");
	DeletarPerfil($valorcsp, "teste");

	$SQL = "DELETE FROM perfil WHERE id = :id";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':id', $id, PDO::PARAM_INT); 
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ecs'], "success", "index.php?p=perfil");
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
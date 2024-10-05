<?php
	include("conexao.php");
	include_once("functions.php");
	include_once(Idioma(1));
	if(ProtegePag() == true){
	global $_TRA;
	
	$ColunaAcesso = array('ImagemperfilExcluir');
	$VerificarAcesso = VerificarAcesso('imagemperfil', $ColunaAcesso);
	$ImagemperfilExcluir = $VerificarAcesso[0];

	if($ImagemperfilExcluir == 'S'){

	if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
	$id = (isset($_POST['id'])) ? $_POST['id'] : '';

	if(empty($id)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	else{
		
	//Verifica a imagem atual e deleta dos arquivos
	$SQLImg = "SELECT img FROM perfil_icone WHERE id = :id";
	$SQLImg = $painel_geral->prepare($SQLImg);
	$SQLImg->bindParam(':id', $id, PDO::PARAM_INT);
	$SQLImg->execute();
	$LnImg = $SQLImg->fetch();
		
	if(!empty($LnImg['img'])) unlink("img/perfil/".$LnImg['img']);
		
	$SQL = "DELETE FROM perfil_icone WHERE id = :id";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':id', $id, PDO::PARAM_INT); 
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ecs'], "success", "index.php?p=imagem-perfil");
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
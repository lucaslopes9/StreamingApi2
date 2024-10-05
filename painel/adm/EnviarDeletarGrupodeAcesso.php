<?php
	include("conexao.php");
	include_once("functions.php");
	include_once(Idioma(1));
	if(ProtegePag() == true){
	global $_TRA;
	
	$ColunaAcesso = array('OpcoesGrupoAcesso');
	$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
	$OpcoesGrupoAcesso = $VerificarAcesso[0];

	if($OpcoesGrupoAcesso == 'S'){

	if ($_SERVER['REQUEST_METHOD'] == 'POST') {
 
	$id = (isset($_POST['id'])) ? $_POST['id'] : '';

	if(empty($id)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	else{
	
	$ExcluirPorUsuario = ExcluirPorGrupo($id);
	
	$CadUser = InfoUser(2);
	$SQL = "DELETE FROM grupodeacesso WHERE id = :id AND CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':id', $id, PDO::PARAM_INT); 
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ecs'], "success", "index.php?p=grupo-de-acesso");
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